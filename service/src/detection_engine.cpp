/*
 * detection_engine.cpp -- DetectionEngine implementation.
 *
 * The detection engine is the "brain" of the anticheat service. It
 * receives events from all detection sources and applies a confidence
 * scoring system to decide when to raise alarms.
 *
 * Scoring model:
 *   - Each event has a base confidence (0.0 - 1.0) from its source
 *   - The source weight multiplies this confidence (driver signals
 *     are weighted higher than process name matches)
 *   - Per-process scores are cumulative: multiple signals about the
 *     same process compound over a time window
 *   - When the cumulative score exceeds the threshold, an alert fires
 *
 * Why cumulative scoring?
 *   A single process name match might be a false positive (maybe the
 *   user has a process called "trainer.exe" that's unrelated). But if
 *   we also see an unexpected DLL injected into the game AND the driver
 *   reports a suspicious PCIe device, the cumulative evidence is strong.
 *   This is how real anticheat systems work -- defense in depth with
 *   correlated evidence.
 */

#include <sentinel/detection_engine.h>

namespace sentinel {

DetectionEngine::DetectionEngine()
    : threshold_(0.7)
    , stats_{} {
}

DetectionEngine::~DetectionEngine() {
    stop();
}

/* -------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------- */

void DetectionEngine::start(const ServiceConfig& config,
                             AlertCallback callback) {
    threshold_ = config.detection_threshold;
    callback_ = std::move(callback);

    /* Open the persistent detection log file. */
    log_file_.open(DETECTION_LOG_PATH, std::ios::app);
    if (!log_file_.is_open()) {
        std::fprintf(stderr,
            "[DetectionEngine] WARNING: Could not open log file %s\n",
            DETECTION_LOG_PATH);
    }
}

void DetectionEngine::stop() {
    if (log_file_.is_open()) {
        log_file_.flush();
        log_file_.close();
    }
}

/* -------------------------------------------------------------------
 * submit_event -- Single entry point for all detection signals.
 *
 * Thread safety: Acquires mutex_ to safely update shared state.
 * Multiple threads (driver poller, process scanner, etc.) call this
 * concurrently.
 * ------------------------------------------------------------------- */

void DetectionEngine::submit_event(const DetectionEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    /* Record in the full event history. */
    all_events_.push_back(event);

    /* Update per-source statistics. */
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.total_events_received++;

        /* Map AlertSource to a stats array index. */
        uint32_t source_idx = static_cast<uint32_t>(event.source);
        if (source_idx >= 100) {
            source_idx = source_idx - 100 + 4; /* User-mode sources at 4+ */
        }
        if (source_idx < 7) {
            stats_.events_by_source[source_idx]++;
        }
    }

    /* Add to per-process tracking. */
    auto& proc_signals = process_signals_[event.process_id];
    proc_signals.events.push_back(event);

    /* Compute the new cumulative score for this process. */
    double cumulative = compute_cumulative_score(event.process_id);
    if (cumulative > proc_signals.peak_score) {
        proc_signals.peak_score = cumulative;
    }

    /* Log every event to the persistent log. */
    log_event(event, cumulative);

    /*
     * Check if we've crossed the threshold for this process.
     * Only fire the callback once per process to avoid alert spam.
     */
    if (cumulative >= threshold_ && !proc_signals.alert_triggered) {
        proc_signals.alert_triggered = true;
        triggered_.push_back(event);

        {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.alerts_triggered++;
        }

        if (callback_) {
            callback_(event, cumulative);
        }
    }
}

/* -------------------------------------------------------------------
 * submit_driver_alert -- Convert a raw driver alert to a DetectionEvent.
 *
 * The driver uses its own alert format (SENTINEL_ALERT). We convert
 * it to our normalized DetectionEvent format and submit it through
 * the standard pipeline.
 * ------------------------------------------------------------------- */

void DetectionEngine::submit_driver_alert(const SENTINEL_ALERT& alert) {
    DetectionEvent event;

    /* Map driver source enum to our AlertSource enum. */
    switch (alert.source) {
        case SENTINEL_SOURCE_PCIE_ENUM:
            event.source = AlertSource::PCIE_ENUM;
            break;
        case SENTINEL_SOURCE_DMA_DETECT:
            event.source = AlertSource::DMA_DETECT;
            break;
        case SENTINEL_SOURCE_MEMORY:
            event.source = AlertSource::MEMORY;
            break;
        case SENTINEL_SOURCE_DEVICE_MONITOR:
            event.source = AlertSource::DEVICE_MONITOR;
            break;
        default:
            event.source = AlertSource::PCIE_ENUM;
            break;
    }

    /* Map driver severity. */
    event.severity = static_cast<SENTINEL_ALERT_SEVERITY>(alert.severity);

    /* Extract the message (null-terminated within the fixed buffer). */
    event.description = std::string(
        reinterpret_cast<const char*>(alert.message),
        strnlen(reinterpret_cast<const char*>(alert.message),
                sizeof(alert.message)));

    event.process_id = 0; /* Driver alerts are system-wide, not per-process. */

    /*
     * Assign confidence based on severity. Driver alerts are generally
     * high-quality signals, so we give them higher base confidence.
     */
    switch (event.severity) {
        case SENTINEL_SEVERITY_CRITICAL: event.confidence = 0.95; break;
        case SENTINEL_SEVERITY_HIGH:     event.confidence = 0.80; break;
        case SENTINEL_SEVERITY_MEDIUM:   event.confidence = 0.60; break;
        case SENTINEL_SEVERITY_LOW:      event.confidence = 0.30; break;
        default:                         event.confidence = 0.10; break;
    }

    event.timestamp = std::chrono::system_clock::now();

    submit_event(event);
}

/* -------------------------------------------------------------------
 * Query interface
 * ------------------------------------------------------------------- */

std::vector<DetectionEvent> DetectionEngine::get_all_events() const {
    std::lock_guard<std::mutex> lock(mutex_);

    /* Return in reverse chronological order. */
    std::vector<DetectionEvent> result(all_events_.rbegin(),
                                       all_events_.rend());
    return result;
}

std::vector<DetectionEvent> DetectionEngine::get_triggered_alerts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return triggered_;
}

DetectionEngine::Stats DetectionEngine::get_stats() const {
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    return stats_;
}

void DetectionEngine::set_threshold(double threshold) {
    std::lock_guard<std::mutex> lock(mutex_);
    threshold_ = threshold;
}

/* -------------------------------------------------------------------
 * source_weight -- How much we trust signals from each source.
 *
 * These weights reflect the relative reliability of each detection
 * source. Driver-level detections (hardware anomalies) are hard to
 * fake, so they get higher weights. Process name matches are easy
 * to evade, so they get lower weights.
 * ------------------------------------------------------------------- */

double DetectionEngine::source_weight(AlertSource source) {
    switch (source) {
        case AlertSource::DMA_DETECT:       return 1.0;  /* Strongest signal */
        case AlertSource::MEMORY:           return 0.9;
        case AlertSource::PCIE_ENUM:        return 0.85;
        case AlertSource::DEVICE_MONITOR:   return 0.8;
        case AlertSource::MODULE_INTEGRITY: return 0.75;
        case AlertSource::SIGNATURE_SCAN:   return 0.7;
        case AlertSource::PROCESS_MONITOR:  return 0.5;  /* Weakest signal */
        default:                            return 0.5;
    }
}

/* -------------------------------------------------------------------
 * compute_cumulative_score -- Sum all signals for a process.
 *
 * The formula is:
 *   cumulative = sum(event.confidence * source_weight(event.source) * decay)
 *   clamped to [0.0, 1.0]
 *
 * Time decay: older signals contribute less. A signal from 30 minutes
 * ago is worth half as much as a fresh one. This prevents stale
 * detections from accumulating indefinitely.
 *
 * Must be called with mutex_ held.
 * ------------------------------------------------------------------- */

double DetectionEngine::compute_cumulative_score(uint32_t pid) const {
    auto it = process_signals_.find(pid);
    if (it == process_signals_.end()) {
        return 0.0;
    }

    auto now = std::chrono::system_clock::now();
    double score = 0.0;

    for (const auto& event : it->second.events) {
        /* Time decay: half-life of 30 minutes. */
        auto age = std::chrono::duration_cast<std::chrono::minutes>(
            now - event.timestamp);
        double decay = 1.0 / (1.0 + (age.count() / 30.0));

        score += event.confidence * source_weight(event.source) * decay;
    }

    /* Clamp to [0.0, 1.0]. */
    if (score > 1.0) score = 1.0;
    if (score < 0.0) score = 0.0;

    return score;
}

/* -------------------------------------------------------------------
 * log_event -- Write an event to the persistent log file.
 *
 * Log format (one JSON object per line for easy parsing):
 *   {"time":"2026-04-11T12:00:00Z","source":"process_monitor",...}
 *
 * Must be called with mutex_ held.
 * ------------------------------------------------------------------- */

void DetectionEngine::log_event(const DetectionEvent& event,
                                 double cumulative_score) {
    if (!log_file_.is_open()) return;

    /*
     * Manual JSON formatting to avoid a library dependency.
     * Each log line is a self-contained JSON object for easy parsing.
     */
    log_file_ << "{"
              << "\"time\":\"" << format_timestamp(event.timestamp) << "\","
              << "\"source\":\"" << alert_source_name(event.source) << "\","
              << "\"severity\":\"" << severity_name(event.severity) << "\","
              << "\"pid\":" << event.process_id << ","
              << "\"confidence\":" << event.confidence << ","
              << "\"cumulative\":" << cumulative_score << ","
              << "\"description\":\"";

    /* Escape the description for JSON. */
    for (char c : event.description) {
        switch (c) {
            case '"':  log_file_ << "\\\""; break;
            case '\\': log_file_ << "\\\\"; break;
            case '\n': log_file_ << "\\n";  break;
            case '\r': log_file_ << "\\r";  break;
            case '\t': log_file_ << "\\t";  break;
            default:   log_file_ << c;       break;
        }
    }

    log_file_ << "\"}" << std::endl;
}

} /* namespace sentinel */
