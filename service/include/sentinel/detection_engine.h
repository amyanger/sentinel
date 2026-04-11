/*
 * sentinel/detection_engine.h
 *
 * DetectionEngine is the brain of the service. It aggregates signals
 * from all detection sources (driver alerts + user-mode scans) and
 * applies a confidence scoring system to decide when to raise alarms.
 *
 * Philosophy: No single signal should trigger a detection on its own.
 * Instead, each signal contributes a weighted confidence score. When
 * the cumulative score for a process/timeframe exceeds a threshold,
 * an alert is raised. This reduces false positives dramatically.
 *
 * Scoring model:
 *   - Each detection source has a base weight (e.g., driver DMA
 *     detection has higher weight than a process name match)
 *   - Correlated signals (same process, close in time) compound
 *   - The final score is clamped to [0.0, 1.0]
 *   - Threshold is configurable (default 0.7)
 *
 * Thread safety: All public methods are safe to call from any thread.
 * Events arrive from multiple threads (driver poller, process scanner,
 * etc.) and are serialized internally via a mutex.
 */

#ifndef SENTINEL_DETECTION_ENGINE_H
#define SENTINEL_DETECTION_ENGINE_H

#include <sentinel/service.h>

namespace sentinel {

class DetectionEngine {
public:
    /* Callback for threshold-exceeding detections. */
    using AlertCallback = std::function<void(const DetectionEvent&, double cumulative_score)>;

    DetectionEngine();
    ~DetectionEngine();

    DetectionEngine(const DetectionEngine&) = delete;
    DetectionEngine& operator=(const DetectionEngine&) = delete;

    /* -------------------------------------------------------------------
     * Lifecycle
     * ------------------------------------------------------------------- */

    /**
     * Initialize the engine with a detection threshold and callback.
     *
     * @param config   Service configuration (contains threshold).
     * @param callback Called when cumulative score exceeds threshold.
     */
    void start(const ServiceConfig& config, AlertCallback callback);

    /** Flush pending state and stop. */
    void stop();

    /* -------------------------------------------------------------------
     * Event submission -- called by all detection modules.
     * ------------------------------------------------------------------- */

    /**
     * Submit a detection event for scoring and aggregation.
     * This is the single entry point for all detection signals.
     *
     * Thread-safe: can be called from any thread at any time.
     *
     * @param event  The detection event to process.
     */
    void submit_event(const DetectionEvent& event);

    /**
     * Submit a driver alert, converting it to a DetectionEvent first.
     *
     * @param alert  Raw alert from the driver.
     */
    void submit_driver_alert(const SENTINEL_ALERT& alert);

    /* -------------------------------------------------------------------
     * Query interface -- used by the API server.
     * ------------------------------------------------------------------- */

    /** Get all recorded events (most recent first). */
    std::vector<DetectionEvent> get_all_events() const;

    /** Get events with cumulative score above the threshold. */
    std::vector<DetectionEvent> get_triggered_alerts() const;

    /** Get summary statistics. */
    struct Stats {
        uint64_t total_events_received;
        uint64_t alerts_triggered;
        uint64_t events_by_source[7]; /* Indexed by AlertSource value */
    };
    Stats get_stats() const;

    /** Update the detection threshold at runtime. */
    void set_threshold(double threshold);

private:
    /* -------------------------------------------------------------------
     * Internal scoring
     * ------------------------------------------------------------------- */

    /**
     * Get the base weight for a detection source.
     * Higher weight = more trusted signal.
     */
    static double source_weight(AlertSource source);

    /**
     * Compute the cumulative score for a process by summing all recent
     * signals with time decay.
     *
     * @param pid  Target process ID.
     * @return Cumulative confidence score [0.0, 1.0].
     */
    double compute_cumulative_score(uint32_t pid) const;

    /** Log a detection event to the persistent log file. */
    void log_event(const DetectionEvent& event, double cumulative_score);

    /* -------------------------------------------------------------------
     * Per-process tracking: all signals for a given process are grouped
     * together so correlated signals compound properly.
     * ------------------------------------------------------------------- */
    struct ProcessSignals {
        std::vector<DetectionEvent> events;
        double peak_score = 0.0;
        bool alert_triggered = false;
    };

    /* --- State --- */
    mutable std::mutex    mutex_;
    std::unordered_map<uint32_t, ProcessSignals> process_signals_;
    std::vector<DetectionEvent> all_events_;    /* Full event history     */
    std::vector<DetectionEvent> triggered_;     /* Threshold-exceeding    */
    AlertCallback         callback_;
    double                threshold_;
    std::ofstream         log_file_;

    /* Statistics */
    mutable std::mutex    stats_mutex_;
    Stats                 stats_;
};

} /* namespace sentinel */

#endif /* SENTINEL_DETECTION_ENGINE_H */
