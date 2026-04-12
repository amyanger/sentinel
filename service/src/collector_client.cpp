/*
 * collector_client.cpp
 *
 * Queue, worker thread, and send pipeline for forwarding detections to
 * the central collector.
 *
 * Task 14: queue + lifecycle + drain logic.
 * Task 15 adds the actual HTTPS send via WinHTTP.
 * Task 16 adds the retry/backoff state machine.
 */

#include <sentinel/collector_client.h>
#include <sentinel/collector_http.h>

#include <cstdio>

namespace sentinel {

CollectorClient::CollectorClient() = default;

CollectorClient::~CollectorClient() {
    stop();
}

void CollectorClient::start(const CollectorConfig& config,
                             const CollectorHostInfo& host,
                             const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (started_) return;
    config_  = config;
    host_    = host;
    version_ = version;
    if (!config_.enabled) {
        std::fprintf(stderr, "collector_client: disabled by config\n");
        return;
    }
    started_        = true;
    stop_requested_ = false;
    worker_ = std::thread(&CollectorClient::worker_loop, this);
    std::fprintf(stderr, "collector_client: started, target=%s\n",
                 config_.url.c_str());
}

void CollectorClient::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!started_) return;
        stop_requested_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
    std::lock_guard<std::mutex> lock(mutex_);
    started_ = false;
}

void CollectorClient::enqueue(const DetectionEvent& event) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!started_ || !config_.enabled) return;
        if (queue_.size() >= COLLECTOR_QUEUE_CAPACITY) {
            queue_.pop_front(); /* drop oldest */
            std::lock_guard<std::mutex> sl(stats_mutex_);
            stats_.dropped_events++;
        }
        queue_.push_back(event);
        std::lock_guard<std::mutex> sl(stats_mutex_);
        stats_.events_enqueued++;
        stats_.queue_depth = queue_.size();
    }
    cv_.notify_one();
}

CollectorClient::Stats CollectorClient::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

bool CollectorClient::drain_batch(std::vector<DetectionEvent>& out) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) return false;
    size_t take = queue_.size();
    if (take > COLLECTOR_MAX_BATCH_SIZE) take = COLLECTOR_MAX_BATCH_SIZE;
    out.reserve(take);
    for (size_t i = 0; i < take; ++i) {
        out.push_back(std::move(queue_.front()));
        queue_.pop_front();
    }
    {
        std::lock_guard<std::mutex> sl(stats_mutex_);
        stats_.queue_depth = queue_.size();
    }
    return true;
}

void CollectorClient::wait_for_work() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait_for(lock,
                 std::chrono::milliseconds(COLLECTOR_FLUSH_INTERVAL_MS),
                 [this] {
                     return stop_requested_ ||
                            queue_.size() >= COLLECTOR_BATCH_THRESHOLD;
                 });
}

void CollectorClient::worker_loop() {
    int backoff_ms = COLLECTOR_BACKOFF_INITIAL_MS;
    std::vector<DetectionEvent> pending; /* batch being retried */

    while (true) {
        if (pending.empty()) {
            wait_for_work();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stop_requested_ && queue_.empty()) break;
            }
            drain_batch(pending);
        }
        if (pending.empty()) continue;

        if (send_batch(pending)) {
            /* Success (or permanent drop — send_batch returned true). */
            {
                std::lock_guard<std::mutex> sl(stats_mutex_);
                stats_.events_sent += pending.size();
            }
            pending.clear();
            backoff_ms = COLLECTOR_BACKOFF_INITIAL_MS;
            continue;
        }

        /* Transient failure — retry with backoff. */
        {
            std::lock_guard<std::mutex> sl(stats_mutex_);
            stats_.retries_total++;
        }

        /* Check for shutdown during backoff. */
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(backoff_ms),
                     [this] { return stop_requested_; });
        if (stop_requested_) break;
        lock.unlock();

        backoff_ms *= 2;
        if (backoff_ms > COLLECTOR_BACKOFF_MAX_MS) {
            backoff_ms = COLLECTOR_BACKOFF_MAX_MS;
        }
    }
}

bool CollectorClient::send_batch(const std::vector<DetectionEvent>& events) {
    if (events.empty()) return true;

    /* Serialize each event, then wrap in a batch. */
    std::vector<std::string> jsons;
    jsons.reserve(events.size());
    for (const auto& e : events) {
        jsons.push_back(serialize_event_json(e, config_.client_id, host_, version_));
    }
    std::string body = serialize_batch(jsons);

    int http_status = 0;
    SendResult result = http_post_events(config_.url, config_.api_key, body, http_status);

    switch (result) {
        case SendResult::Accepted:
            return true;
        case SendResult::PermanentDrop:
            std::fprintf(stderr,
                "collector_client: permanent drop, status=%d, batch=%zu\n",
                http_status, events.size());
            {
                std::lock_guard<std::mutex> sl(stats_mutex_);
                stats_.permanent_failures++;
            }
            return true; /* "true" here means "do not retry" */
        case SendResult::CertError:
            std::fprintf(stderr,
                "collector_client: TLS cert verification failed, failing closed\n");
            {
                std::lock_guard<std::mutex> sl(stats_mutex_);
                stats_.permanent_failures++;
            }
            return true;
        case SendResult::RetryLater:
        default:
            std::fprintf(stderr,
                "collector_client: retry later, status=%d\n", http_status);
            return false; /* Task 16 will re-enqueue on false */
    }
}

} /* namespace sentinel */
