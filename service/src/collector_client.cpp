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
    while (true) {
        wait_for_work();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stop_requested_ && queue_.empty()) break;
        }
        std::vector<DetectionEvent> batch;
        if (!drain_batch(batch) || batch.empty()) continue;
        if (send_batch(batch)) {
            std::lock_guard<std::mutex> sl(stats_mutex_);
            stats_.events_sent += batch.size();
        }
        /* On failure, Task 16 will re-enqueue or retry. For now the
         * batch is dropped -- this is a STUB that Task 16 replaces. */
    }
}

/* Placeholder -- Task 15 replaces this with a real WinHTTP POST. */
bool CollectorClient::send_batch(const std::vector<DetectionEvent>& events) {
    std::fprintf(stderr, "collector_client: stub send_batch, %zu events\n",
                 events.size());
    return true;
}

} /* namespace sentinel */
