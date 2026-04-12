/*
 * sentinel/collector_client.h
 *
 * CollectorClient forwards detection events from the service to a central
 * collector over HTTPS. It runs on its own background thread so the
 * detection path is never blocked by network I/O.
 *
 * Design:
 *   - enqueue() is the single public entry point. Non-blocking, never
 *     throws. Drops oldest on overflow.
 *   - A background sender thread drains the queue and POSTs batches
 *     to the collector with exponential backoff on transient failures.
 *   - start() launches the thread. stop() signals shutdown and joins.
 *
 * Thread safety: all public methods are safe to call from any thread.
 */

#ifndef SENTINEL_COLLECTOR_CLIENT_H
#define SENTINEL_COLLECTOR_CLIENT_H

#include <sentinel/collector_config.h>
#include <sentinel/collector_wire.h>
#include <sentinel/service.h>

#include <condition_variable>
#include <deque>

namespace sentinel {

class CollectorClient {
public:
    struct Stats {
        uint64_t queue_depth        = 0;
        uint64_t events_enqueued    = 0;
        uint64_t events_sent        = 0;
        uint64_t dropped_events     = 0;
        uint64_t retries_total      = 0;
        uint64_t permanent_failures = 0;
    };

    CollectorClient();
    ~CollectorClient();

    CollectorClient(const CollectorClient&) = delete;
    CollectorClient& operator=(const CollectorClient&) = delete;

    /**
     * Start the background sender thread.
     *
     * @param config  Collector configuration. If config.enabled is false,
     *                start() is a no-op and enqueue() drops silently.
     * @param host    Host info attached to every event.
     * @param version Sentinel service version string.
     */
    void start(const CollectorConfig& config,
               const CollectorHostInfo& host,
               const std::string& version);

    /** Signal shutdown and join the background thread. Safe to call multiple times. */
    void stop();

    /**
     * Enqueue a detection event for forwarding. Non-blocking.
     * If the queue is full, the oldest event is dropped.
     * If the client is not started (config.enabled == false), drops silently.
     */
    void enqueue(const DetectionEvent& event);

    /** Copy of the current stats. Thread-safe. */
    Stats get_stats() const;

private:
    /* Background worker loop. Runs until stop_requested_ is true. */
    void worker_loop();

    /* Collect up to COLLECTOR_MAX_BATCH_SIZE events from the queue into out.
     * Returns true if at least one event was drained. */
    bool drain_batch(std::vector<DetectionEvent>& out);

    /* Wait until either the queue has >= COLLECTOR_BATCH_THRESHOLD events,
     * COLLECTOR_FLUSH_INTERVAL_MS has passed, or stop was requested. */
    void wait_for_work();

    /* Send a batch to the collector. Returns true on 202 Accepted. Added in Task 15. */
    bool send_batch(const std::vector<DetectionEvent>& events);

    /* --- state --- */
    CollectorConfig     config_;
    CollectorHostInfo   host_;
    std::string         version_;

    mutable std::mutex          mutex_;
    std::condition_variable     cv_;
    std::deque<DetectionEvent>  queue_;
    bool                        stop_requested_ = false;
    bool                        started_        = false;
    std::thread                 worker_;

    mutable std::mutex stats_mutex_;
    Stats              stats_;
};

} /* namespace sentinel */

#endif /* SENTINEL_COLLECTOR_CLIENT_H */
