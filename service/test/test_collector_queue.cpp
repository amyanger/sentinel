/*
 * Unit tests for CollectorClient queue behavior.
 *
 * We link collector_client.cpp directly into the test binary and provide
 * a fake http_post_events below. This lets us drive the send pipeline
 * without touching the network.
 */

#include <sentinel/collector_http.h>

// Fake http_post_events for unit tests. Tests set g_fake_result to control
// what the next POST attempt returns.
namespace sentinel {
static SendResult g_fake_result = SendResult::Accepted;
SendResult http_post_events(const std::string&, const std::string&,
                             const std::string&, int& http_status) {
    http_status = (g_fake_result == SendResult::Accepted)      ? 202 :
                  (g_fake_result == SendResult::PermanentDrop) ? 400 :
                  (g_fake_result == SendResult::CertError)     ? 0   : 503;
    return g_fake_result;
}
} // namespace sentinel

#include <gtest/gtest.h>
#include <sentinel/collector_client.h>

#include <chrono>
#include <thread>

using namespace sentinel;

static DetectionEvent make_event(int id) {
    DetectionEvent e{};
    e.source      = AlertSource::DMA_DETECT;
    e.severity    = SENTINEL_SEVERITY_HIGH;
    e.description = "test-" + std::to_string(id);
    e.process_id  = static_cast<uint32_t>(id);
    e.confidence  = 0.8;
    e.timestamp   = std::chrono::system_clock::now();
    return e;
}

static CollectorConfig make_config() {
    CollectorConfig c;
    c.enabled   = true;
    c.url       = "https://localhost:1";
    c.client_id = "test";
    c.api_key   = "k";
    return c;
}

TEST(CollectorQueue, DisabledEnqueueIsNoOp) {
    CollectorClient cc;
    CollectorConfig disabled = make_config();
    disabled.enabled = false;
    cc.start(disabled, {"h", "o", "x64"}, "test");
    cc.enqueue(make_event(1));
    auto s = cc.get_stats();
    EXPECT_EQ(s.events_enqueued, 0u);
    cc.stop();
}

TEST(CollectorQueue, EnqueueAndSendHappyPath) {
    g_fake_result = SendResult::Accepted;
    CollectorClient cc;
    cc.start(make_config(), {"h", "o", "x64"}, "test");
    for (int i = 0; i < 5; ++i) cc.enqueue(make_event(i));

    // Give the worker a moment to drain.
    for (int i = 0; i < 50; ++i) {
        if (cc.get_stats().events_sent >= 5) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    auto s = cc.get_stats();
    EXPECT_GE(s.events_enqueued, 5u);
    EXPECT_GE(s.events_sent, 5u);
    EXPECT_EQ(s.dropped_events, 0u);
    cc.stop();
}

TEST(CollectorQueue, OverflowDropsOldest) {
    g_fake_result = SendResult::RetryLater; // Keep queue full by failing sends.
    CollectorClient cc;
    cc.start(make_config(), {"h", "o", "x64"}, "test");

    // Fill beyond capacity.
    for (std::size_t i = 0; i < COLLECTOR_QUEUE_CAPACITY + 50; ++i) {
        cc.enqueue(make_event(static_cast<int>(i)));
    }
    auto s = cc.get_stats();
    EXPECT_GE(s.dropped_events, 50u);
    cc.stop();
}

TEST(CollectorQueue, PermanentDropIncrementsPermanentFailures) {
    g_fake_result = SendResult::PermanentDrop;
    CollectorClient cc;
    cc.start(make_config(), {"h", "o", "x64"}, "test");
    cc.enqueue(make_event(1));

    // Wait up to ~5s for the worker to see the event, send it, and
    // classify the 400 as a permanent failure.
    for (int i = 0; i < 50; ++i) {
        if (cc.get_stats().permanent_failures > 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    auto s = cc.get_stats();
    EXPECT_GE(s.permanent_failures, 1u);
    cc.stop();
}
