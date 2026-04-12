/*
 * Unit tests for the wire format serializer.
 */

#include <gtest/gtest.h>
#include <sentinel/collector_wire.h>

#include <chrono>

using namespace sentinel;

static DetectionEvent sample_event() {
    DetectionEvent e{};
    e.source      = AlertSource::DMA_DETECT;
    e.severity    = SENTINEL_SEVERITY_HIGH;
    e.description = "Unknown PCIe device";
    e.process_id  = 1234;
    e.confidence  = 0.87;
    e.timestamp   = std::chrono::system_clock::from_time_t(1712931807); // 2024-04-12
    return e;
}

TEST(Wire, UUIDv7Shape) {
    std::string id = generate_uuidv7();
    ASSERT_EQ(id.size(), 36u);
    EXPECT_EQ(id[8],  '-');
    EXPECT_EQ(id[13], '-');
    EXPECT_EQ(id[14], '7'); // version nibble
    EXPECT_EQ(id[18], '-');
    EXPECT_EQ(id[23], '-');
}

TEST(Wire, UUIDv7Unique) {
    auto a = generate_uuidv7();
    auto b = generate_uuidv7();
    EXPECT_NE(a, b);
}

TEST(Wire, SerializeEventContainsExpectedFields) {
    std::string j = serialize_event_json(
        sample_event(), "acme-07", {"h", "Win11", "x64"}, "0.3.1");

    EXPECT_NE(j.find("\"schema_version\":1"), std::string::npos);
    EXPECT_NE(j.find("\"client_id\":\"acme-07\""), std::string::npos);
    EXPECT_NE(j.find("\"sentinel_version\":\"0.3.1\""), std::string::npos);
    EXPECT_NE(j.find("\"source\":\"driver\""), std::string::npos);
    EXPECT_NE(j.find("\"detection_type\":\"DMA_ANOMALY\""), std::string::npos);
    EXPECT_NE(j.find("\"severity\":\"high\""), std::string::npos);
    EXPECT_NE(j.find("\"confidence\":87"), std::string::npos);
    EXPECT_NE(j.find("\"summary\":\"Unknown PCIe device\""), std::string::npos);
    EXPECT_NE(j.find("\"hostname\":\"h\""), std::string::npos);
}

TEST(Wire, SerializeEscapesQuotes) {
    DetectionEvent e = sample_event();
    e.description = R"(evil"injection)";
    std::string j = serialize_event_json(e, "c", {"h", "o", "x64"}, "1");
    // The embedded " should become \"
    EXPECT_NE(j.find("evil\\\"injection"), std::string::npos);
}

TEST(Wire, SerializeBatchWrapsEvents) {
    std::vector<std::string> events = {
        R"({"schema_version":1,"a":1})",
        R"({"schema_version":1,"b":2})"
    };
    std::string batch = serialize_batch(events);
    EXPECT_EQ(batch,
        R"({"events":[{"schema_version":1,"a":1},{"schema_version":1,"b":2})" "]}");
}
