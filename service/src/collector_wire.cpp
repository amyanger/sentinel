/*
 * collector_wire.cpp — JSON serialization for wire format v1.
 *
 * We hand-roll JSON here (no nlohmann/json dependency) because:
 *   1. The schema is fixed and small.
 *   2. We only need to WRITE, never parse.
 *   3. Avoids adding a third-party dependency to the service build.
 *
 * Escaping follows RFC 8259 section 7: escape ", \, and control characters.
 * Non-ASCII UTF-8 is passed through unchanged (the collector is Go, which
 * handles UTF-8 natively in encoding/json).
 */

#include <sentinel/collector_wire.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <random>
#include <sstream>

namespace sentinel {

/* -------------------------------------------------------------------
 * JSON escape helper
 * ------------------------------------------------------------------- */
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        unsigned char uc = static_cast<unsigned char>(c);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (uc < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", uc);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

/* -------------------------------------------------------------------
 * Source → detection_type mapping
 * ------------------------------------------------------------------- */
const char* detection_type_for_source(AlertSource src) {
    switch (src) {
        case AlertSource::PCIE_ENUM:        return "PCIE_ENUM";
        case AlertSource::DMA_DETECT:       return "DMA_ANOMALY";
        case AlertSource::MEMORY:           return "MEMORY_INTEGRITY";
        case AlertSource::DEVICE_MONITOR:   return "DEVICE_MONITOR";
        case AlertSource::PROCESS_MONITOR:  return "PROCESS_MONITOR";
        case AlertSource::SIGNATURE_SCAN:   return "SIGNATURE_MATCH";
        case AlertSource::MODULE_INTEGRITY: return "MODULE_TAMPERING";
        default:                            return "UNKNOWN";
    }
}

const char* source_category(AlertSource src) {
    switch (src) {
        case AlertSource::PCIE_ENUM:
        case AlertSource::DMA_DETECT:
        case AlertSource::MEMORY:
        case AlertSource::DEVICE_MONITOR:
            return "driver";
        default:
            return "service";
    }
}

/* -------------------------------------------------------------------
 * UUIDv7 generator
 *
 * Format (RFC 9562):
 *   48 bits: unix_ts_ms
 *   4 bits:  version (0b0111)
 *   12 bits: rand_a
 *   2 bits:  variant (0b10)
 *   62 bits: rand_b
 *
 * Output: 8-4-4-4-12 hex, lowercase, with dashes.
 * ------------------------------------------------------------------- */
std::string generate_uuidv7() {
    using namespace std::chrono;
    uint64_t unix_ms = static_cast<uint64_t>(duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count());

    /* Thread-local RNG to avoid seeding on every call */
    thread_local std::mt19937_64 rng{std::random_device{}()};
    uint64_t rand_a = rng() & 0x0FFFULL;                    /* 12 bits */
    uint64_t rand_b = rng() & 0x3FFFFFFFFFFFFFFFULL;        /* 62 bits */

    /* Assemble 128 bits into two 64-bit halves */
    uint64_t hi = (unix_ms << 16)
                | (0x7000ULL)      /* version 7 */
                | rand_a;
    uint64_t lo = (0x2ULL << 62)   /* variant 0b10 */
                | rand_b;

    char buf[40];
    std::snprintf(buf, sizeof(buf),
        "%08x-%04x-%04x-%04x-%012llx",
        static_cast<uint32_t>((hi >> 32) & 0xFFFFFFFF),
        static_cast<uint32_t>((hi >> 16) & 0xFFFF),
        static_cast<uint32_t>(hi & 0xFFFF),
        static_cast<uint32_t>((lo >> 48) & 0xFFFF),
        static_cast<unsigned long long>(lo & 0xFFFFFFFFFFFFULL));
    return std::string(buf);
}

/* -------------------------------------------------------------------
 * Event serialization
 * ------------------------------------------------------------------- */
std::string serialize_event_json(const DetectionEvent& event,
                                  const std::string& client_id,
                                  const CollectorHostInfo& host,
                                  const std::string& version) {
    int confidence_int = static_cast<int>(event.confidence * 100.0);
    if (confidence_int < 0)   confidence_int = 0;
    if (confidence_int > 100) confidence_int = 100;

    std::ostringstream os;
    os << "{"
       << "\"schema_version\":1,"
       << "\"event_id\":\"" << generate_uuidv7() << "\","
       << "\"client_id\":\"" << json_escape(client_id) << "\","
       << "\"sentinel_version\":\"" << json_escape(version) << "\","
       << "\"timestamp\":\"" << format_timestamp(event.timestamp) << "\","
       << "\"source\":\"" << source_category(event.source) << "\","
       << "\"detection_type\":\"" << detection_type_for_source(event.source) << "\","
       << "\"severity\":\"" << severity_name(event.severity) << "\","
       << "\"confidence\":" << confidence_int << ","
       << "\"summary\":\"" << json_escape(event.description) << "\","
       << "\"host\":{"
           << "\"hostname\":\"" << json_escape(host.hostname) << "\","
           << "\"os_version\":\"" << json_escape(host.os_version) << "\","
           << "\"arch\":\"" << json_escape(host.arch) << "\""
       << "},"
       << "\"context\":{"
           << "\"process_id\":" << event.process_id
       << "}"
       << "}";
    return os.str();
}

std::string serialize_batch(const std::vector<std::string>& event_jsons) {
    std::ostringstream os;
    os << "{\"events\":[";
    for (size_t i = 0; i < event_jsons.size(); ++i) {
        if (i > 0) os << ",";
        os << event_jsons[i];
    }
    os << "]}";
    return os.str();
}

} /* namespace sentinel */
