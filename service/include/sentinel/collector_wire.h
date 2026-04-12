/*
 * sentinel/collector_wire.h
 *
 * Wire format serializer for detection events sent to the collector.
 * Translates sentinel::DetectionEvent (internal C++ type) into the JSON
 * shape defined by the collector's schema v1.
 *
 * This is DELIBERATELY decoupled from detection_event_t and from the
 * driver's SENTINEL_ALERT. The internal types are optimized for fast,
 * in-process use; the wire type is optimized for stable, versioned
 * cross-host transmission. Changing one must not force a change in
 * the other.
 *
 * Output shape (schema_version = 1):
 * {
 *   "schema_version": 1,
 *   "event_id": "<uuid>",
 *   "client_id": "<from config>",
 *   "sentinel_version": "0.3.1",
 *   "timestamp": "2026-04-12T...",
 *   "source": "driver"|"service",
 *   "detection_type": "DMA_ANOMALY",
 *   "severity": "high",
 *   "confidence": 80,
 *   "summary": "...",
 *   "host": { "hostname": "...", "os_version": "...", "arch": "x64" },
 *   "context": { ... }
 * }
 */

#ifndef SENTINEL_COLLECTOR_WIRE_H
#define SENTINEL_COLLECTOR_WIRE_H

#include <sentinel/service.h>

namespace sentinel {

struct CollectorHostInfo {
    std::string hostname;
    std::string os_version;
    std::string arch;          /* "x64", "arm64" */
};

/**
 * Serialize a DetectionEvent into a JSON string matching the collector's
 * schema v1. Generates a UUIDv7 for event_id.
 *
 * @param event        The detection event to serialize.
 * @param client_id    Stable client identifier (from CollectorConfig).
 * @param host         Host info for the "host" object.
 * @param version      Sentinel service version string (e.g., "0.3.1").
 * @return JSON string, UTF-8 encoded, ready for the POST body.
 */
std::string serialize_event_json(const DetectionEvent& event,
                                  const std::string& client_id,
                                  const CollectorHostInfo& host,
                                  const std::string& version);

/**
 * Wrap one or more event JSON strings into a batch body.
 * Input: [`{"schema_version":1,...}`, `{"schema_version":1,...}`]
 * Output: `{"events":[{"schema_version":1,...},{"schema_version":1,...}]}`
 */
std::string serialize_batch(const std::vector<std::string>& event_jsons);

/**
 * Generate a UUIDv7 as a lowercase hex string with dashes.
 * Format: xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx where y is 8,9,a,b.
 */
std::string generate_uuidv7();

/**
 * Convert AlertSource enum to the wire "detection_type" string.
 * Driver sources → "DMA_ANOMALY", "PCIE_ENUM", etc.
 * Service sources → "PROCESS_MONITOR", "SIGNATURE_SCAN", "MODULE_INTEGRITY".
 */
const char* detection_type_for_source(AlertSource src);

/**
 * Return "driver" if src is a driver-side source (0-3), "service" otherwise.
 */
const char* source_category(AlertSource src);

} /* namespace sentinel */

#endif /* SENTINEL_COLLECTOR_WIRE_H */
