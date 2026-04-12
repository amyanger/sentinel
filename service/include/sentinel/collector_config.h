/*
 * sentinel/collector_config.h
 *
 * Compile-time defaults and runtime config struct for the collector client.
 *
 * Runtime values (URL, API key) come from:
 *   - collector_url:  service config file / REST API
 *   - api_key:        Windows credential store (not a config file)
 *
 * Compile-time tuning knobs (queue size, retry policy) live here because
 * MVP does not expose them via runtime config. Change them and rebuild.
 */

#ifndef SENTINEL_COLLECTOR_CONFIG_H
#define SENTINEL_COLLECTOR_CONFIG_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace sentinel {

/* -------------------------------------------------------------------------
 * Compile-time defaults
 * ------------------------------------------------------------------------- */

/* Maximum number of events the in-memory send queue will hold.
 * When full, the OLDEST event is dropped (not the newest) and the
 * dropped_events_total counter is incremented. */
constexpr std::size_t COLLECTOR_QUEUE_CAPACITY = 10000;

/* Maximum number of events per HTTPS POST batch. Must match the collector's
 * MaxBatchEvents constant in collector/internal/ingest/handler.go. */
constexpr std::size_t COLLECTOR_MAX_BATCH_SIZE = 100;

/* Send-trigger thresholds: flush when either condition is met. */
constexpr std::size_t COLLECTOR_BATCH_THRESHOLD = 10;    /* events */
constexpr int         COLLECTOR_FLUSH_INTERVAL_MS = 5000; /* ms */

/* Exponential backoff on retryable errors. */
constexpr int COLLECTOR_BACKOFF_INITIAL_MS = 1000;
constexpr int COLLECTOR_BACKOFF_MAX_MS     = 30000;

/* Credential store target name for the API key. */
constexpr const char* COLLECTOR_CREDENTIAL_TARGET = "SentinelCollectorApiKey";

/* -------------------------------------------------------------------------
 * Runtime config struct
 * ------------------------------------------------------------------------- */

struct CollectorConfig {
    bool        enabled = false;
    std::string url;           /* e.g., "https://collector.internal:8443" */
    std::string client_id;     /* registered with the collector */
    std::string api_key;       /* loaded from credential store at startup */
};

} /* namespace sentinel */

#endif /* SENTINEL_COLLECTOR_CONFIG_H */
