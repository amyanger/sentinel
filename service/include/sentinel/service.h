/*
 * sentinel/service.h
 *
 * Main service header for the Sentinel anticheat user-mode service.
 * Provides common includes, forward declarations, and shared utilities
 * used across all service modules.
 *
 * Design note: This is the "umbrella header" that every .cpp file in
 * the service includes. It pulls in the shared IOCTL contract types
 * and provides common definitions specific to the service layer.
 */

#ifndef SENTINEL_SERVICE_H
#define SENTINEL_SERVICE_H

/* --- Platform headers ------------------------------------------------
 * We target Windows, but provide stubs so static analysis and IDE
 * features work on macOS (where we edit the source).
 * ------------------------------------------------------------------- */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
/* Minimal stubs for non-Windows editing -- never used at runtime. */
#include <cstdint>
using HANDLE = void*;
using DWORD  = uint32_t;
using BOOL   = int;
using BYTE   = uint8_t;
using WORD   = uint16_t;
using HMODULE = void*;
using SOCKET = int;
using SERVICE_STATUS_HANDLE = void*;
constexpr HANDLE INVALID_HANDLE_VALUE = reinterpret_cast<HANDLE>(static_cast<long long>(-1));
constexpr SOCKET INVALID_SOCKET = static_cast<SOCKET>(-1);
constexpr int TRUE = 1;
constexpr int FALSE = 0;
struct SERVICE_STATUS { DWORD dwCurrentState; };
#endif

/* --- Standard library ------------------------------------------------ */
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cstdio>
#include <cstring>

/* --- Shared contract headers ----------------------------------------- */
#include <sentinel/ioctl_codes.h>
#include <sentinel/shared_types.h>
#include <sentinel/collector_config.h>

/* --- Service-wide constants ------------------------------------------ */
namespace sentinel {

/* Device path for opening a handle to the Sentinel kernel driver. */
constexpr const char* DRIVER_DEVICE_PATH = "\\\\.\\Sentinel";

/* Default port for the REST API server (localhost only). */
constexpr int API_SERVER_PORT = 8088;

/* Default interval (ms) between driver alert polls. */
constexpr int DEFAULT_POLL_INTERVAL_MS = 500;

/* Default interval (ms) between process scans. */
constexpr int DEFAULT_SCAN_INTERVAL_MS = 2000;

/* Log file path for detection events. */
constexpr const char* DETECTION_LOG_PATH = "C:\\ProgramData\\Sentinel\\detections.log";

/* Signature database path. */
constexpr const char* SIGNATURE_DB_PATH = "C:\\ProgramData\\Sentinel\\signatures.db";

/* Known-good hash database path. */
constexpr const char* HASH_DB_PATH = "C:\\ProgramData\\Sentinel\\hashes.db";

/* Cheat name database path. */
constexpr const char* CHEAT_NAMES_DB_PATH = "C:\\ProgramData\\Sentinel\\cheatnames.db";

/* -------------------------------------------------------------------
 * Forward declarations for all service modules.
 * Each module is a self-contained class with start/stop lifecycle.
 * ------------------------------------------------------------------- */
class DriverComm;
class ProcessMonitor;
class SignatureScanner;
class ModuleIntegrity;
class DetectionEngine;
class ApiServer;

/* -------------------------------------------------------------------
 * AlertSource -- user-mode alert sources extend the driver's enum.
 *
 * The driver defines sources 0-3 (SENTINEL_SOURCE_*). The service
 * adds its own source identifiers starting at 100 to avoid collision.
 * ------------------------------------------------------------------- */
enum class AlertSource : uint32_t {
    /* Mirror driver sources for unified handling */
    PCIE_ENUM       = SENTINEL_SOURCE_PCIE_ENUM,
    DMA_DETECT      = SENTINEL_SOURCE_DMA_DETECT,
    MEMORY          = SENTINEL_SOURCE_MEMORY,
    DEVICE_MONITOR  = SENTINEL_SOURCE_DEVICE_MONITOR,

    /* User-mode sources (100+) */
    PROCESS_MONITOR  = 100,
    SIGNATURE_SCAN   = 101,
    MODULE_INTEGRITY = 102
};

/* -------------------------------------------------------------------
 * DetectionEvent -- a normalized detection from any source.
 *
 * All detection modules produce these events, which the DetectionEngine
 * aggregates and scores. This is the common currency of the system.
 * ------------------------------------------------------------------- */
struct DetectionEvent {
    AlertSource source;              /* Which module generated this    */
    SENTINEL_ALERT_SEVERITY severity;/* How serious is this signal     */
    std::string description;         /* Human-readable explanation     */
    uint32_t process_id;             /* Target process (0 if N/A)      */
    double confidence;               /* 0.0 - 1.0, how sure we are    */
    std::chrono::system_clock::time_point timestamp;
};

/* -------------------------------------------------------------------
 * ServiceConfig -- runtime configuration for the service.
 * Mutable via the REST API. Protected by a mutex in practice.
 * ------------------------------------------------------------------- */
struct ServiceConfig {
    int poll_interval_ms    = DEFAULT_POLL_INTERVAL_MS;
    int scan_interval_ms    = DEFAULT_SCAN_INTERVAL_MS;
    double detection_threshold = 0.7;  /* Confidence to trigger alert  */
    bool enable_process_monitor = true;
    bool enable_signature_scan  = true;
    bool enable_module_integrity = true;
    CollectorConfig collector;          /* Forwarding to central collector */
};

/* -------------------------------------------------------------------
 * Utility: format a timestamp as ISO 8601 string.
 * Used by the detection logger and API responses.
 * ------------------------------------------------------------------- */
inline std::string format_timestamp(std::chrono::system_clock::time_point tp) {
    auto time_t_val = std::chrono::system_clock::to_time_t(tp);
    struct tm tm_buf;
#ifdef _WIN32
    gmtime_s(&tm_buf, &time_t_val);
#else
    gmtime_r(&time_t_val, &tm_buf);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return std::string(buf);
}

/* -------------------------------------------------------------------
 * Utility: convert AlertSource enum to a human-readable string.
 * ------------------------------------------------------------------- */
inline const char* alert_source_name(AlertSource src) {
    switch (src) {
        case AlertSource::PCIE_ENUM:        return "pcie_enum";
        case AlertSource::DMA_DETECT:       return "dma_detect";
        case AlertSource::MEMORY:           return "memory_integrity";
        case AlertSource::DEVICE_MONITOR:   return "device_monitor";
        case AlertSource::PROCESS_MONITOR:  return "process_monitor";
        case AlertSource::SIGNATURE_SCAN:   return "signature_scan";
        case AlertSource::MODULE_INTEGRITY: return "module_integrity";
        default:                            return "unknown";
    }
}

/* -------------------------------------------------------------------
 * Utility: convert severity enum to a human-readable string.
 * ------------------------------------------------------------------- */
inline const char* severity_name(SENTINEL_ALERT_SEVERITY sev) {
    switch (sev) {
        case SENTINEL_SEVERITY_INFO:     return "info";
        case SENTINEL_SEVERITY_LOW:      return "low";
        case SENTINEL_SEVERITY_MEDIUM:   return "medium";
        case SENTINEL_SEVERITY_HIGH:     return "high";
        case SENTINEL_SEVERITY_CRITICAL: return "critical";
        default:                         return "unknown";
    }
}

} /* namespace sentinel */

#endif /* SENTINEL_SERVICE_H */
