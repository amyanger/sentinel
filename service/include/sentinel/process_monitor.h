/*
 * sentinel/process_monitor.h
 *
 * ProcessMonitor watches the system's running processes for signs of
 * cheat tools and injection techniques. It's one of the user-mode
 * detection pillars -- while the driver watches hardware, this module
 * watches software.
 *
 * Detection strategies:
 *   1. Known cheat tool detection: hash-based lookup of process names
 *   2. DLL injection detection: scan loaded modules for unexpected DLLs
 *   3. Suspicious relationships: flag unusual parent-child process trees
 *
 * Thread safety: The scan runs on a dedicated background thread.
 * Detection events are delivered through a thread-safe callback.
 */

#ifndef SENTINEL_PROCESS_MONITOR_H
#define SENTINEL_PROCESS_MONITOR_H

#include <sentinel/service.h>

namespace sentinel {

class ProcessMonitor {
public:
    /* Callback type for delivering detections to the engine. */
    using DetectionCallback = std::function<void(const DetectionEvent&)>;

    ProcessMonitor();
    ~ProcessMonitor();

    ProcessMonitor(const ProcessMonitor&) = delete;
    ProcessMonitor& operator=(const ProcessMonitor&) = delete;

    /* -------------------------------------------------------------------
     * Lifecycle
     * ------------------------------------------------------------------- */

    /**
     * Start the process monitoring loop.
     *
     * @param scan_interval_ms  How often to scan processes (milliseconds).
     * @param callback          Function called for each detection.
     */
    void start(int scan_interval_ms, DetectionCallback callback);

    /** Stop the monitoring loop. Safe to call multiple times. */
    void stop();

    /** Returns true if the monitor is actively scanning. */
    bool is_running() const;

    /* -------------------------------------------------------------------
     * Manual operations (useful for on-demand scanning)
     * ------------------------------------------------------------------- */

    /** Run a single full scan immediately and return any detections. */
    std::vector<DetectionEvent> scan_once();

private:
    /* --- Internal detection routines --- */

    /**
     * Enumerate all running processes using CreateToolhelp32Snapshot.
     * Returns a list of (pid, process_name) pairs.
     */
    struct ProcessInfo {
        DWORD pid;
        std::string name;
        DWORD parent_pid;
    };
    std::vector<ProcessInfo> enumerate_processes();

    /**
     * Check if a process name matches our known cheat tool database.
     * Uses a precomputed hash for fast O(1) lookup.
     *
     * @param name_lower  Lowercase process name.
     * @return true if this is a known cheat tool.
     */
    bool is_known_cheat_tool(const std::string& name_lower) const;

    /**
     * Enumerate loaded modules for a process and check for injected DLLs.
     *
     * @param pid  Target process ID.
     * @return Detection events for any suspicious modules found.
     */
    std::vector<DetectionEvent> check_injected_dlls(DWORD pid, const std::string& process_name);

    /**
     * Analyze parent-child process relationships for anomalies.
     * For example: a game process spawned by a known injector.
     *
     * @param processes  Full process list from enumerate_processes().
     * @return Detection events for suspicious relationships.
     */
    std::vector<DetectionEvent> check_process_relationships(
        const std::vector<ProcessInfo>& processes);

    /**
     * Compute a simple hash of a string. Used for fast name lookups
     * against the known cheat tool database.
     */
    static uint32_t hash_name(const std::string& name);

    /** Background thread entry point. */
    void scan_loop();

    /* --- State --- */
    std::atomic<bool>     running_;
    std::thread           scan_thread_;
    int                   scan_interval_ms_;
    DetectionCallback     callback_;

    /*
     * Known cheat tool name hashes. We store hashes instead of plaintext
     * names so the binary doesn't contain a readable cheat tool list
     * (mild obfuscation -- not cryptographic security).
     */
    std::unordered_set<uint32_t> known_cheat_hashes_;

    /*
     * Set of DLL name hashes known to be legitimate system/game DLLs.
     * Anything loaded that isn't in this set gets flagged for review.
     */
    std::unordered_set<uint32_t> known_good_dll_hashes_;

    /** Initialize the known cheat tool and DLL hash databases. */
    void init_databases();

    /**
     * Load additional cheat tool names from a file-based database.
     * Merges with the hardcoded set.
     */
    void load_cheat_database(const std::string& db_path);

    /**
     * Check a process for suspicious privileges (SE_DEBUG_NAME).
     */
    std::vector<DetectionEvent> check_process_privileges(
        DWORD pid, const std::string& process_name);

#ifdef _WIN32
    /** Cached LUID for SeDebugPrivilege, resolved once in constructor. */
    LUID debug_privilege_luid_;
    bool debug_privilege_luid_valid_ = false;
#endif
};

} /* namespace sentinel */

#endif /* SENTINEL_PROCESS_MONITOR_H */
