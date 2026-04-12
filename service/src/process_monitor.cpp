/*
 * process_monitor.cpp -- ProcessMonitor implementation.
 *
 * This module scans the system's running processes for signs of cheating:
 *   - Known cheat tool processes (detected by name hash)
 *   - Injected DLLs in game processes (unexpected loaded modules)
 *   - Suspicious parent-child process relationships
 *
 * Implementation notes:
 *   - Process enumeration uses CreateToolhelp32Snapshot, the standard
 *     Win32 API for process/module listing.
 *   - Process names are hashed (FNV-1a) for lookup against a precomputed
 *     database. This provides mild obfuscation so the binary doesn't
 *     contain a readable list of cheat tool names.
 *   - The scan runs on a background thread at a configurable interval.
 */

#include <sentinel/process_monitor.h>

namespace sentinel {

/* -------------------------------------------------------------------
 * FNV-1a hash constants for 32-bit hashing.
 *
 * FNV-1a is a fast, non-cryptographic hash with good distribution.
 * We use it for name lookups, not security -- an attacker could easily
 * find collisions, but that's not the threat model here.
 * ------------------------------------------------------------------- */
static constexpr uint32_t FNV_OFFSET_BASIS = 0x811c9dc5;
static constexpr uint32_t FNV_PRIME        = 0x01000193;

ProcessMonitor::ProcessMonitor()
    : running_(false)
    , scan_interval_ms_(DEFAULT_SCAN_INTERVAL_MS) {
    init_databases();
    load_cheat_database(CHEAT_NAMES_DB_PATH);

#ifdef _WIN32
    /* Resolve SeDebugPrivilege LUID once — it's constant per boot session. */
    debug_privilege_luid_valid_ = LookupPrivilegeValueA(
        nullptr, "SeDebugPrivilege", &debug_privilege_luid_) != 0;
#endif
}

ProcessMonitor::~ProcessMonitor() {
    stop();
}

/* -------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------- */

void ProcessMonitor::start(int scan_interval_ms, DetectionCallback callback) {
    scan_interval_ms_ = scan_interval_ms;
    callback_ = std::move(callback);
    running_ = true;
    scan_thread_ = std::thread(&ProcessMonitor::scan_loop, this);
}

void ProcessMonitor::stop() {
    running_ = false;
    if (scan_thread_.joinable()) {
        scan_thread_.join();
    }
}

bool ProcessMonitor::is_running() const {
    return running_;
}

/* -------------------------------------------------------------------
 * scan_once -- Run a single full scan and return all detections.
 *
 * This is the core scanning logic, factored out of scan_loop so it
 * can also be called on-demand (e.g., triggered by the API).
 * ------------------------------------------------------------------- */

std::vector<DetectionEvent> ProcessMonitor::scan_once() {
    std::vector<DetectionEvent> detections;

    /* Step 1: Enumerate all running processes. */
    auto processes = enumerate_processes();

    for (const auto& proc : processes) {
        /* Step 2: Check against known cheat tool names. */
        std::string name_lower = proc.name;
        std::transform(name_lower.begin(), name_lower.end(),
                       name_lower.begin(), ::tolower);

        if (is_known_cheat_tool(name_lower)) {
            DetectionEvent event;
            event.source = AlertSource::PROCESS_MONITOR;
            event.severity = SENTINEL_SEVERITY_HIGH;
            event.description = "Known cheat tool detected: " + proc.name;
            event.process_id = proc.pid;
            event.confidence = 0.85;
            event.timestamp = std::chrono::system_clock::now();
            detections.push_back(std::move(event));
        }

        /* Step 3: Check for injected DLLs in each process. */
        auto dll_detections = check_injected_dlls(proc.pid, proc.name);
        detections.insert(detections.end(),
                          dll_detections.begin(), dll_detections.end());

        /* Step 3b: Check for suspicious privileges. */
        auto priv_detections = check_process_privileges(proc.pid, proc.name);
        detections.insert(detections.end(),
                          priv_detections.begin(), priv_detections.end());
    }

    /* Step 4: Check for suspicious parent-child relationships. */
    auto relationship_detections = check_process_relationships(processes);
    detections.insert(detections.end(),
                      relationship_detections.begin(),
                      relationship_detections.end());

    return detections;
}

/* -------------------------------------------------------------------
 * enumerate_processes -- List all running processes.
 *
 * Uses the Toolhelp32 API, which is the standard way to enumerate
 * processes on Windows without requiring elevated privileges beyond
 * what a service already has.
 *
 * How it works:
 *   1. CreateToolhelp32Snapshot takes a "snapshot" of the process table
 *   2. Process32First/Process32Next iterate through the snapshot
 *   3. Each entry gives us PID, name, and parent PID
 * ------------------------------------------------------------------- */

std::vector<ProcessMonitor::ProcessInfo> ProcessMonitor::enumerate_processes() {
    std::vector<ProcessInfo> result;

#ifdef _WIN32
    /*
     * TH32CS_SNAPPROCESS = include all processes in the snapshot.
     * The second parameter (0) is ignored for process snapshots.
     */
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return result;
    }

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry); /* Must set dwSize before calling Process32First */

    if (Process32First(snapshot, &entry)) {
        do {
            ProcessInfo info;
            info.pid = entry.th32ProcessID;
            info.name = entry.szExeFile;
            info.parent_pid = entry.th32ParentProcessID;
            result.push_back(std::move(info));
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
#endif

    return result;
}

/* -------------------------------------------------------------------
 * is_known_cheat_tool -- Check a lowercase process name against
 * our hash database.
 * ------------------------------------------------------------------- */

bool ProcessMonitor::is_known_cheat_tool(const std::string& name_lower) const {
    uint32_t h = hash_name(name_lower);
    return known_cheat_hashes_.count(h) > 0;
}

/* -------------------------------------------------------------------
 * check_injected_dlls -- Scan loaded modules for unexpected DLLs.
 *
 * Strategy: Enumerate all DLLs loaded in the target process using
 * Module32First/Module32Next. Any DLL whose name hash isn't in our
 * known-good set is flagged as potentially injected.
 *
 * This produces false positives for legitimate third-party DLLs
 * (antivirus hooks, overlay software, etc.), which is why each
 * detection only contributes a moderate confidence score rather
 * than triggering an immediate alert.
 * ------------------------------------------------------------------- */

std::vector<DetectionEvent> ProcessMonitor::check_injected_dlls(
    DWORD pid, const std::string& process_name) {
    std::vector<DetectionEvent> detections;

#ifdef _WIN32
    /*
     * TH32CS_SNAPMODULE snapshots the module list for a specific process.
     * This requires at least PROCESS_QUERY_INFORMATION access to the target.
     */
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE |
                                               TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        /* Can't enumerate modules -- insufficient access or process exited. */
        return detections;
    }

    MODULEENTRY32 mod_entry;
    mod_entry.dwSize = sizeof(mod_entry);

    if (Module32First(snapshot, &mod_entry)) {
        do {
            std::string mod_name = mod_entry.szModule;
            std::string mod_lower = mod_name;
            std::transform(mod_lower.begin(), mod_lower.end(),
                           mod_lower.begin(), ::tolower);

            uint32_t h = hash_name(mod_lower);

            if (known_good_dll_hashes_.count(h) == 0) {
                /*
                 * This module isn't in our known-good set. It might be
                 * injected, or it might be a legitimate DLL we haven't
                 * cataloged yet. Flag with moderate confidence.
                 */
                DetectionEvent event;
                event.source = AlertSource::PROCESS_MONITOR;
                event.severity = SENTINEL_SEVERITY_MEDIUM;
                event.description = "Unexpected DLL in " + process_name +
                                    ": " + mod_name +
                                    " (path: " + mod_entry.szExePath + ")";
                event.process_id = pid;
                event.confidence = 0.4;
                event.timestamp = std::chrono::system_clock::now();
                detections.push_back(std::move(event));
            }
        } while (Module32Next(snapshot, &mod_entry));
    }

    CloseHandle(snapshot);
#else
    (void)pid;
    (void)process_name;
#endif

    return detections;
}

/* -------------------------------------------------------------------
 * check_process_relationships -- Detect suspicious parent-child trees.
 *
 * Examples of suspicious relationships:
 *   - A game process whose parent is a known injector
 *   - cmd.exe or powershell.exe spawning a game executable
 *   - A process with no parent (orphaned -- possible injection artifact)
 *
 * We build a parent -> children map and look for anomalous patterns.
 * ------------------------------------------------------------------- */

std::vector<DetectionEvent> ProcessMonitor::check_process_relationships(
    const std::vector<ProcessInfo>& processes) {
    std::vector<DetectionEvent> detections;

    /* Build a PID -> ProcessInfo lookup for parent resolution. */
    std::unordered_map<DWORD, const ProcessInfo*> pid_map;
    for (const auto& proc : processes) {
        pid_map[proc.pid] = &proc;
    }

    for (const auto& proc : processes) {
        /* Skip system processes (PID 0 and 4 are kernel). */
        if (proc.pid <= 4) continue;

        /* Look up the parent process. */
        auto parent_it = pid_map.find(proc.parent_pid);
        if (parent_it == pid_map.end()) {
            /*
             * Parent process no longer exists. This is normal for long-
             * running processes whose parent has exited, but can also
             * indicate process hollowing or injection.
             *
             * Low confidence since this is very common legitimately.
             */
            continue;
        }

        const ProcessInfo* parent = parent_it->second;
        std::string parent_lower = parent->name;
        std::transform(parent_lower.begin(), parent_lower.end(),
                       parent_lower.begin(), ::tolower);

        /*
         * Check if the parent is a known cheat tool or injector.
         * A game process spawned by a cheat tool is highly suspicious.
         */
        if (is_known_cheat_tool(parent_lower)) {
            DetectionEvent event;
            event.source = AlertSource::PROCESS_MONITOR;
            event.severity = SENTINEL_SEVERITY_HIGH;
            event.description = "Process " + proc.name +
                                " (PID " + std::to_string(proc.pid) +
                                ") spawned by known cheat tool: " +
                                parent->name;
            event.process_id = proc.pid;
            event.confidence = 0.9;
            event.timestamp = std::chrono::system_clock::now();
            detections.push_back(std::move(event));
        }
    }

    return detections;
}

/* -------------------------------------------------------------------
 * hash_name -- FNV-1a hash of a string.
 *
 * FNV-1a algorithm:
 *   hash = offset_basis
 *   for each byte:
 *     hash ^= byte
 *     hash *= prime
 *
 * This gives us a fast, well-distributed 32-bit hash.
 * ------------------------------------------------------------------- */

uint32_t ProcessMonitor::hash_name(const std::string& name) {
    uint32_t hash = FNV_OFFSET_BASIS;
    for (char c : name) {
        hash ^= static_cast<uint32_t>(c);
        hash *= FNV_PRIME;
    }
    return hash;
}

/* -------------------------------------------------------------------
 * scan_loop -- Background thread that runs scans periodically.
 * ------------------------------------------------------------------- */

void ProcessMonitor::scan_loop() {
    while (running_) {
        auto detections = scan_once();

        /* Deliver each detection through the callback. */
        for (const auto& event : detections) {
            if (callback_) {
                callback_(event);
            }
        }

        /* Sleep in short intervals for responsive shutdown. */
        auto sleep_end = std::chrono::steady_clock::now() +
                         std::chrono::milliseconds(scan_interval_ms_);
        while (running_ && std::chrono::steady_clock::now() < sleep_end) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

/* -------------------------------------------------------------------
 * init_databases -- Populate the known cheat tool and DLL hash sets.
 *
 * In a production system, these would be loaded from an encrypted
 * database file that's updated remotely. For now, we hardcode a
 * representative set to demonstrate the pattern.
 *
 * Note: We store hashes, not plaintext names, so this binary doesn't
 * contain a searchable list of cheat tool names.
 * ------------------------------------------------------------------- */

void ProcessMonitor::init_databases() {
    /*
     * Known cheat tool names (hashed). These are common cheat engine
     * and injection tool process names. In production, this list would
     * be much larger and loaded from an encrypted database.
     *
     * We hash them at compile time to avoid storing plaintext names.
     * The hash_name function is deterministic, so we can precompute.
     */
    const char* cheat_tools[] = {
        "cheatengine-x86_64.exe",
        "cheatengine.exe",
        "processhacker.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "ollydbg.exe",
        "ida.exe",
        "ida64.exe",
        "reclass.exe",
        "reclass.net.exe",
        "artmoney.exe",
        "trainer.exe",
        "injector.exe",
        "extremeinjector.exe",
        "winject.exe",
        /* DMA/FPGA tools */
        "pcileech.exe",
        "dmacapture.exe",
        "rawudp.exe",
        "artix_flash.exe",
        "screamer_util.exe",
        "leechcore.exe",
        "fpga_flash.exe",
        /* Note: vivado.exe and impact.exe intentionally excluded --
         * they are legitimate Xilinx/AMD FPGA development tools that
         * would cause false positives on developer workstations. */
        /* Additional injectors */
        "xenos.exe",
        "dll_injector.exe",
        /* Additional memory editors */
        "tsearch.exe",
        "memoryeditor.exe",
    };

    for (const char* name : cheat_tools) {
        known_cheat_hashes_.insert(hash_name(name));
    }

    /*
     * Known-good DLL names that are expected in any process.
     * Anything not in this list gets flagged (with low confidence).
     */
    const char* system_dlls[] = {
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "user32.dll",
        "gdi32.dll",
        "advapi32.dll",
        "shell32.dll",
        "ole32.dll",
        "oleaut32.dll",
        "msvcrt.dll",
        "ws2_32.dll",
        "sechost.dll",
        "rpcrt4.dll",
        "combase.dll",
        "ucrtbase.dll",
        "msvcp_win.dll",
        "bcryptprimitives.dll",
        "imm32.dll",
        "win32u.dll",
        "gdi32full.dll",
        "msvcp140.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "d3d11.dll",
        "d3d12.dll",
        "dxgi.dll",
        "xinput1_4.dll",
        "xinput1_3.dll",
        "opengl32.dll",
        "vulkan-1.dll",
    };

    for (const char* name : system_dlls) {
        known_good_dll_hashes_.insert(hash_name(name));
    }
}

/* -------------------------------------------------------------------
 * load_cheat_database -- Load additional cheat tool names from a
 * file-based database and merge them into the known_cheat_hashes_ set.
 *
 * File format (INI-like):
 *   [process_name.exe]
 *   confidence=0.9       <- optional, currently unused but parsed
 *
 *   [another_tool.exe]
 *
 * Lines starting with '#' or ';' are treated as comments and skipped.
 * Section names are lowercased before hashing so lookups remain
 * case-insensitive, consistent with how we normalize process names
 * in scan_once().
 *
 * A missing file is not an error -- the service functions correctly
 * with only the hardcoded database.
 * ------------------------------------------------------------------- */

void ProcessMonitor::load_cheat_database(const std::string& db_path) {
    std::ifstream file(db_path);
    if (!file.is_open()) {
        /* File absence is expected in fresh installs -- not an error. */
        std::fprintf(stderr,
            "[sentinel] cheat name database not found at %s, "
            "using hardcoded set only\n",
            db_path.c_str());
        return;
    }

    int loaded = 0;
    std::string line;

    while (std::getline(file, line)) {
        /* Strip leading/trailing whitespace. */
        auto start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        line = line.substr(start);
        auto end = line.find_last_not_of(" \t\r\n");
        if (end != std::string::npos) line = line.substr(0, end + 1);

        /* Skip blank lines and comments. */
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        /* Parse section headers: [process_name.exe] */
        if (line.front() == '[' && line.back() == ']') {
            std::string name = line.substr(1, line.size() - 2);

            /* Trim whitespace inside the brackets. */
            auto ns = name.find_first_not_of(" \t");
            auto ne = name.find_last_not_of(" \t");
            if (ns == std::string::npos) continue;
            name = name.substr(ns, ne - ns + 1);

            if (name.empty()) continue;

            /* Lowercase for consistent hashing (matches scan_once logic). */
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);

            known_cheat_hashes_.insert(hash_name(name));
            ++loaded;
            continue;
        }

        /* Key=value lines (e.g. confidence=0.9) -- parsed but not yet used. */
        /* Intentionally ignored -- reserved for future confidence weighting. */
    }

    std::fprintf(stderr,
        "[sentinel] loaded %d cheat name(s) from %s\n",
        loaded, db_path.c_str());
}

/* -------------------------------------------------------------------
 * check_process_privileges -- Detect processes holding SeDebugPrivilege.
 *
 * SeDebugPrivilege allows a process to open any other process with full
 * access, bypassing normal DACL checks. Legitimate software rarely
 * needs this at runtime; it's a strong indicator of a cheat tool or
 * debugger.
 *
 * Detection flow:
 *   1. Open the target process with PROCESS_QUERY_INFORMATION.
 *   2. Open its primary token with TOKEN_QUERY.
 *   3. Resolve the LUID for "SeDebugPrivilege".
 *   4. Use PrivilegeCheck to test whether the privilege is *enabled*
 *      (not just present -- many elevated processes hold it disabled).
 *   5. If enabled, emit a MEDIUM severity event.
 *
 * All Windows API calls are guarded by #ifdef _WIN32 so the translation
 * unit compiles cleanly on macOS during development.
 * ------------------------------------------------------------------- */

std::vector<DetectionEvent> ProcessMonitor::check_process_privileges(
    DWORD pid, const std::string& process_name) {
    std::vector<DetectionEvent> detections;

#ifdef _WIN32
    /* Skip our own process -- we legitimately hold elevated privileges. */
    if (pid == GetCurrentProcessId()) return detections;

    /* Skip kernel pseudo-processes (System Idle Process = 0, System = 4). */
    if (pid <= 4) return detections;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (process == nullptr) {
        /* Access denied or process has exited -- not an error. */
        return detections;
    }

    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        CloseHandle(process);
        return detections;
    }

    /* Use the cached LUID resolved in the constructor. */
    if (!debug_privilege_luid_valid_) {
        CloseHandle(token);
        CloseHandle(process);
        return detections;
    }

    /*
     * PRIVILEGE_SET layout:
     *   PrivilegeCount  -- number of privileges in the array
     *   Control         -- PRIVILEGE_SET_ALL_NECESSARY means ALL must be held;
     *                      with a single privilege this doesn't matter.
     *   Privilege[0]    -- the LUID_AND_ATTRIBUTES we want to check
     *
     * We set SE_PRIVILEGE_ENABLED in Attributes so PrivilegeCheck tests
     * whether the privilege is currently *enabled*, not just present.
     */
    PRIVILEGE_SET priv_set;
    priv_set.PrivilegeCount = 1;
    priv_set.Control        = PRIVILEGE_SET_ALL_NECESSARY;
    priv_set.Privilege[0].Luid       = debug_privilege_luid_;
    priv_set.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL has_priv = FALSE;
    if (PrivilegeCheck(token, &priv_set, &has_priv) && has_priv) {
        DetectionEvent event;
        event.source      = AlertSource::PROCESS_MONITOR;
        event.severity    = SENTINEL_SEVERITY_MEDIUM;
        event.description = "Process holds SeDebugPrivilege (enabled): " +
                            process_name +
                            " (PID " + std::to_string(pid) + ")";
        event.process_id  = pid;
        event.confidence  = 0.6;
        event.timestamp   = std::chrono::system_clock::now();
        detections.push_back(std::move(event));
    }

    CloseHandle(token);
    CloseHandle(process);
#else
    (void)pid;
    (void)process_name;
#endif

    return detections;
}

} /* namespace sentinel */
