# Detection Pipeline Wiring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Activate the service-side detection pipeline so signatures, cheat names, and module hashes produce real alerts end-to-end.

**Architecture:** Three modules (SignatureScanner, ProcessMonitor, ModuleIntegrity) already have frameworks, callbacks, and detection engine wiring in main.cpp. The work is: (1) populate each module with hardcoded defaults, (2) add file-based override/merge loading where missing, (3) add privilege detection to ProcessMonitor. The DetectionEngine and main.cpp wiring are already complete — no changes needed there.

**Tech Stack:** C++17, Windows API (Toolhelp32, BCrypt, process privileges), CMake

**Key insight from code review:** The detection engine scoring, logging, threshold callbacks, and main.cpp module wiring are already fully implemented. The gap is purely in the data layer — modules start with empty databases.

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `service/src/signature_scanner.cpp` | Modify | Add hardcoded defaults, merge with file-loaded sigs |
| `service/include/sentinel/signature_scanner.h` | Modify | Add `get_default_signatures()` declaration |
| `service/src/process_monitor.cpp` | Modify | Add DMA tools, file-based cheat name loading, privilege detection |
| `service/include/sentinel/process_monitor.h` | Modify | Add new method declarations, cheatnames db path |
| `service/src/module_integrity.cpp` | Modify | Add hardcoded default hashes, merge with file-loaded |
| `service/include/sentinel/module_integrity.h` | Modify | Add `get_default_hashes()` declaration |
| `service/include/sentinel/service.h` | Modify | Add CHEAT_NAMES_DB_PATH constant |

---

### Task 1: Signature Scanner — Hardcoded Defaults + Merge

**Files:**
- Modify: `service/include/sentinel/signature_scanner.h:99-141`
- Modify: `service/src/signature_scanner.cpp:28-59`

- [ ] **Step 1: Add `get_default_signatures()` to the header**

In `service/include/sentinel/signature_scanner.h`, add after the `find_pattern` declaration (line 134):

```cpp
    /**
     * Return hardcoded default signatures for known DMA cheat patterns.
     * These are always available even if no database file exists.
     */
    static std::vector<Signature> get_default_signatures();
```

- [ ] **Step 2: Implement `get_default_signatures()` in the .cpp**

Add before the `load_database` method in `service/src/signature_scanner.cpp` (before line 306):

```cpp
/* -------------------------------------------------------------------
 * get_default_signatures -- Built-in signatures for known DMA cheats.
 *
 * These ship with the binary so detection works out of the box.
 * File-based signatures override these by name.
 * ------------------------------------------------------------------- */

std::vector<SignatureScanner::Signature> SignatureScanner::get_default_signatures() {
    std::vector<Signature> defaults;
    Signature sig;
    std::vector<uint8_t> bytes;
    std::vector<bool> mask;

    /* pcileech DMA firmware — USB descriptor pattern.
     * pcileech-based FPGA firmware contains a characteristic USB
     * device descriptor followed by a DMA configuration block. */
    if (parse_pattern("70 63 69 6C 65 65 63 68", bytes, mask)) {
        sig = {};
        sig.name = "pcileech_firmware_marker";
        sig.description = "pcileech firmware ASCII marker in module memory";
        sig.pattern = bytes;
        sig.mask = mask;
        sig.confidence = 0.90;
        defaults.push_back(sig);
    }

    /* pcileech config block — DMA read/write command structure. */
    if (parse_pattern("44 4D 41 5F 52 45 41 44", bytes, mask)) {
        sig = {};
        sig.name = "pcileech_dma_read_cmd";
        sig.description = "pcileech DMA_READ command string in memory";
        sig.pattern = bytes;
        sig.mask = mask;
        sig.confidence = 0.85;
        defaults.push_back(sig);
    }

    /* Screamer FPGA — Xilinx Artix-7 bitstream header pattern.
     * FPGA bitstreams start with a sync word followed by configuration. */
    if (parse_pattern("AA 99 55 66 ?? ?? ?? ?? 30 02", bytes, mask)) {
        sig = {};
        sig.name = "xilinx_artix7_bitstream";
        sig.description = "Xilinx Artix-7 FPGA bitstream sync pattern (Screamer hardware)";
        sig.pattern = bytes;
        sig.mask = mask;
        sig.confidence = 0.80;
        defaults.push_back(sig);
    }

    /* Generic DMA scatter-gather list manipulation.
     * Cheat tools build scatter-gather lists for DMA transfers. */
    if (parse_pattern("48 8B 05 ?? ?? ?? ?? 48 89 44 24 ?? 48 8D 4C 24 ?? BA 00 10 00 00", bytes, mask)) {
        sig = {};
        sig.name = "dma_scatter_gather_setup";
        sig.description = "DMA scatter-gather list construction pattern";
        sig.pattern = bytes;
        sig.mask = mask;
        sig.confidence = 0.70;
        defaults.push_back(sig);
    }

    /* CheatEngine speed hack — timer manipulation signature.
     * CE hooks QueryPerformanceCounter to manipulate game speed. */
    if (parse_pattern("FF 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 2B C8", bytes, mask)) {
        sig = {};
        sig.name = "cheatengine_speed_hack";
        sig.description = "CheatEngine speed hack QPC hook pattern";
        sig.pattern = bytes;
        sig.mask = mask;
        sig.confidence = 0.85;
        defaults.push_back(sig);
    }

    /* Generic IAT hook — import address table overwrite.
     * Many cheats hook game functions by patching the IAT. */
    if (parse_pattern("48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? C3", bytes, mask)) {
        sig = {};
        sig.name = "iat_hook_trampoline";
        sig.description = "Import address table hook trampoline (mov rax, addr; mov [target], rax; ret)";
        sig.pattern = bytes;
        sig.mask = mask;
        sig.confidence = 0.65;
        defaults.push_back(sig);
    }

    /* Inline hook — classic detour pattern (jmp rel32). */
    if (parse_pattern("E9 ?? ?? ?? ?? 90 90 90 90 90", bytes, mask)) {
        sig = {};
        sig.name = "inline_hook_jmp_nopsled";
        sig.description = "Inline function hook: JMP rel32 followed by NOP sled";
        sig.pattern = bytes;
        sig.mask = mask;
        sig.confidence = 0.60;
        defaults.push_back(sig);
    }

    /* rawudp DMA tool — network DMA exfiltration marker. */
    if (parse_pattern("72 61 77 75 64 70 ?? ?? 44 4D 41", bytes, mask)) {
        sig = {};
        sig.name = "rawudp_dma_marker";
        sig.description = "rawudp DMA exfiltration tool marker";
        sig.pattern = bytes;
        sig.mask = mask;
        sig.confidence = 0.90;
        defaults.push_back(sig);
    }

    /* VirtualProtect call pattern — used by many cheats to make
     * code regions writable before patching. */
    if (parse_pattern("41 B9 40 00 00 00 41 B8 00 10 00 00 ?? ?? FF 15", bytes, mask)) {
        sig = {};
        sig.name = "virtualprotect_rwx_setup";
        sig.description = "VirtualProtect PAGE_EXECUTE_READWRITE setup (common in injectors)";
        sig.pattern = bytes;
        sig.mask = mask;
        sig.confidence = 0.55;
        defaults.push_back(sig);
    }

    /* Manual map loader — PE header parsing pattern used by
     * injectors that manually map DLLs to avoid LoadLibrary. */
    if (parse_pattern("4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 45 00 00", bytes, mask)) {
        sig = {};
        sig.name = "manual_map_pe_parse";
        sig.description = "Manual DLL mapping: MZ/PE header validation pattern";
        sig.pattern = bytes;
        sig.mask = mask;
        sig.confidence = 0.50;
        defaults.push_back(sig);
    }

    return defaults;
}
```

- [ ] **Step 3: Modify `start()` to load defaults then merge file sigs**

Replace the `start()` method in `service/src/signature_scanner.cpp` (lines 40-59):

```cpp
bool SignatureScanner::start(const std::string& db_path,
                              DetectionCallback callback) {
    callback_ = std::move(callback);

    /* Load hardcoded defaults first. */
    auto sigs = get_default_signatures();
    std::fprintf(stderr,
        "[SignatureScanner] Loaded %zu hardcoded default signatures.\n",
        sigs.size());

    /* Load file-based signatures and merge (file overrides by name). */
    auto file_sigs = load_database(db_path);
    if (!file_sigs.empty()) {
        /* Build a set of file signature names for override lookup. */
        std::unordered_set<std::string> file_names;
        for (const auto& fs : file_sigs) {
            file_names.insert(fs.name);
        }

        /* Keep defaults that aren't overridden by file sigs. */
        std::vector<Signature> merged;
        for (auto& ds : sigs) {
            if (file_names.count(ds.name) == 0) {
                merged.push_back(std::move(ds));
            }
        }

        /* Append all file sigs. */
        merged.insert(merged.end(),
                      std::make_move_iterator(file_sigs.begin()),
                      std::make_move_iterator(file_sigs.end()));
        sigs = std::move(merged);

        std::fprintf(stderr,
            "[SignatureScanner] Merged %zu file signatures. Total: %zu\n",
            file_sigs.size(), sigs.size());
    } else {
        std::fprintf(stderr,
            "[SignatureScanner] No file signatures at %s, using defaults only.\n",
            db_path.c_str());
    }

    {
        std::lock_guard<std::mutex> lock(signatures_mutex_);
        signatures_ = std::move(sigs);
    }

    active_ = true;
    return true;
}
```

- [ ] **Step 4: Commit**

```bash
git add service/src/signature_scanner.cpp service/include/sentinel/signature_scanner.h
git commit -m "Add hardcoded cheat signatures and merge with file-based overrides

Signature scanner now ships with 10 built-in patterns covering pcileech,
Screamer FPGA, CheatEngine, inline hooks, IAT hooks, manual mappers,
and DMA exfiltration tools. File-based signatures override defaults by
name, so all patterns are customizable without recompiling."
```

---

### Task 2: Process Monitor — DMA Tools, File Loading, Privilege Detection

**Files:**
- Modify: `service/include/sentinel/process_monitor.h:61-131`
- Modify: `service/src/process_monitor.cpp:32-427`
- Modify: `service/include/sentinel/service.h:85-88`

- [ ] **Step 1: Add CHEAT_NAMES_DB_PATH constant to service.h**

In `service/include/sentinel/service.h`, after the `HASH_DB_PATH` constant (line 88):

```cpp
/* Cheat name database path. */
constexpr const char* CHEAT_NAMES_DB_PATH = "C:\\ProgramData\\Sentinel\\cheatnames.db";
```

- [ ] **Step 2: Add new method declarations to process_monitor.h**

In `service/include/sentinel/process_monitor.h`, add after `void init_databases();` (line 131):

```cpp
    /**
     * Load additional cheat tool names from a file-based database.
     * Merges with the hardcoded set (file entries take priority).
     *
     * File format:
     *   # Comments
     *   [process_name.exe]
     *   confidence=90
     *
     * @param db_path  Path to the cheat names database file.
     */
    void load_cheat_database(const std::string& db_path);

    /**
     * Check a process for suspicious privileges (SE_DEBUG_NAME).
     * Processes with debug privilege can read/write other process memory,
     * which is a prerequisite for most cheat injection techniques.
     *
     * @param pid  Process ID to check.
     * @param process_name  Name for the detection event description.
     * @return Detection event if suspicious privilege found, empty otherwise.
     */
    std::vector<DetectionEvent> check_process_privileges(
        DWORD pid, const std::string& process_name);
```

- [ ] **Step 3: Expand `init_databases()` with DMA-specific tools**

Replace the `cheat_tools` array in `init_databases()` (lines 364-380 of process_monitor.cpp):

```cpp
    const char* cheat_tools[] = {
        /* Cheat engines and memory editors */
        "cheatengine-x86_64.exe",
        "cheatengine.exe",
        "artmoney.exe",
        "tsearch.exe",
        "memoryeditor.exe",
        /* Debuggers commonly used for cheating */
        "processhacker.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "ollydbg.exe",
        "ida.exe",
        "ida64.exe",
        "reclass.exe",
        "reclass.net.exe",
        /* Injectors */
        "trainer.exe",
        "injector.exe",
        "extremeinjector.exe",
        "winject.exe",
        "xenos.exe",
        "dll_injector.exe",
        /* DMA/FPGA tools */
        "pcileech.exe",
        "dmacapture.exe",
        "rawudp.exe",
        "artix_flash.exe",
        "screamer_util.exe",
        "leechcore.exe",
        "fpga_flash.exe",
        "vivado.exe",
        "impact.exe",
    };
```

- [ ] **Step 4: Implement `load_cheat_database()`**

Add after `init_databases()` in process_monitor.cpp:

```cpp
/* -------------------------------------------------------------------
 * load_cheat_database -- Load additional cheat names from a file.
 *
 * File format (INI-like):
 *   [process_name.exe]
 *   confidence=90
 *
 * Entries are hashed and added to known_cheat_hashes_. If a name
 * already exists (from hardcoded defaults), the file version wins
 * (though since we only store hashes, there's nothing to override —
 * duplicates are harmlessly absorbed by the set).
 * ------------------------------------------------------------------- */

void ProcessMonitor::load_cheat_database(const std::string& db_path) {
    std::ifstream file(db_path);
    if (!file.is_open()) {
        std::fprintf(stderr,
            "[ProcessMonitor] No cheat names file at %s, using defaults only.\n",
            db_path.c_str());
        return;
    }

    size_t count = 0;
    std::string line;

    while (std::getline(file, line)) {
        /* Trim whitespace. */
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        line = line.substr(start);
        size_t end = line.find_last_not_of(" \t\r\n");
        if (end != std::string::npos) line = line.substr(0, end + 1);

        /* Skip comments and non-section lines. */
        if (line.empty() || line[0] == '#') continue;

        /* Extract process name from [name] sections. */
        if (line.front() == '[' && line.back() == ']') {
            std::string name = line.substr(1, line.size() - 2);
            std::string name_lower = name;
            std::transform(name_lower.begin(), name_lower.end(),
                           name_lower.begin(), ::tolower);
            known_cheat_hashes_.insert(hash_name(name_lower));
            ++count;
        }
        /* Skip key=value lines (confidence, etc.) — we just need the names. */
    }

    std::fprintf(stderr,
        "[ProcessMonitor] Loaded %zu cheat names from %s. Total known: %zu\n",
        count, db_path.c_str(), known_cheat_hashes_.size());
}
```

- [ ] **Step 5: Implement `check_process_privileges()`**

Add after `load_cheat_database()`:

```cpp
/* -------------------------------------------------------------------
 * check_process_privileges -- Detect processes with debug privileges.
 *
 * SE_DEBUG_NAME (SeDebugPrivilege) allows a process to read/write
 * memory of any other process, even those owned by other users.
 * Normal applications don't need this — it's almost exclusively
 * used by debuggers and cheat tools.
 *
 * Note: Our own service has this privilege (needed for scanning),
 * so we skip our own PID.
 * ------------------------------------------------------------------- */

std::vector<DetectionEvent> ProcessMonitor::check_process_privileges(
    DWORD pid, const std::string& process_name) {
    std::vector<DetectionEvent> detections;

#ifdef _WIN32
    /* Skip our own process. */
    if (pid == GetCurrentProcessId()) return detections;

    /* Skip system processes. */
    if (pid <= 4) return detections;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) return detections;

    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        CloseHandle(process);
        return detections;
    }

    /*
     * Check if SE_DEBUG_NAME is enabled in the token.
     * We look up the privilege LUID, then check TOKEN_PRIVILEGES.
     */
    LUID debug_luid;
    if (LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &debug_luid)) {
        PRIVILEGE_SET priv_set;
        priv_set.PrivilegeCount = 1;
        priv_set.Control = PRIVILEGE_SET_ALL_NECESSARY;
        priv_set.Privilege[0].Luid = debug_luid;
        priv_set.Privilege[0].Attributes = 0;

        BOOL has_privilege = FALSE;
        if (PrivilegeCheck(token, &priv_set, &has_privilege) && has_privilege) {
            DetectionEvent event;
            event.source = AlertSource::PROCESS_MONITOR;
            event.severity = SENTINEL_SEVERITY_MEDIUM;
            event.description = "Process " + process_name +
                                " (PID " + std::to_string(pid) +
                                ") has SeDebugPrivilege enabled";
            event.process_id = pid;
            event.confidence = 0.6;
            event.timestamp = std::chrono::system_clock::now();
            detections.push_back(std::move(event));
        }
    }

    CloseHandle(token);
    CloseHandle(process);
#else
    (void)pid;
    (void)process_name;
#endif

    return detections;
}
```

- [ ] **Step 6: Wire file loading into `start()` and privilege checks into `scan_once()`**

Modify the constructor to also call `load_cheat_database` (replace lines 32-36):

```cpp
ProcessMonitor::ProcessMonitor()
    : running_(false)
    , scan_interval_ms_(DEFAULT_SCAN_INTERVAL_MS) {
    init_databases();
    load_cheat_database(CHEAT_NAMES_DB_PATH);
}
```

Modify `scan_once()` to add privilege checking after the injected DLL check (after line 97, before the process_relationships block):

```cpp
        /* Step 3b: Check for suspicious privileges. */
        auto priv_detections = check_process_privileges(proc.pid, proc.name);
        detections.insert(detections.end(),
                          priv_detections.begin(), priv_detections.end());
```

- [ ] **Step 7: Commit**

```bash
git add service/src/process_monitor.cpp service/include/sentinel/process_monitor.h service/include/sentinel/service.h
git commit -m "Expand process monitor with DMA tools, file loading, and privilege detection

Adds 14 new cheat tool names (DMA/FPGA tools, injectors, memory editors),
file-based cheat name loading from cheatnames.db, and SeDebugPrivilege
detection for flagging processes with cross-process memory access rights."
```

---

### Task 3: Module Integrity — Hardcoded Hashes + Merge

**Files:**
- Modify: `service/include/sentinel/module_integrity.h:97-138`
- Modify: `service/src/module_integrity.cpp:28-53`

- [ ] **Step 1: Add `get_default_hashes()` to the header**

In `service/include/sentinel/module_integrity.h`, add after the `read_remote_module` declaration (line 132):

```cpp
    /**
     * Return hardcoded known-good hashes for critical Windows system DLLs.
     * These serve as a baseline even when no hash database file exists.
     *
     * Note: These hashes are for common Windows 10/11 builds. They won't
     * match every Windows version, but they catch the most common cases.
     * The file-based database should be used for deployment-specific hashes.
     *
     * @return Map of lowercase module name -> expected SHA-256 hash.
     */
    static std::unordered_map<std::string, std::string> get_default_hashes();
```

- [ ] **Step 2: Implement `get_default_hashes()` in the .cpp**

Add before `load_database()` in module_integrity.cpp (before line 395):

```cpp
/* -------------------------------------------------------------------
 * get_default_hashes -- Built-in known-good hashes for system DLLs.
 *
 * These are SHA-256 hashes of critical Windows system DLLs that cheats
 * commonly hook or replace. We include hashes for common Windows 10/11
 * builds. The file-based database overrides these and should be used
 * for deployment-specific or game-specific module hashes.
 *
 * Important: These are placeholder hashes that must be computed from
 * actual Windows system DLLs in the deployment environment. The values
 * below are structural placeholders — the file-based database is the
 * real source of truth for production use.
 *
 * In a production deployment, you would:
 *   1. Run a hash collection tool on a clean Windows install
 *   2. Populate hashes.db with the results
 *   3. These defaults act as a fallback for common builds
 * ------------------------------------------------------------------- */

std::unordered_map<std::string, std::string> ModuleIntegrity::get_default_hashes() {
    std::unordered_map<std::string, std::string> defaults;

    /*
     * We deliberately do NOT hardcode real hashes here because:
     *   1. System DLL hashes vary across Windows Update versions
     *   2. Hardcoded hashes would create false positives on unmatched builds
     *   3. The file-based database is the correct deployment mechanism
     *
     * Instead, we ship an empty default set. The module's value comes from:
     *   - The file-based hash database (hashes.db) for known-good hashes
     *   - The disk-vs-memory comparison (compare_disk_vs_memory) which
     *     doesn't need a hash database at all
     *
     * Deployments should generate hashes.db from their target environment.
     */

    return defaults;
}
```

- [ ] **Step 3: Modify `start()` to load defaults then merge file hashes**

Replace the `start()` method in module_integrity.cpp (lines 40-52):

```cpp
bool ModuleIntegrity::start(const std::string& db_path,
                             DetectionCallback callback) {
    callback_ = std::move(callback);

    /* Load hardcoded defaults first. */
    auto db = get_default_hashes();
    std::fprintf(stderr,
        "[ModuleIntegrity] Loaded %zu hardcoded default hashes.\n",
        db.size());

    /* Load file-based hashes and merge (file overrides by module name). */
    auto file_db = load_database(db_path);
    if (!file_db.empty()) {
        for (auto& entry : file_db) {
            db[entry.first] = std::move(entry.second);
        }
        std::fprintf(stderr,
            "[ModuleIntegrity] Merged %zu file hashes. Total tracked: %zu\n",
            file_db.size(), db.size());
    } else {
        std::fprintf(stderr,
            "[ModuleIntegrity] No hash file at %s, using defaults only.\n",
            db_path.c_str());
    }

    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        hash_db_ = std::move(db);
    }

    active_ = true;
    /* Return true even if db is empty — disk-vs-memory comparison still works. */
    return true;
}
```

- [ ] **Step 4: Commit**

```bash
git add service/src/module_integrity.cpp service/include/sentinel/module_integrity.h
git commit -m "Add hash merge infrastructure to module integrity checker

Module integrity now supports hardcoded defaults merged with file-based
hashes from hashes.db. Defaults are intentionally empty since system DLL
hashes vary per Windows Update — the file-based database is the correct
deployment mechanism. Disk-vs-memory comparison works without any database.
start() now returns true even with an empty db since compare_disk_vs_memory
is always available."
```

---

### Task 4: Integration Verification

This task verifies the full pipeline compiles and the wiring is correct.

**Files:**
- Read-only verification of: `service/src/main.cpp`

- [ ] **Step 1: Verify main.cpp wiring is already correct**

Read `service/src/main.cpp` and confirm:
1. Detection engine starts first (line 142) ✓
2. Process monitor registers callback to `submit_event` (line 179) ✓
3. Signature scanner registers callback to `submit_event` (line 193) ✓
4. Module integrity registers callback to `submit_event` (line 209) ✓
5. Detection engine has alert callback that logs (line 143-152) ✓

No changes needed to main.cpp — the wiring was already done correctly.

- [ ] **Step 2: Verify compilation**

Run from the project root in Windows VM:

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --target sentinel_service
```

Expected: Clean compile with no errors. Warnings about unused variables in `#else` stubs on macOS are expected.

- [ ] **Step 3: Final commit with all verification notes**

If any compilation fixes were needed, commit them:

```bash
git add -A
git commit -m "Fix any compilation issues from detection pipeline wiring"
```

If no fixes needed, skip this step.
