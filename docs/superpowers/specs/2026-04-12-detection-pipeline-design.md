# Detection Pipeline Wiring — Design Spec

**Date:** 2026-04-12
**Status:** Approved
**Approach:** Vertical Slice (end-to-end per module, hardcoded defaults + file-based loading)

## Overview

Wire up the service-side detection pipeline so that the signature scanner, process monitor, and module integrity checker produce real detection signals, the detection engine aggregates them into confidence scores, and alerts flow through the REST API to the dashboard.

Currently the frameworks exist for all modules but databases are empty, callbacks are not registered, and alerts never fire. This spec covers populating data, connecting callbacks, and activating alert generation.

## Database Strategy

All three modules follow the same pattern:

1. **Hardcoded defaults** — compiled into the binary, available immediately
2. **File-based overrides** — loaded from `C:\ProgramData\Sentinel\` on startup
3. **Merge logic** — file entries override hardcoded entries by name; all others are additive

If a file doesn't exist on disk, the module runs with hardcoded defaults only (no error).

## Slice 1: Signature Scanner Pipeline

### Hardcoded Signatures (~10-15 entries)

Known DMA cheat tool patterns:
- pcileech firmware signatures (multiple variants)
- Screamer FPGA patterns
- Common cheat engine injection stubs
- Known DMA hardware utility signatures
- Memory manipulation tool patterns

Each signature entry:
```
struct SignatureEntry {
    char name[64];
    uint8_t pattern[256];
    uint8_t mask[256];       // 0xFF = must match, 0x00 = wildcard
    size_t pattern_length;
    uint8_t severity;        // 1-10
    char category[32];       // "dma_firmware", "injection", "memory_tool"
};
```

### File-Based Loading

Path: `C:\ProgramData\Sentinel\signatures.db`

Text format, one signature per block:
```
[signature_name]
pattern=4D5A90??00000000
severity=8
category=dma_firmware
```

`??` in pattern indicates wildcard bytes. Parsed into pattern/mask arrays.

### Integration

- On startup: load hardcoded sigs, then merge file-based sigs
- `scan_process_modules()` iterates loaded modules, matches against signature database
- On match: call detection engine callback with `SIGNAL_SIGNATURE_MATCH`
- Signal payload: signature name, severity, matched process name/PID, module path

## Slice 2: Process Monitor Pipeline

### Hardcoded Cheat Names (~20-30 entries)

Known cheat tool process names with FNV-1a hashes:
- DMA tools: pcileech, dmacapture, rawudp, artix_flash, screamer_util
- Memory editors: cheatengine, artmoney, tsearch, memoryeditor
- Injectors: xenos, extremeinjector, processhacker, dll_injector
- Debug tools used for cheating: x64dbg, ollydbg, ida (when attached to game processes)
- Generic: trainer, hack, inject (substring matches)

Each entry:
```
struct CheatNameEntry {
    char name[64];
    uint32_t name_hash;     // FNV-1a hash (pre-computed)
    uint8_t confidence;     // 0-100, how confident this name indicates cheating
    bool substring_match;   // true = match anywhere in process name
};
```

### File-Based Loading

Path: `C:\ProgramData\Sentinel\cheatnames.db`

Text format:
```
[process_name]
confidence=90
substring=false
```

### Behavior Detection

Wire up two currently-stubbed checks:

1. **Parent-child analysis:** Flag processes spawned by known injectors or with unusual parent chains (e.g., cmd.exe spawning a memory editor spawned from an unknown parent)
2. **Privilege detection:** Flag user-mode processes with SE_DEBUG_NAME privilege enabled — required for cross-process memory access, common in cheat tools

### Integration

- On each scan cycle: enumerate processes, check name hashes against database
- Run behavior/privilege checks on all processes (not just name matches)
- On match: call detection engine with `SIGNAL_SUSPICIOUS_PROCESS`
- Signal payload: process name, PID, match reason (name/behavior/privilege), confidence

## Slice 3: Module Integrity Pipeline

### Hardcoded Hashes

Known-good hashes for commonly-hooked Windows DLLs:
- `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`
- `ws2_32.dll`, `user32.dll`, `gdi32.dll`
- `advapi32.dll`, `msvcrt.dll`

Multiple hash entries per DLL to cover common Windows builds (10 21H2, 10 22H2, 11 23H2, etc.).

Each entry:
```
struct HashEntry {
    char module_name[260];
    uint8_t expected_hash[32];  // SHA-256 or bcrypt hash
    char windows_build[32];     // "10.0.19044" etc., empty = any
};
```

### File-Based Loading

Path: `C:\ProgramData\Sentinel\hashes.db`

Text format:
```
[module_path]
hash=a1b2c3d4...
build=10.0.19044
```

### Integrity Check Flow

Three violation types:
1. **Memory vs disk mismatch** — module patched in memory (inline hooking)
2. **Disk vs database mismatch** — module replaced on disk
3. **Unknown module in protected process** — injected DLL not in any database

### Integration

- On scan cycle: check loaded modules in monitored processes
- Compare in-memory vs on-disk (existing logic), plus compare against hash database
- On violation: call detection engine with `SIGNAL_INTEGRITY_VIOLATION`
- Signal payload: module path, process, violation type, expected vs actual hash

## Slice 4: Detection Engine Wiring

### Callback Registration

Each module calls `register_detection_callback()` during its `start()` method. The detection engine stores callbacks and invokes them during the scan loop.

Startup order in `main.cpp`:
1. Detection engine starts first
2. Signature scanner, process monitor, module integrity register callbacks
3. Polling loop begins

### Signal Weights

| Signal Type | Weight Range | Notes |
|-------------|-------------|-------|
| `SIGNAL_SIGNATURE_MATCH` | 0.7 - 0.9 | Based on signature severity |
| `SIGNAL_SUSPICIOUS_PROCESS` | 0.4 - 0.6 | Based on match type (name=0.5, behavior=0.4, privilege=0.6) |
| `SIGNAL_INTEGRITY_VIOLATION` | 0.6 - 0.8 | Memory patch=0.8, disk replace=0.7, unknown DLL=0.6 |

Multiple signals for the same process compound additively (capped at 1.0).

### Alert Generation

- Threshold: configurable, default 0.7 (adjustable via `PUT /api/config`)
- When a process's cumulative confidence crosses the threshold, generate an alert
- Alert pushed to service alert store, visible via `GET /api/alerts`
- Dashboard renders alerts automatically (no dashboard changes needed)

### Logging

Write detection events to `C:\ProgramData\Sentinel\detection.log`:
- Timestamp, process name, PID, signal type, signal weight, cumulative score
- Whether an alert was generated
- One line per event, machine-parseable format

## Files Modified

| File | Changes |
|------|---------|
| `service/src/signature_scanner.cpp` | Hardcoded signatures, file loading, callback registration |
| `service/src/process_monitor.cpp` | Hardcoded cheat names, behavior/privilege checks, callback registration |
| `service/src/module_integrity.cpp` | Hardcoded hashes, file loading, callback registration |
| `service/src/detection_engine.cpp` | Callback registration API, alert generation, logging |
| `service/src/main.cpp` | Module startup ordering |
| `service/include/` | Signal type enums, database entry structs (if not already present) |

## Files NOT Modified

- Driver code (no changes needed)
- Dashboard code (already renders alerts from API)
- Shared headers (IOCTL contract unchanged)
- Build system (no new dependencies)

## Design Decisions

- **FNV-1a for name hashing** — already used in process monitor, fast and sufficient for lookup
- **Text-based database files** — simple to edit, no parser dependency, human-readable
- **Additive confidence scoring** — multiple weak signals can trigger an alert, mirrors real-world cheat tool behavior
- **Hardcoded defaults as fallback** — service works out of the box without any config files
- **No dashboard changes** — alert rendering already works, this is purely service-side wiring
