# Sentinel Anticheat — Design Spec

**Date:** 2026-04-11
**Status:** Approved

## Overview

Sentinel is a full anticheat system for Windows PC games with a focus on DMA (Direct Memory Access) hardware cheat detection. It operates across kernel and user-mode with a web dashboard for monitoring and configuration.

The system targets the most difficult class of cheats — external DMA hardware (FPGA boards like Squirrel/DMA cards) that read game memory from a separate physical device, invisible to traditional software-only anticheat.

## Target Platform

- **Runtime:** Windows 10/11 (x64)
- **Development:** macOS (source editing) + Windows VM (compilation, testing)
- **Build system:** CMake (C/C++ components), npm (dashboard)
- **Kernel driver:** Windows Driver Model (WDM), requires Windows Driver Kit (WDK)

## Architecture

```
┌─────────────────────────────────┐
│     Sentinel Dashboard          │  Web UI (status, config, logs)
│     + REST API                  │
├─────────────────────────────────┤
│     Sentinel Service            │  Windows service (C++)
│  - Process monitor              │
│  - Signature scanner            │
│  - Module integrity checker     │
│  - Detection orchestrator       │
│  - REST API server              │
├─────────────────────────────────┤
│     Sentinel Driver             │  Kernel driver (C, WDM)
│  - PCIe/DMA detection           │
│  - Memory integrity             │
│  - Device monitoring            │
└─────────────────────────────────┘
```

**Communication paths:**
- Driver ↔ Service: Windows IOCTLs
- Service ↔ Dashboard: REST API (HTTP, localhost)

## Component 1: Sentinel Driver (C, WDM, Ring 0)

The kernel driver is the core detection engine for hardware-level threats.

### Detection Modules

**1. PCIe Device Enumerator (`pcie_enum.c`)**
- Scans and fingerprints all PCIe devices on driver load and periodically thereafter
- Maintains a whitelist of known-good vendor/device ID pairs
- Flags unknown or suspicious devices (FPGA boards, repurposed capture cards)
- Reports device tree changes to the service

**2. DMA Anomaly Detector (`dma_detect.c`)**
- Monitors IOMMU/VT-d state — checks if DMA remapping is enabled and intact
- Detects devices making unexpected DMA reads to game memory regions
- Uses timing analysis to identify latency patterns characteristic of external DMA reads
- Checks for IOMMU bypass attempts

**3. Memory Integrity Monitor (`memory_integrity.c`)**
- Marks game memory regions as protected via the IOCTL interface
- Monitors for unauthorized access from unexpected sources
- Detects page table manipulation
- Reports integrity violations with source and target information

**4. Device Callback Monitor (`device_monitor.c`)**
- Registers PnP (Plug and Play) notifications for device arrivals/removals
- Catches hot-plugged DMA hardware during gameplay
- Logs all device changes with timestamps
- Immediately triggers a PCIe rescan on new device events

### IOCTL Interface

The driver exposes the following control codes for service communication:

| IOCTL Code | Direction | Purpose |
|---|---|---|
| `SENTINEL_IOCTL_GET_DEVICES` | Driver → Service | List all detected PCIe devices with trust status |
| `SENTINEL_IOCTL_GET_ALERTS` | Driver → Service | Pull pending detection alerts from the alert queue |
| `SENTINEL_IOCTL_SET_CONFIG` | Service → Driver | Update detection parameters (scan intervals, thresholds) |
| `SENTINEL_IOCTL_PROTECT_REGION` | Service → Driver | Mark a memory region for integrity monitoring |

Alerts are queued in a ring buffer in kernel memory. The service polls for alerts at a configurable interval.

## Component 2: Sentinel Service (C++, User-Mode)

The service runs as a Windows system service with elevated privileges. It handles user-mode detections and orchestrates the overall system.

### Modules

**1. Process Monitor (`process_monitor.cpp`)**
- Enumerates running processes via `CreateToolhelp32Snapshot` and `NtQuerySystemInformation`
- Detects known cheat tools by name, hash, and behavior
- Watches for process injection techniques: DLL injection, thread hijacking, manual mapping
- Monitors for suspicious parent-child process relationships

**2. Signature Scanner (`signature_scanner.cpp`)**
- Maintains a database of known cheat signatures (byte patterns with wildcards)
- Scans loaded modules in the target game process
- Supports masked/wildcard patterns for resilient matching
- Database is loaded from a local signature file, updatable without recompilation

**3. Module Integrity Checker (`module_integrity.cpp`)**
- Validates game DLLs against known-good hashes
- Detects hollowed, replaced, or patched modules
- Compares in-memory module images against on-disk originals
- Reports specific bytes/regions that differ

**4. Driver Communication (`driver_comm.cpp`)**
- Manages the IOCTL connection to the kernel driver
- Polls for alerts at a configurable interval
- Sends configuration updates and memory protection requests
- Handles driver load/unload lifecycle

**5. Detection Engine (`detection_engine.cpp`)**
- Aggregates signals from all sources (driver alerts + user-mode detections)
- Applies confidence scoring — individual signals are weighted, correlated signals compound
- Thresholds are configurable: a single low-confidence signal won't trigger, but multiple signals will
- Logs all events with timestamps, evidence, and confidence scores

**6. REST API Server (`api_server.cpp`)**
- Lightweight HTTP server bound to localhost only
- Serves detection events, device lists, configuration, and status to the dashboard
- Endpoints:
  - `GET /api/status` — service and driver health
  - `GET /api/devices` — PCIe device list with trust status
  - `GET /api/alerts` — detection events (paginated)
  - `GET /api/config` — current configuration
  - `PUT /api/config` — update configuration
  - `GET /api/stats` — detection statistics

## Component 3: Sentinel Dashboard (Web)

A web-based dashboard for real-time monitoring and configuration.

### Views

- **Status** — Service health, driver status, uptime, active protections
- **Devices** — PCIe device table with vendor/device IDs, trust status, first-seen/last-seen timestamps
- **Alerts** — Real-time feed of detection events with severity, source, evidence, confidence scores
- **Configuration** — Scan intervals, detection thresholds, whitelist management, protected memory regions
- **Logs** — Searchable event log with export capability

### Tech Stack

- Standard web stack (HTML/CSS/JS or a lightweight framework)
- Communicates with the service via the REST API
- Runs locally — no external network access needed

## Component 4: Shared Headers

Common definitions used by both the driver and service, stored in `shared/include/sentinel/`:

- `ioctl_codes.h` — IOCTL control code definitions, shared between driver and service
- `shared_types.h` — Data structures passed through IOCTLs (device info, alert structures, config)

These headers are the contract between kernel and user-mode. Changes here must be synchronized across both components.

## Project Structure

```
sentinel/
├── CLAUDE.md
├── CMakeLists.txt               # Top-level CMake
├── README.md
├── docs/
│   └── superpowers/
│       └── specs/
├── driver/                      # Kernel driver (C, WDM)
│   ├── CMakeLists.txt
│   ├── src/
│   │   ├── main.c
│   │   ├── ioctl.c
│   │   ├── pcie_enum.c
│   │   ├── dma_detect.c
│   │   ├── memory_integrity.c
│   │   └── device_monitor.c
│   └── include/
│       └── sentinel/
│           ├── driver.h
│           └── types.h
├── service/                     # User-mode service (C++)
│   ├── CMakeLists.txt
│   ├── src/
│   │   ├── main.cpp
│   │   ├── process_monitor.cpp
│   │   ├── signature_scanner.cpp
│   │   ├── module_integrity.cpp
│   │   ├── driver_comm.cpp
│   │   ├── detection_engine.cpp
│   │   └── api_server.cpp
│   └── include/
│       └── sentinel/
├── dashboard/                   # Web dashboard
│   ├── package.json
│   ├── src/
│   └── public/
├── shared/                      # Shared headers
│   └── include/
│       └── sentinel/
│           ├── ioctl_codes.h
│           └── shared_types.h
└── tools/                       # Dev utilities
```

## Development Environment

- **Source editing:** macOS (user's primary machine)
- **Build and test:** Windows VM (UTM, Parallels, or VMware Fusion)
- **Source sharing:** Project directory shared from Mac into the Windows VM
- **Driver building:** Requires WDK installed in the Windows VM
- **Dashboard development:** Can run natively on macOS

## Build Order

1. **Shared headers** — define the IOCTL contract first
2. **Kernel driver** — build the core detection engine
3. **Service** — build user-mode detections and driver communication
4. **REST API** — add the API server to the service
5. **Dashboard** — build the web UI last

This order ensures each layer has its dependencies ready before development begins.

## Detection Philosophy

- **Defense in depth:** Multiple detection layers so bypassing one doesn't defeat the system
- **Confidence scoring:** No single signal triggers a detection — correlated evidence is required
- **DMA as first-class threat:** Unlike most anticheats that bolt on DMA detection, Sentinel treats it as a primary attack vector
- **Transparency:** All detections are logged with full evidence chains for review
