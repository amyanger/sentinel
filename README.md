# Sentinel Anticheat

Sentinel is a Windows anticheat system focused on detecting DMA (Direct Memory Access) hardware cheats -- external FPGA boards that read game memory from a separate physical device, invisible to traditional software-only anticheat. It operates across kernel mode and user mode with a web dashboard for real-time monitoring and configuration.

## Architecture

```
+----------------------------------+
|     Sentinel Dashboard           |  Web UI (status, config, logs)
|     + REST API                   |
+----------------------------------+
|     Sentinel Service             |  Windows service (C++)
|  - Process monitor               |
|  - Signature scanner             |
|  - Module integrity checker      |
|  - Detection orchestrator        |
|  - REST API server               |
+----------------------------------+
|     Sentinel Driver              |  Kernel driver (C, WDM)
|  - PCIe/DMA detection            |
|  - Memory integrity              |
|  - Device monitoring             |
+----------------------------------+
```

**Communication:** Driver <-> Service via Windows IOCTLs. Service <-> Dashboard via REST API (localhost only).

## Build Requirements

- **CMake** 3.20+
- **Windows Driver Kit (WDK)** -- required for the kernel driver
- **MSVC** (Visual Studio 2019+ with C++ workload)
- **Node.js** 18+ -- for the dashboard
- **Windows 10/11 x64** -- build and test environment

## Build Instructions

```bash
# Configure
cmake -B build -G "Visual Studio 17 2022"

# Build all C/C++ components
cmake --build build --config Release

# Dashboard
cd dashboard
npm install
npm run build
```

> **Note:** The kernel driver requires WDK and must be built on Windows. Source editing can be done on macOS with the project directory shared into a Windows VM for compilation.

## Project Structure

```
sentinel/
  CLAUDE.md               Project conventions
  CMakeLists.txt          Top-level CMake
  README.md
  driver/                 Kernel driver (C, WDM)
    CMakeLists.txt
    src/                  pcie_enum, dma_detect, memory_integrity, device_monitor
    include/sentinel/     Driver-private headers
  service/                User-mode service (C++)
    CMakeLists.txt
    src/                  process_monitor, signature_scanner, detection_engine, api_server
    include/sentinel/     Service-private headers
  shared/                 IOCTL contract (headers shared between driver and service)
    include/sentinel/
      ioctl_codes.h       IOCTL control code definitions
      shared_types.h      Data structures passed through IOCTLs
  dashboard/              Web dashboard
    src/
    public/
  docs/                   Design specs and documentation
  tools/                  Dev utilities
```
