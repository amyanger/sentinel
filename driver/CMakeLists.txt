# driver/CMakeLists.txt — Build configuration for the Sentinel kernel driver
#
# This CMake file builds a Windows WDM kernel driver (.sys file).
# It requires the Windows Driver Kit (WDK) to be installed.
#
# The WDK provides:
#   - Kernel-mode headers (ntddk.h, wdm.h, etc.)
#   - Kernel libraries (ntoskrnl.lib, hal.lib)
#   - Driver build rules and link flags
#
# Build instructions (in Windows VM):
#   mkdir build && cd build
#   cmake -G "Visual Studio 17 2022" -A x64 ..
#   cmake --build . --config Release
#
# Note: Kernel drivers CANNOT be built with MinGW or Clang on Windows.
# They require the MSVC toolchain with WDK integration.

cmake_minimum_required(VERSION 3.16)

# --- Find the Windows Driver Kit ---
#
# The WDK installs to a well-known path and sets environment variables.
# We look for it in the standard locations. If FindWDK is available
# (from CMake modules), use it; otherwise, configure paths manually.

# WDK root is typically: C:\Program Files (x86)\Windows Kits\10
# The km (kernel-mode) headers are under Include/<version>/km/
# The libraries are under Lib/<version>/km/x64/

if(NOT DEFINED WDK_ROOT)
    # Try the environment variable first, then the standard path.
    if(DEFINED ENV{WDKContentRoot})
        set(WDK_ROOT "$ENV{WDKContentRoot}")
    else()
        set(WDK_ROOT "C:/Program Files (x86)/Windows Kits/10")
    endif()
endif()

# Detect the WDK version (newest available).
if(EXISTS "${WDK_ROOT}/Include")
    file(GLOB WDK_VERSIONS RELATIVE "${WDK_ROOT}/Include" "${WDK_ROOT}/Include/10.*")
    if(WDK_VERSIONS)
        list(SORT WDK_VERSIONS)
        list(GET WDK_VERSIONS -1 WDK_VERSION)
        message(STATUS "Detected WDK version: ${WDK_VERSION}")
    else()
        message(WARNING "WDK versions not found under ${WDK_ROOT}/Include")
    endif()
endif()

# WDK include directories for kernel-mode development.
set(WDK_INCLUDE_DIRS
    "${WDK_ROOT}/Include/${WDK_VERSION}/km"
    "${WDK_ROOT}/Include/${WDK_VERSION}/shared"
    "${WDK_ROOT}/Include/${WDK_VERSION}/km/crt"
)

# WDK library directory for x64 kernel-mode.
set(WDK_LIB_DIR "${WDK_ROOT}/Lib/${WDK_VERSION}/km/x64")

# --- Driver target ---

set(SENTINEL_DRIVER_SOURCES
    src/main.c
    src/ioctl.c
    src/pcie_enum.c
    src/dma_detect.c
    src/memory_integrity.c
    src/device_monitor.c
)

set(SENTINEL_DRIVER_HEADERS
    include/sentinel/driver.h
    include/sentinel/types.h
)

# Build as a kernel driver (.sys).
# In a proper WDK-integrated build, this would use wdk_add_driver().
# For a standard CMake setup, we build a shared library and rename to .sys.
add_library(sentinel_driver SHARED
    ${SENTINEL_DRIVER_SOURCES}
    ${SENTINEL_DRIVER_HEADERS}
)

# Set the output name and extension to produce sentinel.sys.
set_target_properties(sentinel_driver PROPERTIES
    OUTPUT_NAME "sentinel"
    SUFFIX ".sys"
    PREFIX ""
)

# --- Compiler settings ---

# C11 standard as specified in CLAUDE.md.
set_property(TARGET sentinel_driver PROPERTY C_STANDARD 11)

# Kernel-mode compile definitions.
# These tell the Windows headers we're building a kernel driver.
target_compile_definitions(sentinel_driver PRIVATE
    _AMD64_                # Target architecture
    _WIN64                 # 64-bit build
    NTDDI_VERSION=0x0A000000   # Windows 10 minimum
    _WIN32_WINNT=0x0A00        # Windows 10 minimum
    WINVER=0x0A00              # Windows 10 minimum
    _KERNEL_MODE               # We're in kernel mode
    DEPRECATE_DDK_FUNCTIONS=1  # Warn on deprecated DDK APIs
)

# Include paths: our own headers, the shared headers, and WDK headers.
target_include_directories(sentinel_driver PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../shared/include
    ${WDK_INCLUDE_DIRS}
)

# --- Kernel-mode compiler flags (MSVC) ---
if(MSVC)
    target_compile_options(sentinel_driver PRIVATE
        /kernel           # Generate kernel-mode code
        /GS-              # Disable buffer security check (not available in kernel)
        /Gy               # Enable function-level linking
        /W4               # Warning level 4 (high)
        /WX               # Treat warnings as errors
        /Zi               # Generate debug info (PDB)
        /Od               # Disable optimization for debug builds
        /Zp8              # 8-byte struct alignment
        /d1nodatetime     # Don't embed build timestamps for reproducibility
    )

    # Kernel-mode linker flags.
    target_link_options(sentinel_driver PRIVATE
        /DRIVER           # Build a driver image
        /SUBSYSTEM:NATIVE # Native subsystem (no Win32)
        /ENTRY:DriverEntry # Driver entry point
        /NODEFAULTLIB     # Don't link CRT (kernel has its own runtime)
        /MANIFEST:NO      # No manifest for drivers
    )
endif()

# --- Link kernel libraries ---
#
# ntoskrnl.lib: Core kernel exports (IoCreateDevice, KeAcquireSpinLock, etc.)
# hal.lib:      Hardware Abstraction Layer (HalGetBusDataByOffset, etc.)
# ntstrsafe.lib: Safe string functions for kernel (RtlStringCb*)
# wdmsec.lib:   WDM security helpers

target_link_directories(sentinel_driver PRIVATE ${WDK_LIB_DIR})

target_link_libraries(sentinel_driver PRIVATE
    ntoskrnl
    hal
    ntstrsafe
    wdmsec
)

# --- Installation ---
# The .sys file needs to be copied to the Windows VM and installed
# via sc create or the INF file. No install target for now.

message(STATUS "Sentinel driver configured:")
message(STATUS "  WDK root: ${WDK_ROOT}")
message(STATUS "  Sources: ${SENTINEL_DRIVER_SOURCES}")
