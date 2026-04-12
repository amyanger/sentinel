# service/CMakeLists.txt
#
# Build configuration for the Sentinel anticheat user-mode service.
#
# This produces a Windows executable (not a DLL) that registers itself
# with the Windows Service Control Manager. It can also run as a console
# app for development/testing with the --console flag.

cmake_minimum_required(VERSION 3.16)
project(SentinelService LANGUAGES CXX)

# C++17 standard (as specified in CLAUDE.md)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Source files ---
set(SERVICE_SOURCES
    src/main.cpp
    src/driver_comm.cpp
    src/process_monitor.cpp
    src/signature_scanner.cpp
    src/module_integrity.cpp
    src/detection_engine.cpp
    src/api_server.cpp
    src/collector_wire.cpp
    src/collector_client.cpp
    src/collector_http_win.cpp
)

# Build as a standard Windows executable.
# For a real Windows service you might use WIN32 subsystem, but we keep
# it as a console app so --console mode works and stderr is visible.
add_executable(sentinel_service ${SERVICE_SOURCES})

# --- Include paths ---
# 1. Service's own headers (service/include/)
# 2. Shared contract headers (shared/include/) -- IOCTL codes and types
target_include_directories(sentinel_service PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/shared/include
)

# --- Platform-specific libraries ---
if(WIN32)
    # ws2_32    -- Winsock2 (API server HTTP)
    # advapi32  -- Service Control Manager APIs
    # psapi     -- Process Status API (EnumProcessModules, etc.)
    # bcrypt    -- Cryptographic hashing (SHA-256 for module integrity)
    target_link_libraries(sentinel_service PRIVATE
        ws2_32
        advapi32
        psapi
        bcrypt
        winhttp
    )
endif()

# --- Compiler warnings ---
if(MSVC)
    target_compile_options(sentinel_service PRIVATE
        /W4        # High warning level
        /WX        # Treat warnings as errors
        /permissive-  # Strict standards conformance
    )
else()
    # GCC/Clang (for cross-platform static analysis on macOS)
    target_compile_options(sentinel_service PRIVATE
        -Wall -Wextra -Wpedantic
    )
endif()

# --- Output ---
set_target_properties(sentinel_service PROPERTIES
    OUTPUT_NAME "sentinel_service"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
