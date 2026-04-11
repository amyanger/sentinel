cmake_minimum_required(VERSION 3.20)
project(sentinel LANGUAGES C CXX)

# Language standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Shared headers available to all sub-projects
add_library(sentinel_shared INTERFACE)
target_include_directories(sentinel_shared INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/include
)

# Sub-projects
add_subdirectory(driver)
add_subdirectory(service)
