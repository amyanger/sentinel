# service/test/CMakeLists.txt
#
# GoogleTest-based unit tests for the service. Fetches GoogleTest at
# configure time so no system-wide install is required. Only the parts
# of the service that are meaningfully testable in isolation are built
# here — specifically the collector queue and wire format serializer.
#
# Enable with: cmake -DSENTINEL_SERVICE_TESTS=ON ...

cmake_minimum_required(VERSION 3.20)

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
# Prevent GoogleTest from overriding our compiler/linker options
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(sentinel_service_tests
    test_collector_queue.cpp
    test_collector_wire.cpp
    # Include the translation units under test directly. This avoids
    # needing to produce a static library from the service. The real
    # collector_http_win.cpp is NOT linked — test_collector_queue.cpp
    # provides a fake http_post_events instead.
    ${CMAKE_SOURCE_DIR}/service/src/collector_client.cpp
    ${CMAKE_SOURCE_DIR}/service/src/collector_wire.cpp
)

target_include_directories(sentinel_service_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/service/include
    ${CMAKE_SOURCE_DIR}/shared/include
)

target_link_libraries(sentinel_service_tests PRIVATE
    GTest::gtest_main
)

# The service's main build uses /W4 /WX. Tests relax warnings-as-errors
# to avoid GoogleTest's own warnings breaking the build under MSVC.
if(MSVC)
    target_compile_options(sentinel_service_tests PRIVATE /W4)
endif()

include(GoogleTest)
gtest_discover_tests(sentinel_service_tests)
