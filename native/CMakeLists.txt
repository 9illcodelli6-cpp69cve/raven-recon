cmake_minimum_required(VERSION 3.20)
project(raven_native VERSION 6.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── Build options ────────────────────────────────────────────────────────────
option(RAVEN_NATIVE_BUILD_TESTS      "Build native unit tests"      ON)
option(RAVEN_NATIVE_BUILD_BENCHMARKS "Build benchmarks"             ON)
option(RAVEN_NATIVE_ASAN             "Enable AddressSanitizer"      OFF)
option(RAVEN_NATIVE_UBSAN            "Enable UndefinedBehaviorSan"  OFF)
option(RAVEN_NATIVE_BUILD_PYTHON_EXT "Build pybind11 Python module" ON)

# ─── Compiler warnings ────────────────────────────────────────────────────────
if(MSVC)
    add_compile_options(/W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
    # Disable specific warnings that are noisy in pybind11 headers
    add_compile_options(/wd4100 /wd4127 /wd4244 /wd4267 /wd4702)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror
        -Wno-unused-parameter -Wno-missing-field-initializers)
    if(RAVEN_NATIVE_ASAN)
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
    if(RAVEN_NATIVE_UBSAN)
        add_compile_options(-fsanitize=undefined)
        add_link_options(-fsanitize=undefined)
    endif()
endif()

# ─── Core native library ──────────────────────────────────────────────────────
add_library(raven_native_core STATIC
    src/normalize.cpp
    src/diff.cpp
    src/json_diff.cpp
    src/hash.cpp
    src/simhash.cpp
    src/entropy.cpp
    src/pattern_scan.cpp
    src/features.cpp
    src/compression.cpp
    src/fingerprint.cpp
)

target_include_directories(raven_native_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Platform crypto / compression backends (Linux port):
#   Windows — SHA-256 via BCrypt (linked by #pragma comment in hash.cpp); zlib
#             only if its header happens to be on the include path.
#   Linux/macOS — SHA-256 via OpenSSL EVP (hash.cpp) and zlib inflate when
#             <zlib.h> exists (compression.cpp uses __has_include). Both must be
#             linked explicitly or the extension fails to import (undefined syms).
if(NOT WIN32)
    set_target_properties(raven_native_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
    find_package(OpenSSL REQUIRED COMPONENTS Crypto)
    target_link_libraries(raven_native_core PUBLIC OpenSSL::Crypto)
    find_package(ZLIB)
    if(ZLIB_FOUND)
        target_link_libraries(raven_native_core PUBLIC ZLIB::ZLIB)
    endif()
endif()

# ─── pybind11 Python extension ────────────────────────────────────────────────
if(RAVEN_NATIVE_BUILD_PYTHON_EXT)
    find_package(Python3 REQUIRED COMPONENTS Interpreter Development)

    # Prefer pip-installed pybind11; fall back to FetchContent
    find_package(pybind11 CONFIG QUIET)
    if(NOT pybind11_FOUND)
        include(FetchContent)
        FetchContent_Declare(
            pybind11
            GIT_REPOSITORY https://github.com/pybind/pybind11.git
            GIT_TAG        v2.13.6
        )
        FetchContent_MakeAvailable(pybind11)
    endif()

    pybind11_add_module(raven_native_ext
        src/python_bridge.cpp
    )
    target_link_libraries(raven_native_ext PRIVATE raven_native_core)
    set_target_properties(raven_native_ext PROPERTIES
        OUTPUT_NAME "_raven_native"
        LIBRARY_OUTPUT_DIRECTORY         "${CMAKE_SOURCE_DIR}/../raven/native"
        LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/../raven/native"
        RUNTIME_OUTPUT_DIRECTORY         "${CMAKE_SOURCE_DIR}/../raven/native"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/../raven/native"
    )
endif()

# ─── Tests ────────────────────────────────────────────────────────────────────
if(RAVEN_NATIVE_BUILD_TESTS)
    enable_testing()

    # Fetch GoogleTest
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.15.2
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(raven_native_tests
        tests/test_normalize.cpp
        tests/test_diff.cpp
        tests/test_json_diff.cpp
        tests/test_hash.cpp
        tests/test_simhash.cpp
        tests/test_entropy.cpp
        tests/test_binary_inspect.cpp
        tests/test_pattern_scan.cpp
        tests/test_features.cpp
        tests/test_compression.cpp
        tests/test_malformed_inputs.cpp
        tests/test_resource_limits.cpp
    )
    target_link_libraries(raven_native_tests PRIVATE
        raven_native_core
        GTest::gtest_main
    )
    include(GoogleTest)
    gtest_discover_tests(raven_native_tests)
endif()

# ─── Benchmarks ───────────────────────────────────────────────────────────────
if(RAVEN_NATIVE_BUILD_BENCHMARKS)
    include(FetchContent)
    FetchContent_Declare(
        benchmark
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG        v1.9.1
    )
    set(BENCHMARK_ENABLE_TESTING OFF)
    set(BENCHMARK_ENABLE_INSTALL OFF)
    FetchContent_MakeAvailable(benchmark)

    add_executable(raven_native_benchmarks
        benchmarks/bench_normalize.cpp
        benchmarks/bench_diff.cpp
        benchmarks/bench_hash.cpp
        benchmarks/bench_simhash.cpp
        benchmarks/bench_pattern_scan.cpp
        benchmarks/bench_features.cpp
    )
    target_link_libraries(raven_native_benchmarks PRIVATE
        raven_native_core
        benchmark::benchmark_main
    )
endif()
