# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Google Benchmark targets, built only with
# CRYPTO_SERVICE_SDK_BUILD_BENCHMARKS=ON (`make bench`). The scenario
# names are shared by every Crypto Service SDK: crypto_service_bench_client
# runs encode_request, decode_response and decode_problem with no
# network; crypto_service_bench_loopback runs round_trip_hash against
# CRYPTO_SERVICE_URL and skips without it.

FetchContent_Declare(
  googlebenchmark
  URL https://github.com/google/benchmark/archive/refs/tags/v1.10.0.tar.gz
  URL_HASH SHA256=acc5c7c0fbed855c4aaa2d7c3c36fb82b0c15c28f4e151e3f679c2fc0aa404af
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_WERROR OFF CACHE BOOL "" FORCE)
set(BENCHMARK_INSTALL_DOCS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googlebenchmark)

foreach(name client loopback)
  set(target crypto_service_bench_${name})
  add_executable(${target} ${name}_bench.cpp)
  target_link_libraries(${target} PRIVATE crypto_service::sdk benchmark::benchmark)
  crypto_service_sdk_warnings(${target})
endforeach()
