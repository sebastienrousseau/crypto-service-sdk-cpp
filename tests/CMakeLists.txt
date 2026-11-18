# SPDX-License-Identifier: Apache-2.0 OR MIT
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau

FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/releases/download/v1.18.0/googletest-1.18.0.tar.gz
  URL_HASH SHA256=6e3191c1455468b3fc35a417fb565c1c5071aee1b7e7f85e30cf48a98d37d8b5
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(
  crypto_service_sdk_tests
  async_client_test.cpp
  client_test.cpp
  codec_full_test.cpp
  codec_test.cpp
  conformance_test.cpp
  curl_seam_test.cpp
  encoding_test.cpp
  kit_test.cpp
  live_test.cpp
  operations_test.cpp
  problem_test.cpp
  retry_test.cpp
  settings_test.cpp
  transport_test.cpp
  support/dispatch.cpp
  support/http_server.cpp
  support/kit.cpp
  support/pattern.cpp
  support/sha256.cpp)
# Tests include the internal headers in src/ (the codec and schemas) to
# build canned responses and to check the encoders directly, and
# curl_common.hpp (hence libcurl's headers) to reach its test seam.
target_include_directories(crypto_service_sdk_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                                            ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(crypto_service_sdk_tests PRIVATE crypto_service::sdk CURL::libcurl
                                                       GTest::gtest_main)
target_compile_definitions(
  crypto_service_sdk_tests PRIVATE CRYPTO_SERVICE_KIT_DIR="${PROJECT_SOURCE_DIR}/conformance"
                                   CRYPTO_SERVICE_PROJECT_VERSION="${PROJECT_VERSION}")
crypto_service_sdk_warnings(crypto_service_sdk_tests)

include(GoogleTest)
# The conformance and live tests skip unless CRYPTO_SERVICE_URL is set;
# ctest passes the environment through, so the same run covers both.
gtest_discover_tests(crypto_service_sdk_tests DISCOVERY_MODE PRE_TEST)
