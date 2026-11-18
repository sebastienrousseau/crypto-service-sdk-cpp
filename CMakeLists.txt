# SPDX-License-Identifier: Apache-2.0 OR MIT
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
cmake_minimum_required(VERSION 3.20)

# The version below is the single source of truth: version.hpp is
# generated from it and scripts/verify-release-versions checks every
# other file against it.
project(crypto_service_sdk VERSION 0.0.41 DESCRIPTION "C++ client for the crypto-server REST API"
        LANGUAGES CXX)

include(FetchContent)
include(GNUInstallDirs)

# PROJECT_IS_TOP_LEVEL needs CMake 3.21; this works from 3.20.
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(CRYPTO_SERVICE_SDK_TOP_LEVEL ON)
else()
  set(CRYPTO_SERVICE_SDK_TOP_LEVEL OFF)
endif()

# Build as C++17 (the supported baseline) unless the caller chose a
# standard, so newer compiler defaults cannot hide a C++20 dependency.
if(CRYPTO_SERVICE_SDK_TOP_LEVEL AND NOT DEFINED CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
endif()

option(CRYPTO_SERVICE_SDK_BUILD_TESTS "Build the test suite" ${CRYPTO_SERVICE_SDK_TOP_LEVEL})
option(CRYPTO_SERVICE_SDK_BUILD_EXAMPLES "Build the examples" ${CRYPTO_SERVICE_SDK_TOP_LEVEL})
option(CRYPTO_SERVICE_SDK_WERROR "Treat compiler warnings as errors" OFF)
option(CRYPTO_SERVICE_SDK_BUILD_FUZZERS "Build the fuzz targets in fuzz/" OFF)
option(CRYPTO_SERVICE_SDK_BUILD_BENCHMARKS "Build the Google Benchmark targets in benchmarks/" OFF)
option(CRYPTO_SERVICE_SDK_INSTALL "Generate the install rules and CMake package config"
       ${CRYPTO_SERVICE_SDK_TOP_LEVEL})

# The installed package exports crypto_service::sdk, which links
# nlohmann_json publicly, so nlohmann/json installs its own headers and
# package config into the same prefix.
if(CRYPTO_SERVICE_SDK_INSTALL)
  set(JSON_Install ON CACHE BOOL "Install nlohmann/json with crypto_service_sdk" FORCE)
endif()

# Third-party sources come from release archives pinned by SHA-256, so a
# changed upstream archive fails the configure step instead of building.
FetchContent_Declare(
  nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
  URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(nlohmann_json)

# libcurl 7.85 or later (CURLOPT_PROTOCOLS_STR), from the system.
find_package(CURL 7.85 REQUIRED)
find_package(Threads REQUIRED)

function(crypto_service_sdk_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 $<$<BOOL:${CRYPTO_SERVICE_SDK_WERROR}>:/WX>)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic
                                             $<$<BOOL:${CRYPTO_SERVICE_SDK_WERROR}>:-Werror>)
  endif()
endfunction()

set(CRYPTO_SERVICE_GENERATED ${PROJECT_BINARY_DIR}/generated/include)
configure_file(cmake/version.hpp.in ${CRYPTO_SERVICE_GENERATED}/crypto_service/version.hpp @ONLY)

add_library(
  crypto_service_sdk
  src/async_client.cpp
  src/client.cpp
  src/codec.cpp
  src/curl_common.cpp
  src/curl_transport.cpp
  src/encoding.cpp
  src/problem.cpp
  src/retry.cpp
  src/settings.cpp
  src/wire.cpp)
add_library(crypto_service::sdk ALIAS crypto_service_sdk)
target_compile_features(crypto_service_sdk PUBLIC cxx_std_17)
set_target_properties(crypto_service_sdk PROPERTIES CXX_EXTENSIONS OFF EXPORT_NAME sdk)
target_include_directories(
  crypto_service_sdk
  PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
         $<BUILD_INTERFACE:${CRYPTO_SERVICE_GENERATED}>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(crypto_service_sdk PUBLIC nlohmann_json::nlohmann_json Threads::Threads
                      PRIVATE CURL::libcurl)
crypto_service_sdk_warnings(crypto_service_sdk)

# The examples, each built as crypto_service_<name>; the conformance job
# runs every one against a live server (README, Examples).
set(CRYPTO_SERVICE_EXAMPLES hash aead sign_verify ml_kem errors async_concurrent)
if(CRYPTO_SERVICE_SDK_BUILD_EXAMPLES)
  foreach(name ${CRYPTO_SERVICE_EXAMPLES})
    add_executable(crypto_service_${name} examples/${name}.cpp)
    target_link_libraries(crypto_service_${name} PRIVATE crypto_service::sdk)
    crypto_service_sdk_warnings(crypto_service_${name})
  endforeach()
endif()

if(CRYPTO_SERVICE_SDK_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(CRYPTO_SERVICE_SDK_BUILD_FUZZERS)
  add_subdirectory(fuzz)
endif()

if(CRYPTO_SERVICE_SDK_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()

# `cmake --install` puts the library, the public headers (version.hpp
# included) and lib/cmake/crypto_service_sdk/ (package config, targets,
# version) under the prefix, so a consumer writes
# find_package(crypto_service_sdk 0.0.41 CONFIG) and links
# crypto_service::sdk. Every 0.0.x release may break the API, so the
# version file accepts the exact version only.
if(CRYPTO_SERVICE_SDK_INSTALL)
  include(CMakePackageConfigHelpers)
  set(CRYPTO_SERVICE_SDK_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/crypto_service_sdk)
  install(
    TARGETS crypto_service_sdk
    EXPORT crypto_service_sdkTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  install(DIRECTORY include/ ${CRYPTO_SERVICE_GENERATED}/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
  install(
    EXPORT crypto_service_sdkTargets
    NAMESPACE crypto_service::
    DESTINATION ${CRYPTO_SERVICE_SDK_CMAKE_DIR})
  configure_package_config_file(
    cmake/crypto_service_sdkConfig.cmake.in ${PROJECT_BINARY_DIR}/crypto_service_sdkConfig.cmake
    INSTALL_DESTINATION ${CRYPTO_SERVICE_SDK_CMAKE_DIR})
  write_basic_package_version_file(${PROJECT_BINARY_DIR}/crypto_service_sdkConfigVersion.cmake
                                   COMPATIBILITY ExactVersion)
  install(FILES ${PROJECT_BINARY_DIR}/crypto_service_sdkConfig.cmake
                ${PROJECT_BINARY_DIR}/crypto_service_sdkConfigVersion.cmake
          DESTINATION ${CRYPTO_SERVICE_SDK_CMAKE_DIR})
  install(FILES LICENSE-APACHE LICENSE-MIT DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/crypto_service_sdk)
  install(
    FILES ${nlohmann_json_SOURCE_DIR}/LICENSE.MIT
    DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/crypto_service_sdk
    RENAME nlohmann_json-LICENSE.MIT)
endif()
