#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Extracts every ```cpp block of README.md, compiles each as its own
# program against the SDK built in <build-dir>, and runs it against the
# crypto-server at CRYPTO_SERVICE_URL (with CRYPTO_SERVICE_API_KEY). A
# block that does not compile or exits non-zero fails. ```cmake and
# ```sh blocks are checked elsewhere (make package-test, the CI jobs).
#
# Usage: scripts/readme-snippets.sh [build-dir]
set -euo pipefail
cd "$(dirname "$0")/.."

build=$(cd "${1:-build}" && pwd)
: "${CRYPTO_SERVICE_URL:?set CRYPTO_SERVICE_URL to a running crypto-server}"
: "${CRYPTO_SERVICE_API_KEY:?set CRYPTO_SERVICE_API_KEY}"
work=$(mktemp -d "${TMPDIR:-/tmp}/readme-snippets.XXXXXX")
trap 'rm -rf "$work"' EXIT

awk -v dir="$work" '
  /^```cpp$/ { n++; file = sprintf("%s/snippet_%02d.cpp", dir, n); inside = 1; next }
  /^```$/ && inside { inside = 0; close(file); next }
  inside { print > file }
' README.md

count=0
for src in "$work"/snippet_*.cpp; do
  [ -e "$src" ] || { echo "readme-snippets: no cpp blocks in README.md" >&2; exit 1; }
  name=$(basename "$src" .cpp)
  cat > "$work/CMakeLists.txt" <<CMAKE
cmake_minimum_required(VERSION 3.20)
project(readme_snippet LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
add_subdirectory("$PWD" sdk EXCLUDE_FROM_ALL)
add_executable(snippet "$src")
target_link_libraries(snippet PRIVATE crypto_service::sdk)
CMAKE
  rm -rf "$work/build"
  cmake -S "$work" -B "$work/build" -DCRYPTO_SERVICE_SDK_BUILD_TESTS=OFF \
    -DCRYPTO_SERVICE_SDK_BUILD_EXAMPLES=OFF -DCRYPTO_SERVICE_SDK_INSTALL=OFF \
    "-DFETCHCONTENT_SOURCE_DIR_NLOHMANN_JSON=$build/_deps/nlohmann_json-src" > "$work/$name.log"
  cmake --build "$work/build" --parallel >> "$work/$name.log" 2>&1 ||
    { cat "$work/$name.log"; echo "FAIL $name: does not compile"; exit 1; }
  if "$work/build/snippet" > "$work/$name.out" 2>&1; then
    echo "ok   $name"
    sed 's/^/     /' "$work/$name.out"
  else
    sed 's/^/     /' "$work/$name.out"
    echo "FAIL $name: exited non-zero"
    exit 1
  fi
  count=$((count + 1))
done
echo "readme-snippets: $count blocks compiled and ran"
