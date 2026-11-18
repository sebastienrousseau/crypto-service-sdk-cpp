<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# Packaging

How the SDK is distributed, and what a packager needs. The decision is
recorded in [ADR 0006](adr/0006-cmake-package-github-release-no-registry.md).

## What each release provides

| Channel | Status |
| :--- | :--- |
| GitHub release (`v0.0.40` onwards) | A source archive `crypto-service-sdk-cpp-<version>.tar.gz`, a CycloneDX SBOM (`.cdx.json`), `SHA256SUMS`, and a build provenance attestation |
| Installed CMake package | `cmake --install` exports `crypto_service::sdk` for `find_package(crypto_service_sdk <version> CONFIG)` |
| Package registry (vcpkg, Conan) | **None.** Submitting a port is a later decision ([roadmap](ROADMAP.md)); C++ has no single registry, and each needs its maintainers' review |
| Distribution packages (deb, rpm, Homebrew, Nix) | **Not provided.** The SDK is a small static library consumed by C++ projects that build from source; no distribution has asked for it. The notes below are for one that does |

## Consuming a release

```sh
curl -LO https://github.com/sebastienrousseau/crypto-service-sdk-cpp/releases/download/v0.0.40/crypto-service-sdk-cpp-0.0.40.tar.gz
curl -LO https://github.com/sebastienrousseau/crypto-service-sdk-cpp/releases/download/v0.0.40/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify crypto-service-sdk-cpp-0.0.40.tar.gz --repo sebastienrousseau/crypto-service-sdk-cpp
tar xzf crypto-service-sdk-cpp-0.0.40.tar.gz
cmake -S crypto-service-sdk-cpp-0.0.40 -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix /opt/crypto-service
```

The archive and the SBOM can be rebuilt from the signed tag and
compared with `SHA256SUMS` ([reproducing a release](REPRODUCING.md)).

Then, in the consuming project:

```cmake
find_package(crypto_service_sdk 0.0.40 CONFIG REQUIRED)  # CMAKE_PREFIX_PATH=/opt/crypto-service
target_link_libraries(your_app PRIVATE crypto_service::sdk)
```

The version file accepts the exact version only (`ExactVersion`): every
`0.0.x` step may change the API
([ADR 0005](adr/0005-source-compatibility-not-abi-stability.md)).

## Notes for distribution packagers

- **Licence.** Apache-2.0 OR MIT, at the user's option
  (`LICENSE-APACHE`, `LICENSE-MIT`); every file carries an SPDX
  identifier or is covered by `REUSE.toml`, and `reuse lint` passes. The
  installed prefix includes the licences under
  `share/doc/crypto_service_sdk/`, with nlohmann/json's MIT licence.
- **Toolchain floor.** C++17 and CMake 3.20, as
  [the toolchain policy](POLICIES.md) states; raising either is
  announced in the changelog first.
- **Dependencies and pins.** libcurl 7.85 or newer is the system library
  (`find_package(CURL 7.85)`), with Threads. nlohmann/json 3.12.0 is
  fetched by CMake `FetchContent` from its release archive and checked
  against a SHA-256 in `CMakeLists.txt`; GoogleTest 1.18.0 (tests) and
  Google Benchmark 1.10.0 (benchmarks, off by default) the same way.
  There is no option yet to use a system nlohmann/json.
- **Hardening flags.** The CMake files set warnings only; your
  toolchain's hardening flags apply. CI builds and tests the library
  with `_FORTIFY_SOURCE=3`, `_GLIBCXX_ASSERTIONS`, stack protector,
  stack-clash and CET protection, and full RELRO on GCC and Clang
  ([compiler hardening](ASSURANCE.md#compiler-hardening)).
- **Offline builds.** Point FetchContent at unpacked sources and forbid
  downloads:
  `-DFETCHCONTENT_FULLY_DISCONNECTED=ON -DFETCHCONTENT_SOURCE_DIR_NLOHMANN_JSON=<dir>`
  (and `..._GOOGLETEST=<dir>` when building the tests).
- **Tests.** `ctest` runs the unit tests with no network beyond
  127.0.0.1 (a scripted loopback server). The conformance and live
  tests skip unless `CRYPTO_SERVICE_URL` names a running crypto-server.
- **Signatures.** Release tags and commits are SSH-signed; verify a tag
  with `git verify-tag v0.0.40` against the maintainer's published
  signing key.
