<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# Policies

## Toolchain floor

- **C++17.** The public headers use `std::optional`, `std::string_view`,
  `inline constexpr` and `std::future`, so C++17 is the floor. Raising it
  is a breaking change and is announced in the changelog first.
- **CMake 3.20.** The floor `cmake_minimum_required` declares. Raising
  it is announced the same way.
- **Compilers.** CI builds with the GCC and Clang 18 that Ubuntu 24.04
  ships. Other compilers that implement C++17 are expected to work but
  are not tested; MSVC flags are set in `CMakeLists.txt` but no Windows
  build runs in CI.
- **libcurl.** The system library, 7.85 or newer
  (`CURLOPT_PROTOCOLS_STR`). HTTP/2 is used when the libcurl build
  supports it and the server offers it over TLS.

## Server compatibility

Each release is tested against the crypto-server commit in
`ci/server.ref`, with the conformance kit vendored from that commit.
The v1 routes (deprecated, sunset 2027-01-01) and `/metrics` have no
typed methods; `request()` reaches them if needed.

## Dependencies

Third-party sources are fetched from release archives pinned by
SHA-256 in CMake (`URL_HASH`). Dependabot does not track CMake
`FetchContent`, so a version bump is a reviewed change that updates the
URL and the hash together, verified against the downloaded archive.

## Versioning

`0.0.x`, one `0.0.1` step at a time, in lockstep with the Crypto
Service ecosystem. Pre-1.0, any step may change the API; the CI `api`
job reports source incompatibilities against the last tag
([ADR 0005](adr/0005-source-compatibility-not-abi-stability.md)).
