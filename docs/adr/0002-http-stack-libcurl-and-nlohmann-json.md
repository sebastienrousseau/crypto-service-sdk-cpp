<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# 0002. HTTP stack: libcurl (easy and multi) and nlohmann/json

- **Status:** Accepted
- **Date:** 2026-11-16
- **Deciders:** Sebastien Rousseau

## Context

C++ has no HTTP client or JSON library in its standard library. The
SDK needs connection reuse, keep-alive, HTTP/2 multiplexing for the
asynchronous client, TLS verification that cannot be turned off,
redirect refusal and per-transfer timeouts and cancellation. Every
dependency it adds is one its callers must build, audit and keep
patched.

## Options considered

1. libcurl for HTTP (the easy interface for the blocking client, the
   multi interface for the asynchronous one), nlohmann/json for JSON.
2. cpr (a C++ wrapper over libcurl's easy interface), Boost.Beast with
   Boost.Asio, or a platform API (WinHTTP, NSURLSession).
3. RapidJSON or simdjson for JSON.

## Decision

Option 1. libcurl is on every platform the SDK targets and is the
system library on Linux distributions and macOS, so it gets the
operating system's security updates. Its multi interface drives many
transfers from one thread with HTTP/2 multiplexing and a shared
connection cache, which is what the asynchronous client needs
([ADR 0004](0004-async-model.md)); cpr does not expose it, and Beast
would add Boost and its own TLS integration. The SDK links libcurl
privately, wraps every handle in a `std::unique_ptr` with its cleanup
function, and sets the same hardening on every transfer: protocols
`http,https` only, `CURLOPT_FOLLOWLOCATION` off, peer and host
verification on, TCP keep-alive, `CURLOPT_NOSIGNAL`.

nlohmann/json is header-only, readable, and appears in the public
headers only where the API carries free-form JSON (the CBOM metadata,
ISO 20022 signed payloads, problem extensions, `RawResponse::json()`). Request and result structs are
encoded and decoded by a table-driven codec in `src/`, so a struct's
wire names are listed once.

nlohmann/json 3.12.0 is fetched by CMake from its release archive,
pinned by SHA-256, as are GoogleTest 1.18.0 for the tests and Google
Benchmark 1.10.0 for the opt-in benchmarks. Neither test dependency is
linked into the library. libcurl 7.85 or newer is required
(`CURLOPT_PROTOCOLS_STR`).

## Consequences

- The `Transport` and `AsyncTransport` interfaces keep HTTP replaceable:
  a caller with another stack implements them.
- nlohmann/json's major version is part of the API: a caller who uses
  another major version in the same program cannot mix them.
- HTTP/2 depends on how the system libcurl was built; without nghttp2
  the client speaks HTTP/1.1 with keep-alive.
- No dependency comes from a package registry, so no automated
  advisory scanner covers them; SECURITY.md says how they are tracked.
