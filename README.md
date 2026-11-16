<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

<p align="center">
  <img src="https://cloudcdn.pro/crypto-service/v1/logos/crypto-service.svg" alt="Crypto Service logo" width="128" />
</p>

<h1 align="center">Crypto Service SDK for C++</h1>

<p align="center">
  A typed C++17 client for the Crypto Service REST API: hashing, AEAD, server-held signing keys, post-quantum KEMs and signatures, HPKE and KMS from C++, with the cryptography kept on the server.
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/crypto-service-sdk-cpp/actions"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/crypto-service-sdk-cpp/ci.yml?style=for-the-badge&logo=github" alt="Build" height="28" /></a>
  <a href="https://github.com/sebastienrousseau/crypto-service-sdk-cpp/releases"><img src="https://img.shields.io/github/v/release/sebastienrousseau/crypto-service-sdk-cpp?style=for-the-badge&color=fc8d62&logo=cplusplus" alt="Registry" height="28" /></a>
  <a href="https://sebastienrousseau.com/crypto-service-sdk-cpp/api-reference/"><img src="https://img.shields.io/badge/docs-API%20reference-blue?style=for-the-badge&labelColor=555555&logo=readthedocs" alt="Docs" height="28" /></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/sebastienrousseau/crypto-service-sdk-cpp"><img src="https://img.shields.io/ossf-scorecard/github.com/sebastienrousseau/crypto-service-sdk-cpp?style=for-the-badge&label=OpenSSF%20Scorecard&logo=openssf" alt="OpenSSF Scorecard" height="28" /></a>
  <a href="LICENSE-APACHE"><img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg?style=for-the-badge" alt="License: Apache-2.0 OR MIT" height="28" /></a>
  <a href="https://github.com/sebastienrousseau/crypto-service-sdk-cpp/blob/main/docs/POLICIES.md"><img src="https://img.shields.io/badge/C%2B%2B-17%2B-93450a.svg?style=for-the-badge&logo=cplusplus" alt="C++17 or newer, CMake 3.20 or newer" height="28" /></a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/sebastienrousseau/crypto-service-sdk-cpp/main/.github/demo.gif" alt="A terminal running the hash example against a local crypto-server: the server's health, then SHA-256 and BLAKE3 digests computed through the SDK" width="100%" />
</p>

---

## Contents

**Getting started**

- [Install](#install): CMake `FetchContent`, `add_subdirectory`, or an installed package with `find_package`
- [Requirements](#requirements): toolchain floor, server, platforms
- [Quick Start](#quick-start): one blocking call, its errors, and concurrent calls with `AsyncClient`

**The Crypto Service ecosystem**

- [The Crypto Service ecosystem](#the-crypto-service-ecosystem): the server and its packages, the six language SDKs and the website

**Library reference**

- [Capabilities at a glance](#capabilities-at-a-glance): the current surface by theme
- [Ecosystem comparison](#ecosystem-comparison): short matrix; full table at [`docs/COMPARISON.md`](docs/COMPARISON.md)
- [Benchmarks](#benchmarks): scenarios; results at [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)
- [Features](#features): module-level capability list
- [Configuration](#configuration): client and retry options
- [Examples](#examples): runnable example index

**Operational**

- [When not to use Crypto Service](#when-not-to-use-crypto-service): limitations
- [Development](#development): make targets, conformance, CI
- [Security](#security): guarantees and reporting
- [Documentation](#documentation): all reference docs
- [Stability guarantees](#stability-guarantees): versioning, compatibility, toolchain floor
- [License](#license)

---

## Install

### As a C++ library

```cmake
include(FetchContent)
FetchContent_Declare(
  crypto_service_sdk
  GIT_REPOSITORY https://github.com/sebastienrousseau/crypto-service-sdk-cpp.git
  GIT_TAG        v0.0.40)
FetchContent_MakeAvailable(crypto_service_sdk)

target_link_libraries(your_app PRIVATE crypto_service::sdk)
```

**`add_subdirectory`** on a checkout works the same way. Tests, examples
and install rules are only generated when the SDK is the top-level
project.

**An installed package.** Build and install a release once, then find
it from any project:

```sh
cmake -S crypto-service-sdk-cpp -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix /opt/crypto-service
```

```cmake
find_package(crypto_service_sdk 0.0.40 CONFIG REQUIRED)  # with CMAKE_PREFIX_PATH=/opt/crypto-service
target_link_libraries(your_app PRIVATE crypto_service::sdk)
```

The package version file accepts the exact version only. Each GitHub
release carries the source archive, a CycloneDX SBOM, `SHA256SUMS` and
a build provenance attestation. There is no vcpkg or Conan package yet
([`docs/packaging.md`](docs/packaging.md)); until the first tag is
published, pin a commit SHA instead.

---

## Requirements

- A C++17 compiler and CMake 3.20 or newer
  ([toolchain policy](docs/POLICIES.md)). CI builds with GCC and Clang 18
  on Ubuntu 24.04.
- libcurl 7.85 or newer with its development headers
  (`libcurl4-openssl-dev` on Debian and Ubuntu; macOS ships libcurl).
  HTTP/2 is used when the libcurl build supports it.
- nlohmann/json 3.12.0, fetched by CMake from its release archive pinned
  by SHA-256 (GoogleTest 1.18.0 and Google Benchmark 1.10.0 the same
  way, for the tests and the opt-in benchmarks).
- A running crypto-server from
  [crypto-service](https://github.com/sebastienrousseau/crypto-service).
  The SDK implements no cryptography itself
  ([ADR 0001](docs/adr/0001-thin-client-over-the-server.md)).

---

## Quick Start

```cpp
#include <cstdlib>
#include <iostream>

#include "crypto_service/crypto_service.hpp"

int main() {
  crypto_service::ClientOptions options;
  options.base_url = std::getenv("CRYPTO_SERVICE_URL");  // e.g. http://127.0.0.1:3104
  options.api_key = std::getenv("CRYPTO_SERVICE_API_KEY");
  options.retry.max_retries = 2;  // off by default
  crypto_service::Client client(options);

  try {
    const auto digest = client.hash({"sha256", "abc"});
    std::cout << digest.algorithm << ": " << crypto_service::to_hex(digest.digest) << '\n';

    (void)client.sign({"k_AAAAAAAAAAAAAAAAAAAAAA", "a message"});  // no such key
  } catch (const crypto_service::ApiError& error) {  // the server's RFC 9457 problem
    std::cout << error.status() << ' ' << error.problem().type << ' '
              << error.problem().code.value_or("") << '\n';
  } catch (const crypto_service::TransportError& error) {  // no usable response
    std::cerr << error.what() << (error.timed_out() ? " (timed out)" : "") << '\n';
    return 1;
  }
  return 0;
}
```

`hash` posts to `POST /v2/hash` and returns a `HashResult` whose `digest`
holds the bytes the server sent as hex. Signing with an unknown key id
comes back as an `ApiError` with status 404, type
`urn:crypto-service:problem:key-not-found` and code `KEY_NOT_FOUND`.

`AsyncClient` has the same methods, each returning a `std::future`. One
instance is safe to share across threads; its event-loop thread
multiplexes the calls over pooled connections:

```cpp
#include <cstdlib>
#include <future>
#include <iostream>
#include <vector>

#include "crypto_service/crypto_service.hpp"

int main() {
  crypto_service::ClientOptions options;
  options.base_url = std::getenv("CRYPTO_SERVICE_URL");
  options.api_key = std::getenv("CRYPTO_SERVICE_API_KEY");
  crypto_service::AsyncClient client(options);

  std::vector<std::future<crypto_service::HashResult>> pending;
  for (const char* algorithm : {"sha256", "sha3-256", "blake3"}) {
    pending.push_back(client.hash({algorithm, "abc"}));
  }
  for (auto& result : pending) {
    const auto digest = result.get();  // rethrows ApiError or TransportError
    std::cout << digest.algorithm << ": " << crypto_service::to_hex(digest.digest) << '\n';
  }
}
```

---

## The Crypto Service ecosystem

This library is one client of the Crypto Service suite, which releases
at one version, server first. The design is one engine (crypto-server)
and thin typed clients per language, all held to one conformance kit
that the server repository publishes and every client vendors byte for
byte.

| Component | Purpose | Use case |
| :--- | :--- | :--- |
| [`crypto-service`][core] | The server and 18 npm packages (`@sebastienrousseau/crypto-*`: lib, server, CLI, TypeScript SDK, middleware, KMS, WASM, MCP, LSP, CBOM and more) | The engine behind every client |
| **`crypto-service-sdk-cpp`** | Typed C++17 client for the REST API | C and C++ systems |
| [`crypto-service-sdk-go`][go] | Typed Go client for the REST API | Go services |
| [`crypto-service-sdk-rust`][rust] | Typed Rust client for the REST API | Rust services |
| [`crypto-service-sdk-java`][java] | Typed Java client for the REST API | JVM services |
| [`crypto-service-sdk-dotnet`][dotnet] | Typed .NET client for the REST API | .NET services |
| [`crypto-service-sdk-python`][python] | Typed Python client for the REST API | Python services and notebooks |
| [crypto-service.co][site] | Project website | Overview and documentation entry point |

---

## Capabilities at a glance

| Area | Capability | Status |
| :--- | :--- | :--- |
| Hashing and MACs | `hash` (SHA-2, SHA-3, BLAKE2b, BLAKE3), `mac`, `mac_verify` | Supported |
| Key derivation | `kdf` (scrypt, HKDF, PBKDF2), `password_hash`, `password_verify` (Argon2id) | Supported |
| Symmetric | `encrypt`, `decrypt`, `secretbox_seal`, `secretbox_open`, `password_encrypt`, `password_decrypt`, `key_wrap`, `key_unwrap` | Supported |
| Server-held keys | `generate_key_pair`, `export_key`, `keys_delete`, `sign`, `verify`, `stream_sign`, `stream_verify` | Supported |
| Post-quantum | ML-KEM (`ml_kem_*`), hybrid X25519 + ML-KEM (`pq_generate_key_pair`, `pq_encapsulate`, `pq_decapsulate`), ML-DSA (`pq_sign_keygen`, `pq_sign`, `pq_verify`), SLH-DSA (`pq_hash_*`) | Supported |
| Public-key encryption | Sealed boxes (classical and hybrid), `multi_recipient_encrypt`, STREAM (`stream_pq_*`, `stream_multi_pq_*`), HPKE (`hpke_*`) | Supported |
| Payments | `stream_iso20022`: dual-signed ISO 20022 envelope verification | Supported |
| KMS | `kms_create_key`, `kms_wrap`, `kms_unwrap`, `kms_generate_data_key`, `kms_encrypt`, `kms_decrypt` | Supported |
| OPAQUE | `opaque_register_init`, `opaque_register_finish`, `opaque_login_init`, `opaque_login_finish` (transport only; the protocol runs on the caller's side) | Supported |
| Metadata | `health`, `live`, `ready`, `root`, `algorithms`, `get_dora_compliance`, `get_cbom` | Supported |
| Escape hatch | `request`: any GET or POST, status, headers and body, whatever the status | Supported |
| v1 OpenPGP routes, `/metrics` | Deprecated (sunset 2027-01-01) and operational | Not wrapped; reachable through `request` |

Every one of the 59 v2 operations in the OpenAPI document has a method
on both `Client` and `AsyncClient`.

---

## Ecosystem comparison

The suite's SDKs share one method surface, one option set and one
resilience contract, and are held to the conformance kit that
crypto-server runs in its own test suite.

| Project | Language | Conformance kit | Types |
| :--- | :---: | :---: | :---: |
| **crypto-service-sdk-cpp** | **C++17** | **Every vector, in CI, against the pinned server** | **Hand-written** |
| `@sebastienrousseau/crypto-sdk` | TypeScript | The server's own suite runs the kit | Hand-written |
| crypto-service-sdk-go, -rust, -java, -dotnet, -python | Their languages | See each repository | Hand-written |
| Raw HTTP | Any | No | None |

See [`docs/COMPARISON.md`](docs/COMPARISON.md) for the complete matrix.

---

## Benchmarks

Google Benchmark targets under the scenario names every Crypto Service
SDK uses: `encode_request`, `decode_response` and `decode_problem`
measure the client's own work with no network; `round_trip_hash` is one
loopback `POST /v2/hash` to a local crypto-server and runs only when
`CRYPTO_SERVICE_URL` is set. No numbers are published yet: results will
be generated into [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) with their
environment, and CI smoke-runs every scenario (`make bench`).

---

## Features

- **One include.** `crypto_service/crypto_service.hpp`, namespace
  `crypto_service`, CMake target `crypto_service::sdk`.
- **Two clients, one surface.** `AsyncClient` (primary) returns a
  `std::future<T>` from every method and drives libcurl's multi
  interface on one owned event-loop thread: calls are multiplexed over
  HTTP/2 where the server offers it, and connections are reused.
  `Client` is the blocking form with the same method names and
  arguments ([ADR 0004](docs/adr/0004-async-model.md)).
- **Thread safety, stated per class.** Every `AsyncClient` member except
  the destructor is thread-safe. A `Client` is thread-compatible: use
  one per thread, or share an `AsyncClient`.
- **Clean shutdown.** Destroying an `AsyncClient` cancels the calls in
  flight: each pending future becomes ready with `CancelledError`, the
  loop thread is joined, and no callback runs afterwards (tested under
  ThreadSanitizer).
- **Cancellation.** `CancelSource` and `CancelToken`, passed per call in
  `CallOptions`.
- **Encodings as the API defines them.** Binary values are
  `crypto_service::Bytes`; the SDK encodes and decodes the hex or base64
  each field uses on the wire, and UTF-8 text stays `std::string`. KMS
  calls send an explicit encoding; HPKE and KMS decrypt return both the
  bytes and the server's UTF-8 decoding of them.
- **Errors as RFC 9457 problems.** `Error` is the base (a
  `std::runtime_error`). `ApiError` carries the status and the problem
  (`type`, `title`, `status`, `detail`, `instance`, `code`, `errors[]`
  and any extension members); a non-problem error body becomes an
  `about:blank` problem. `TransportError` (with `timed_out()`) means no
  usable response; `CancelledError` derives from it
  ([ADR 0003](docs/adr/0003-error-model.md)).
- **Resilience.** Per-attempt timeout, overall deadline, opt-in retries
  with exponential backoff and full jitter, `Retry-After` honoured up to
  `max_delay`; stateful operations are never resent after a 504 or a
  lost connection.
- **Pluggable transport.** `Transport` (blocking) and `AsyncTransport`
  take any HTTP stack; the tests use in-memory doubles and a scripted
  loopback server.

---

## Configuration

`ClientOptions`:

| Field | Type | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `base_url` | `std::string` | none | `http://` or `https://` origin, optionally with a path prefix; trailing `/` removed |
| `api_key` | `std::optional<std::string>` | unset | Sent as `x-api-key` |
| `token` | `std::optional<std::string>` | unset | Sent as `Authorization: Bearer <token>` |
| `timeout` | `std::chrono::milliseconds` | 30 s | Per attempt, connect plus transfer |
| `deadline` | `std::optional<std::chrono::milliseconds>` | unset | Whole call, retries and backoff included |
| `retry` | `RetryOptions` | no retries | See below |
| `traceparent` | `std::optional<std::string>` | unset | A fixed W3C `traceparent` for every request |
| `auto_traceparent` | `bool` | false | A fresh random `traceparent` per request |
| `sleep` | `std::function<void(milliseconds)>` | interruptible sleep | How `Client` waits between attempts (tests) |

`RetryOptions`: `max_retries` (0), `initial_delay` (200 ms), `max_delay`
(2 s). Idempotent and pure operations are retried after 429, 503, 504
and a lost connection or timeout. Stateful operations (key generation
and deletion, every keygen, `kms_create_key`, OPAQUE registration) are
retried only after 429 or 503. A `Retry-After` longer than `max_delay`
makes the response final. Credentials and request bodies never appear
in messages; `describe(options)` prints the options with the
credentials redacted. Bad options throw `std::invalid_argument`.

The tests and examples read `CRYPTO_SERVICE_URL` and
`CRYPTO_SERVICE_API_KEY`; the library itself reads no environment
variables. Every request carries
`User-Agent: crypto-service-sdk-cpp/0.0.40`.

---

## Examples

Each is built as `build/crypto_service_<name>` and run by CI against a
live crypto-server (`make examples`).

| Example | Shows | Run |
| :--- | :--- | :--- |
| [`hash.cpp`](examples/hash.cpp) | `hash()` with SHA-256 and BLAKE3 | `crypto_service_hash` |
| [`aead.cpp`](examples/aead.cpp) | `encrypt()` and `decrypt()` round trip with a synthetic key | `crypto_service_aead` |
| [`sign_verify.cpp`](examples/sign_verify.cpp) | A server-held Ed25519 key: `generate_key_pair`, `sign` by key id, `verify`, `keys_delete` | `crypto_service_sign_verify` |
| [`ml_kem.cpp`](examples/ml_kem.cpp) | A server-held ML-KEM-768 key: `ml_kem_encapsulate`, then `ml_kem_decapsulate` by key id | `crypto_service_ml_kem` |
| [`errors.cpp`](examples/errors.cpp) | `ApiError` problems (unknown key, validation errors) and `TransportError` | `crypto_service_errors` |
| [`async_concurrent.cpp`](examples/async_concurrent.cpp) | Concurrent calls on one `AsyncClient` | `crypto_service_async_concurrent` |

---

## When not to use Crypto Service

- **You cannot run crypto-server.** This client does nothing without it;
  there is no offline mode and no local cryptography.
- **You need cryptography inside your process**, for example on a
  device with no network, or where a round trip per operation is too
  slow. Use a vetted library such as libsodium or OpenSSL directly.
- **You need the v1 OpenPGP routes.** They are deprecated and sunset on
  2027-01-01; the client does not wrap them (only `request` reaches
  them). `/metrics` is for scrapers and is not wrapped either.
- **You need stateful calls retried after a lost connection.** Key
  generation, deletion and registration are not resent when the server
  may already have acted; deciding that is left to the caller.
- **You need a vcpkg or Conan package, or a prebuilt binary.** Neither
  exists yet; build from source or install with CMake.

---

## Development

```sh
git clone https://github.com/sebastienrousseau/crypto-service-sdk-cpp
cd crypto-service-sdk-cpp
make check          # versions, format, file size, complexity, -Werror build, ctest, clang-tidy
make coverage       # 100% line and branch coverage of include/ and src/ (clang)
make tsan           # ThreadSanitizer on the shared-client and shutdown tests
make regression     # builds and starts the pinned crypto-server, runs everything against it
make bench          # Google Benchmark: client-side and loopback
make docs           # Doxygen API reference and the MkDocs manual
```

`make check` builds with `-Wall -Wextra -Wpedantic -Werror` and runs the
GoogleTest suite through ctest; clang-format, clang-tidy and
rust-code-analysis run when installed and say so when they are not.
`make conformance` runs all 119 vectors of the vendored kit against the
server at `CRYPTO_SERVICE_URL` and fails, rather than skips, without
one. `make regression` builds crypto-server at the commit in
`ci/server.ref`, starts it on a free loopback port with synthetic
credentials, runs the gate, the kit, every example, every README block,
the benchmark smoke run, coverage and the package test, and stops the
server even on failure. CI adds GCC and Clang sanitizer builds,
libFuzzer, CodeQL, the API compatibility check and the docs lint.
[`DEVELOPMENT.md`](DEVELOPMENT.md) maps every CI gate to its local
command; `make demo` re-renders the GIF above with
[VHS](https://github.com/charmbracelet/vhs).

---

## Security

The SDK sends requests to the server you configure and nothing else. It
never logs, and its exception messages name only the HTTP status, the
problem type or the transport failure: never credentials, keys,
plaintexts or bodies. libcurl is limited to `http` and `https`, does not
follow redirects, and always verifies TLS certificates; there is no
option to turn verification off. Use `https://` for any server that is
not on loopback. Credentials, header names and values are checked for
control characters so they cannot inject headers. Response decoding and
problem parsing are fuzzed with libFuzzer under ASan and UBSan, and the
seed corpus is replayed by ctest on every build. Releases carry
`SHA256SUMS`, a CycloneDX SBOM and a build provenance attestation.

Report vulnerabilities according to [`SECURITY.md`](SECURITY.md).

---

## Documentation

[User manual](https://sebastienrousseau.com/crypto-service-sdk-cpp/) ·
[API reference](https://sebastienrousseau.com/crypto-service-sdk-cpp/api-reference/) ·
[Developer docs](DEVELOPMENT.md) ·
[Family map](#the-crypto-service-ecosystem)

Also: [Architecture](docs/ARCHITECTURE.md) ·
[Decision records](docs/adr/README.md) · [Roadmap](docs/ROADMAP.md) ·
[Packaging](docs/packaging.md) · [Policies](docs/POLICIES.md) ·
[Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) ·
[Governance](GOVERNANCE.md) · [Support](SUPPORT.md) ·
[Conformance kit](conformance/README.md) · [Agent rules](AGENTS.md)

---

## Stability guarantees

The project is pre-1.0 and versions advance in `0.0.1` steps, in
lockstep with the Crypto Service suite: SDK 0.0.N vendors the
conformance kit of the server commit in `ci/server.ref` and is tested
against that server. The breaking axis is the public headers: a removed
or renamed method, field or type, or a changed exception type for a
given response, is breaking and the changelog calls it out. CI checks
source compatibility against the last release tag; binary (ABI)
compatibility is not promised, so rebuild against each release
([ADR 0005](docs/adr/0005-source-compatibility-not-abi-stability.md)).
The client covers the v2 API only: the v1 routes are deprecated by the
server and sunset on 2027-01-01. The C++ standard and CMake floors move
only as described in the [toolchain policy](docs/POLICIES.md).

---

## License

This project is dual-licensed under either:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([`LICENSE-MIT`](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option. Dependencies keep their own licences: nlohmann/json
(MIT), libcurl (curl licence), and, for the tests and benchmarks only,
GoogleTest (BSD-3-Clause) and Google Benchmark (Apache-2.0).

[core]: https://github.com/sebastienrousseau/crypto-service
[go]: https://github.com/sebastienrousseau/crypto-service-sdk-go
[rust]: https://github.com/sebastienrousseau/crypto-service-sdk-rust
[java]: https://github.com/sebastienrousseau/crypto-service-sdk-java
[dotnet]: https://github.com/sebastienrousseau/crypto-service-sdk-dotnet
[python]: https://github.com/sebastienrousseau/crypto-service-sdk-python
[site]: https://crypto-service.co
