<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
advance in `0.0.1` steps in lockstep with the Crypto Service ecosystem.

## [Unreleased]

### Added

- `docs/ASSURANCE.md`, the assurance case: assets, actors, entry
  points, trust boundaries, the secure design principles applied and
  the common weaknesses countered, each with its code and test.
- `docs/security-review-2026-11.md`, the first recorded security
  review, with eleven findings and their dispositions.
- `docs/REPRODUCING.md`: how to rebuild a release's archive and SBOM
  and check them against `SHA256SUMS`; the `0.0.40` archive rebuilds
  bit for bit.
- `scripts/osv-check.py` and the OSV workflow: the pinned
  nlohmann/json, GoogleTest and Google Benchmark archives are checked
  against OSV on every change and weekly.
- CI builds and tests with the recommended compiler hardening flags on
  GCC and Clang (`gcc-hardened`, `clang-hardened`).
- `SPDX-FileCopyrightText` in every source file beside its licence
  identifier.

### Changed

- The release SBOM's `serialNumber` is derived from its content, so a
  rebuild gives the same bytes; the release workflow builds the files
  twice and compares them.

### Security

- The release workflow accepts only a numeric version and passes step
  outputs to scripts through the environment, never by interpolation.
- A release published by `workflow_dispatch` now needs the same signed
  tag as a tag push, pointing at the commit being built
  (`scripts/verify-release-tag`).

### Fixed

- `ClientOptions::timeout` and `ClientOptions::deadline` are now
  rejected above 24 hours with `std::invalid_argument`. An unbounded
  deadline overflowed the `steady_clock` arithmetic of the call budget
  (undefined behaviour, found in the 2026-11 security review), and a
  timeout above about 24.8 days did not fit libcurl's `long` on
  Windows.

## [0.0.40] - 2026-11-16

The first release of the C++ SDK, in lockstep with crypto-service
0.0.40, tested against crypto-server at commit `3e8ecfd` (`ci/server.ref`).

### Added

- `crypto_service::AsyncClient`, the primary client: one owned
  event-loop thread drives a libcurl multi handle (connection reuse,
  keep-alive, HTTP/2 multiplexing over TLS where offered), and every
  operation returns a `std::future`. Thread-safe; destruction ends every
  pending future with `CancelledError` and joins the loop thread.
- `crypto_service::Client`, a blocking client with the same methods on
  one reusable libcurl easy handle. Thread-compatible.
- One typed method per v2 operation of the OpenAPI document (59 of 59),
  plus `root`, `health`, `live`, `ready`, `algorithms`,
  `get_cbom` and `get_dora_compliance`, and a raw `request()` for any
  other route. Binary values are `Bytes`, encoded as the spec says
  (lowercase hex for keys, signatures and digests; padded base64 for
  AEAD, secretbox, sealed-box, stream and key-wrap output); KMS
  requests take an explicit encoding and HPKE and KMS decrypt return
  both UTF-8 and hex.
- The resilience contract shared by every Crypto Service SDK:
  `base_url`, `api_key` (`x-api-key`) or `token` (Bearer), a per-attempt
  `timeout` (30 s), an optional overall `deadline`, opt-in retries
  (`max_retries` 0, `initial_delay` 200 ms, `max_delay` 2 s) with
  exponential backoff, full jitter and `Retry-After`, the stateful-route
  rule ported from the TypeScript SDK's `request.ts`, a fixed or
  generated W3C `traceparent`, and cooperative cancellation through
  `CancelSource` and `CancelToken`.
- Errors under `crypto_service::Error`: `ApiError` with the RFC 9457
  problem (`type`, `title`, `status`, `detail`, `instance`, `code`,
  `errors[]`, extensions; an `about:blank` problem for a non-problem
  body), `TransportError` with `timed_out()`, and `CancelledError`.
  No message carries credentials, keys, plaintexts or bodies.
- `Transport` and `AsyncTransport` interfaces for other HTTP stacks and
  test doubles. The libcurl transports refuse redirects, always verify
  TLS, speak HTTP and HTTPS only and send
  `User-Agent: crypto-service-sdk-cpp/0.0.40`.
- The conformance kit vendored byte for byte from crypto-service in
  `conformance/` (119 vectors, pinned by `SHA256SUMS`), with a
  GoogleTest runner that sends every vector through a typed method where
  one exists and `request()` otherwise; `make conformance` fails on a
  missing server or a skip.
- Examples: hash, AEAD round trip, server-held Ed25519 sign and verify,
  ML-KEM-768 encapsulate and decapsulate, problem details, concurrent
  async calls; run by CI against a live server, as is every README code
  block.
- libFuzzer targets for the success-response decoder and the problem
  parser, with a seed corpus and a JSON dictionary.
- Google Benchmark scenarios `encode_request`, `decode_response`,
  `decode_problem` and `round_trip_hash`.
- CMake build (C++17, CMake 3.20), nlohmann/json 3.12.0, GoogleTest
  1.18.0 and Google Benchmark 1.10.0 by `FetchContent` pinned by
  SHA-256, and an installed package: `find_package(crypto_service_sdk
  0.0.40 CONFIG)` with target `crypto_service::sdk`.
- Gates: `make check`, 100% line and branch coverage with no
  exclusions, complexity ceilings (rust-code-analysis-cli 0.0.25),
  clang-format and clang-tidy 18, GCC and Clang with ASan and UBSan,
  ThreadSanitizer, an API compatibility check, codespell, REUSE,
  markdownlint and lychee.
- CI, fuzz, CodeQL, Scorecard, DCO, docs-lint, manual and release
  workflows; the release attaches a source archive, a CycloneDX SBOM,
  `SHA256SUMS` and a build provenance attestation. No package registry.
- Documentation: README, AGENTS.md, CONTRIBUTING.md, DEVELOPMENT.md,
  GOVERNANCE.md, SUPPORT.md, SECURITY.md, a MkDocs manual with a
  Doxygen API reference, and decision records 0001 to 0006.
