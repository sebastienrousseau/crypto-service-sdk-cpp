<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Comparison

Which client should a program use to talk to crypto-server? The Crypto
Service ecosystem has the TypeScript reference SDK, published with the
server, and six language SDKs. All of them follow one resilience
contract (options, retry table, error model) and run the crypto-service
conformance kit against a live crypto-server in CI.

| Project | Language | Conformance kit in CI | Types | Distribution |
| :--- | :--- | :---: | :--- | :--- |
| `@sebastienrousseau/crypto-sdk` (in crypto-service) | TypeScript | Yes (the reference runner) | Hand-written | npm |
| crypto-service-sdk-python | Python | Yes | Hand-written | See its README |
| crypto-service-sdk-go | Go | Yes | Hand-written | See its README |
| crypto-service-sdk-rust | Rust | Yes | Hand-written | See its README |
| crypto-service-sdk-java | Java | Yes | Hand-written | See its README |
| crypto-service-sdk-dotnet | .NET | Yes | Hand-written | See its README |
| **crypto-service-sdk-cpp** | **C++17** | **Yes** | **Hand-written** | **GitHub release, CMake package** |
| Raw HTTP | Any | No | None | Your HTTP client |

Each SDK's own README and manifest are the authority for its language
floor, dependencies and call model; this page does not restate them, so
it cannot drift from them.

## Evidence

| Project | Where to check |
| :--- | :--- |
| TypeScript SDK | [crypto-service `packages/crypto-sdk`](https://github.com/sebastienrousseau/crypto-service/tree/main/packages/crypto-sdk) |
| crypto-service-sdk-python | [repository](https://github.com/sebastienrousseau/crypto-service-sdk-python) |
| crypto-service-sdk-go | [repository](https://github.com/sebastienrousseau/crypto-service-sdk-go) |
| crypto-service-sdk-rust | [repository](https://github.com/sebastienrousseau/crypto-service-sdk-rust) |
| crypto-service-sdk-java | [repository](https://github.com/sebastienrousseau/crypto-service-sdk-java) |
| crypto-service-sdk-dotnet | [repository](https://github.com/sebastienrousseau/crypto-service-sdk-dotnet) |
| **crypto-service-sdk-cpp** | [`ci.yml`, job `conformance`](https://github.com/sebastienrousseau/crypto-service-sdk-cpp/blob/main/.github/workflows/ci.yml); [`CMakeLists.txt`](https://github.com/sebastienrousseau/crypto-service-sdk-cpp/blob/main/CMakeLists.txt) (C++17, libcurl 7.85+, nlohmann/json 3.12.0) |

The kit itself is
[`conformance/`](https://github.com/sebastienrousseau/crypto-service/tree/main/conformance)
in crypto-service; every SDK vendors it byte for byte and pins it with
`conformance/SHA256SUMS`.

## For C++ callers

- **crypto-service-sdk-cpp** gives typed request and result structs,
  binary values as `Bytes` with the spec's encodings applied, one
  exception hierarchy carrying the RFC 9457 problem
  ([ADR 0003](adr/0003-error-model.md)), an `AsyncClient` returning
  `std::future` and a blocking `Client`
  ([ADR 0004](adr/0004-async-model.md)), and a `Transport` interface
  for another HTTP stack.
- **Raw HTTP** (libcurl, cpr, Boost.Beast) needs no dependency beyond
  your HTTP client, but you write the request bodies, the encodings, the
  retry rules and the problem parsing, and nothing tests them against
  the server.
- **A local cryptography library** (OpenSSL, libsodium, liboqs) is the
  alternative when you do not want a server at all; this SDK is for
  programs that want keys held and operations performed by
  crypto-server.
