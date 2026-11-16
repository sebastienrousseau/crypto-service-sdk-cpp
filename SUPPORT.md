<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Getting support

## Read first

- [README.md](README.md): install, quick start, configuration and the
  limits of the SDK.
- [The examples](examples/): hashing, AEAD, server-held signing,
  ML-KEM, error handling and concurrent async calls; CI runs every one
  against a live server.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how a call travels
  through the SDK.
- [DEVELOPMENT.md](DEVELOPMENT.md): building, testing and every CI gate.

## Supported versions

While pre-`1.0`, the latest released `0.0.x` is supported; older ones
are not. The SDK follows the Crypto Service ecosystem's version, and
each release is tested against the crypto-server commit recorded in
`ci/server.ref`.

| Version | Status | Supported |
| :--- | :--- | :--- |
| `0.0.40` (latest) | Current | Yes |
| `main` | In development | Yes |

## Questions and bugs

Open an [issue](https://github.com/sebastienrousseau/crypto-service-sdk-cpp/issues/new/choose)
(GitHub Discussions are not enabled). For a bug, include the SDK
version, the crypto-server version or commit (`GET /`), your compiler,
CMake and libcurl versions, and a minimal reproducer. Use synthetic
values only: no real keys, tokens or API keys.

A behaviour that comes from the server (an algorithm's output, a
problem type, a validation rule) belongs in
[crypto-service's issues](https://github.com/sebastienrousseau/crypto-service/issues).

## Security

Never report a vulnerability in a public issue; follow
[SECURITY.md](SECURITY.md).

## Response times

The project is maintained in a personal capacity, with no SLA. The goal
is a first answer within a few working days.
