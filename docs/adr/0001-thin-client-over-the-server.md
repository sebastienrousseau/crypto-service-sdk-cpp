<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 0001. A thin client over crypto-server, no local cryptography

- **Status:** Accepted
- **Date:** 2026-11-16
- **Deciders:** Sebastien Rousseau

## Context

crypto-server exposes hashing, MACs, KDFs, password hashing, AEAD,
server-held signing keys, ML-KEM, ML-DSA, SLH-DSA, hybrid KEMs, HPKE,
KMS and OPAQUE over a REST API, implemented once in crypto-lib. A C++
application that needs those operations can link a cryptography
library and reimplement the service's behaviour, or call the server.

## Options considered

1. Implement the operations locally (OpenSSL, libsodium, liboqs). Two
   implementations of every algorithm choice, parameter set and
   encoding would drift, server-held keys could not be used, and the
   SDK would need its own cryptographic review.
2. Embed the TypeScript implementation (a JavaScript runtime in the C++
   process). One engine, but every caller ships a runtime.
3. A typed client for the REST API, with no cryptography of its own.

## Decision

Option 3. The SDK builds JSON requests, sends them over HTTP and decodes
the responses into structs. Every hash, cipher, signature, KEM and KDF
runs in the server; the client only converts binary values to and from
the encodings the OpenAPI document names (hex, base64, UTF-8).
Behaviour is pinned by the conformance kit vendored from crypto-service
(`conformance/`), which CI runs against a live server at the commit in
`ci/server.ref`.

## Consequences

- A caller must run or reach a crypto-server; the README says so under
  "When not to use".
- Keys can stay on the server: signing, decapsulation, HPKE and KMS
  calls take a `keyId`, so private keys need never reach the client.
- A new algorithm string works without an SDK release where the
  request shape is unchanged: algorithm names are strings.
- The SDK version moves in lockstep with the ecosystem, and each
  release is tested against one pinned server commit.
- The SDK's own cost is JSON encoding and decoding; the benchmarks
  measure that separately from the round trip (docs/BENCHMARKS.md).
