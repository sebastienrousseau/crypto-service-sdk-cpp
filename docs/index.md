<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# crypto-service-sdk-cpp

A typed C++17 client for the crypto-server REST API of the Crypto
Service ecosystem: hashing, MACs, KDFs, AEAD, server-held signing keys,
post-quantum KEMs and signatures, HPKE, KMS and OPAQUE. The SDK has no
cryptography of its own; the server does the work, and the
crypto-service conformance kit proves the two agree in CI.

## Install

```cmake
include(FetchContent)
FetchContent_Declare(
  crypto_service_sdk
  GIT_REPOSITORY https://github.com/sebastienrousseau/crypto-service-sdk-cpp.git
  GIT_TAG        v0.0.41)
FetchContent_MakeAvailable(crypto_service_sdk)
target_link_libraries(your_app PRIVATE crypto_service::sdk)
```

Or install it and use `find_package(crypto_service_sdk 0.0.41 CONFIG)`;
see [Packaging](packaging.md). The snippets name the version `main`
prepares; until its tag exists, use the newest release (`v0.0.40`).

## Quick start

```cpp
#include <iostream>

#include "crypto_service/crypto_service.hpp"

int main() {
  crypto_service::ClientOptions options;
  options.base_url = "http://127.0.0.1:3104";
  options.api_key = "conformance-key-0123456789abcdef";  // synthetic

  crypto_service::AsyncClient client(options);
  auto digest = client.hash({"sha256", "abc"});  // std::future<HashResult>
  std::cout << crypto_service::to_hex(digest.get().digest) << '\n';
}
```

`crypto_service::Client` has the same methods and blocks instead of
returning futures. The examples in
[`examples/`](https://github.com/sebastienrousseau/crypto-service-sdk-cpp/tree/main/examples)
cover hashing, AEAD, server-held Ed25519 signing, ML-KEM-768, problem
details and concurrent async calls.

## Where to go next

- [API reference](api-reference.md): every type and method, from the
  headers' documentation.
- [Architecture](ARCHITECTURE.md): how a call travels through the SDK.
- [Comparison](COMPARISON.md): the ecosystem's SDKs side by side.
- [Benchmarks](BENCHMARKS.md): the client's own cost and a loopback
  round trip.
- [Decision records](adr/README.md): why it is shaped this way.
