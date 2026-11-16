<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Roadmap

What may come next, and what would decide it. Nothing here is a
commitment or has a date; the SDK moves with the Crypto Service
ecosystem, one `0.0.x` step at a time. Items are added here before they
become work.

## Done in 0.0.40

- `AsyncClient` (futures over a libcurl multi handle) and a blocking
  `Client`, one method per v2 operation
  ([ADR 0004](adr/0004-async-model.md)).
- The shared resilience contract: timeouts, deadline, opt-in retries
  with the stateful-route rule, traceparent, cancellation.
- The conformance kit against a live server, 100% line and branch
  coverage, ThreadSanitizer, fuzzing, benchmarks, an installed CMake
  package and a tag-triggered GitHub release
  ([ADR 0006](adr/0006-cmake-package-github-release-no-registry.md)).

## Candidates

| Item | Why | What decides it |
| :--- | :--- | :--- |
| vcpkg port and Conan recipe | `find_package` without building from source | Demand from users; each registry's review of the port |
| Published benchmark results | `docs/BENCHMARKS.md` from a recorded run | A reproducible benchmark host shared by the ecosystem's SDKs |
| Callback or coroutine API beside `std::future` | Integration with event loops (Asio, C++20 coroutines) without blocking a thread on `get()` | Demand, and whether it fits without a second transport |
| Streaming request bodies for large payloads | Avoid holding a whole plaintext in memory | A streaming endpoint in crypto-server |
| A Windows CI build (MSVC) | The CMake has MSVC flags but nothing tests them | A user on Windows |
| A system nlohmann/json option for packagers | Distributions ship their own nlohmann/json | A distribution packaging the SDK |
| OSS-Fuzz | Continuous fuzzing beyond the 60 s per pull request | Acceptance by the OSS-Fuzz project |

## Not planned

- Cryptography in the client ([ADR 0001](adr/0001-thin-client-over-the-server.md)).
- Typed methods for the v1 routes, sunset 2027-01-01, or `/metrics`.
- An option to disable TLS verification or follow redirects.
- Retrying a stateful operation after a 504 or a lost connection
  ([ADR 0004](adr/0004-async-model.md)).
- A stable binary ABI before 1.0 ([ADR 0005](adr/0005-source-compatibility-not-abi-stability.md)).
