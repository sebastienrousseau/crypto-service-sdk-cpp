<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# Architecture

How a call travels through the SDK, and where each part lives. For the
reasons behind the shape, see the [decision records](adr/README.md).

## One call, end to end

```text
caller
  │  client.sign({key_id, "message"})          (AsyncClient or Client)
  ▼
Operations<Derived, Ret> (include/crypto_service/operations.hpp)
  │  route (method, path, wrapped?) + request struct
  │  encode: table-driven codec (src/codec.cpp, src/schemas*.hpp),
  │  binary fields as hex or base64 as the spec says
  ▼
Settings (src/settings.cpp)
  │  URL, Accept, User-Agent, credentials, traceparent, Content-Type;
  │  per-call Budget (per-attempt timeout, optional deadline)
  ▼
AsyncClient (src/async_client.cpp)        Client (src/client.cpp)
  │  queue → loop thread → AsyncTransport   │  Transport::send, blocking
  │  retries on timers (src/retry.cpp)      │  retries with sleep (src/retry.cpp)
  ▼                                         ▼
libcurl multi handle                      libcurl easy handle
(src/curl_transport.cpp)                  (src/curl_common.cpp)
  │                                         │
  └──────────────► crypto-server ◄──────────┘
                     │  HttpResponse {status, body, headers}
                     ▼
2xx: decode into the result struct (src/codec.cpp, src/wire.cpp)
non-2xx: RFC 9457 problem → ApiError (src/problem.cpp)
no response, bad shape: TransportError; cancelled: CancelledError
  ▼
std::future<Result> (AsyncClient) or Result (Client)
```

## Source layout

| Path | What it holds |
| :--- | :--- |
| `include/crypto_service/` | The public API: both clients, `Operations`, options, errors, encodings, the transport interfaces, and the request and result structs in `models/` |
| `include/crypto_service/detail/wire.hpp` | Internal declarations the templates in the public headers need (routes, encode and decode entry points) |
| `src/async_client.cpp` | The event loop: one owned thread, a queue of calls, timers for backoff, completion of futures |
| `src/client.cpp` | The blocking client: the attempt loop, retries and waits |
| `src/curl_common.cpp`, `src/curl_transport.cpp` | The libcurl easy and multi transports, RAII ownership of every handle, the shared hardening (no redirects, TLS verification, HTTP and HTTPS only) |
| `src/settings.cpp` | Option validation, request construction, traceparent generation, the stateful-route table, the per-call time budget |
| `src/retry.cpp` | Backoff with full jitter, `Retry-After`, which outcomes retry |
| `src/codec.cpp`, `src/schemas*.hpp`, `src/wire.cpp` | The table-driven JSON codec for every request and result struct |
| `src/problem.cpp` | RFC 9457 problem parsing and the `about:blank` fallback |
| `src/encoding.cpp` | Hex and base64 |
| `tests/` | GoogleTest: fake-transport unit tests for both clients and every operation, the libcurl transports against a scripted loopback server, the kit runner, and the conformance and live tests against a server |
| `tests/package/` | A consumer of the installed CMake package |
| `fuzz/` | libFuzzer targets for the success-response decoder and the problem parser |
| `benchmarks/` | Google Benchmark: `encode_request`, `decode_response`, `decode_problem`, `round_trip_hash` |
| `examples/` | Runnable programs, run by CI against a server |
| `conformance/` | The kit vendored from crypto-service; never edited here |

## Design rules

- **No cryptography.** Every operation is a call to crypto-server
  ([ADR 0001](adr/0001-thin-client-over-the-server.md)).
- **One method surface, two call models.** `Operations` is a CRTP base
  parameterised by the return wrapper: `std::future<T>` for
  `AsyncClient`, `T` for `Client`. Both send the same requests and
  decode the same results ([ADR 0004](adr/0004-async-model.md)).
- **Never log.** No code path writes to a stream. Error messages name
  the status, problem type or transport failure only
  ([ADR 0003](adr/0003-error-model.md)); `describe()` redacts
  credentials.
- **Strings for open sets.** Algorithm names, problem types and codes
  are strings, so a newer server works without an SDK release.
- **Thread safety.** `AsyncClient` is thread-safe; `Client` is
  thread-compatible (one per thread, or a caller's own mutex).
- **Retries are opt-in**, and stateful routes are retried only after
  429 or 503 ([ADR 0004](adr/0004-async-model.md)).

## How it is proven

- Unit tests reach every line and branch outcome of `include/` and
  `src/` (`make coverage`, with no exclusions; the defensive libcurl
  paths are reached through a test seam, see DEVELOPMENT.md).
- The conformance kit (`conformance/*.json`, 119 vectors) runs against
  a live crypto-server at `ci/server.ref`, through the typed methods
  wherever a vector's body is one they can express, and `request()`
  otherwise.
- ThreadSanitizer runs the `AsyncClient` tests, including destruction
  with calls in flight.
- The fuzz targets feed arbitrary bodies through the decoders and check
  that only the documented exceptions escape and that messages never
  repeat the body.
