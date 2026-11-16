<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 0004. Async model: futures from one owned event-loop thread, and the retry table

- **Status:** Accepted
- **Date:** 2026-11-16
- **Deciders:** Sebastien Rousseau

## Context

Every Crypto Service SDK offers an asynchronous API first and a
blocking one second, with identical resilience semantics. C++17 has no
standard event loop or coroutines; its standard asynchronous result is
`std::future`. Callers range from single-threaded tools to servers that
fan out many requests at once and want them multiplexed over few
connections. Retrying must never repeat an operation that may already
have changed state on the server.

## Options considered

1. `std::async` per call over a blocking client. One thread per call in
   flight, one connection per thread, no multiplexing.
2. Callbacks or C++20 coroutines over a caller-supplied event loop
   (Asio). Efficient, but it imposes a loop and, for coroutines, C++20.
3. An `AsyncClient` that owns one event-loop thread driving libcurl's
   multi interface, returning a `std::future` for every operation; a
   blocking `Client` beside it with the same methods.

## Decision

Option 3.

- **Shape.** `Operations<Derived, Ret>` holds one method per operation;
  `AsyncClient` derives from `Operations<AsyncClient, std::future>`,
  `Client` from `Operations<Client, Same>`, so both have the same names,
  arguments and result types.
- **The loop.** A call validates its arguments, queues its request under
  a mutex, wakes the loop and returns its future at once. The loop
  thread alone touches the `AsyncTransport` (by default one libcurl
  multi handle: shared connection cache, keep-alive, HTTP/2 multiplexing
  over TLS where the server offers it). Each turn it adopts new calls,
  ends cancelled ones, starts attempts that are due, polls the transport
  until the next timer, decodes finished responses and fulfils their
  promises. Backoff waits are timers on the loop, so a waiting retry
  blocks no thread and no other call.
- **Thread safety.** `AsyncClient`: every member function except the
  destructor is thread-safe; many threads may share one instance. The
  destructor must not run concurrently with a call. Futures may be
  waited on from any thread, and a ready future's value is complete
  (decoding happens on the loop thread). `AsyncClient` is neither
  copyable nor movable. `Client`: thread-compatible, not thread-safe; it
  owns one libcurl easy handle whose connection is reused between
  calls, so use one per thread or guard it with a mutex. It is movable.
  `CancelSource::cancel()` may be called from any thread.
- **Cancellation.** `CallOptions::cancel` takes a `CancelToken` from a
  `CancelSource`. The loop notices a cancelled token within about 10 ms
  and ends the call with `CancelledError`; the blocking client notices
  it within about a second (libcurl's progress callback) and while
  waiting between attempts. A cancelled call is not retried.
- **Destruction.** `~AsyncClient` stops the loop, cancels every transfer
  still in flight, ends each pending future with `CancelledError` (never
  a broken promise), and joins the thread; no completion runs
  afterwards. ThreadSanitizer runs the tests that destroy a client with
  calls in flight.
- **Time.** `timeout` (default 30 s) bounds each attempt; `deadline`,
  when set, bounds the whole call including retries and waits, and
  shortens the last attempt's timeout to what remains.

### The retry table

Ported from the TypeScript SDK's `request.ts`, identical in every SDK.
Retries are off by default (`max_retries` 0). With `max_retries` set,
attempt n+1 waits a uniformly random time in
`[0, min(initial_delay * 2^(n-1), max_delay)]` (full jitter; defaults
200 ms and 2 s), or what a 429, 503 or 504 response's `Retry-After`
asks for (delta-seconds or an HTTP-date); a `Retry-After` longer than
`max_delay` makes that response final.

| Outcome | Idempotent or pure operation (every GET, every other POST) | Stateful operation |
| :--- | :---: | :---: |
| 429 Too Many Requests | Retry | Retry |
| 503 Service Unavailable | Retry | Retry |
| 504 Gateway Timeout | Retry | **Never** |
| Connection error or attempt timeout | Retry | **Never** |
| Any other status | Final | Final |
| Cancelled, or deadline reached | Final | Final |

Stateful operations are those whose path contains `/keys/generate`,
`/keys/delete`, `/keygen` (every key generation route: ML-KEM, hybrid,
ML-DSA, SLH-DSA, HPKE), `/kms/create-key` or `/opaque/register/`. After
a 429 or 503 the server certainly did nothing; after a 504 or a lost
connection it may already have created or deleted a key.

## Consequences

- An `AsyncClient` costs one thread and one multi handle; create one
  per server and share it, not one per call.
- Many concurrent calls share connections and, over HTTP/2,
  multiplex on one.
- `std::future::get()` blocks the caller's thread; callers that need
  callbacks or coroutines wrap the future or implement an
  `AsyncTransport` (a candidate in docs/ROADMAP.md).
- The worst case for one call without a deadline is
  `(max_retries + 1) * timeout` plus the waits; set `deadline` to bound
  it.
