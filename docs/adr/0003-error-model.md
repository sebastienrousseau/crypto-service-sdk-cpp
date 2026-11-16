<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 0003. One exception hierarchy carrying the RFC 9457 problem

- **Status:** Accepted
- **Date:** 2026-11-16
- **Deciders:** Sebastien Rousseau

## Context

A call can fail in five ways: the options or arguments are bad, no
HTTP response arrives (connection, TLS, timeout, deadline, refused
redirect), the call is cancelled, the server answers with an error
status, or a 2xx body does not have the documented shape. crypto-server
answers errors with RFC 9457 problem details
(`application/problem+json`): `type`
(`urn:crypto-service:problem:<slug>`), `title`, `status`, `detail`,
`instance`, a crypto-lib or key-store `code`, and `errors[]` for
validation failures. A proxy in front of it may answer with HTML or
nothing. Request bodies carry keys and plaintexts, and `what()` strings
are logged by default in most applications. Every Crypto Service SDK
shares the same error model.

## Decision

Every error derives from `crypto_service::Error` (a
`std::runtime_error`):

- `ApiError`: a non-2xx status. `status()` is the code and `problem()`
  the parsed `Problem` (`type`, `title`, `status`, `detail`,
  `instance`, `code`, `errors` as `FieldError` items, and any other
  members in `extensions`). A body that is not a problem becomes an
  `about:blank` problem for the status. `what()` is
  `crypto-service: HTTP <status> (<type>)` and nothing else.
- `TransportError`: no usable response, with `timed_out()` set when the
  per-attempt timeout or the overall deadline ended it; also a 2xx body
  that is not JSON or lacks a required member.
- `CancelledError`, a `TransportError`: the call's `CancelToken` fired,
  or its `AsyncClient` was destroyed while it was in flight.

Bad options (URL scheme, credentials or a query in `base_url`, an API
key, token or header with a control character, a non-positive timeout
or deadline, retry settings out of range, a malformed traceparent)
throw `std::invalid_argument` before anything is sent. `request()` is
the one call that returns a non-2xx response instead of throwing.
`AsyncClient` delivers the same exceptions through the future.

## Consequences

- One `catch (const crypto_service::Error&)` handles everything the SDK
  throws; the specific types are there for callers who branch on them,
  and `problem().code` lets a caller react to `KEY_NOT_FOUND` and
  similar codes without parsing text.
- Logging `what()` never leaks a key, plaintext, credential or body;
  printing `problem().detail` is the caller's explicit choice.
- The fuzz targets check that only these types escape and that
  `what()` never repeats the body.
