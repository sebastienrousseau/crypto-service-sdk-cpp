<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# Assurance case

This document argues that crypto-service-sdk-cpp meets its security
requirements: what it protects, from whom, where the trust boundaries
are, how secure design principles are applied, and how the common
weaknesses of an HTTP client library written in C++ are countered. Each
claim points at the code that implements it and the test or CI job that
keeps it true. The
[security policy](https://github.com/sebastienrousseau/crypto-service-sdk-cpp/blob/main/SECURITY.md)
has the reporting process and the short threat table; the
[security review of November 2026](security-review-2026-11.md) checked
this case against the code and records what it found.

## The claim

Used as documented, the SDK sends each request only to the server the
caller configured, over verified TLS when the URL is `https://`; it
never discloses the caller's credentials or data through its own
output; it never repeats a request that may already have changed
server state; and malformed or hostile responses end in a typed error,
never in memory corruption or a crash. The SDK performs no cryptography
itself, so the strength of every cryptographic result is crypto-server's
responsibility, not this library's.

## Scope

In scope: the library (`include/`, `src/`), its build and install
rules, the release pipeline and the CI that guards them. Out of scope:
crypto-server and its cryptography
([its own advisories](https://github.com/sebastienrousseau/crypto-service/security/advisories/new)),
libcurl and the TLS library, which come from the operating system, and
the security of the application that embeds the SDK.

## Assets

| Asset | Where it lives in the SDK | Why it matters |
| :--- | :--- | :--- |
| Credentials: API key and bearer token | `ClientOptions::api_key`, `ClientOptions::token`; copied into `detail::Settings::credentials` (`src/settings.cpp`, `settle`) | They authorise every operation on the caller's keys |
| Request payloads: plaintexts, passwords, key material, KMS data keys | Request structs, the JSON body in `HttpRequest::body` | Confidential by definition in a cryptography API |
| Results: ciphertexts, signatures, shared secrets, unwrapped keys | Result structs decoded in `src/wire.cpp` | Confidentiality and integrity of the caller's data |
| Correct server state | Keys created or deleted on the server | A duplicated `keys/generate` or `keys/delete` is a real side effect |
| The caller's process | Memory and threads the SDK runs in | A memory-safety bug in a library is the host application's bug |
| The released artefacts | Source archive, SBOM, `SHA256SUMS`, provenance attestation | What consumers build from |

## Actors

| Actor | Trust | What they control |
| :--- | :--- | :--- |
| The calling application and its developer | Trusted | `ClientOptions`, every request, custom `Transport` implementations |
| crypto-server at `base_url` | Trusted to perform the cryptography and authorisation; its responses are still parsed defensively | Response status, headers and bodies |
| The network, proxies and middleboxes | Untrusted | Anything on a plain `http://` connection; availability on any connection |
| A hostile or compromised server, or one impersonated on `http://` | Untrusted | Arbitrary status codes, headers, bodies and timing |
| Upstream projects: nlohmann/json, GoogleTest, Google Benchmark, libcurl | Trusted at a pinned version | Code compiled into the library or its tests |
| GitHub Actions and the maintainer's signing key | Trusted | The release build and its signatures |
| Pull request authors | Untrusted until reviewed | Code and workflow changes proposed to the repository |

## Entry points

1. **The public API** (`include/crypto_service/`): `ClientOptions`,
   the typed operations on `Client` and `AsyncClient`, the raw
   `request()`, `describe()`, and the `Transport` and `AsyncTransport`
   interfaces a caller may implement.
2. **HTTP responses**: the status, headers and body a transport returns,
   parsed by `src/curl_common.cpp` (headers), `src/problem.cpp` (RFC
   9457 problems), `src/wire.cpp` and `src/codec.cpp` (success bodies)
   and `src/retry.cpp` (`Retry-After`).
3. **The build**: the CMake files and the archives they fetch.
4. **CI and release**: the workflows in `.github/workflows/`, and the
   crypto-server commit in `ci/server.ref` that CI builds.

The library reads no environment variable, file or command line of its
own. libcurl does read the standard proxy variables (`http_proxy`,
`HTTPS_PROXY`, `NO_PROXY` and the like); see the network boundary
below.

## Trust boundaries

```text
 caller (trusted)
   | ClientOptions, requests          validated: settle(), build()
   v
 SDK  -- HttpRequest -->  Transport (libcurl, or the caller's own)
   ^                         | TLS verify on, no redirects, http/https only
   | typed result or error   v
   +--- parsed defensively -- network (untrusted) -- crypto-server
                                                      (trusted for crypto)
 build:  CMake -- SHA-256-pinned archives -- GitHub release downloads
 CI:     pull request (untrusted) -- read-only token -- signed tag -- release
```

| Boundary | What crosses it | How it is guarded |
| :--- | :--- | :--- |
| Caller to SDK | Options, request structs, raw paths and headers | `settle()` and `build()` in `src/settings.cpp` validate the base URL, credentials, timeouts, retry ranges, traceparent, method, path and every header before anything is sent; the request text must be valid UTF-8 (`encode` in `src/wire.cpp`) |
| SDK to network | The HTTP request | `set_security()` in `src/curl_common.cpp` sets, on every transfer, `CURLOPT_FOLLOWLOCATION 0`, `CURLOPT_SSL_VERIFYPEER 1`, `CURLOPT_SSL_VERIFYHOST 2` and `CURLOPT_PROTOCOLS_STR "http,https"`; no option turns them off. Proxies from libcurl's environment variables are honoured, as for any libcurl program: an HTTPS request goes through a proxy as a CONNECT tunnel with the server's certificate still verified, and a plain `http://` request is visible to the proxy |
| Network to SDK | Status, headers, body | Redirects become `TransportError` (`refuse_redirect`); problem bodies are parsed with exceptions off (`problem_of`); success bodies must have the documented shape or raise `TransportError` naming the member, never its value (`decode`) |
| SDK to crypto-server | Authorisation and cryptography | The server enforces scopes, quotas and key sizes; the SDK sends credentials only on operations that need them (`Route::anonymous` for `/health`, `/live`, `/ready`; `Settings.BuildHeaders`) |
| Registries and upstream sources to the build | nlohmann/json, GoogleTest, Google Benchmark archives | `URL_HASH SHA256` in the CMake files fails the configure step on any change; `scripts/osv-check.py` checks the pinned tags against OSV on every change and weekly |
| Pull requests to CI | Code, workflows, `ci/server.ref` | Workflows run on `pull_request` (never `pull_request_target`) with a read-only token and `persist-credentials: false`; actions are pinned by commit SHA; `ci/server.ref` must be a 40-character commit SHA before it is fetched |
| CI to release | The tag, the archive, the SBOM | Only a signed, annotated tag whose signature verifies against `KEYS.asc` and which is the commit being built publishes, whether the run came from a tag push or a dispatch (`scripts/verify-release-tag`); the version must be digits and dots; the files are rebuilt twice and compared, attested with GitHub build provenance, and published from the `release` environment |

## Secure design principles

The principles of Saltzer and Schroeder, and how each shows up in the
code.

| Principle | How it is applied |
| :--- | :--- |
| **Economy of mechanism** | The SDK is a thin client: every operation is one HTTP call, and the library contains no cipher, hash, signature or KDF ([ADR 0001](adr/0001-thin-client-over-the-server.md)). Hex and base64 (`src/encoding.cpp`) are the only byte transforms. Two transports share one setup function (`prepare` in `src/curl_common.cpp`), so the security options are set in one place. |
| **Fail-safe defaults** | TLS verification is on and cannot be disabled; redirects are refused; retries are off (`RetryOptions::max_retries = 0`); unknown routes are treated as idempotent only when they are not on the stateful list, and the stateful list matches by substring, so a new keygen path is refused a risky retry rather than allowed one (`is_idempotent` in `src/settings.cpp`). A response that does not decode is an error, never a default-constructed result. |
| **Complete mediation** | Every request, typed or raw, goes through `build()`, which validates the method, path and headers, and through one `execute()` (`src/client.cpp`) or one event loop (`src/async_client.cpp`) that applies the timeout, deadline, cancellation, retry rule and redirect refusal. There is no second path to the transport. |
| **Least privilege** | Health probes send no credentials (`Route::anonymous`). CI jobs hold `contents: read`; only the jobs that need it get `security-events`, `id-token`, `attestations`, `pages` or `contents: write`, and the release publish job runs in a protected environment. |
| **Separation of privilege** | Publishing a release needs a signed tag that verifies against `KEYS.asc` and the `release` environment; a pull request alone cannot publish. (A second human reviewer is not yet available; see GOVERNANCE.md.) |
| **Least common mechanism** | Each `Client` owns its own libcurl easy handle and each `AsyncClient` its own multi handle and thread; nothing is shared between clients except libcurl's process-wide initialisation, done once (`ensure_curl_global`). |
| **Open design** | The source, the threat model, this case and the review are public; security rests on TLS and the server's keys, not on secrecy of the client. |
| **Psychological acceptability** | Secure behaviour needs no configuration: a caller who only sets `base_url` and a credential gets verified TLS, no redirects, bounded timeouts and redacted `describe()` output. Errors are typed (`ApiError`, `TransportError`, `CancelledError`) so callers can handle them without parsing messages. |

## Common weaknesses and how they are countered

Mapped to the 2024 CWE Top 25 and the OWASP Top 10 categories that
apply to an HTTP client library. Web-application weaknesses with no
counterpart in a client library (cross-site scripting, SQL injection,
CSRF, file upload) are omitted.

| Weakness | Counter | Evidence |
| :--- | :--- | :--- |
| Out-of-bounds read and write, use after free, NULL dereference (CWE-787, CWE-125, CWE-416, CWE-476) | Standard containers and `std::string_view` only; RAII owners for every libcurl handle and header list (`EasyHandle`, `HeaderList`, `MultiDeleter`); a null transport is rejected in the client constructors | Unit tests under ASan and UBSan with GCC and Clang (`ci.yml`, `build`); libFuzzer with ASan and UBSan on both response parsers (`fuzz.yml`); `_GLIBCXX_ASSERTIONS` bounds checks in the hardened builds; `Client.NullTransportIsRejected`, `AsyncClient.InvalidArguments` |
| Integer overflow (CWE-190) | `Retry-After` delta-seconds above nine digits saturate instead of overflowing (`delta_seconds` in `src/retry.cpp`); timeouts and deadlines are capped at 24 hours, so the call budget's clock arithmetic stays in range | `Retry.RetryAfterValues`, `Settings.TimeoutAndDeadlineAreAtMostADay` |
| Improper input validation (CWE-20) | `settle()` and `build()` validate every option and request part; the decoder checks types, integer ranges and hex and base64 alphabets and canonical padding | `Settings.*`, `Codec.DecodeFailuresNameTheMember`, `Codec.OtherDecodeFailures`, `Encoding.*RejectsMalformedInput` |
| CRLF injection and HTTP request splitting (CWE-93, CWE-113) | Credentials, the traceparent, extra header names and values, the base URL and the path are rejected if they contain a control character | `Settings.CredentialsTimeoutsAndTraceparent`, `Settings.BuildRejectsBadPathsMethodsAndHeaders`, `Settings.BaseUrl` |
| Exposure of sensitive information, log injection (CWE-200, CWE-532, CWE-117) | The SDK never writes to a stream. `ApiError::what()` names only the status and the problem type, with control characters replaced; decode errors name the member, never the value; `describe()` prints `<redacted>` for credentials and user information | `Problem.ApiErrorMessageNamesStatusAndTypeOnly`, `Problem.ApiErrorMessageReplacesControlCharactersInTheType`, `Settings.DescribeRedactsCredentials`; the response fuzzer aborts if a body appears in an error message |
| Improper certificate validation (CWE-295) | Peer and host-name verification always on (`set_security`) | `CurlTransport.TlsIsVerifiedAndAPlainServerFails` shows an `https://` URL never falls back to plain text; there is no test with an untrusted certificate yet (review finding F-06) |
| Cleartext transmission (CWE-319) | `https://` verified as above. `http://` is accepted for any host, for local development and private networks, and documented as unsafe for credentials elsewhere | SECURITY.md threat table; accepted in the review (F-04) |
| Credentials in URLs (CWE-598) | A `base_url` with user information, a query or a fragment is rejected | `Settings.BaseUrl` |
| Server-side request forgery and open redirect (CWE-918, CWE-601) | The destination is only ever `base_url` plus a validated path; 3xx responses are errors and `Location` is never followed | `Client.RedirectsAreRefused`, `AsyncClient.RedirectsAreRefused`, `CurlTransport.RedirectsAreNotFollowed` |
| Uncontrolled resource consumption (CWE-400) | Per-attempt timeout (default 30 s) and optional deadline; at most 100 retries with delays capped at one hour; `Retry-After` beyond `max_delay` ends retrying; cancellation within about 10 ms on `AsyncClient`. Response bodies are not size-limited (review finding F-03, accepted) | `Client.DeadlineBoundsTheAttemptTimeout`, `Retry.RetryAfterIsHonouredUpToMaxDelay`, `Settings.RetryRanges` |
| Race conditions (CWE-362) | `AsyncClient` state touched by callers is guarded by one mutex; everything else belongs to the loop thread; cancel tokens are atomics | `make tsan` (`ci.yml`, `tsan`): `AsyncClient.ManyThreadsShareOneClient`, `AsyncClient.DestructionCancelsCallsInFlight`, `CurlMultiTransport.CancelAndDestroyWithTransfersInFlight` |
| Deserialisation of untrusted data (CWE-502) | Bodies are parsed as JSON by nlohmann/json with exceptions off, then mapped onto fixed structs; no polymorphic or code-bearing format | `Decode.ShapeErrorsAreTransportErrors`, the two fuzz targets |
| Duplicated side effects (business-logic flaw) | Stateful routes are retried only after 429 or 503, never after a 504 or a lost connection ([ADR 0004](adr/0004-async-model.md)) | `Client.StatefulCallsAreNotRetriedAfterLostConnectionOr504`, `AsyncClient.StatefulCallsAreNotRetriedAfterALostConnection`, `Retry.StatefulRoutes` |
| Use of weak cryptography, weak randomness (CWE-327, CWE-330; OWASP A02) | No cryptography in the client. `std::mt19937_64` is used only for traceparent ids and retry jitter, which are not secrets | `src/settings.cpp` (`make_traceparent`), `src/retry.cpp` (`jittered`) |
| Hard-coded credentials (CWE-798) | None in the library; CI and tests use values marked synthetic | `ci.yml` (`conformance` job comment), AGENTS.md data rule |
| OS command injection (CWE-78) in the pipeline | The release version must match `^[0-9]+\.[0-9]+\.[0-9]+$`, and step outputs reach scripts through environment variables, not `${{ }}` interpolation | `release.yml` (`Resolve the version`); review finding F-02 |
| Vulnerable and outdated components (CWE-1104; OWASP A06) | Archives pinned by SHA-256; OSV checked on every change and weekly; Dependabot for actions and the manual's Python requirements; libcurl from the OS | `osv.yml`, `scripts/osv-check.py`, `.github/dependabot.yml` |
| Software and data integrity failures (CWE-494; OWASP A08) | Signed commits and tags, SHA-pinned actions, the vendored conformance kit checked against its `SHA256SUMS`, reproducible release files with provenance attestations | `Kit.VendoredFilesMatchTheirChecksums`, `release.yml`, [REPRODUCING.md](REPRODUCING.md) |

## Compiler hardening

The SDK is distributed as source: the release contains no binary, and
every consumer compiles it with their own toolchain and flags. The
CMake files therefore set warnings only (`-Wall -Wextra -Wpedantic`, and
`-Werror` when asked), and impose no hardening flags, for three
reasons:

- The consumer, or their distribution, owns the code-generation policy.
  Debian and Ubuntu (`dpkg-buildflags`, and Ubuntu's GCC defaults),
  Fedora (`redhat-rpm-config`) and others already inject a hardening
  set; a library adding its own on top can conflict with it, for
  example by redefining `_FORTIFY_SOURCE` at a different level.
- `_FORTIFY_SOURCE` needs optimisation, and `-fcf-protection` and
  `-fstack-clash-protection` are target-specific, so a flag set fixed in
  the library would be wrong for some builds (Debug, MSVC, non-x86).
- Flags set on the library target would cover only its own objects,
  not the application that links it, which gives a false sense of
  coverage.

What the project does instead is check that the recommended set works.
The CI `build` matrix compiles and tests the library with GCC and with
Clang using

```text
-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS
-fstack-protector-strong -fstack-clash-protection -fcf-protection
-Wl,-z,relro,-z,now
```

under `-Werror` (jobs `gcc-hardened` and `clang-hardened`), so a consumer
can apply them through `CMAKE_CXX_FLAGS` and `CMAKE_EXE_LINKER_FLAGS`
knowing the build stays warning-free and the tests pass. The unit tests
also run under ASan, UBSan and TSan, and the parsers under libFuzzer.

## Supply chain and pipeline

- **Dependencies.** One run-time dependency besides the system libcurl:
  nlohmann/json, header-only, fetched from its release archive and
  checked against a SHA-256. GoogleTest and Google Benchmark are fetched
  the same way and never linked into the library. The SBOM lists exactly
  these pins.
- **Static analysis.** CodeQL (`security-extended`) and clang-tidy run
  on every pull request; OpenSSF Scorecard runs weekly.
- **Release integrity.** See the CI-to-release boundary above and
  [REPRODUCING.md](REPRODUCING.md).

## Residual risks

These are known and accepted; the security review explains each.

- Response bodies are buffered whole with no size limit, and
  compressed responses are decompressed, so a hostile or compromised
  server can make a call use a lot of memory (F-03).
- `http://` is accepted for any host; credentials sent that way are
  visible on the network (F-04).
- Credentials and payloads live in ordinary `std::string` and
  `std::vector` memory and are not wiped after use (F-05).
- A caller-supplied `Transport` replaces libcurl and with it every
  network guarantee above; it is the caller's code.

## Keeping the case true

Each claim names a test, a fuzz target or a CI job, and every one of
those runs on every pull request, so a change that breaks a claim fails
CI. AGENTS.md forbids the changes that would invalidate the case
outright (an option to disable TLS verification, following redirects,
relaxing the stateful-route rule). This document is revisited at each
security review and whenever a trust boundary changes.
