<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# Security review, November 2026

| | |
| :--- | :--- |
| **Date** | 2026-11-18 |
| **Reviewer** | Sebastien Rousseau, with AI-assisted analysis (Claude) |
| **Baseline** | `main` at `aabd6de` (release `v0.0.40`), and the fixes on `feat/v0.0.41` |
| **Measured against** | [The assurance case](ASSURANCE.md) |

## Scope

Everything the project ships or runs:

- The library: `include/crypto_service/` and `src/` (options and
  request validation, both libcurl transports, TLS and redirect
  settings, credential handling, retries and the time budget, the
  response, problem and `Retry-After` parsers, hex and base64, the
  `AsyncClient` event loop).
- The build: `CMakeLists.txt` and the FetchContent pins in the three
  CMake files, the installed package.
- CI and release: every workflow in `.github/workflows/`, their
  permissions and triggers, `scripts/`, `ci/server.ref`, and the
  `v0.0.40` release files.
- The dependency set: libcurl, nlohmann/json 3.12.0, GoogleTest 1.18.0,
  Google Benchmark 1.10.0.

Out of scope: crypto-server, libcurl's and the TLS library's own code,
and GitHub's platform.

## Method

1. Read every source file in `src/` and the public headers in full,
   following each value from `ClientOptions` and each response byte to
   where it is used, against the claims of the assurance case.
2. Checked each claim's evidence: that the named test exists and
   asserts what the case says, and that the CI job runs it.
3. Reviewed each workflow for its trigger (`pull_request` versus
   `pull_request_target`), token permissions, `persist-credentials`,
   action pinning, and every `${{ }}` expression that reaches a `run:`
   script; the release workflow step by step for which checks guard
   which publishing path.
4. Rebuilt the `v0.0.40` source archive and SBOM in a clean
   `ubuntu:24.04` container and compared them with the published
   `SHA256SUMS` ([REPRODUCING.md](REPRODUCING.md)).
5. Queried OSV for every pinned dependency tag
   (`scripts/osv-check.py`); checked the repository's Dependabot,
   code-scanning and secret-scanning alerts.
6. Reproduced each suspected defect before calling it a finding, and
   kept a fix only when a test or a run showed it working.

Severity is the impact on a caller of the SDK, taking into account who
can trigger it: **High** (a remote party can compromise the caller's
data or process), **Medium** (a remote party can degrade it, or a
plausible misuse exposes data), **Low** (needs a trusted party to
misbehave, or a narrow condition), **Info** (hardening or a gap in
evidence, no defect).

## Findings

| Id | Severity | Finding | Disposition |
| :--- | :--- | :--- | :--- |
| F-01 | Low | Unbounded `deadline` overflowed the call budget's clock arithmetic | Fixed |
| F-02 | Low | Release version check accepted shell metacharacters, interpolated into a script | Fixed |
| F-03 | Low | Response bodies have no size limit | Accepted |
| F-04 | Low | `http://` is accepted for any host | Accepted, documentation clarified |
| F-05 | Info | Secrets are not wiped from memory | Accepted |
| F-06 | Info | No test shows an untrusted TLS certificate being rejected | Accepted, follow-up proposed |
| F-07 | Low | A dispatched release could publish without the tag check, from another commit | Fixed |
| F-08 | Info | Extra header names are not checked to be HTTP tokens | Accepted, follow-up proposed |
| F-09 | Info | libcurl removes dot segments, so a raw path can leave the `base_url` path prefix | Accepted |
| F-10 | Info | libcurl honours proxy environment variables | Accepted, documented |
| F-11 | Info | The Markdown lint runs `npx` without a lockfile | Accepted |

### F-01: Unbounded deadline overflowed the call budget (Low, fixed)

`ClientOptions::deadline` was checked only to be positive.
`detail::Budget` adds it to a `steady_clock::time_point`, whose
representation is nanoseconds, so a deadline near
`milliseconds::max()` overflowed a signed 64-bit integer: undefined
behaviour, which UBSan reports as
`signed integer overflow: 9223372036854775807 * 1000000`. The
per-attempt `timeout` goes to libcurl as a `long`, 32 bits on Windows,
so a timeout above about 24.8 days was narrowed. Only the caller sets
these values, hence Low.

**Fix**: both are rejected above 24 hours with `std::invalid_argument`,
like the existing one-hour cap on retry delays (`check_options` in
`src/settings.cpp`). The test `Settings.TimeoutAndDeadlineAreAtMostADay`
failed before the change and passes after it.

### F-02: Release version check accepted shell metacharacters (Low, fixed)

`release.yml` validated the version with the shell pattern
`[0-9]*.[0-9]*.[0-9]*`, where each `*` matches any text, so a tag such
as `v0.0.41$(id)` (a valid git ref name) passed. The next step expanded
`${{ steps.version.outputs.version }}` directly into a `run:` script, so
the text would have run as shell, before the tag signature check, in a
job that holds `id-token: write` and `attestations: write`. The API
job interpolated its baseline tag the same way. Pushing a tag or
dispatching the workflow already needs write access, so this is defence
in depth.

**Fix**: the version must match `^[0-9]+\.[0-9]+\.[0-9]+$`, and both
values reach their scripts through environment variables. Checked with
the old and new checks side by side: the old one accepts `0.0.41$(id)`
and `0.0.41";touch${IFS}x;"`, the new one rejects both and accepts
`0.0.41`. actionlint passes on every workflow.

### F-03: Response bodies have no size limit (Low, accepted)

`write_body` (`src/curl_common.cpp`) appends the whole body to a string,
and `CURLOPT_ACCEPT_ENCODING ""` accepts every compression libcurl
supports, so a hostile or compromised server, or anyone on a plain
`http://` path, can make one call allocate as much memory as it sends,
or more through a compression bomb, until the timeout ends it.

**Disposition**: accepted. The server is the caller's chosen, trusted
endpoint, and over `https://` nobody else can inject a body. A limit
needs an option and a default that suits every operation (stream
encryption responses can legitimately be large), which is an API
decision for a future release rather than a fix. Recorded as a residual
risk in the assurance case.

### F-04: `http://` is accepted for any host (Low, accepted)

SECURITY.md said `http://` was accepted "for loopback development",
which read as if other hosts were refused; the code accepts `http://`
for any host, and credentials then travel in clear text.

**Disposition**: accepted. Plain HTTP to a sidecar or a service on a
private network is a legitimate deployment, and refusing it would break
callers without a migration path. SECURITY.md now states the behaviour
exactly, and the assurance case lists it as a residual risk.

### F-05: Secrets are not wiped from memory (Info, accepted)

API keys, tokens, request bodies and results live in `std::string` and
`std::vector`, which are not zeroed when freed; libcurl keeps its own
copies of the headers and body while a transfer runs.

**Disposition**: accepted. The standard library offers no reliable way
to wipe these buffers (reallocation leaves copies), libcurl's copies are
out of reach, and the caller holds the same secrets in its own memory.
An attacker who can read the process's memory has already won.

### F-06: No test shows an untrusted certificate being rejected (Info, accepted)

`set_security()` sets `CURLOPT_SSL_VERIFYPEER 1` and
`CURLOPT_SSL_VERIFYHOST 2` on every transfer, and nothing can unset
them, but the only TLS test (`CurlTransport.TlsIsVerifiedAndAPlainServerFails`)
points an `https://` URL at a plain-HTTP server. It proves there is no
fallback to plain text, not that a self-signed or wrong-host
certificate is refused.

**Disposition**: accepted as a gap in evidence, not a defect: the code
path is short and reviewed. A test against a loopback TLS server with a
throwaway self-signed certificate is proposed as follow-up work.

### F-07: A dispatched release skipped the tag check (Low, fixed)

The publish job runs on a tag push or on a `workflow_dispatch` with
`dry_run` off, but the step that checks the tag (annotated, signed by a
key in `KEYS.asc`, with the release message) ran on tag pushes only. A
non-dry-run dispatch on `main` would have built the archive from
`main`'s HEAD and attached it, unsigned and unchecked, to the release of
whichever tag the version named. It needs a maintainer and the
`release` environment, hence Low, but it breaks the guarantee that the
release files come from the signed tag.

**Fix**: the check moved to `scripts/verify-release-tag`, runs whenever
the run can publish, and also requires the tag to point at the commit
being built. Tested in a clone: at `v0.0.40` it verifies the signature
and exits 0; at `v0.0.40~1` it exits 1.

### F-08: Extra header names are not checked to be tokens (Info, accepted)

`append_extra` (`src/settings.cpp`) rejects control characters in a
caller's extra header names and values, which prevents CRLF injection,
but accepts a name containing `:` or a space, which yields a malformed
header line instead of an error.

**Disposition**: accepted; only the trusted caller supplies these names,
and no request splitting is possible. Validating names as RFC 9110
tokens is proposed as follow-up work.

### F-09: Dot segments in a raw path (Info, accepted)

`build()` rejects a path without a leading `/`, with a query,
fragment, space or control character, but not `/../`. libcurl removes
dot segments by default (`CURLOPT_PATH_AS_IS` is off), so
`request({"GET", "/../other"})` against `https://host/api` reaches
`https://host/other`.

**Disposition**: accepted. The path prefix of `base_url` is not a
security boundary: the same caller chooses `base_url` and can reach any
path on that host anyway, and the host itself cannot change.

### F-10: Proxy environment variables (Info, accepted)

libcurl honours `http_proxy`, `HTTPS_PROXY`, `ALL_PROXY` and
`NO_PROXY`. Whoever controls the process environment can route requests
through a proxy; over `https://` the proxy sees only a CONNECT tunnel
and the server's certificate is still verified, over `http://` it sees
everything.

**Disposition**: accepted; this is the standard behaviour of libcurl
programs and what operators expect, and the environment is the
caller's. Documented at the network boundary of the assurance case.

### F-11: Markdown lint runs `npx` without a lockfile (Info, accepted)

`docs-lint.yml` runs `npx --yes markdownlint-cli2@0.23.3`. The
top-level package is pinned, its dependencies are resolved at run time.

**Disposition**: accepted. The job has a read-only token, no secrets,
and its output does not feed a release.

## Reviewed with no finding

- **Header injection.** Credentials, traceparent, extra headers, base
  URL, method and path are all checked for control characters before
  use, and the tests cover each.
- **Redirects and protocols.** Both transports set
  `CURLOPT_FOLLOWLOCATION 0` and `CURLOPT_PROTOCOLS_STR "http,https"`;
  both clients turn a final 3xx into `TransportError`; tested on a real
  socket.
- **Error messages.** No message carries a body, credential or value;
  the problem type is sanitised; the response fuzzer aborts on a leak.
- **Parsers.** `Retry-After` saturates long delta-seconds and accepts
  only IMF-fixdate; JSON is parsed with exceptions off and mapped onto
  fixed structs; hex and base64 reject bad alphabets and non-canonical
  padding. Both parsers are fuzzed under ASan and UBSan.
- **Concurrency.** `AsyncClient`'s shared state is guarded by one
  mutex and the rest belongs to the loop thread; destruction with calls
  in flight is tested under TSan.
- **Stateful-route retries.** Matched by substring, so new keygen paths
  are refused risky retries; tested on both clients.
- **CI.** Every workflow triggers on `pull_request`, never
  `pull_request_target`; the default token is read-only and write
  scopes are granted per job; checkouts set `persist-credentials:
  false`; every action is pinned by commit SHA; `ci/server.ref` is
  validated as a full SHA before use.
- **Dependencies.** OSV lists no vulnerability for nlohmann/json
  v3.12.0, GoogleTest v1.18.0 or Google Benchmark v1.10.0 (queried
  2026-11-18); the repository had no open Dependabot, secret-scanning
  or code-scanning alert other than Scorecard's best-practices badge
  check.
- **Release reproducibility.** The `v0.0.40` archive rebuilds bit for
  bit; its SBOM differed only in the random serial number, which is now
  derived from the content.

## Changes made with this review

- `src/settings.cpp`: timeout and deadline capped at 24 hours (F-01).
- `.github/workflows/release.yml`, `.github/workflows/ci.yml`: version
  regex and environment variables instead of interpolation (F-02); tag
  check on every publishing run (F-07, `scripts/verify-release-tag`); a
  second build compared with `SHA256SUMS`.
- `scripts/sbom.py`: content-derived serial number.
- `scripts/osv-check.py` and `.github/workflows/osv.yml`: automated
  advisory checks for the pinned archives.
- `ci.yml`: builds with the recommended hardening flags on GCC and
  Clang.
- `SECURITY.md`, [ASSURANCE.md](ASSURANCE.md),
  [REPRODUCING.md](REPRODUCING.md): documentation of the above.

## Next review

At the latest in November 2027, or earlier when a trust boundary in the
assurance case changes (a new transport, an option touching TLS or
redirects, a new dependency, or a change to the release pipeline).
