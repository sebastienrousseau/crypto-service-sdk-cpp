<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Security Policy

## Supported versions

This package follows the
[Crypto Service](https://github.com/sebastienrousseau/crypto-service)
ecosystem cadence. While pre-`1.0`, the latest released `0.0.x`
receives security fixes; older `0.0.x` versions do not. `0.0.40` is the
first release of this SDK.

| Version | Status | Receives security fixes? |
| :--- | :--- | :--- |
| `0.0.40` (latest) | Current | Yes |
| `main` | In development | Yes |

## Reporting a vulnerability

**Do not open a public issue for security reports.**

Use GitHub Private Vulnerability Reporting:
<https://github.com/sebastienrousseau/crypto-service-sdk-cpp/security/advisories/new>.
The maintainers are notified automatically.

Please include a description and its impact, a minimal reproducer
(preferably a failing test), the commit or version affected, and any
proposed fix. A vulnerability in the server itself belongs in
[crypto-service's advisories](https://github.com/sebastienrousseau/crypto-service/security/advisories/new).

These are goals, not guarantees: the project is maintained in a personal
capacity, with no SLA. **Acknowledgement**: the goal is within 5 working
days. **Triage**: a severity assessment and remediation plan after
acknowledgement.

## Security posture

### Scope

The SDK is an HTTP client. It builds JSON requests, sends them with
libcurl to the server named in `ClientOptions::base_url`, and decodes
the JSON responses. It implements no cryptography: every hash, cipher,
signature, KEM and KDF runs in crypto-server. It does not write files.

### Threat model

| Surface | How it's handled |
| :--- | :--- |
| **Secrets in logs** | The SDK never logs. `ApiError::what()` names only the HTTP status and the problem type; `TransportError` messages name the failure only. No message carries credentials, keys, plaintexts or bodies. `describe(options)` replaces credentials with `<redacted>`. |
| **Header injection** | An API key, token, traceparent or extra header containing a control character (CR, LF and NUL included) is rejected with `std::invalid_argument` before anything is sent. |
| **Protocol and redirect abuse** | libcurl is limited to `http` and `https` and never follows a redirect; a 3xx is an error. |
| **TLS** | Peer and host-name verification are always on; there is no option to turn them off. |
| **Credentials in URLs** | A `base_url` with user information, a query or a fragment is rejected. |
| **Plain-text transport** | `http://` is accepted for loopback development; use `https://` elsewhere, as API keys, tokens, keys and plaintexts travel in the requests. |
| **Duplicated side effects** | Stateful operations (key generation and deletion, every keygen, KMS key creation, OPAQUE registration) are never retried after a 504 or a lost connection, when the server may already have acted. |
| **Malformed responses** | A 2xx body that is not JSON or lacks a required member raises `TransportError`; a non-2xx body that is not a problem becomes an `about:blank` problem. Both parsers are fuzzed. |
| **Dependency CVEs** | libcurl comes from the system; nlohmann/json, GoogleTest and Google Benchmark are fetched from release archives pinned by SHA-256. |

### Dependency audit

The SDK has one run-time dependency besides libcurl, and no automated
advisory scan covers them, because none comes from a package registry
that an audit tool reads:

| Dependency | How it is obtained | How advisories are tracked |
| :--- | :--- | :--- |
| libcurl 7.85 or newer | The system package (`libcurl4-openssl-dev` in CI) | The operating system's security updates; CI installs the current Ubuntu 24.04 package on every run. |
| nlohmann/json `3.12.0` | Release archive, `URL_HASH SHA256` in `CMakeLists.txt` | By hand: its GitHub security advisories are reviewed before a release or a pin bump. |
| GoogleTest `1.18.0` (tests only) | Release archive, `URL_HASH SHA256` in `tests/CMakeLists.txt` | By hand, as above; it is never linked into the library. |
| Google Benchmark `1.10.0` (benchmarks only, off by default) | Release archive, `URL_HASH SHA256` in `benchmarks/CMakeLists.txt` | By hand, as above; it is never linked into the library. |

Dependabot has no CMake `FetchContent` ecosystem, so it cannot propose
updates for the archives; it does track the workflow actions. A changed
upstream archive fails the CMake configure step on its SHA-256 instead
of building.
