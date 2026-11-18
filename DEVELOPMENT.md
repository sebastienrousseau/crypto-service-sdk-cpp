<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# Development

The single entry point for working on crypto-service-sdk-cpp: the
toolchain, how to run every CI gate locally, how the tests are laid out,
and how a release is made. [CONTRIBUTING.md](CONTRIBUTING.md) has the
rules for a pull request.

## Toolchain

| Tool | Version | Used for |
| :--- | :--- | :--- |
| A C++17 compiler | GCC or Clang 18 in CI; newer GCC and Clang work locally | Everything |
| CMake | 3.20 or newer (CI: the runner's) | Configure, build, install |
| libcurl with headers | 7.85 or newer, system package (`libcurl4-openssl-dev`) | The library |
| clang-format | 18 | `make format-check` |
| clang-tidy | 18 | `make tidy` |
| rust-code-analysis-cli | 0.0.25 (`cargo install --locked`) | `make complexity` |
| llvm-cov, llvm-profdata | Matching the clang that builds | `make coverage` |
| Node.js and pnpm | Node 24, pnpm 11.9.0 | Building and running crypto-server for the kit |
| Python | 3.12 or newer | The scripts in `scripts/`, MkDocs |
| Doxygen | 1.9 or newer | `make docs` |
| vhs, ttyd, ffmpeg | Any recent | `make demo` only |

nlohmann/json 3.12.0, GoogleTest 1.18.0 and Google Benchmark 1.10.0 are
fetched by CMake from release archives pinned by SHA-256; there is
nothing to install for them. `mise.toml` pins the tools mise can
install.

## Every CI gate, locally

| CI job (workflow) | Local command | What it checks |
| :--- | :--- | :--- |
| Format, file size, complexity and clang-tidy (`ci.yml`, `lint`) | `make versions format-check filesize complexity tidy` | Version files agree, clang-format 18, 500 lines per file, the AGENTS.md complexity ceilings, clang-tidy |
| Build and unit tests, GCC and Clang, with ASan and UBSan and with the hardening flags of [docs/ASSURANCE.md](docs/ASSURANCE.md#compiler-hardening) (`ci.yml`, `build`) | `make test`; with sanitizers `make test CMAKE_ARGS="-DCMAKE_CXX_COMPILER=clang++ -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'"` | `-Wall -Wextra -Wpedantic -Werror`, ctest |
| ThreadSanitizer (`ci.yml`, `tsan`) | `make tsan` (clang) | `AsyncClient` shared across threads and destroyed with calls in flight, the multi transport, both clients |
| Installed CMake package (`ci.yml`, `package`) | `make package-test` | `cmake --install`, then `find_package(crypto_service_sdk CONFIG)` from `tests/package/` |
| Coverage (`ci.yml`, `coverage`) | `make coverage` (clang: `CC=clang CXX=clang++`) | 100% of lines and branch outcomes in `include/` and `src/` |
| Conformance kit, examples, README snippets, benchmark smoke (`ci.yml`, `conformance`) | `make regression`, or by hand: start a server, then `make conformance examples readme-snippets bench` | All 119 vectors and the typed tests against crypto-server at `ci/server.ref`, every example, every README code block, every benchmark runs |
| API breakage (`ci.yml`, `api`) | `scripts/api-check.sh <last-tag>` (Linux) | Source compatibility with the last release ([ADR 0005](docs/adr/0005-source-compatibility-not-abi-stability.md)) |
| libFuzzer (`fuzz.yml`) | `make fuzz CXX=clang++ FUZZ_SECONDS=60` (not Apple clang) | Success-response decoding and problem parsing under ASan and UBSan |
| Markdown, spelling, licences, README shape, links (`docs-lint.yml`) | `npx markdownlint-cli2 "**/*.md"`, `codespell`, `reuse lint`, `scripts/readme-check.sh`, `lychee --offline '**/*.md'` | Style, typos, SPDX on every file, the README template, intra-repo links |
| Manual (`manual.yml`) | `make docs` | Doxygen with warnings as errors, then `mkdocs build --strict` |
| Known vulnerabilities in the pinned archives (`osv.yml`, also weekly) | `python3 scripts/osv-check.py` | OSV has no advisory for the nlohmann/json, GoogleTest or Google Benchmark release a CMake file pins |
| CodeQL (`codeql.yml`), Scorecard (`scorecard.yml`), DCO (`dco.yml`) | none | Static analysis, supply-chain score, `Signed-off-by` on every commit |

`make check` runs the cheap local gate: versions, format, file size,
complexity, the `-Werror` build (fuzz targets with a replay main, and
the benchmarks, compiled but not run), ctest and clang-tidy. A tool
that is not installed is reported and skipped; CI always has it.

In CI the server is checked out to `.server/`. Every linter, size and
complexity check skips `.server/`, other dot-directories and
`node_modules/`, so nothing from the server's tree is measured as SDK
code.

### Running against a server

```sh
make regression
```

builds crypto-server at the commit in `ci/server.ref`, starts it on a
free 127.0.0.1 port with a synthetic `CRYPTO_API_KEY` and `JWT_SECRET`,
runs `make check`, `make conformance`, `make examples`, `make
readme-snippets`, the benchmark smoke run, `make coverage` (clang only)
and `make package-test`, and stops the server even when a step fails.

By hand, CONTRIBUTING.md shows how to start the server. The conformance
target needs three variables, and fails (not skips) without them:

| Variable | Value |
| :--- | :--- |
| `CRYPTO_SERVICE_URL` | The server, e.g. `http://127.0.0.1:3104` |
| `CRYPTO_SERVICE_API_KEY` | The server's `CRYPTO_API_KEY` (synthetic) |
| `CRYPTO_SERVICE_JWT_SECRET` | The server's `JWT_SECRET` (synthetic), to mint test tokens with the scopes some vectors need and to spread the kit over several test users under the per-user quota |

## Test layout

| Path | Runs | Needs |
| :--- | :--- | :--- |
| `tests/operations_test.cpp` | Every typed operation on both clients: method, path, credentials, body and decoded result | Nothing (in-memory fake transport) |
| `tests/client_test.cpp` | The blocking `Client`: errors, retries, the stateful-route rule, deadline, cancellation, redirects, raw requests, moves | Nothing |
| `tests/async_client_test.cpp` | `AsyncClient`'s event loop: concurrent callers, timers, deadline, cancellation, destruction with calls in flight | Nothing |
| `tests/retry_test.cpp` | Backoff bounds, `Retry-After`, which outcomes retry | Nothing (waits are recorded, not slept) |
| `tests/settings_test.cpp` | Option validation, `describe()`, request construction, traceparent, time budget | Nothing |
| `tests/codec_test.cpp`, `tests/codec_full_test.cpp` | Every request and result struct in both directions, every decode failure | Nothing |
| `tests/encoding_test.cpp` | Hex and base64 against RFC 4648 vectors | Nothing |
| `tests/problem_test.cpp` | RFC 9457 problems, the `about:blank` fallback, the error types | Nothing |
| `tests/transport_test.cpp` | The libcurl easy and multi transports on a real socket | Nothing (`tests/support/http_server.cpp`, a scripted server on 127.0.0.1) |
| `tests/kit_test.cpp` | The kit runner, `SHA256SUMS`, `ci/server.ref`, token minting | Nothing |
| `tests/conformance_test.cpp` | Every vector in `conformance/*.json`, through typed methods where one exists | `CRYPTO_SERVICE_URL` (skips otherwise; `make conformance` fails on a skip) |
| `tests/live_test.cpp` | Typed round trips the kit does not cover | `CRYPTO_SERVICE_URL` |
| `tests/package/` | A consumer of the installed package | `make package-test` |
| `fuzz/` | Seed corpus replay under ctest; libFuzzer with `make fuzz` | Nothing |
| `benchmarks/` | Google Benchmark, `make bench` | `CRYPTO_SERVICE_URL` for `round_trip_hash` |
| `examples/` | `scripts/run-examples.sh` | A server and `CRYPTO_SERVICE_API_KEY` |

### Coverage exclusions

`make coverage` counts every line and both outcomes of every branch, per
template instantiation, in `include/` and `src/`. An exclusion is an
inline `LCOV_EXCL_LINE`, `LCOV_EXCL_BR_LINE` or `LCOV_EXCL_START` /
`LCOV_EXCL_STOP` marker followed by a reason; `scripts/coverage-gate.py`
fails a marker without one and prints every exclusion. There are none.

The defensive paths libcurl cannot be made to take are reached through
`detail::CurlCalls` (`src/curl_common.hpp`), a test-only table of the
libcurl calls involved that defaults to libcurl's own functions:

| Path | Test |
| :--- | :--- |
| `curl_easy_init` fails (out of memory) | `CurlSeam.EasyHandleCreationFailureIsATransportError` |
| `curl_multi_init` fails (out of memory) | `CurlSeam.MultiHandleCreationFailureIsATransportError` |
| The multi handle queues a message that is not a finished transfer of ours | `CurlSeam.StrayMessagesOnTheMultiHandleAreSkipped` |
| A failed transfer leaves libcurl's error buffer empty | `CurlFailure.EmptyErrorBufferFallsBackToTheCodeDescription` |
| A custom `AsyncTransport` reports a transfer after `cancel()` | `AsyncClient.ResultAfterCancelIsDropped` |

A test swaps a call in and restores the defaults while no transport or
`AsyncClient` runs on another thread; production code never changes
them.

## Release model

Versions are `0.0.x`, one `0.0.1` step at a time, in lockstep with the
Crypto Service ecosystem ([AGENTS.md](AGENTS.md)). A release is prepared
on `feat/v<version>` and merged into `main` through one pull request,
the only one open against `main`.

1. **Prepare** (in the release pull request): every version file says
   the version (`make versions`), `CHANGELOG.md`'s
   `## [<version>] - Unreleased` gets its date, and
   `docs/releases/<version>.md` holds the hand-written Highlights.
2. **Dry run**: run the Release workflow by hand (`workflow_dispatch`,
   `dry_run: true`) on `main`. It builds, tests, attests and prints the
   notes, uploads everything as a workflow artifact, and publishes
   nothing.
3. **Tag**: the maintainer pushes a signed, annotated tag whose message
   is `crypto-service-sdk-cpp v<version>`:
   `git tag -s v0.0.40 -m "crypto-service-sdk-cpp v0.0.40" && git push origin v0.0.40`.
4. **Release**: the tag triggers `release.yml`. It checks the tag
   (`scripts/verify-release-tag`: annotated, signed by a key in
   `KEYS.asc`, with the release message, and the commit being built)
   and the version files, runs the tests and the package test,
   builds `crypto-service-sdk-cpp-<version>.tar.gz` (`git archive`), the
   CycloneDX SBOM (`scripts/sbom.py`, from the CMake pins) and
   `SHA256SUMS`, builds the archive and SBOM a second time and checks
   them against `SHA256SUMS` ([reproducing a release](docs/REPRODUCING.md)),
   attests their provenance, and creates the release
   titled `crypto-service-sdk-cpp <version>` with notes from
   `scripts/release-notes.sh`. The publish job runs in the `release`
   environment. Re-running it updates the release in place; a
   `workflow_dispatch` with `dry_run` off must be run on the tag itself.
5. **Audit**: the workflow checks the live title and notes; then
   confirm with `gh release view v<version> --json name,body`.

There is no package registry to publish to
([ADR 0006](docs/adr/0006-cmake-package-github-release-no-registry.md)).

### Settings the maintainer creates once

No secret is needed: the release uses the workflow's `GITHUB_TOKEN` and
GitHub's OIDC token for the attestation. These are repository settings
only a maintainer can change:

| Setting | Where | Why |
| :--- | :--- | :--- |
| Environment `release` | Settings, Environments | The publish job runs in it; add a required reviewer and a deployment rule for `v*` tags if wanted |
| Pages source: GitHub Actions | Settings, Pages | `manual.yml` deploys the manual; until this is set its deploy job fails on `main` |
| Tag protection for `v*` | Settings, Rules | Only the maintainer creates release tags |
