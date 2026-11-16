<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# AGENTS.md

`crypto-service-sdk-cpp` is the C++17 client for the crypto-server REST
API. The Crypto Service ecosystem has one engine, the TypeScript
crypto-server, and thin typed clients per language, all proven by one
conformance kit vendored from crypto-service. This repository's value is
that a C++ caller gets the same behaviour the kit pins, with typed
results, the shared resilience contract, and no cryptography of its own.
Read [CONTRIBUTING.md](CONTRIBUTING.md) as well.

## Rules

- **Version.** `0.0.x`, moving by exactly `0.0.1`, in lockstep with the
  Crypto Service ecosystem. Never propose a `0.1.0` or `1.0` jump, and
  never bump it as a side effect. The single source of truth is
  `project(... VERSION)` in `CMakeLists.txt`; when it moves, every file
  `scripts/verify-release-versions` lists moves with it (`CITATION.cff`,
  the SECURITY and SUPPORT tables, the README and manual install
  snippets, `Doxyfile`, `docs/packaging.md`, the bug template and
  `tests/package/`), and `CHANGELOG.md` gets the new heading. Work for
  the next version starts on `feat/v<next-version>`.
- **`conformance/` is vendored from crypto-service, never edit it here.**
  It is replaced as a whole from the server's `conformance/` at the
  commit in `ci/server.ref`, byte for byte, with its `SHA256SUMS`; the
  `Kit` tests fail on any local edit.
- **Thin client, no cryptography.** Every operation is an HTTP call to
  crypto-server. Never implement a cipher, hash, signature or KDF
  locally ([ADR 0001](docs/adr/0001-thin-client-over-the-server.md)).
  Hex and base64 encoding of the wire format is not cryptography and is
  allowed.
- **Never log or expose secrets.** No code path writes to a stream.
  Credentials, keys, plaintexts and bodies never appear in `what()`,
  `describe()` or any debug output; `describe()` redacts credentials.
- **Security invariants.** Redirects stay refused, TLS verification stays
  on with no option to turn it off, and the stateful-route retry rule
  (docs/adr/0004) is not relaxed.
- **Complexity.** Per function: cyclomatic 10, cognitive 15, Halstead
  difficulty 30, 60 lines (`make complexity`, and clang-tidy); 500 lines
  per file. No new suppressions; `scripts/complexity-baseline.json` only
  shrinks.
- **Coverage.** 100% of lines and branch outcomes in `include/` and
  `src/` (`make coverage`). An exclusion is an inline `LCOV_EXCL_*`
  marker with a reason, listed in DEVELOPMENT.md.
- **Commits.** Conventional, subject at most 50 characters, body wrapped
  at 72, signed off (`git commit -s`), SSH-signed, with an
  `Assisted-by:` trailer for agent work. Never rewrite pushed history.
- **Data.** Synthetic only: no real keys, tokens or credentials, in
  tests, examples or docs.

## The gate

```sh
make check        # the local gate
make coverage     # 100% lines and branches (clang)
make regression   # everything, against a crypto-server it builds, starts and stops
```

DEVELOPMENT.md maps every CI job to its local command.

## Leave alone

`conformance/`, `ci/server.ref` (unless the task is to move the server
pin, then re-vendor the kit with it), `LICENSE*`, `LICENSES/`,
`DCO.txt`, and the pinned hashes in `CMakeLists.txt`,
`tests/CMakeLists.txt` and `benchmarks/CMakeLists.txt` unless the task
is to update them (then verify each new hash against the downloaded
archive). Generated output (`build*/`, `docs/api/`, `site/`) is never
committed.
