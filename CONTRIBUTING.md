<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Contributing

Thanks for looking. This package is a thin, typed C++ client for the
crypto-server REST API. Cryptography belongs in the server
([`crypto-service`](https://github.com/sebastienrousseau/crypto-service));
a change here should make the client more correct, safer or easier to
use.

## Before you open a pull request

Everything CI checks, you can run locally:

```sh
make check            # versions, format, file size, complexity, -Werror build, ctest, clang-tidy
make coverage         # 100% lines and branches (clang)
```

`make check` skips clang-format, clang-tidy and rust-code-analysis-cli,
and says so, when they are not installed; CI always runs them. To run
the conformance kit and the typed tests, start a crypto-server from the
commit in `ci/server.ref` and point the tests at it:

```sh
git clone https://github.com/sebastienrousseau/crypto-service.git .server
git -C .server checkout "$(cat ci/server.ref)"
(cd .server && pnpm install --frozen-lockfile && pnpm -r run build)
(cd .server/packages/crypto-server && PORT=3104 HOST=127.0.0.1 \
  CRYPTO_API_KEY=conformance-key-0123456789abcdef \
  JWT_SECRET=conformance-jwt-secret-0123456789abcdef0123 \
  RATE_LIMIT_MAX=100000 NODE_ENV=development node dist/index.js) &
export CRYPTO_SERVICE_URL=http://127.0.0.1:3104
export CRYPTO_SERVICE_API_KEY=conformance-key-0123456789abcdef
export CRYPTO_SERVICE_JWT_SECRET=conformance-jwt-secret-0123456789abcdef0123
make conformance examples readme-snippets
```

`make conformance` fails if any vector is skipped or a variable is
missing, so a run without a server cannot pass by accident. The kit
signs short-lived test JWTs with `CRYPTO_SERVICE_JWT_SECRET` and spreads
its vectors over several test users, because the server's per-user quota
is lower than the number of vectors. Use synthetic values only.
`make regression` does all of this for you.

`make check` also builds the fuzz targets in `fuzz/` with a replay main
and runs their seed corpus. To fuzz them, use a clang with the libFuzzer
runtime (not Apple clang); CI does this on every pull request:

```sh
make fuzz CXX=clang++ FUZZ_SECONDS=60   # ASan and UBSan, per target
```

A reproducer lands in `build-fuzz/artifacts/`. Add an input that found a
bug to `fuzz/corpus/<target>/` with the fix, and a unit test for it.

## The README demo

`make demo` renders `.github/demo.gif` from `.github/demo.tape` with
[VHS](https://github.com/charmbracelet/vhs) (it needs `vhs`, `ttyd` and
`ffmpeg`). It builds `examples/hash.cpp` into `build-demo/` and runs it
against the server at `CRYPTO_SERVICE_URL` with
`CRYPTO_SERVICE_API_KEY`. Re-render the GIF in the same change as
anything that alters what it shows, and say in the commit what it shows.

## Rules

- **`conformance/` is vendored from crypto-service.** Never edit it
  here: a change to a vector is made in crypto-service and re-vendored
  with a new `ci/server.ref`, and the `Kit` tests fail on any local edit.
- **No cryptography in the client.** Every operation is a call to the
  server ([ADR 0001](docs/adr/0001-thin-client-over-the-server.md)).
- **Complexity ceilings.** Every function stays within cyclomatic 10,
  cognitive 15, Halstead difficulty 30 and 60 lines (`make complexity`,
  rust-code-analysis-cli 0.0.25; clang-tidy checks cognitive complexity
  and length too), and every file within 500 lines
  (`scripts/check-file-size.sh`).
- **100% coverage.** `make coverage` fails below 100% of lines and
  branch outcomes in `include/` and `src/`; add the test with the code.
- **No new warnings, no suppressions.** The build uses
  `-Wall -Wextra -Wpedantic -Werror`; fix the cause rather than adding
  `NOLINT` or a pragma.
- **Tests with the change**, in the same commit.
- **Never log** credentials, keys, plaintexts or bodies, and never put
  them in an exception message.

## Commits

Conventional commits (`feat:`, `fix:`, `docs:`, `ci:`, `test:`,
`chore:`), an imperative subject of at most 50 characters, and a body
wrapped at 72 characters that explains what and why. Every commit
carries a `Signed-off-by:` trailer (`git commit -s`), which certifies
the [DCO](DCO.txt), and is SSH-signed.

## Versioning

The version lives in `CMakeLists.txt` (`project(... VERSION)`), from
which `crypto_service/version.hpp` is generated, and is restated in the
files `scripts/verify-release-versions` lists; `make check` and CI run
it. **Versions increment by 0.0.1**, in lockstep with the ecosystem.
[DEVELOPMENT.md](DEVELOPMENT.md) describes the release model.

## Licence

Apache-2.0 OR MIT, at your option. By contributing you agree your work is
released under the same dual grant.
