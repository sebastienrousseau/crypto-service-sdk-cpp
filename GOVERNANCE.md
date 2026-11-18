<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# Governance

How crypto-service-sdk-cpp is run, who decides, and what happens if the
maintainer is unavailable.

## Scope

The SDK is the C++17 client for the crypto-server REST API. It carries
no cryptography of its own
([ADR 0001](docs/adr/0001-thin-client-over-the-server.md)); changes are
weighed against that: correctness against the conformance kit, security
and clarity over feature breadth.

## Roles

| Role | Who | Responsibilities |
| :--- | :--- | :--- |
| **Maintainer** | Sebastien Rousseau (single maintainer) | Reviews and merges pull requests, cuts and signs releases, triages issues and security reports, sets direction, holds the repository's admin rights |
| **Contributor** | Anyone with a merged pull request | Proposes changes with tests, reviews others' pull requests |
| **User** | Everyone | Reports bugs, asks questions, requests features through issues |

## Decisions

- **Day-to-day changes** (fixes, tests, docs, additive features within
  scope) go through a pull request into the release branch
  `feat/v<next-version>`; the maintainer merges once CI is green.
- **Significant changes** (a breaking change to a public header, a new
  dependency, a change to the version line, the server pin or the
  conformance kit) start as an issue and get an ADR in `docs/adr/`.
- **The ecosystem version** is decided for the whole Crypto Service
  family: this SDK moves in lockstep with crypto-service, one `0.0.1`
  step at a time.

Every change passes the CI gates (format, complexity, `-Werror` builds,
sanitizers, ThreadSanitizer, 100% line and branch coverage, the
conformance kit against a live server, fuzzing, CodeQL, the DCO check)
before merge. Pull requests are mandatory on `main`; with one
maintainer, no second approval is required.

## Releases

Releases follow the process in [DEVELOPMENT.md](DEVELOPMENT.md#release-model):
a signed `v<version>` tag triggers the release workflow. Only the
maintainer pushes tags.

## Access continuity

A single-maintainer project has to plan for its maintainer being away.

- **Code and history** are public on GitHub; anyone can fork and build
  from them. Every commit and tag is signed, so a fork can prove what it
  started from.
- **No secret is needed to build or test.** The only credentials are the
  GitHub account and the SSH signing key; no registry account exists
  ([ADR 0006](docs/adr/0006-cmake-package-github-release-no-registry.md)).
- **The Crypto Service ecosystem** shares this governance; the server
  repository,
  [crypto-service](https://github.com/sebastienrousseau/crypto-service),
  is where cross-SDK decisions are recorded.
- **If the maintainer is unreachable** for 90 days, the project should
  be treated as unmaintained: users should pin a release, and a fork may
  continue it under a new name. Adding a second maintainer with admin
  rights and a registered signing key is a standing goal.

## Code of conduct

Everyone in the project follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
