<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# 0006. Ship a CMake package and a GitHub release; no package registry

- **Status:** Accepted
- **Date:** 2026-11-16
- **Deciders:** Sebastien Rousseau

## Context

The ecosystem's other SDKs publish to their language's registry (npm,
PyPI, the Go module proxy, crates.io, Maven Central, NuGet). C++ has no
single registry: vcpkg and Conan each need a port or recipe reviewed by
their maintainers, and Linux distributions package libraries through
their own processes. Consumers still need a verifiable artifact and a
way to use an installed copy.

## Decision

Each release is a GitHub release only, created by `release.yml` from a
signed annotated tag: a source archive
`crypto-service-sdk-cpp-<version>.tar.gz` (`git archive`), a CycloneDX
SBOM generated from the CMake pins, `SHA256SUMS`, and a build
provenance attestation (`actions/attest-build-provenance`). The library
installs with `cmake --install`, exporting `crypto_service::sdk`
through `find_package(crypto_service_sdk 0.0.40 CONFIG)` with an exact
version match. A consumer project in `tests/package/` builds against
the installed package in CI (`make package-test`). Submitting to vcpkg
or Conan is a later, separate decision, recorded in docs/ROADMAP.md.

## Consequences

- Three ways to consume the SDK: FetchContent, `add_subdirectory`, or
  an installed prefix with `find_package`.
- The release needs no registry account or secret: the workflow's
  `GITHUB_TOKEN` and OIDC token suffice, and the publish job runs in the
  `release` environment.
- The installed prefix includes nlohmann/json's headers and package
  config, since `crypto_service::sdk` links it publicly.
- docs/packaging.md tells consumers how to verify a release and
  packagers what they need; distribution packages are not provided.
