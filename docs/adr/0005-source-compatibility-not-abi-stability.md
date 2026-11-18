<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# 0005. Promise source compatibility, check it against the last tag

- **Status:** Accepted
- **Date:** 2026-11-16
- **Deciders:** Sebastien Rousseau

## Context

The ecosystem's other SDKs check their public API against the last
release with their language's tool. C++ has two separate questions:
does code that compiled against the old headers still compile (source
compatibility), and does a binary built against the old library still
link and run against the new one (ABI compatibility).

The public headers expose `std::string`, `std::optional`,
`std::vector`, `std::future`, `std::function` and `nlohmann::json` in
their structs and signatures. Their layout depends on the standard
library, its ABI flags and the nlohmann/json version the caller builds
with. The SDK is consumed as source (FetchContent, `add_subdirectory`)
or as a static library built by the caller's own toolchain; no prebuilt
shared library is published.

## Options considered

1. No check, a written N/A.
2. Promise ABI stability and check it. Adding a member to an options or
   result struct would be a break, and pre-1.0 every additive change
   would need a pimpl redesign.
3. Promise source compatibility and check it with abi-compliance-checker
   in its `-source` mode; print the binary report without gating on it.

## Decision

Option 3. `scripts/api-check.sh <ref>` builds the library at the
baseline and at the working tree as shared libraries with debug info,
dumps the public headers' symbols and types with abi-dumper and compares
them with abi-compliance-checker. A source incompatibility fails; the
binary report is informational. The CI `api` job runs it against the
last `v*` tag. Until the first tag exists it runs against `main` for
information only and passes.

## Consequences

- A removed or renamed function, type or member, or a changed
  signature, fails CI unless the changelog announces it as breaking
  (pre-1.0 the maintainer may still ship it, deliberately).
- Adding struct members and functions stays possible within 0.0.x.
- Callers must rebuild against each release; the installed package's
  version file (`ExactVersion`) already refuses a different version.
- If a prebuilt shared library is ever published, this decision is
  revisited (the binary report becomes the gate).
