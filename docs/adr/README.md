<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# Architecture decision records

Decisions that will be questioned later, with the options weighed and
why one was chosen. A new record takes the next number; a reversed
decision gets a new record that supersedes the old one.

| Record | Decision |
| :--- | :--- |
| [0001](0001-thin-client-over-the-server.md) | A thin client over crypto-server, no local cryptography |
| [0002](0002-http-stack-libcurl-and-nlohmann-json.md) | libcurl (easy and multi) and nlohmann/json, nothing else at run time |
| [0003](0003-error-model.md) | One exception hierarchy carrying the RFC 9457 problem; no secrets in `what()` |
| [0004](0004-async-model.md) | `AsyncClient` with futures from one owned event-loop thread, a blocking `Client`, and the shared retry table |
| [0005](0005-source-compatibility-not-abi-stability.md) | Source compatibility, checked against the last tag; no ABI promise |
| [0006](0006-cmake-package-github-release-no-registry.md) | An installed CMake package and a GitHub release; no registry |
