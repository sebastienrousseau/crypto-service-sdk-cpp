#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
"""Fail when OSV lists a known vulnerability in a pinned dependency.

nlohmann/json, GoogleTest and Google Benchmark are FetchContent archives
pinned by URL and SHA-256 in the CMake files (the pins scripts/sbom.py
reads), so no registry-based audit sees them. OSV (https://osv.dev)
indexes C and C++ projects by their git repository and tag, the GIT
ecosystem; this asks it about each pinned release tag.

A canary query for a libcurl release with published CVEs must return
some, so an API change that empties every answer fails the check instead
of passing it. libcurl itself is not checked here: CI links the system
package, which takes the operating system's security fixes without
changing its upstream version.

Usage: scripts/osv-check.py
"""

import json
import sys
import urllib.request

import sbom  # the pins, from scripts/ beside this file

OSV_QUERY = "https://api.osv.dev/v1/query"
CANARY = ("curl/curl", "curl-8_5_0")


def known_vulnerabilities(repository, tag):
    """The OSV ids affecting `tag` of github.com/`repository`."""
    query = {
        "package": {"name": f"https://github.com/{repository}.git", "ecosystem": "GIT"},
        "version": tag,
    }
    request = urllib.request.Request(
        OSV_QUERY,
        data=json.dumps(query).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        answer = json.load(response)
    return sorted(vuln["id"] for vuln in answer.get("vulns", []))


def main():
    if not known_vulnerabilities(*CANARY):
        print(f"osv-check: canary {CANARY} returned nothing; is the OSV API answering?")
        return 1
    status = 0
    for component in sbom.pinned_components():
        repository = component["purl"].split("pkg:github/")[1].split("@")[0]
        tag = "v" + component["version"]
        found = known_vulnerabilities(repository, tag)
        print(f"{repository} {tag}: {', '.join(found) if found else 'no known vulnerabilities'}")
        if found:
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
