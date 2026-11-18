<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# Reproducing a release

Every GitHub release carries three files: the source archive
`crypto-service-sdk-cpp-<version>.tar.gz`, the CycloneDX SBOM
`crypto-service-sdk-cpp-<version>.cdx.json`, and `SHA256SUMS`. Anyone
can rebuild the first two from the signed tag and check them against
`SHA256SUMS`, bit for bit, without trusting the release workflow. The
SDK ships no binaries, so there is no compiler output to reproduce;
what you build from the archive is compiled by your own toolchain.

## What the release workflow runs

`release.yml` builds both files on `ubuntu-24.04` from the tagged
commit, with no input other than the tree and the version:

```sh
git archive --format=tar.gz --prefix="crypto-service-sdk-cpp-$VERSION/" \
  -o "dist/crypto-service-sdk-cpp-$VERSION.tar.gz" HEAD
python3 scripts/sbom.py "$VERSION" > "dist/crypto-service-sdk-cpp-$VERSION.cdx.json"
(cd dist && sha256sum -- * > SHA256SUMS)
```

- **The archive.** `git archive` writes file modes and the commit's own
  timestamp, never the clock or the file system's, so the tar stream
  depends only on the commit. Git compresses it with its built-in gzip
  over zlib; another zlib (zlib-ng, as some distributions ship) can
  produce different compressed bytes from the same tar stream.
- **The SBOM.** `scripts/sbom.py` reads the FetchContent pins in the
  CMake files and has no timestamp. From `0.0.41` on, its
  `serialNumber` is a version 5 UUID of the document's own content, so
  the same tree and version give the same bytes.
- **The check.** The workflow builds both files a second time and runs
  `sha256sum --check` against the first build before it attests and
  publishes anything, and CI fails any pull request after which two SBOM
  runs differ.

## Rebuilding a release

Use the release's own environment, an Ubuntu 24.04 container (Docker
or Podman). This rebuilds the files from a fresh clone of the tag and
checks them against the published `SHA256SUMS`:

```sh
docker run --rm docker.io/library/ubuntu:24.04 bash -euc '
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends git ca-certificates python3 curl > /dev/null
  VERSION=0.0.40
  git clone -q --branch "v$VERSION" https://github.com/sebastienrousseau/crypto-service-sdk-cpp.git src
  cd src && mkdir dist
  git archive --format=tar.gz --prefix="crypto-service-sdk-cpp-$VERSION/" \
    -o "dist/crypto-service-sdk-cpp-$VERSION.tar.gz" HEAD
  python3 scripts/sbom.py "$VERSION" > "dist/crypto-service-sdk-cpp-$VERSION.cdx.json"
  cd dist
  curl -sSLO "https://github.com/sebastienrousseau/crypto-service-sdk-cpp/releases/download/v$VERSION/SHA256SUMS"
  sha256sum --check SHA256SUMS'
```

Verify the tag's signature too, in a clone on your machine:
`git verify-tag v<version>` with
[`KEYS.asc`](https://github.com/sebastienrousseau/crypto-service-sdk-cpp/blob/main/KEYS.asc)
as the allowed signers file (`git config gpg.ssh.allowedSignersFile KEYS.asc`).
The build provenance attestation is checked with
`gh attestation verify <file> --repo sebastienrousseau/crypto-service-sdk-cpp`.

## Expected results

| Release | File | SHA-256 | Reproduces? |
| :--- | :--- | :--- | :--- |
| `0.0.40` | `crypto-service-sdk-cpp-0.0.40.tar.gz` | `f676b8df6e13bb62ec69b2955f28fa18e9dfa07b25f563443a306e1363f45590` | Yes. Rebuilt on 2026-11-18 in `ubuntu:24.04` (git 2.43.0): `OK` |
| `0.0.40` | `crypto-service-sdk-cpp-0.0.40.cdx.json` | `ed5b1ef2e4bc6e2a479a01f7ed169a27f82c2c1fd923e4d9eeb202a9cb0a606b` | No: `0.0.40` predates the content-derived serial and carries a random one. Apart from `serialNumber` the rebuilt document is identical (compare with `jq -S 'del(.serialNumber)'`) |

For `0.0.40`, `sha256sum --check` therefore reports the archive `OK` and
the SBOM `FAILED`; every later release is expected to report both `OK`.

Outside the container, the tar stream itself is independent of the
zlib build. With git on any platform:

```sh
git archive --format=tar --prefix=crypto-service-sdk-cpp-0.0.40/ v0.0.40 | sha256sum
# c2546762f5bab4d27518c263e604684b64ad822afac23b439889c2b74c6c3033
gzip -dc crypto-service-sdk-cpp-0.0.40.tar.gz | sha256sum   # the released archive, the same digest
```

A mismatch in the container is a finding: report it as the
[security policy](https://github.com/sebastienrousseau/crypto-service-sdk-cpp/blob/main/SECURITY.md)
describes.
