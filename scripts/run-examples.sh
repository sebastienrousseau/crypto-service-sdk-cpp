#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
#
# Runs every example in examples/ against the crypto-server at
# CRYPTO_SERVICE_URL (started with CRYPTO_API_KEY set to
# CRYPTO_SERVICE_API_KEY) and checks what each prints. Used by CI's
# conformance job and scripts/regression.sh.
#
# Usage: scripts/run-examples.sh [build-dir]
set -euo pipefail
cd "$(dirname "$0")/.."

bin=${1:-build}
: "${CRYPTO_SERVICE_URL:?set CRYPTO_SERVICE_URL to a running crypto-server}"
: "${CRYPTO_SERVICE_API_KEY:?set CRYPTO_SERVICE_API_KEY to the CRYPTO_API_KEY of the server}"

out=$(mktemp)
trap 'rm -f "$out"' EXIT
failures=0

# expect NAME PATTERN: the example exits 0 and prints PATTERN.
expect() {
  local name=$1 pattern=$2
  if "$bin/crypto_service_$name" > "$out" 2>&1 && grep -qE -- "$pattern" "$out"; then
    echo "ok   $name"
  else
    echo "FAIL $name (wanted /$pattern/)"
    sed 's/^/     /' "$out"
    failures=$((failures + 1))
  fi
}

expect hash '^sha256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad$'
expect aead '^decrypted: attack at dawn$'
expect sign_verify '^valid: true, tampered valid: false$'
expect ml_kem '^ml-kem-768: 1088-byte ciphertext, shared secrets match$'
expect errors '^1. ApiError 404 urn:crypto-service:problem:key-not-found code=KEY_NOT_FOUND$'
expect errors '^2. ApiError 400 field /algorithm: '
expect errors '^3. TransportError \(timed out: false\)$'
expect async_concurrent 'post-quantum algorithms$'

if [ "$failures" -ne 0 ]; then
  echo "run-examples: $failures failed"
  exit 1
fi
echo "run-examples: every example passed"
