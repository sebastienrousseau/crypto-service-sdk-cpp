#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
#
# The whole regression run against a real crypto-server, in one command
# (`make regression`):
#
#   1. The server is the checkout in CRYPTO_SERVICE_SERVER_DIR (already
#      built), or sebastienrousseau/crypto-service at the commit in
#      ci/server.ref, cloned into .server/ and built with pnpm.
#   2. It starts on a free 127.0.0.1 port (CRYPTO_SERVICE_PORT to choose
#      one) with a synthetic CRYPTO_API_KEY and JWT_SECRET.
#   3. make check (the conformance kit and typed tests run inside ctest),
#      make conformance (fails on any skip), make examples, make
#      readme-snippets, the benchmark smoke run, make coverage (clang
#      only) and make package-test.
#   4. The server stops on success, failure or Ctrl-C (trap).
#
# Only the build directories and .server/ stay behind, so it can be run
# again as is.
set -euo pipefail
cd "$(dirname "$0")/.."

MAKE=${MAKE:-make}
ref=$(tr -d '[:space:]' < ci/server.ref)
if ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
  echo "regression: ci/server.ref must hold a full 40-character commit SHA" >&2
  exit 1
fi
server_pid=""
log=$(mktemp "${TMPDIR:-/tmp}/crypto-service-regression.XXXXXX")

cleanup() {
  if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -f "$log"
}
trap cleanup EXIT INT TERM

checkout_server() {
  local dir=.server
  if [ ! -d "$dir/.git" ]; then
    git clone --quiet https://github.com/sebastienrousseau/crypto-service.git "$dir" >&2
  fi
  git -C "$dir" fetch --quiet origin "$ref" >&2
  git -C "$dir" checkout --quiet --detach "$ref" >&2
  echo "== building crypto-server at $ref" >&2
  (cd "$dir" && pnpm install --frozen-lockfile > /dev/null && pnpm -r run build > /dev/null) >&2
  echo "$PWD/$dir"
}

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

server=${CRYPTO_SERVICE_SERVER_DIR:-}
if [ -z "$server" ]; then
  server=$(checkout_server)
fi
port=${CRYPTO_SERVICE_PORT:-$(free_port)}
export CRYPTO_SERVICE_URL="http://127.0.0.1:$port"
export CRYPTO_SERVICE_API_KEY=regression-synthetic-key-0123456789
export CRYPTO_SERVICE_JWT_SECRET=regression-synthetic-jwt-secret-0123456789abcdef

echo "== starting crypto-server ($ref) on $CRYPTO_SERVICE_URL"
(cd "$server/packages/crypto-server" &&
  PORT=$port HOST=127.0.0.1 NODE_ENV=development RATE_LIMIT_MAX=100000 \
    CRYPTO_API_KEY=$CRYPTO_SERVICE_API_KEY JWT_SECRET=$CRYPTO_SERVICE_JWT_SECRET \
    exec node dist/index.js > "$log" 2>&1) &
server_pid=$!
for _ in $(seq 1 60); do
  if curl -fsS "$CRYPTO_SERVICE_URL/health" > /dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$log"
    exit 1
  fi
  sleep 1
done
curl -fsS "$CRYPTO_SERVICE_URL/health"
echo

echo "== make check (with the server: kit and typed tests run in ctest)"
"$MAKE" check
echo "== make conformance"
"$MAKE" conformance
echo "== make examples"
"$MAKE" examples
echo "== make readme-snippets"
"$MAKE" readme-snippets
echo "== benchmark smoke run"
"$MAKE" bench BENCH_ARGS=--benchmark_min_time=0.01s
if "${CC:-cc}" --version 2>/dev/null | grep -q clang &&
  "${CXX:-c++}" --version 2>/dev/null | grep -q clang; then
  echo "== make coverage"
  "$MAKE" coverage
else
  echo "== make coverage skipped: it needs clang (set CC=clang CXX=clang++)"
fi
echo "== make package-test"
"$MAKE" package-test
echo "== regression: every step passed against crypto-server $ref"
