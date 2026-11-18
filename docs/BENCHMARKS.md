<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->

# Benchmarks

Every SDK call is one HTTP request to crypto-server, which does the
cryptography. The benchmarks separate the two costs. Every Crypto
Service SDK uses the same scenario names, so their results can be read
side by side when measured on the same machine.

| Scenario | Binary | What it measures |
| :--- | :--- | :--- |
| `encode_request` | `crypto_service_bench_client` | Building a request (JSON encoding of a typed request, URL and headers), no network |
| `decode_response` | `crypto_service_bench_client` | Decoding a recorded 2xx body into its typed result, no network |
| `decode_problem` | `crypto_service_bench_client` | Parsing an RFC 9457 problem and throwing and catching `ApiError`, no network |
| `round_trip_hash` | `crypto_service_bench_loopback` | `hash()` against a crypto-server on 127.0.0.1 through libcurl; skipped with a message when `CRYPTO_SERVICE_URL` is unset |

The client-side scenarios use a replay transport that returns canned
responses, so they measure the SDK's own work only. Most of a round
trip's time is the server's and the network's.

Nothing is asserted: CI smoke-runs both binaries on every pull request
(`make bench BENCH_ARGS=--benchmark_min_time=0.01s` in the conformance
job) so they keep compiling and running.

## Method

```sh
make bench BENCH_ARGS="--benchmark_repetitions=5 --benchmark_report_aggregates_only=true"
```

`make bench` builds a Release tree in `build-bench/` with Google
Benchmark 1.10.0 and runs both binaries. Google Benchmark picks the
iteration count; report the median and the coefficient of variation
across repetitions, with the machine, compiler, libcurl version, server
commit and load average.

## Results

No numbers are published yet. This page will be generated from a
recorded run, with its environment, in a later release; until then,
run `make bench` on your own hardware and read the results as specific
to that machine.
