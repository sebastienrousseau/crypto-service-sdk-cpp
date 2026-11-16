// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// round_trip_hash: one SHA-256 of a short text through the blocking
// client to the crypto-server at CRYPTO_SERVICE_URL (with
// CRYPTO_SERVICE_API_KEY), over libcurl on loopback, reusing one
// connection. Skips with a message when the variable is unset; reports
// an error (without aborting the run) when a call fails. The times are
// mostly the server's work and the loopback, not the SDK's. The server's
// tenant quota (60 requests a minute) applies, so retries absorb 429s.

#include <benchmark/benchmark.h>

#include <chrono>
#include <cstdlib>
#include <optional>
#include <utility>

#include "crypto_service/crypto_service.hpp"

namespace crypto_service {

std::optional<Client> live_client(benchmark::State& state) {
  const char* url = std::getenv("CRYPTO_SERVICE_URL");
  if (url == nullptr || *url == '\0') {
    state.SkipWithMessage("CRYPTO_SERVICE_URL is unset; start crypto-server and set it");
    return std::nullopt;
  }
  ClientOptions options;
  options.base_url = url;
  const char* key = std::getenv("CRYPTO_SERVICE_API_KEY");
  if (key != nullptr && *key != '\0') {
    options.api_key = key;
  }
  options.retry.max_retries = 3;
  options.retry.max_delay = std::chrono::seconds(60);
  return Client(std::move(options));
}

void round_trip_hash(benchmark::State& state) {
  std::optional<Client> client = live_client(state);
  if (!client) {
    return;
  }
  try {
    for (auto _ : state) {
      HashResult result = client->hash({"sha256", "abc"});
      benchmark::DoNotOptimize(result);
    }
  } catch (const Error& error) {
    state.SkipWithError(error.what());
  }
}

}  // namespace crypto_service

// Registered here rather than with BENCHMARK(): no static initialisers.
int main(int argc, char** argv) {
  benchmark::RegisterBenchmark("round_trip_hash", crypto_service::round_trip_hash);
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  return 0;
}
