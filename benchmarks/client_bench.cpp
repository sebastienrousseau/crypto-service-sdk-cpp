// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The client's own cost, no network: encode_request (a typed request
// to its JSON body), decode_response (a 200 body to its typed result)
// and decode_problem (an RFC 9457 error body to ApiError, through the
// blocking client and a transport that replays one response).

#include <benchmark/benchmark.h>

#include <memory>
#include <string>
#include <utility>

#include "crypto_service/crypto_service.hpp"

namespace crypto_service {

constexpr const char* kHashBody =
    R"({"data":{"digest":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",)"
    R"("algorithm":"sha256","length":32}})";
constexpr const char* kProblemBody =
    R"({"type":"urn:crypto-service:problem:key-not-found","title":"Key not found",)"
    R"("status":404,"detail":"Key not found","instance":"/v2/sign","code":"KEY_NOT_FOUND"})";

class ReplayTransport final : public Transport {
 public:
  explicit ReplayTransport(HttpResponse response) : response_(std::move(response)) {}
  HttpResponse send(const HttpRequest& /*request*/) override { return response_; }

 private:
  HttpResponse response_;
};

Client replay_client(long status, const std::string& body) {
  ClientOptions options;
  options.base_url = "http://bench.invalid";
  options.api_key = "bench-synthetic-key";
  return Client(std::move(options),
                std::make_unique<ReplayTransport>(HttpResponse{status, body, {}}));
}

void encode_request(benchmark::State& state) {
  SignRequest request{"k_AAAAAAAAAAAAAAAAAAAAAA", std::string(1024, 'm')};
  for (auto _ : state) {
    std::string body = detail::encode(request);
    benchmark::DoNotOptimize(body);
  }
}

void decode_response(benchmark::State& state) {
  const HttpResponse response{200, kHashBody, {}};
  for (auto _ : state) {
    HashResult result = detail::decode<HashResult>(response, true);
    benchmark::DoNotOptimize(result);
  }
}

void decode_problem(benchmark::State& state) {
  Client client = replay_client(404, kProblemBody);
  for (auto _ : state) {
    try {
      (void)client.sign({"k_AAAAAAAAAAAAAAAAAAAAAA", "m"});
    } catch (const ApiError& error) {
      long status = error.status();
      benchmark::DoNotOptimize(status);
    }
  }
}

}  // namespace crypto_service

// Registered here rather than with BENCHMARK(): no static initialisers.
int main(int argc, char** argv) {
  benchmark::RegisterBenchmark("encode_request", crypto_service::encode_request);
  benchmark::RegisterBenchmark("decode_response", crypto_service::decode_response);
  benchmark::RegisterBenchmark("decode_problem", crypto_service::decode_problem);
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  return 0;
}
