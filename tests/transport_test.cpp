// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The libcurl transports against a scripted loopback HTTP server: what
// goes on the wire, timeouts, refused connections, cancellation, TLS,
// redirects (never followed), and the multi handle driven by AsyncClient
// and directly.

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "crypto_service/crypto_service.hpp"
#include "support/http_server.hpp"

namespace crypto_service {
namespace {

using kit::http_reply;
using kit::LoopbackServer;
using kit::ScriptedReply;
using std::chrono::milliseconds;

const char* const kHashBody = R"({"data":{"algorithm":"sha256","digest":"00","length":1}})";

ClientOptions options_for(const std::string& base_url) {
  ClientOptions options;
  options.base_url = base_url;
  options.api_key = "synthetic-test-key";
  options.timeout = milliseconds(5000);
  return options;
}

std::string closed_port_url() {
  std::string url;
  {
    const LoopbackServer server({});
    url = server.base_url();
  }
  return url;  // nothing listens there any more
}

TEST(CurlTransport, SendsTheRequestAndReadsTheResponse) {
  const LoopbackServer server({{http_reply(200, kHashBody, {"X-Empty: ", "Retry-After: 1"})},
                               {http_reply(200, kHashBody)}});
  Client client(options_for(server.base_url()));
  EXPECT_EQ(client.hash({"sha256", "abc"}).length, 1);
  RawRequest put;
  put.method = "PUT";
  put.path = "/v2/hash";
  EXPECT_EQ(client.request(put).headers.size() > 0, true);
  const auto requests = server.requests();
  ASSERT_EQ(requests.size(), 2U);
  EXPECT_EQ(requests[0].request_line, "POST /v2/hash HTTP/1.1");
  EXPECT_EQ(requests[0].header("x-api-key"), "synthetic-test-key");
  EXPECT_EQ(requests[0].header("Content-Type"), "application/json");
  EXPECT_EQ(requests[0].header("User-Agent"),
            "crypto-service-sdk-cpp/" CRYPTO_SERVICE_PROJECT_VERSION);
  EXPECT_EQ(requests[0].body, R"({"algorithm":"sha256","data":"abc"})");
  EXPECT_EQ(requests[1].request_line, "PUT /v2/hash HTTP/1.1");
}

TEST(CurlTransport, PostWithoutABody) {
  const LoopbackServer server({{http_reply(200, "{}")}});
  Client client(options_for(server.base_url()));
  RawRequest post;
  post.method = "POST";
  EXPECT_EQ(client.request(post).status, 200);
  EXPECT_EQ(server.requests().at(0).header("Content-Length"), "0");
}

TEST(CurlTransport, TimeoutIsReported) {
  const LoopbackServer server({{http_reply(200, kHashBody), milliseconds(1000)}});
  ClientOptions options = options_for(server.base_url());
  options.timeout = milliseconds(50);
  Client client(options);
  try {
    (void)client.health();
    FAIL() << "no error";
  } catch (const TransportError& e) {
    EXPECT_TRUE(e.timed_out());
  }
}

TEST(CurlTransport, RefusedConnection) {
  Client client(options_for(closed_port_url()));
  try {
    (void)client.health();
    FAIL() << "no error";
  } catch (const TransportError& e) {
    EXPECT_FALSE(e.timed_out());
    EXPECT_NE(std::string(e.what()).find("request failed"), std::string::npos);
  }
}

TEST(CurlTransport, TlsIsVerifiedAndAPlainServerFails) {
  const LoopbackServer server({{http_reply(200, kHashBody)}});
  std::string url = server.base_url();
  url.replace(0, 4, "https");
  Client client(options_for(url));
  EXPECT_THROW((void)client.health(), TransportError);
}

TEST(CurlTransport, RedirectsAreNotFollowed) {
  const LoopbackServer server(
      {{http_reply(302, "", {"Location: http://127.0.0.1:1/elsewhere"})}, {http_reply(200, "{}")}});
  Client client(options_for(server.base_url()));
  EXPECT_THROW((void)client.health(), TransportError);
  EXPECT_EQ(server.requests().size(), 1U);
}

TEST(CurlTransport, CancellationAbortsATransfer) {
  const LoopbackServer server({{http_reply(200, kHashBody), milliseconds(3000)}});
  Client client(options_for(server.base_url()));
  CancelSource source;
  std::thread canceller([&source] {
    std::this_thread::sleep_for(milliseconds(50));
    source.cancel();
  });
  const auto start = std::chrono::steady_clock::now();
  EXPECT_THROW((void)client.hash({}, {source.token()}), CancelledError);
  canceller.join();
  EXPECT_LT(std::chrono::steady_clock::now() - start, milliseconds(2900));
}

TEST(CurlTransport, RejectedOptionIsATransportError) {
  // libcurl refuses URLs over 8 MB, which makes curl_easy_setopt fail.
  Client client(options_for("http://127.0.0.1:1"));
  RawRequest request;
  request.path = "/" + std::string(std::size_t{9} * 1024 * 1024, 'a');
  EXPECT_THROW((void)client.request(request), TransportError);
}

TEST(CurlMultiTransport, ConcurrentCallsThroughAsyncClient) {
  std::vector<ScriptedReply> script;
  script.reserve(8);
  for (int i = 0; i < 8; ++i) {
    script.push_back({http_reply(200, kHashBody)});
  }
  const LoopbackServer server(script);
  AsyncClient client(options_for(server.base_url()));
  std::vector<std::future<HashResult>> futures;
  futures.reserve(8);
  for (int i = 0; i < 8; ++i) {
    futures.push_back(client.hash({"sha256", std::to_string(i)}));
  }
  for (auto& future : futures) {
    EXPECT_EQ(future.get().length, 1);
  }
  EXPECT_EQ(server.requests().size(), 8U);
}

TEST(CurlMultiTransport, TimeoutRefusalAndBadOption) {
  const LoopbackServer server({{http_reply(200, kHashBody), milliseconds(1000)}});
  ClientOptions options = options_for(server.base_url());
  options.timeout = milliseconds(50);
  AsyncClient client(options);
  try {
    (void)client.health().get();
    FAIL() << "no error";
  } catch (const TransportError& e) {
    EXPECT_TRUE(e.timed_out());
  }
  AsyncClient refused(options_for(closed_port_url()));
  EXPECT_THROW(refused.health().get(), TransportError);
  RawRequest request;
  request.path = "/" + std::string(std::size_t{9} * 1024 * 1024, 'a');
  EXPECT_THROW(refused.request(request).get(), TransportError);
}

TEST(CurlMultiTransport, CancelAndDestroyWithTransfersInFlight) {
  const LoopbackServer server({{http_reply(200, kHashBody), milliseconds(3000)},
                               {http_reply(200, kHashBody), milliseconds(3000)}});
  auto client = std::make_unique<AsyncClient>(options_for(server.base_url()));
  CancelSource source;
  auto cancelled = client->hash({}, {source.token()});
  auto destroyed = client->hash({});
  std::this_thread::sleep_for(milliseconds(100));
  source.cancel();
  EXPECT_THROW(cancelled.get(), CancelledError);
  client.reset();
  EXPECT_THROW(destroyed.get(), CancelledError);
}

TEST(CurlMultiTransport, DirectUse) {
  const LoopbackServer server(
      {{http_reply(200, "{}"), milliseconds(200)}, {http_reply(200, "{}"), milliseconds(200)}});
  auto transport = make_curl_multi_transport();
  HttpRequest request;
  request.method = "GET";
  request.url = server.base_url() + "/health";
  request.timeout = milliseconds(5000);
  transport->start(1, request);
  transport->cancel(42);  // unknown: nothing happens
  transport->wakeup();
  (void)transport->poll(milliseconds(10));
  transport->cancel(1);
  transport->start(2, request);
  (void)transport->poll(milliseconds(10));
  // Destroyed with the second transfer still running.
}

}  // namespace
}  // namespace crypto_service
