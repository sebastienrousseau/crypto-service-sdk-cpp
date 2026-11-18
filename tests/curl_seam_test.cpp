// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// The libcurl paths a test cannot provoke through libcurl itself, reached
// through the detail::CurlCalls seam and detail::failure: handle
// creation failing (out of memory), messages on the multi handle that are
// not a finished transfer of ours, and a failed transfer with an empty
// error buffer. Each test restores the real libcurl calls.

#include <curl/curl.h>
#include <gtest/gtest.h>

#include <chrono>
#include <exception>
#include <string>
#include <vector>

#include "crypto_service/crypto_service.hpp"
#include "curl_common.hpp"
#include "support/http_server.hpp"

namespace crypto_service {
namespace {

using std::chrono::milliseconds;

class CurlSeam : public ::testing::Test {
 protected:
  void TearDown() override { detail::curl_calls() = detail::CurlCalls{}; }
};

CURL* no_easy_handle() { return nullptr; }
CURLM* no_multi_handle() { return nullptr; }

// Two messages libcurl never queues for us, then libcurl's own queue: a
// message that is not CURLMSG_DONE, and a finished transfer of a handle
// the transport does not track.
struct Stray {
  static inline int unknown = 0;  // its address stands for a foreign handle
  static inline std::vector<CURLMsg> queue;

  static CURLMsg* read(CURLM* multi, int* queued) {
    if (queue.empty()) {
      return curl_multi_info_read(multi, queued);
    }
    static CURLMsg current;
    current = queue.back();
    queue.pop_back();
    *queued = static_cast<int>(queue.size());
    return &current;
  }
};

TEST_F(CurlSeam, EasyHandleCreationFailureIsATransportError) {
  detail::curl_calls().easy_init = &no_easy_handle;
  try {
    (void)make_curl_transport();
    FAIL() << "no error";
  } catch (const TransportError& e) {
    EXPECT_EQ(std::string(e.what()), "crypto-service: libcurl could not create a handle");
  }
}

TEST_F(CurlSeam, MultiHandleCreationFailureIsATransportError) {
  detail::curl_calls().multi_init = &no_multi_handle;
  EXPECT_THROW((void)make_curl_multi_transport(), TransportError);
  ClientOptions options;
  options.base_url = "http://127.0.0.1:1/";
  EXPECT_THROW(AsyncClient{options}, TransportError);
}

TEST_F(CurlSeam, StrayMessagesOnTheMultiHandleAreSkipped) {
  const kit::LoopbackServer server({{kit::http_reply(200, "{}")}});
  auto transport = make_curl_multi_transport();
  HttpRequest request;
  request.method = "GET";
  request.url = server.base_url() + "/health";
  request.timeout = milliseconds(5000);
  transport->start(7, request);
  CURLMsg foreign{};
  foreign.msg = CURLMSG_DONE;
  foreign.easy_handle = &Stray::unknown;
  CURLMsg not_done{};
  not_done.msg = CURLMSG_NONE;
  Stray::queue = {foreign, not_done};
  detail::curl_calls().multi_info_read = &Stray::read;
  std::vector<TransferResult> done;
  for (int turn = 0; turn < 500 && done.empty(); ++turn) {
    done = transport->poll(milliseconds(10));
  }
  EXPECT_TRUE(Stray::queue.empty());
  ASSERT_EQ(done.size(), 1U);
  EXPECT_EQ(done[0].id, 7U);
  EXPECT_EQ(done[0].response.value_or(HttpResponse{}).status, 200);
}

TEST(CurlFailure, EmptyErrorBufferFallsBackToTheCodeDescription) {
  const detail::Exchange exchange;
  try {
    std::rethrow_exception(detail::failure(CURLE_COULDNT_CONNECT, exchange));
  } catch (const TransportError& e) {
    EXPECT_EQ(std::string(e.what()), std::string("crypto-service: request failed: ") +
                                         curl_easy_strerror(CURLE_COULDNT_CONNECT));
    EXPECT_FALSE(e.timed_out());
  }
}

}  // namespace
}  // namespace crypto_service
