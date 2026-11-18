// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// AsyncClient's event loop on a fake transport: concurrent callers,
// retries on timers, the deadline, cancellation, a transport that
// refuses to start, redirects, raw requests, and destruction with calls
// in flight (every future ends with CancelledError, none is broken).

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

#include "crypto_service/crypto_service.hpp"
#include "support/fake_transport.hpp"

namespace crypto_service {
namespace {

using kit::FakeState;
using std::chrono::milliseconds;

const char* const kHashBody = R"({"data":{"algorithm":"sha256","digest":"00","length":1}})";

kit::Reply hang() {
  kit::Reply r;
  r.hang = true;
  return r;
}

std::unique_ptr<AsyncClient> make(const std::shared_ptr<FakeState>& state,
                                  ClientOptions options = kit::fake_options()) {
  return std::make_unique<AsyncClient>(std::move(options),
                                       std::make_unique<kit::FakeAsyncTransport>(state));
}

ClientOptions retrying(int count) {
  ClientOptions options = kit::fake_options();
  options.retry.max_retries = count;
  options.retry.initial_delay = milliseconds(1);
  options.retry.max_delay = milliseconds(5);
  return options;
}

TEST(AsyncClient, InvalidArguments) {
  EXPECT_THROW(AsyncClient(kit::fake_options(), nullptr), std::invalid_argument);
  ClientOptions bad;
  bad.base_url = "nope";
  EXPECT_THROW(AsyncClient{bad}, std::invalid_argument);
}

TEST(AsyncClient, ManyThreadsShareOneClient) {
  auto state = std::make_shared<FakeState>();
  constexpr int kCalls = 64;
  for (int i = 0; i < kCalls; ++i) {
    state->push(kit::reply(200, kHashBody));
  }
  auto client = make(state);
  std::vector<std::future<HashResult>> futures(kCalls);
  std::vector<std::thread> threads;
  threads.reserve(4);
  for (int t = 0; t < 4; ++t) {
    threads.emplace_back([&, t] {
      for (int i = t; i < kCalls; i += 4) {
        futures[static_cast<std::size_t>(i)] = client->hash({"sha256", "x"});
      }
    });
  }
  for (auto& thread : threads) {
    thread.join();
  }
  for (auto& future : futures) {
    EXPECT_EQ(future.get().length, 1);
  }
  EXPECT_GT(state->wakeups, 0);
}

TEST(AsyncClient, ErrorsReachTheFuture) {
  auto state = std::make_shared<FakeState>();
  state->push(kit::reply(400, R"({"detail":"bad","type":"urn:t"})"));
  state->push(kit::failing(TransportError("down")));
  state->push(kit::reply(200, R"({"data":{}})"));
  auto client = make(state);
  auto api = client->hash({});
  auto transport = client->hash({});
  auto shape = client->hash({});
  EXPECT_THROW(api.get(), ApiError);
  EXPECT_THROW(transport.get(), TransportError);
  EXPECT_THROW(shape.get(), TransportError);
}

TEST(AsyncClient, RetriesOnTimers) {
  auto state = std::make_shared<FakeState>();
  state->push(kit::reply(503, ""));
  state->push(kit::failing(TransportError("reset")));
  state->push(kit::reply(200, kHashBody));
  auto client = make(state, retrying(2));
  EXPECT_EQ(client->hash({}).get().length, 1);
  EXPECT_EQ(state->seen().size(), 3U);
}

TEST(AsyncClient, StatefulCallsAreNotRetriedAfterALostConnection) {
  auto state = std::make_shared<FakeState>();
  state->push(kit::failing(TransportError("reset")));
  auto client = make(state, retrying(3));
  EXPECT_THROW(client->ml_kem_generate_key_pair().get(), TransportError);
  EXPECT_EQ(state->seen().size(), 1U);
}

TEST(AsyncClient, TransportCancellationIsNotRetried) {
  auto state = std::make_shared<FakeState>();
  state->push(kit::failing(CancelledError("aborted")));
  auto client = make(state, retrying(3));
  EXPECT_THROW(client->hash({}).get(), CancelledError);
}

TEST(AsyncClient, RefusedStartIsATransportError) {
  auto state = std::make_shared<FakeState>();
  kit::Reply refused;
  refused.refuse_start = true;
  state->push(refused);
  state->push(kit::reply(200, kHashBody));
  auto client = make(state, retrying(1));
  EXPECT_EQ(client->hash({}).get().length, 1);
}

TEST(AsyncClient, RedirectsAreRefused) {
  auto state = std::make_shared<FakeState>();
  state->push(kit::reply(301, ""));
  auto client = make(state);
  EXPECT_THROW(client->hash({}).get(), TransportError);
}

TEST(AsyncClient, DeadlineEndsWaitingRetries) {
  auto state = std::make_shared<FakeState>();
  state->push(kit::reply(503, "", {{"Retry-After", "0.05"}}));
  ClientOptions options = retrying(3);
  options.retry.initial_delay = options.retry.max_delay = milliseconds(100);
  options.deadline = milliseconds(30);
  auto client = make(state, options);
  // Retry-After 50 ms would pass the 30 ms deadline: the 503 is final.
  EXPECT_THROW(client->hash({}).get(), ApiError);
}

// A call queued while the loop thread is held (in a slow start) for
// longer than the deadline never starts: deadline error, timed_out.
TEST(AsyncClient, DeadlinePassedBeforeTheFirstAttempt) {
  auto state = std::make_shared<FakeState>();
  state->push(kit::slow(kit::reply(200, kHashBody), milliseconds(150)));
  ClientOptions options = kit::fake_options();
  options.deadline = milliseconds(50);
  auto client = make(state, options);
  auto holder = client->hash({});
  std::this_thread::sleep_for(milliseconds(20));
  auto late = client->hash({});
  try {
    (void)late.get();
    FAIL() << "no error";
  } catch (const TransportError& e) {
    EXPECT_TRUE(e.timed_out());
  }
  EXPECT_EQ(holder.get().length, 1);
  EXPECT_EQ(state->seen().size(), 1U);
}

// A retry whose start the deadline overtakes reports the last outcome.
TEST(AsyncClient, DeadlinePassedWhileWaitingReportsTheLastOutcome) {
  auto state = std::make_shared<FakeState>();
  state->push(kit::reply(503, "", {{"Retry-After", "0.05"}}));
  state->push(kit::slow(kit::reply(200, kHashBody), milliseconds(150)));
  ClientOptions options = retrying(1);
  options.retry.max_delay = milliseconds(100);
  options.deadline = milliseconds(100);
  auto client = make(state, options);
  auto retried = client->hash({});
  std::this_thread::sleep_for(milliseconds(20));
  auto holder = client->hash({});
  EXPECT_THROW(retried.get(), ApiError);
  EXPECT_EQ(holder.get().length, 1);
  EXPECT_EQ(state->seen().size(), 2U);
}

TEST(AsyncClient, DeadlinePassedWhileWaitingReportsTheLastError) {
  auto state = std::make_shared<FakeState>();
  // Whichever call the slow reply reaches, the retried call ends with a
  // TransportError: its last outcome, or its second attempt's.
  state->push(kit::failing(TransportError("reset")));
  state->push(kit::slow(kit::failing(TransportError("slow")), milliseconds(150)));
  state->push(kit::slow(kit::failing(TransportError("slow")), milliseconds(150)));
  ClientOptions options = retrying(1);
  options.retry.initial_delay = options.retry.max_delay = milliseconds(50);
  options.deadline = milliseconds(100);
  auto client = make(state, options);
  auto retried = client->hash({});
  std::this_thread::sleep_for(milliseconds(5));
  auto holder = client->hash({});
  EXPECT_THROW(retried.get(), TransportError);
  EXPECT_THROW(holder.get(), TransportError);
}

TEST(AsyncClient, CancelTokenEndsAHangingCall) {
  auto state = std::make_shared<FakeState>();
  state->push(hang());
  auto client = make(state);
  CancelSource source;
  auto future = client->hash({}, {source.token()});
  std::this_thread::sleep_for(milliseconds(20));
  source.cancel();
  EXPECT_THROW(future.get(), CancelledError);
  const std::lock_guard<std::mutex> lock(state->mutex);
  EXPECT_EQ(state->cancelled.size(), 1U);
}

// A transport that still reports a transfer after cancel() (the fake's
// `late` mode): the loop drops the result, whose call has already
// ended, and carries on with the next call.
TEST(AsyncClient, ResultAfterCancelIsDropped) {
  auto state = std::make_shared<FakeState>();
  state->push(hang());
  state->push(kit::reply(200, kHashBody));
  AsyncClient client(kit::fake_options(), std::make_unique<kit::FakeAsyncTransport>(state, true));
  CancelSource source;
  auto cancelled = client.hash({}, {source.token()});
  std::this_thread::sleep_for(milliseconds(20));
  source.cancel();
  EXPECT_THROW(cancelled.get(), CancelledError);
  // The late result was queued before this call started, so it has been
  // polled (and dropped) by the time this one ends.
  EXPECT_EQ(client.hash({}).get().length, 1);
  const std::lock_guard<std::mutex> lock(state->mutex);
  EXPECT_EQ(state->cancelled.size(), 1U);
}

// Retry-After fixes the wait at 10 s: a jittered backoff is uniform in
// [0, max_delay] and sometimes ended before the cancel at 20 ms.
TEST(AsyncClient, CancelTokenEndsAWaitingRetry) {
  auto state = std::make_shared<FakeState>();
  state->push(kit::reply(503, "", {{"Retry-After", "10"}}));
  ClientOptions options = retrying(1);
  options.retry.initial_delay = options.retry.max_delay = milliseconds(10000);
  auto client = make(state, options);
  CancelSource source;
  auto future = client->hash({}, {source.token()});
  std::this_thread::sleep_for(milliseconds(20));
  source.cancel();
  EXPECT_THROW(future.get(), CancelledError);
  const std::lock_guard<std::mutex> lock(state->mutex);
  EXPECT_TRUE(state->cancelled.empty());
}

TEST(AsyncClient, DestructionCancelsCallsInFlight) {
  auto state = std::make_shared<FakeState>();
  state->push(hang());
  state->push(hang());
  auto client = make(state);
  auto first = client->hash({});
  auto raw = client->request(RawRequest{});
  std::this_thread::sleep_for(milliseconds(20));
  client.reset();
  EXPECT_THROW(first.get(), CancelledError);
  EXPECT_THROW(raw.get(), CancelledError);
}

TEST(AsyncClient, DestructionRightAfterSubmitting) {
  auto state = std::make_shared<FakeState>();
  auto client = make(state);
  auto future = client->hash({});
  client.reset();
  try {
    (void)future.get();
  } catch (const TransportError&) {
    SUCCEED();  // CancelledError, or the fake's "nothing scripted" if it ran first
  }
}

TEST(AsyncClient, RawRequest) {
  auto state = std::make_shared<FakeState>();
  state->push(kit::reply(404, R"({"detail":"no"})"));
  auto client = make(state);
  RawRequest request;
  request.path = "/v2/no-such-route";
  const RawResponse response = client->request(request).get();
  EXPECT_EQ(response.status, 404);
  EXPECT_EQ(state->seen().at(0).method, "GET");
}

}  // namespace
}  // namespace crypto_service
