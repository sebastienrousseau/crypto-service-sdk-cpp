// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// The blocking Client on a fake transport: errors, retries and their
// waits, the stateful-route rule, the deadline, cancellation, redirects,
// raw requests and moves.

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "crypto_service/crypto_service.hpp"
#include "support/fake_transport.hpp"

namespace crypto_service {
namespace {

using kit::FakeState;
using std::chrono::milliseconds;

const char* const kHashBody = R"({"data":{"algorithm":"sha256","digest":"00","length":1}})";

struct Fixture {
  std::shared_ptr<FakeState> state = std::make_shared<FakeState>();
  std::vector<milliseconds> waits;

  Client client(ClientOptions options = kit::fake_options()) {
    if (!options.sleep) {
      options.sleep = [this](milliseconds delay) { waits.push_back(delay); };
    }
    return Client(std::move(options), std::make_unique<kit::FakeTransport>(state));
  }
  static ClientOptions retrying(int count) {
    ClientOptions options = kit::fake_options();
    options.retry.max_retries = count;
    options.retry.initial_delay = milliseconds(1);
    options.retry.max_delay = milliseconds(50);
    return options;
  }
};

TEST(Client, NullTransportIsRejected) {
  EXPECT_THROW(Client(kit::fake_options(), nullptr), std::invalid_argument);
  ClientOptions bad;
  bad.base_url = "nope";
  EXPECT_THROW(Client{bad}, std::invalid_argument);
}

TEST(Client, ApiErrorCarriesTheProblem) {
  Fixture f;
  f.state->push(kit::reply(404, R"({"type":"urn:x","title":"Key not found","status":404,)"
                                R"("detail":"Key not found","code":"KEY_NOT_FOUND"})"));
  Client client = f.client();
  try {
    (void)client.sign({"k_AAAAAAAAAAAAAAAAAAAAAA", "m"});
    FAIL() << "no error";
  } catch (const ApiError& e) {
    EXPECT_EQ(e.status(), 404);
    EXPECT_EQ(e.problem().code, "KEY_NOT_FOUND");
  }
}

TEST(Client, RetriesTransientStatusesThenSucceeds) {
  Fixture f;
  f.state->push(kit::reply(503, ""));
  f.state->push(kit::reply(429, "", {{"Retry-After", "0.01"}}));
  f.state->push(kit::reply(504, ""));
  f.state->push(kit::reply(200, kHashBody));
  Client client = f.client(Fixture::retrying(3));
  EXPECT_EQ(client.hash({"sha256", "a"}).length, 1);
  EXPECT_EQ(f.state->seen().size(), 4U);
  ASSERT_EQ(f.waits.size(), 3U);
  EXPECT_EQ(f.waits[1], milliseconds(10));
}

TEST(Client, GivesUpAfterTheLastRetry) {
  Fixture f;
  f.state->push(kit::reply(503, ""));
  f.state->push(kit::reply(503, ""));
  Client client = f.client(Fixture::retrying(1));
  EXPECT_THROW((void)client.hash({}), ApiError);
  EXPECT_EQ(f.state->seen().size(), 2U);
}

TEST(Client, RetriesLostConnectionsForIdempotentCalls) {
  Fixture f;
  f.state->push(kit::failing(TransportError("reset")));
  f.state->push(kit::reply(200, kHashBody));
  Client client = f.client(Fixture::retrying(1));
  EXPECT_EQ(client.hash({}).length, 1);
}

TEST(Client, StatefulCallsAreNotRetriedAfterLostConnectionOr504) {
  Fixture f;
  f.state->push(kit::failing(TransportError("reset")));
  f.state->push(kit::reply(504, ""));
  Client client = f.client(Fixture::retrying(3));
  EXPECT_THROW((void)client.generate_key_pair(), TransportError);
  EXPECT_THROW((void)client.generate_key_pair(), ApiError);
  EXPECT_EQ(f.state->seen().size(), 2U);
}

TEST(Client, LastTransportErrorIsRethrown) {
  Fixture f;
  f.state->push(kit::failing(TransportError("down", true)));
  Client client = f.client();
  try {
    (void)client.health();
    FAIL() << "no error";
  } catch (const TransportError& e) {
    EXPECT_TRUE(e.timed_out());
  }
}

TEST(Client, DeadlineBoundsTheAttemptTimeout) {
  Fixture f;
  f.state->push(kit::reply(200, kHashBody));
  ClientOptions options = kit::fake_options();
  options.deadline = milliseconds(40);
  Client client = f.client(options);
  (void)client.hash({});
  EXPECT_LE(f.state->seen().at(0).timeout, milliseconds(40));
}

TEST(Client, NoRetryWhenTheWaitWouldPassTheDeadline) {
  Fixture f;
  f.state->push(kit::slow(kit::reply(503, ""), milliseconds(30)));
  f.state->push(kit::slow(kit::failing(TransportError("reset")), milliseconds(30)));
  ClientOptions options = Fixture::retrying(5);
  options.deadline = milliseconds(20);
  Client client = f.client(options);
  EXPECT_THROW((void)client.hash({}), ApiError);
  EXPECT_THROW((void)client.hash({}), TransportError);
  EXPECT_EQ(f.state->seen().size(), 2U);
}

TEST(Client, DeadlinePassedBeforeAnAttempt) {
  Fixture f;
  f.state->push(kit::reply(503, ""));
  ClientOptions options = Fixture::retrying(1);
  options.retry.initial_delay = options.retry.max_delay = milliseconds(0);
  options.deadline = milliseconds(20);
  options.sleep = [](milliseconds) { std::this_thread::sleep_for(milliseconds(30)); };
  Client client = f.client(options);
  try {
    (void)client.hash({});
    FAIL() << "no error";
  } catch (const TransportError& e) {
    EXPECT_TRUE(e.timed_out());
  }
}

TEST(Client, CancelledBeforeSending) {
  Fixture f;
  Client client = f.client();
  CancelSource source;
  source.cancel();
  EXPECT_THROW((void)client.hash({}, {source.token()}), CancelledError);
  EXPECT_TRUE(f.state->seen().empty());
}

TEST(Client, CancellationEndsTheBackoffWait) {
  Fixture f;
  f.state->push(kit::reply(503, ""));
  ClientOptions options = Fixture::retrying(1);
  options.retry.initial_delay = options.retry.max_delay = milliseconds(5000);
  options.sleep = nullptr;
  CancelSource source;
  Client client(options, std::make_unique<kit::FakeTransport>(f.state));
  std::thread canceller([&source] {
    std::this_thread::sleep_for(milliseconds(30));
    source.cancel();
  });
  const auto start = std::chrono::steady_clock::now();
  EXPECT_THROW((void)client.hash({}, {source.token()}), CancelledError);
  canceller.join();
  EXPECT_LT(std::chrono::steady_clock::now() - start, milliseconds(2000));
}

TEST(Client, RealSleepWaitsOutShortBackoff) {
  Fixture f;
  f.state->push(kit::reply(503, ""));
  f.state->push(kit::reply(200, kHashBody));
  ClientOptions options = Fixture::retrying(1);
  options.retry.initial_delay = options.retry.max_delay = milliseconds(1);
  options.sleep = nullptr;
  Client client(options, std::make_unique<kit::FakeTransport>(f.state));
  EXPECT_EQ(client.hash({}).length, 1);
}

TEST(Client, CancelledErrorFromTheTransportIsNotRetried) {
  Fixture f;
  f.state->push(kit::failing(CancelledError("cancelled")));
  Client client = f.client(Fixture::retrying(3));
  EXPECT_THROW((void)client.hash({}), CancelledError);
  EXPECT_EQ(f.state->seen().size(), 1U);
}

TEST(Client, RedirectsAreRefused) {
  Fixture f;
  f.state->push(kit::reply(307, "", {{"Location", "https://elsewhere.test/"}}));
  Client client = f.client(Fixture::retrying(3));
  EXPECT_THROW((void)client.hash({}), TransportError);
  EXPECT_EQ(f.state->seen().size(), 1U);
}

TEST(Client, RawRequestReturnsAnyStatus) {
  Fixture f;
  f.state->push(
      kit::reply(415, R"({"detail":"x"})", {{"Content-Type", "application/problem+json"}}));
  Client client = f.client();
  RawRequest request;
  request.method = "POST";
  request.path = "/v2/hash";
  request.body = "<a/>";
  request.headers = {{"Content-Type", "application/xml"}};
  const RawResponse response = client.request(request);
  EXPECT_EQ(response.status, 415);
  EXPECT_EQ(response.json().at("detail"), "x");
  EXPECT_EQ(f.state->seen().at(0).body.value_or(""), "<a/>");
}

TEST(Client, MovesKeepTheTransport) {
  Fixture f;
  f.state->push(kit::reply(200, kHashBody));
  Client first = f.client();
  Client second(std::move(first));
  Client third = f.client();
  third = std::move(second);
  EXPECT_EQ(third.hash({}).length, 1);
}

}  // namespace
}  // namespace crypto_service
