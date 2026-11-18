// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// The retry decisions (ported from the TypeScript SDK's request.ts):
// which outcomes retry, the backoff bounds, Retry-After and the
// stateful-route rule.

#include <gtest/gtest.h>

#include <chrono>
#include <string>

#include "crypto_service/crypto_service.hpp"
#include "retry.hpp"
#include "settings.hpp"

namespace crypto_service {
namespace {

using std::chrono::milliseconds;
using Now = std::chrono::system_clock;

RetryOptions retries(int count) {
  RetryOptions retry;
  retry.max_retries = count;
  retry.initial_delay = milliseconds(100);
  retry.max_delay = milliseconds(1000);
  return retry;
}

HttpResponse status(long code, const std::string& retry_after = "") {
  HttpResponse r{code, "", {}};
  if (!retry_after.empty()) {
    r.headers.emplace_back("Retry-After", retry_after);
  }
  return r;
}

TEST(Retry, StatefulRoutes) {
  for (const char* path : {"/v2/keys/generate", "/v2/keys/delete", "/v2/pq/keygen",
                           "/v2/pq/dsa/keygen", "/v2/hpke/keygen", "/v2/kms/create-key",
                           "/v2/opaque/register/init", "/v2/opaque/register/finish"}) {
    EXPECT_FALSE(detail::is_idempotent("POST", path)) << path;
  }
  EXPECT_TRUE(detail::is_idempotent("GET", "/v2/keys/generate"));
  EXPECT_TRUE(detail::is_idempotent("POST", "/v2/hash"));
  EXPECT_TRUE(detail::is_idempotent("POST", "/v2/opaque/login/init"));
}

TEST(Retry, AfterAnError) {
  EXPECT_FALSE(detail::delay_after_error(1, retries(0), true));
  EXPECT_FALSE(detail::delay_after_error(1, retries(2), false));
  EXPECT_FALSE(detail::delay_after_error(3, retries(2), true));
  for (int attempt = 1; attempt <= 6; ++attempt) {
    const auto delay = detail::delay_after_error(attempt, retries(10), true);
    const milliseconds wait = delay.value_or(milliseconds(-1));
    EXPECT_GE(wait.count(), 0);
    EXPECT_LE(wait, std::min(milliseconds(100U << (attempt - 1U)), milliseconds(1000)));
  }
}

TEST(Retry, AfterAResponse) {
  const RetryOptions retry = retries(3);
  EXPECT_FALSE(detail::delay_after_response(1, status(200), retry, true));
  EXPECT_FALSE(detail::delay_after_response(1, status(500), retry, true));
  EXPECT_FALSE(detail::delay_after_response(4, status(503), retry, true));
  EXPECT_TRUE(detail::delay_after_response(1, status(504), retry, true));
  EXPECT_FALSE(detail::delay_after_response(1, status(504), retry, false));
  EXPECT_TRUE(detail::delay_after_response(1, status(429), retry, false));
  EXPECT_TRUE(detail::delay_after_response(1, status(503), retry, false));
}

TEST(Retry, RetryAfterIsHonouredUpToMaxDelay) {
  const RetryOptions retry = retries(3);
  EXPECT_EQ(detail::delay_after_response(1, status(429, "0.5"), retry, true), milliseconds(500));
  EXPECT_FALSE(detail::delay_after_response(1, status(429, "2"), retry, true));
  const auto fallback = detail::delay_after_response(1, status(429, "soon"), retry, true);
  const milliseconds wait = fallback.value_or(milliseconds(-1));
  EXPECT_GE(wait.count(), 0);
  EXPECT_LE(wait, milliseconds(100));
}

TEST(Retry, RetryAfterValues) {
  const auto now = Now::from_time_t(784111777);  // Sun, 06 Nov 1994 08:49:37 GMT
  EXPECT_EQ(detail::retry_after("3", now), milliseconds(3000));
  EXPECT_EQ(detail::retry_after("1.25", now), milliseconds(1250));
  EXPECT_EQ(detail::retry_after("1.2345", now), milliseconds(1234));
  EXPECT_EQ(detail::retry_after("1234567890", now), milliseconds::max());
  EXPECT_EQ(detail::retry_after("Sun, 06 Nov 1994 08:49:40 GMT", now), milliseconds(3000));
  EXPECT_EQ(detail::retry_after("Sun, 06 Nov 1994 08:49:30 GMT", now), milliseconds(0));
  EXPECT_FALSE(detail::retry_after("", now));
  EXPECT_FALSE(detail::retry_after(".5", now));
  EXPECT_FALSE(detail::retry_after("1.x", now));
  EXPECT_FALSE(detail::retry_after("-1", now));
  EXPECT_FALSE(detail::retry_after("tomorrow", now));
}

}  // namespace
}  // namespace crypto_service
