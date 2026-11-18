// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Option validation, the redacted description, request construction,
// traceparent generation and the per-call time budget.

#include <gtest/gtest.h>

#include <chrono>
#include <regex>
#include <stdexcept>
#include <string>

#include "crypto_service/crypto_service.hpp"
#include "settings.hpp"
#include "support/fake_transport.hpp"

namespace crypto_service {
namespace {

using std::chrono::milliseconds;

ClientOptions base() {
  ClientOptions options;
  options.base_url = "https://crypto.test/api//";
  return options;
}

void rejects(ClientOptions options) {
  EXPECT_THROW((void)detail::settle(std::move(options)), std::invalid_argument);
}

TEST(Settings, BaseUrl) {
  EXPECT_EQ(detail::settle(base()).base_url, "https://crypto.test/api");
  for (const char* url : {"ftp://crypto.test", "crypto.test", "http://", "http:///path",
                          "http://user:pw@crypto.test", "http://crypto.test?x=1",
                          "http://crypto.test/#f", "http://crypto .test", "http://crypto\n.test"}) {
    ClientOptions options = base();
    options.base_url = url;
    rejects(options);
  }
}

TEST(Settings, CredentialsTimeoutsAndTraceparent) {
  const auto with = [](auto change) {
    ClientOptions options = base();
    change(options);
    return options;
  };
  rejects(with([](ClientOptions& o) { o.api_key = ""; }));
  rejects(with([](ClientOptions& o) { o.api_key = "a\r\nb"; }));
  rejects(with([](ClientOptions& o) { o.token = std::string("a\0b", 3); }));
  rejects(with([](ClientOptions& o) { o.token = "a\x7f"; }));
  rejects(with([](ClientOptions& o) { o.timeout = milliseconds(0); }));
  rejects(with([](ClientOptions& o) { o.deadline = milliseconds(0); }));
  rejects(with([](ClientOptions& o) { o.traceparent = "00-abc"; }));
  rejects(with([](ClientOptions& o) {
    o.traceparent = "00_0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
  }));
  rejects(with([](ClientOptions& o) {
    o.traceparent = "00-0af7651916cd43dd8448eb211c80319c_b7ad6b7169203331-01";
  }));
  rejects(with([](ClientOptions& o) {
    o.traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331_01";
  }));
  rejects(with([](ClientOptions& o) {
    o.traceparent = "00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01";
  }));
  EXPECT_NO_THROW((void)detail::settle(with([](ClientOptions& o) {
    o.traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    o.deadline = milliseconds(5);
  })));
}

TEST(Settings, RetryRanges) {
  const auto with_retry = [](int count, int initial, int max) {
    ClientOptions options = base();
    options.retry.max_retries = count;
    options.retry.initial_delay = milliseconds(initial);
    options.retry.max_delay = milliseconds(max);
    return options;
  };
  rejects(with_retry(-1, 0, 0));
  rejects(with_retry(101, 0, 0));
  rejects(with_retry(1, -1, 0));
  rejects(with_retry(1, 10, 5));
  rejects(with_retry(1, 0, 3600001));
  EXPECT_NO_THROW((void)detail::settle(with_retry(100, 0, 3600000)));
}

// A deadline is added to a steady_clock time point in nanoseconds, so
// an unbounded one overflowed (undefined behaviour); a timeout goes to
// libcurl as a long, 32 bits on Windows. Both are capped at a day.
TEST(Settings, TimeoutAndDeadlineAreAtMostADay) {
  const auto with = [](auto change) {
    ClientOptions options = base();
    change(options);
    return options;
  };
  constexpr auto kDay = std::chrono::hours(24);
  rejects(with([](ClientOptions& o) { o.deadline = milliseconds::max(); }));
  rejects(with([&](ClientOptions& o) { o.deadline = kDay + milliseconds(1); }));
  rejects(with([](ClientOptions& o) { o.timeout = milliseconds::max(); }));
  rejects(with([&](ClientOptions& o) { o.timeout = kDay + milliseconds(1); }));
  EXPECT_NO_THROW((void)detail::settle(with([&](ClientOptions& o) {
    o.timeout = kDay;
    o.deadline = kDay;
  })));
}

TEST(Settings, DescribeRedactsCredentials) {
  ClientOptions options = base();
  options.base_url = "https://user:pw@crypto.test/x";
  options.api_key = "key-value";
  options.token = "token-value";
  options.deadline = milliseconds(9);
  const std::string text = describe(options);
  EXPECT_EQ(text.find("key-value"), std::string::npos);
  EXPECT_EQ(text.find("token-value"), std::string::npos);
  EXPECT_EQ(text.find("pw"), std::string::npos);
  EXPECT_NE(text.find("api_key=<redacted>"), std::string::npos);
  EXPECT_NE(text.find("deadline=9ms"), std::string::npos);
  EXPECT_NE(text.find("traceparent=<unset>"), std::string::npos);

  options.auto_traceparent = true;
  EXPECT_NE(describe(options).find("traceparent=<auto>"), std::string::npos);
  options.traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
  EXPECT_NE(describe(options).find("b7ad6b7169203331"), std::string::npos);

  ClientOptions plain = base();
  EXPECT_NE(describe(plain).find("api_key=<unset>, token=<unset>"), std::string::npos);
  EXPECT_NE(describe(plain).find("deadline=<unset>"), std::string::npos);
  plain.base_url = "no-scheme@host";
  EXPECT_EQ(describe(plain).find("no-scheme"), std::string::npos);
  plain.base_url = "http://host/a@b";
  EXPECT_NE(describe(plain).find("http://host/a@b"), std::string::npos);
}

TEST(Settings, BuildHeaders) {
  ClientOptions options = base();
  options.api_key = "k";
  options.token = "t";
  options.auto_traceparent = true;
  const detail::Settings settings = detail::settle(options);
  const HttpRequest request =
      detail::build(settings, {"POST", "/v2/hash"}, std::string("{}"), {{"X-Extra", "1"}}, {});
  const HttpResponse view{0, "", request.headers};
  EXPECT_EQ(request.url, "https://crypto.test/api/v2/hash");
  EXPECT_EQ(view.header("User-Agent"), "crypto-service-sdk-cpp/" CRYPTO_SERVICE_PROJECT_VERSION);
  EXPECT_EQ(view.header("x-api-key"), "k");
  EXPECT_EQ(view.header("Authorization"), "Bearer t");
  EXPECT_EQ(view.header("Content-Type"), "application/json");
  EXPECT_EQ(view.header("X-Extra"), "1");
  EXPECT_TRUE(std::regex_match(view.header("traceparent").value_or(""),
                               std::regex("00-[0-9a-f]{32}-[0-9a-f]{16}-01")));

  const HttpRequest probe = detail::build(settings, {"GET", "/health", false, true}, std::nullopt,
                                          {{"content-type", "text/plain"}}, {});
  const HttpResponse probe_view{0, "", probe.headers};
  EXPECT_FALSE(probe_view.header("x-api-key"));
  EXPECT_FALSE(probe_view.header("Authorization"));
  EXPECT_EQ(probe_view.header("Content-Type"), "text/plain");

  const HttpRequest raw = detail::build(settings, {"POST", "/v2/hash"}, std::string("x"),
                                        {{"Content-Type", "text/xml"}}, {});
  EXPECT_EQ(HttpResponse({0, "", raw.headers}).header("Content-Type"), "text/xml");
}

TEST(Settings, FixedTraceparentWinsOverAuto) {
  ClientOptions options = base();
  options.auto_traceparent = true;
  options.traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
  const auto settings = detail::settle(options);
  const HttpRequest request = detail::build(settings, {"GET", "/"}, std::nullopt, {}, {});
  int count = 0;
  for (const auto& header : request.headers) {
    count += header.first == "traceparent" ? 1 : 0;
  }
  EXPECT_EQ(count, 1);
}

TEST(Settings, BuildRejectsBadPathsMethodsAndHeaders) {
  const auto settings = detail::settle(base());
  const auto build = [&](std::string_view method, std::string_view path,
                         const detail::Headers& extra) {
    return detail::build(settings, {method, path}, std::nullopt, extra, {});
  };
  EXPECT_THROW(build("GET", "v2", {}), std::invalid_argument);
  EXPECT_THROW(build("GET", "/v2?x", {}), std::invalid_argument);
  EXPECT_THROW(build("GET", "/v\n2", {}), std::invalid_argument);
  EXPECT_THROW(build("", "/", {}), std::invalid_argument);
  EXPECT_THROW(build("get", "/", {}), std::invalid_argument);
  EXPECT_THROW(build("GET", "/", {{"", "v"}}), std::invalid_argument);
  EXPECT_THROW(build("GET", "/", {{"X\r", "v"}}), std::invalid_argument);
  EXPECT_THROW(build("GET", "/", {{"X", "v\n"}}), std::invalid_argument);
}

TEST(Settings, TraceparentsDiffer) {
  EXPECT_NE(detail::make_traceparent(), detail::make_traceparent());
}

TEST(Budget, TimeoutAndDeadline) {
  ClientOptions options = base();
  options.timeout = milliseconds(100);
  const auto start = detail::Clock::now();
  const detail::Budget open(detail::settle(options), start);
  EXPECT_EQ(open.attempt_timeout(start + std::chrono::hours(1)), milliseconds(100));
  EXPECT_TRUE(open.fits(start, std::chrono::hours(1)));

  options.deadline = milliseconds(250);
  const detail::Budget bounded(detail::settle(options), start);
  EXPECT_EQ(bounded.attempt_timeout(start), milliseconds(100));
  EXPECT_EQ(bounded.attempt_timeout(start + milliseconds(200)), milliseconds(50));
  EXPECT_FALSE(bounded.attempt_timeout(start + milliseconds(250)));
  EXPECT_TRUE(bounded.fits(start, milliseconds(249)));
  EXPECT_FALSE(bounded.fits(start, milliseconds(250)));
  EXPECT_TRUE(detail::deadline_exceeded().timed_out());
}

TEST(Budget, RedirectsAreRefused) {
  EXPECT_NO_THROW(detail::refuse_redirect({200, "", {}}));
  EXPECT_NO_THROW(detail::refuse_redirect({400, "", {}}));
  EXPECT_THROW(detail::refuse_redirect({302, "", {}}), TransportError);
  EXPECT_NO_THROW(detail::refuse_redirect({299, "", {}}));
}

TEST(CancelToken, States) {
  const CancelToken never;
  EXPECT_FALSE(never.cancellable());
  EXPECT_FALSE(never.cancelled());
  CancelSource source;
  const CancelToken token = source.token();
  EXPECT_TRUE(token.cancellable());
  EXPECT_FALSE(source.cancelled());
  source.cancel();
  EXPECT_TRUE(token.cancelled());
  EXPECT_TRUE(source.cancelled());
}

}  // namespace
}  // namespace crypto_service
