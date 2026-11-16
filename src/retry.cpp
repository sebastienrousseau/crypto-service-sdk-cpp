// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Exponential backoff with full jitter, Retry-After, and the
// stateful-route rule: a request that may have created or deleted
// something is retried only after 429 or 503, when the server certainly
// did not process it.

#include "retry.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <locale>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>

namespace crypto_service::detail {
namespace {

using std::chrono::milliseconds;

// Delta-seconds as milliseconds: digits, optionally a fraction. More
// than nine integer digits is longer than any honoured wait.
std::optional<milliseconds> delta_seconds(std::string_view value) {
  const auto dot = value.find('.');
  const std::string_view whole = value.substr(0, dot);
  const std::string_view fraction =
      dot == std::string_view::npos ? std::string_view() : value.substr(dot + 1);
  const auto digits = [](std::string_view s) {
    return s.find_first_not_of("0123456789") == std::string_view::npos;
  };
  if (whole.empty() || !digits(whole) || !digits(fraction)) {
    return std::nullopt;
  }
  if (whole.size() > 9) {
    return milliseconds::max();
  }
  std::int64_t ms = std::stoll(std::string(whole)) * 1000;
  std::int64_t scale = 100;
  for (const char c : fraction.substr(0, 3)) {
    ms += (c - '0') * scale;
    scale /= 10;
  }
  return milliseconds(ms);
}

// An IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT") as a time point.
std::optional<std::chrono::system_clock::time_point> http_date(std::string_view value) {
  std::tm parts{};
  std::istringstream in{std::string(value)};
  in.imbue(std::locale::classic());
  in >> std::get_time(&parts, "%a, %d %b %Y %H:%M:%S GMT");
  if (in.fail()) {
    return std::nullopt;
  }
#ifdef _WIN32
  const std::time_t seconds = _mkgmtime(&parts);
#else
  const std::time_t seconds = timegm(&parts);
#endif
  return std::chrono::system_clock::from_time_t(seconds);
}

bool transient(long status) { return status == 429 || status == 503 || status == 504; }

// A uniformly random wait in [0, min(initial * 2^(attempt-1), max)].
milliseconds jittered(int attempt, const RetryOptions& retry) {
  milliseconds cap = retry.initial_delay;
  for (int i = 1; i < attempt && cap < retry.max_delay; ++i) {
    cap *= 2;
  }
  cap = std::min(cap, retry.max_delay);
  thread_local std::mt19937_64 engine{std::random_device{}()};
  std::uniform_int_distribution<milliseconds::rep> pick(0, cap.count());
  return milliseconds(pick(engine));
}

}  // namespace

std::optional<milliseconds> retry_after(std::string_view value,
                                        std::chrono::system_clock::time_point now) {
  if (const auto delta = delta_seconds(value)) {
    return delta;
  }
  const auto date = http_date(value);
  if (!date) {
    return std::nullopt;
  }
  return std::max(milliseconds(0), std::chrono::duration_cast<milliseconds>(*date - now));
}

std::optional<milliseconds> delay_after_error(int attempt, const RetryOptions& retry,
                                              bool idempotent) {
  if (!idempotent || attempt > retry.max_retries) {
    return std::nullopt;
  }
  return jittered(attempt, retry);
}

std::optional<milliseconds> delay_after_response(int attempt, const HttpResponse& response,
                                                 const RetryOptions& retry, bool idempotent) {
  if (attempt > retry.max_retries || !transient(response.status)) {
    return std::nullopt;
  }
  if (!idempotent && response.status == 504) {
    return std::nullopt;  // the server may have done the work
  }
  const std::optional<std::string> header = response.header("Retry-After");
  const std::optional<milliseconds> asked =
      header ? retry_after(*header, std::chrono::system_clock::now()) : std::nullopt;
  if (!asked) {
    return jittered(attempt, retry);
  }
  if (*asked > retry.max_delay) {
    return std::nullopt;
  }
  return asked;
}

}  // namespace crypto_service::detail
