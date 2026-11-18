// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Option validation, request construction, the retry-safety rule for
// stateful routes, traceparent generation and the per-call time budget.

#include "settings.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "crypto_service/errors.hpp"
#include "crypto_service/version.hpp"

namespace crypto_service {
namespace detail {
namespace {

using std::chrono::milliseconds;

constexpr auto kLongestDelay = std::chrono::hours(1);
// The longest timeout or deadline: a deadline is added to a steady_clock
// time point, and a timeout goes to libcurl as a long (32 bits on
// Windows); a day keeps both in range.
constexpr auto kLongestWait = std::chrono::hours(24);
constexpr int kMostRetries = 100;

bool starts_with(std::string_view text, std::string_view prefix) {
  return text.substr(0, prefix.size()) == prefix;
}

// Whether `text` has a control character (CR, LF and NUL included).
bool has_control(std::string_view text) {
  return std::any_of(text.begin(), text.end(), [](char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte < 0x20U || byte == 0x7FU;
  });
}

void require(bool ok, const char* message) {
  if (!ok) {
    throw std::invalid_argument(message);
  }
}

std::string checked_base_url(std::string url) {
  const bool https = starts_with(url, "https://");
  require(https || starts_with(url, "http://"), "base_url must start with http:// or https://");
  const std::string_view rest = std::string_view(url).substr(https ? 8 : 7);
  const std::string_view authority = rest.substr(0, rest.find('/'));
  require(!authority.empty(), "base_url has no host");
  require(authority.find('@') == std::string_view::npos, "base_url must not hold credentials");
  require(url.find_first_of("?#") == std::string::npos,
          "base_url must not have a query or fragment");
  require(!has_control(url) && url.find(' ') == std::string::npos,
          "base_url must not contain spaces or control characters");
  while (url.back() == '/') {
    url.pop_back();  // never empties it: the authority is not empty
  }
  return url;
}

void check_secret(const std::optional<std::string>& secret, const char* message) {
  require(!secret || (!secret->empty() && !has_control(*secret)), message);
}

// A W3C traceparent: `vv-<32 hex>-<16 hex>-ff`, lowercase.
bool valid_traceparent(std::string_view value) {
  if (value.size() != 55 || value[2] != '-' || value[35] != '-' || value[52] != '-') {
    return false;
  }
  for (std::size_t i = 0; i < value.size(); ++i) {
    const char c = value[i];
    const bool dash = i == 2 || i == 35 || i == 52;
    if (!dash && std::string_view("0123456789abcdef").find(c) == std::string_view::npos) {
      return false;
    }
  }
  return true;
}

void check_retry(const RetryOptions& retry) {
  require(retry.max_retries >= 0 && retry.max_retries <= kMostRetries,
          "retry.max_retries must be between 0 and 100");
  require(retry.initial_delay.count() >= 0 && retry.max_delay >= retry.initial_delay,
          "retry delays must satisfy 0 <= initial_delay <= max_delay");
  require(retry.max_delay <= kLongestDelay, "retry.max_delay must be at most one hour");
}

void check_options(const ClientOptions& options) {
  check_secret(options.api_key, "api_key must be non-empty without control characters");
  check_secret(options.token, "token must be non-empty without control characters");
  require(options.timeout.count() > 0 && options.timeout <= kLongestWait,
          "timeout must be positive and at most 24 hours");
  require(!options.deadline || (options.deadline->count() > 0 && *options.deadline <= kLongestWait),
          "deadline must be positive and at most 24 hours");
  require(!options.traceparent || valid_traceparent(*options.traceparent),
          "traceparent must be a W3C traceparent (00-<32 hex>-<16 hex>-<2 hex>)");
  check_retry(options.retry);
}

void append_hex(std::string& out, std::mt19937_64& engine, std::size_t bytes) {
  static constexpr std::string_view kHex = "0123456789abcdef";
  std::uniform_int_distribution<unsigned> pick(0, 255);
  for (std::size_t i = 0; i < bytes; ++i) {
    // The first byte is never zero, so the id is never all zeros (invalid).
    const unsigned byte = i == 0 ? 1 + pick(engine) % 255 : pick(engine);
    out.push_back(kHex[byte >> 4U]);
    out.push_back(kHex[byte & 0x0FU]);
  }
}

bool has_header(const Headers& headers, std::string_view name) {
  return std::any_of(headers.begin(), headers.end(), [name](const auto& header) {
    return std::equal(header.first.begin(), header.first.end(), name.begin(), name.end(),
                      [](char a, char b) {
                        return std::tolower(static_cast<unsigned char>(a)) ==
                               std::tolower(static_cast<unsigned char>(b));
                      });
  });
}

void check_route(const Route& route) {
  require(starts_with(route.path, "/") && !has_control(route.path) &&
              route.path.find_first_of(" ?#") == std::string_view::npos,
          "path must start with / and have no query, fragment, space or control character");
  require(!route.method.empty() && route.method.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ") ==
                                       std::string_view::npos,
          "method must be an upper-case HTTP method name");
}

void append_extra(Headers& headers, const Headers& extra) {
  for (const auto& [name, value] : extra) {
    require(!name.empty() && !has_control(name) && !has_control(value),
            "header names and values must not contain control characters");
    headers.emplace_back(name, value);
  }
}

}  // namespace

Settings settle(ClientOptions options) {
  check_options(options);
  Settings settings;
  settings.base_url = checked_base_url(std::move(options.base_url));
  settings.common.emplace_back("User-Agent", std::string(kUserAgent));
  settings.common.emplace_back("Accept", "application/json");
  if (options.traceparent) {
    settings.common.emplace_back("traceparent", *options.traceparent);
  }
  if (options.api_key) {
    settings.credentials.emplace_back("x-api-key", *options.api_key);
  }
  if (options.token) {
    settings.credentials.emplace_back("Authorization", "Bearer " + *options.token);
  }
  settings.options = std::move(options);
  return settings;
}

HttpRequest build(const Settings& settings, const Route& route, std::optional<std::string> body,
                  const Headers& extra, const CancelToken& cancel) {
  check_route(route);
  HttpRequest request;
  request.method = std::string(route.method);
  request.url = settings.base_url + std::string(route.path);
  request.headers = settings.common;
  if (!route.anonymous) {
    request.headers.insert(request.headers.end(), settings.credentials.begin(),
                           settings.credentials.end());
  }
  if (settings.options.auto_traceparent && !settings.options.traceparent) {
    request.headers.emplace_back("traceparent", make_traceparent());
  }
  append_extra(request.headers, extra);
  if (body && !has_header(extra, "Content-Type")) {
    request.headers.emplace_back("Content-Type", "application/json");
  }
  request.body = std::move(body);
  request.cancel = cancel;
  return request;
}

bool is_idempotent(std::string_view method, std::string_view path) {
  static constexpr std::array<std::string_view, 5> kStateful{
      "/keygen", "/keys/generate", "/keys/delete", "/kms/create-key", "/opaque/register/"};
  return method == "GET" || std::none_of(kStateful.begin(), kStateful.end(), [path](auto route) {
           return path.find(route) != std::string_view::npos;
         });
}

std::string make_traceparent() {
  thread_local std::mt19937_64 engine{std::random_device{}()};
  std::string out = "00-";
  append_hex(out, engine, 16);
  out.push_back('-');
  append_hex(out, engine, 8);
  out.append("-01");
  return out;
}

Budget::Budget(const Settings& settings, Clock::time_point start)
    : timeout_(settings.options.timeout) {
  if (settings.options.deadline) {
    end_ = start + *settings.options.deadline;
  }
}

std::optional<milliseconds> Budget::attempt_timeout(Clock::time_point now) const {
  if (!end_) {
    return timeout_;
  }
  const auto left = std::chrono::duration_cast<milliseconds>(*end_ - now);
  if (left.count() <= 0) {
    return std::nullopt;
  }
  return std::min(timeout_, left);
}

bool Budget::fits(Clock::time_point now, milliseconds delay) const {
  return !end_ || now + delay < *end_;
}

TransportError deadline_exceeded() {
  return TransportError("crypto-service: the call's deadline passed", true);
}

void refuse_redirect(const HttpResponse& response) {
  if (response.status >= 300 && response.status < 400) {
    throw TransportError("crypto-service: refused a redirect (HTTP " +
                         std::to_string(response.status) + ")");
  }
}

}  // namespace detail

namespace {

// `url` with any user information before the host replaced.
std::string redacted_url(const std::string& url) {
  const auto scheme = url.find("://");
  const auto start = scheme == std::string::npos ? 0 : scheme + 3;
  const auto at = url.find('@', start);
  if (at == std::string::npos || at > url.find('/', start)) {
    return url;
  }
  return url.substr(0, start) + "<redacted>" + url.substr(at);
}

}  // namespace

std::string describe(const ClientOptions& options) {
  const auto ms = [](std::chrono::milliseconds value) {
    return std::to_string(value.count()) + "ms";
  };
  const auto secret = [](const std::optional<std::string>& value) {
    return value ? std::string("<redacted>") : std::string("<unset>");
  };
  std::string out = "ClientOptions{base_url=" + redacted_url(options.base_url);
  out += ", api_key=" + secret(options.api_key) + ", token=" + secret(options.token);
  out += ", timeout=" + ms(options.timeout);
  out += ", deadline=" + (options.deadline ? ms(*options.deadline) : std::string("<unset>"));
  out += ", retry={max_retries=" + std::to_string(options.retry.max_retries);
  out += ", initial_delay=" + ms(options.retry.initial_delay);
  out += ", max_delay=" + ms(options.retry.max_delay) + "}";
  out += ", traceparent=" + (options.traceparent
                                 ? *options.traceparent
                                 : std::string(options.auto_traceparent ? "<auto>" : "<unset>"));
  return out + "}";
}

}  // namespace crypto_service
