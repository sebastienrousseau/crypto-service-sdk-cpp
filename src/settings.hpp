// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Internal: validated client options, request construction and the
// per-call time budget, shared by Client and AsyncClient.

#ifndef CRYPTO_SERVICE_SRC_SETTINGS_HPP
#define CRYPTO_SERVICE_SRC_SETTINGS_HPP

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "crypto_service/detail/wire.hpp"
#include "crypto_service/errors.hpp"
#include "crypto_service/options.hpp"
#include "crypto_service/transport.hpp"

namespace crypto_service::detail {

using Clock = std::chrono::steady_clock;
using Headers = std::vector<std::pair<std::string, std::string>>;

/// ClientOptions after validation.
struct Settings {
  std::string base_url;   ///< Without trailing slashes.
  Headers common;         ///< User-Agent, Accept, fixed traceparent.
  Headers credentials;    ///< x-api-key and/or Authorization.
  ClientOptions options;  ///< The rest, unchanged.
};

/// Validates `options`; std::invalid_argument names the bad option.
Settings settle(ClientOptions options);

/// The request for one call: URL, headers (credentials unless the route
/// is anonymous, a fresh traceparent when auto_traceparent is on, and
/// `extra`), body and cancel token. The timeout is set per attempt.
HttpRequest build(const Settings& settings, const Route& route, std::optional<std::string> body,
                  const Headers& extra, const CancelToken& cancel);

/// Whether repeating `method path` cannot create or delete anything
/// twice: every GET, and every POST except the stateful routes.
bool is_idempotent(std::string_view method, std::string_view path);

/// A random W3C traceparent: `00-<trace-id>-<parent-id>-01`.
std::string make_traceparent();

/// The time budget of one call: the per-attempt timeout bounded by the
/// overall deadline.
class Budget {
 public:
  Budget(const Settings& settings, Clock::time_point start);

  /// The timeout of an attempt starting at `now`, or nullopt when the
  /// deadline has passed.
  [[nodiscard]] std::optional<std::chrono::milliseconds> attempt_timeout(
      Clock::time_point now) const;
  /// Whether waiting `delay` from `now` still ends before the deadline.
  [[nodiscard]] bool fits(Clock::time_point now, std::chrono::milliseconds delay) const;

 private:
  std::chrono::milliseconds timeout_;
  std::optional<Clock::time_point> end_;
};

/// The error raised when the deadline ends a call.
TransportError deadline_exceeded();

/// TransportError when `response` is a redirect, which is never followed.
void refuse_redirect(const HttpResponse& response);

}  // namespace crypto_service::detail

#endif  // CRYPTO_SERVICE_SRC_SETTINGS_HPP
