// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Internal: the retry decisions, ported from the TypeScript SDK's
// request.ts so every SDK retries the same requests the same way.

#ifndef CRYPTO_SERVICE_SRC_RETRY_HPP
#define CRYPTO_SERVICE_SRC_RETRY_HPP

#include <chrono>
#include <optional>
#include <string_view>

#include "crypto_service/options.hpp"
#include "crypto_service/transport.hpp"

namespace crypto_service::detail {

/// The wait before retrying after attempt `attempt` (from 1) got no
/// response, or nullopt: not idempotent, or no attempts left.
std::optional<std::chrono::milliseconds> delay_after_error(int attempt, const RetryOptions& retry,
                                                           bool idempotent);

/// The wait before retrying after attempt `attempt` got `response`, or
/// nullopt: not 429, 503 or 504; a 504 for a stateful route; no
/// attempts left; or a Retry-After longer than `max_delay`.
std::optional<std::chrono::milliseconds> delay_after_response(int attempt,
                                                              const HttpResponse& response,
                                                              const RetryOptions& retry,
                                                              bool idempotent);

/// What a Retry-After value asks for (delta-seconds, possibly with a
/// fraction, or an IMF-fixdate), or nullopt when it is neither.
std::optional<std::chrono::milliseconds> retry_after(std::string_view value,
                                                     std::chrono::system_clock::time_point now);

}  // namespace crypto_service::detail

#endif  // CRYPTO_SERVICE_SRC_RETRY_HPP
