// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Client configuration (ClientOptions, RetryOptions), per-call options
// (CallOptions) and cooperative cancellation (CancelSource, CancelToken).

#ifndef CRYPTO_SERVICE_OPTIONS_HPP
#define CRYPTO_SERVICE_OPTIONS_HPP

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace crypto_service {

/// Retries for transient failures (docs/adr/0004-async-model.md has the
/// table). Off by default: `max_retries` is 0.
///
/// Attempt n+1 waits a uniformly random time in
/// [0, min(initial_delay * 2^(n-1), max_delay)] ("full jitter"), or what
/// a 429, 503 or 504 response's `Retry-After` asks for (delta-seconds or
/// an HTTP-date); when that is longer than `max_delay` the response is
/// final. Idempotent and pure operations are retried after 429, 503, 504
/// and a lost connection or timeout. Stateful operations (keys/generate,
/// keys/delete, every keygen, kms/create-key, opaque/register/*) are
/// retried only after 429 or 503, when the server certainly did nothing.
struct RetryOptions {
  /// Retries after the first attempt. 0 sends every request once.
  int max_retries = 0;
  /// The cap of the first backoff; it doubles for each later attempt.
  std::chrono::milliseconds initial_delay{200};
  /// The largest backoff, and the longest Retry-After honoured.
  std::chrono::milliseconds max_delay{2000};
};

/// How to reach the server. Credentials are never logged, and
/// `describe()` redacts them.
struct ClientOptions {
  /// `http://` or `https://` origin, optionally with a path prefix; no
  /// user information, query or fragment. Trailing slashes are dropped.
  std::string base_url;
  /// Sent as `x-api-key`.
  std::optional<std::string> api_key;
  /// Sent as `Authorization: Bearer <token>` (an HS256 JWT).
  std::optional<std::string> token;
  /// Per-attempt timeout (connect plus transfer). Must be positive.
  std::chrono::milliseconds timeout{std::chrono::seconds(30)};
  /// Overall time budget per call, retries and backoff included. Unset
  /// means only the per-attempt timeout applies.
  std::optional<std::chrono::milliseconds> deadline;
  /// Retries for transient failures; none by default.
  RetryOptions retry{};
  /// A fixed W3C `traceparent` sent with every request.
  std::optional<std::string> traceparent;
  /// When true (and `traceparent` is unset), a fresh random W3C
  /// traceparent (version 00, sampled) is generated for every request.
  bool auto_traceparent = false;
  /// How the blocking Client waits between attempts. Empty means
  /// std::this_thread::sleep_for in slices that notice cancellation; set
  /// it to observe or skip the waits in tests. AsyncClient ignores it.
  std::function<void(std::chrono::milliseconds)> sleep{};
};

/// The options with the base URL, timeouts and retry settings, and the
/// credentials replaced by `<redacted>`: safe to log.
[[nodiscard]] std::string describe(const ClientOptions& options);

/// Observes a CancelSource. Default-constructed tokens never cancel.
/// Copies share state; any thread may read it.
class CancelToken {
 public:
  CancelToken() = default;

  /// Whether the source has been cancelled.
  [[nodiscard]] bool cancelled() const noexcept {
    return state_ != nullptr && state_->load(std::memory_order_acquire);
  }
  /// Whether this token can ever be cancelled.
  [[nodiscard]] bool cancellable() const noexcept { return state_ != nullptr; }

 private:
  friend class CancelSource;
  explicit CancelToken(std::shared_ptr<std::atomic<bool>> state) : state_(std::move(state)) {}
  std::shared_ptr<std::atomic<bool>> state_;
};

/// Requests cancellation of every call given one of its tokens.
/// Thread-safe: cancel() may be called from any thread, any number of
/// times. A blocking call notices within about a second (libcurl's
/// progress callback) and while waiting between attempts; an
/// AsyncClient call within about 10 ms. A cancelled call ends with
/// CancelledError and is not retried.
class CancelSource {
 public:
  CancelSource() : state_(std::make_shared<std::atomic<bool>>(false)) {}

  /// A token observing this source.
  [[nodiscard]] CancelToken token() const { return CancelToken(state_); }
  /// Cancels every call holding one of this source's tokens.
  void cancel() noexcept { state_->store(true, std::memory_order_release); }
  /// Whether cancel() has been called.
  [[nodiscard]] bool cancelled() const noexcept { return state_->load(std::memory_order_acquire); }

 private:
  std::shared_ptr<std::atomic<bool>> state_;
};

/// Options for one call.
struct CallOptions {
  /// Cancels the call when its source is cancelled.
  CancelToken cancel{};
};

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_OPTIONS_HPP
