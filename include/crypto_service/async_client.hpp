// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The asynchronous client: every operation returns a std::future.
//
// One AsyncClient owns one event-loop thread and one AsyncTransport (by
// default a libcurl multi handle: a shared connection cache, keep-alive,
// HTTP/2 multiplexing over TLS where the server offers it). Calls queue
// their request and return at once; the loop thread sends it, waits out
// retries without blocking other calls, decodes the result and fulfils
// the future.
//
// Thread safety: every member function except the destructor and the
// move operations is thread-safe; many threads may call one AsyncClient
// concurrently. The destructor must not run concurrently with a call.
// Futures may be waited on from any thread. Result decoding happens on
// the loop thread, so a future's value is complete when it is ready.
//
// Destruction cancels every call still in flight: each pending future
// becomes ready with CancelledError (never a broken promise), the loop
// thread is joined, and no callback runs afterwards.

#ifndef CRYPTO_SERVICE_ASYNC_CLIENT_HPP
#define CRYPTO_SERVICE_ASYNC_CLIENT_HPP

#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "crypto_service/client.hpp"
#include "crypto_service/detail/wire.hpp"
#include "crypto_service/operations.hpp"
#include "crypto_service/options.hpp"
#include "crypto_service/transport.hpp"

namespace crypto_service {

namespace detail {
/// How a call ended: the final response, or an exception.
struct Outcome {
  std::optional<HttpResponse> response;  ///< Set when a response arrived.
  std::exception_ptr error;              ///< Otherwise the error.
};

/// Called once, on the loop thread, when a call ends.
using Completion = std::function<void(Outcome)>;

/// The response of a successful outcome; rethrows its error, or throws
/// ApiError for a non-2xx response.
HttpResponse success(Outcome outcome);
}  // namespace detail

/// An asynchronous, thread-safe client for one crypto-server.
class AsyncClient : public Operations<AsyncClient, std::future> {
 public:
  /// Uses libcurl's multi interface. Throws std::invalid_argument when
  /// an option is outside its documented range.
  explicit AsyncClient(ClientOptions options);
  /// Uses `transport` (tests, custom HTTP stacks).
  AsyncClient(ClientOptions options, std::unique_ptr<AsyncTransport> transport);

  AsyncClient(const AsyncClient&) = delete;
  AsyncClient& operator=(const AsyncClient&) = delete;
  AsyncClient(AsyncClient&&) = delete;
  AsyncClient& operator=(AsyncClient&&) = delete;
  /// Cancels the calls in flight (their futures end with
  /// CancelledError) and joins the loop thread.
  ~AsyncClient();

  /// As Client::request, asynchronously.
  [[nodiscard]] std::future<RawResponse> request(const RawRequest& request,
                                                 const CallOptions& call = {});

 private:
  friend class Operations<AsyncClient, std::future>;

  template <typename Result>
  std::future<Result> dispatch(const detail::Route& route, std::optional<std::string> body,
                               const CallOptions& call) {
    auto promise = std::make_shared<std::promise<Result>>();
    std::future<Result> future = promise->get_future();
    const bool wrapped = route.wrapped;
    submit(route, std::move(body), {}, call, [promise, wrapped](detail::Outcome outcome) {
      try {
        promise->set_value(detail::decode<Result>(detail::success(std::move(outcome)), wrapped));
      } catch (...) {
        promise->set_exception(std::current_exception());
      }
    });
    return future;
  }

  void submit(const detail::Route& route, std::optional<std::string> body,
              const std::vector<std::pair<std::string, std::string>>& extra,
              const CallOptions& call, detail::Completion done);

  struct Loop;
  std::unique_ptr<Loop> loop_;
};

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_ASYNC_CLIENT_HPP
