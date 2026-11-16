// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The blocking Client: one call at a time through its Transport, with
// retries, backoff waits that notice cancellation, and the deadline.

#include "crypto_service/client.hpp"

#include <algorithm>
#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "crypto_service/errors.hpp"
#include "retry.hpp"
#include "settings.hpp"

namespace crypto_service {
namespace {

using std::chrono::milliseconds;

constexpr milliseconds kCancelSlice{10};

void throw_if_cancelled(const CancelToken& cancel) {
  if (cancel.cancelled()) {
    throw CancelledError("crypto-service: the call was cancelled");
  }
}

// Waits `delay`, in slices so a cancellation ends the wait early.
void pause(const ClientOptions& options, milliseconds delay, const CancelToken& cancel) {
  if (options.sleep) {
    options.sleep(delay);
  } else {
    const auto end = detail::Clock::now() + delay;
    while (!cancel.cancelled() && detail::Clock::now() < end) {
      std::this_thread::sleep_for(std::min(kCancelSlice, delay));
    }
  }
  throw_if_cancelled(cancel);
}

// The timeout of the next attempt; CancelledError or the deadline error
// when there is none.
milliseconds attempt_timeout(const detail::Budget& budget, const CancelToken& cancel) {
  throw_if_cancelled(cancel);
  const std::optional<milliseconds> timeout = budget.attempt_timeout(detail::Clock::now());
  if (!timeout) {
    throw detail::deadline_exceeded();
  }
  return *timeout;
}

}  // namespace

struct Client::State {
  detail::Settings settings;
  std::unique_ptr<Transport> transport;
};

Client::Client(ClientOptions options) : Client(std::move(options), make_curl_transport()) {}

Client::Client(ClientOptions options, std::unique_ptr<Transport> transport)
    : state_(std::make_unique<State>(
          State{detail::settle(std::move(options)), std::move(transport)})) {
  if (!state_->transport) {
    throw std::invalid_argument("transport must not be null");
  }
}

Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;
Client::~Client() = default;

HttpResponse Client::execute(const detail::Route& route, std::optional<std::string> body,
                             const std::vector<std::pair<std::string, std::string>>& extra,
                             const CallOptions& call) {
  const detail::Settings& settings = state_->settings;
  const RetryOptions& retry = settings.options.retry;
  HttpRequest request = detail::build(settings, route, std::move(body), extra, call.cancel);
  const bool idempotent = detail::is_idempotent(route.method, route.path);
  const detail::Budget budget(settings, detail::Clock::now());
  for (int attempt = 1;; ++attempt) {
    request.timeout = attempt_timeout(budget, call.cancel);
    std::optional<milliseconds> delay;
    std::optional<HttpResponse> response;
    try {
      response = state_->transport->send(request);
    } catch (const CancelledError&) {
      throw;
    } catch (const TransportError&) {
      delay = detail::delay_after_error(attempt, retry, idempotent);
      if (!delay || !budget.fits(detail::Clock::now(), *delay)) {
        throw;
      }
    }
    if (response) {
      delay = detail::delay_after_response(attempt, *response, retry, idempotent);
      if (!delay || !budget.fits(detail::Clock::now(), *delay)) {
        detail::refuse_redirect(*response);
        return std::move(*response);
      }
    }
    pause(settings.options, *delay, call.cancel);
  }
}

RawResponse Client::request(const RawRequest& request, const CallOptions& call) {
  const detail::Route route{request.method, request.path, false, false};
  HttpResponse response = execute(route, request.body, request.headers, call);
  return RawResponse{response.status, std::move(response.body), std::move(response.headers)};
}

}  // namespace crypto_service
