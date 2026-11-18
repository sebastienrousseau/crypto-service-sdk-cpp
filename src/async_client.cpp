// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// AsyncClient's event loop. Callers queue calls under a mutex and wake
// the loop; the loop thread alone touches the transport and the calls in
// flight. Each turn it adopts new calls, ends cancelled ones, starts the
// attempts that are due (new calls, and retries whose backoff is over),
// then polls the transport until the next timer and handles the
// transfers that ended. Destruction stops the loop, which ends every
// call with CancelledError before the thread is joined.

#include "crypto_service/async_client.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <map>
#include <mutex>
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

// How often the loop looks at cancel tokens while calls hold one, and
// the longest it sleeps otherwise (wakeup() ends a sleep early).
constexpr milliseconds kCancelPoll{10};
constexpr milliseconds kIdlePoll{1000};

// One call: its request, retry state and completion.
struct Call {
  HttpRequest request;
  bool idempotent = true;
  int attempt = 0;
  detail::Budget budget;
  detail::Clock::time_point due;
  bool in_flight = false;
  detail::Outcome last;  // the outcome to report if the deadline ends the call
  detail::Completion done;
};

std::exception_ptr cancelled(const char* why) {
  return std::make_exception_ptr(CancelledError(std::string("crypto-service: ") + why));
}

}  // namespace

namespace detail {

HttpResponse success(Outcome outcome) {
  if (outcome.response) {
    require_success(*outcome.response);
    return std::move(*outcome.response);
  }
  std::rethrow_exception(outcome.error);
}

}  // namespace detail

struct AsyncClient::Loop {
  Loop(detail::Settings settings_in, std::unique_ptr<AsyncTransport> transport_in)
      : settings(std::move(settings_in)), transport(std::move(transport_in)) {}

  detail::Settings settings;
  std::unique_ptr<AsyncTransport> transport;

  std::mutex mutex;  // guards stopping, next_id and queued
  bool stopping = false;
  std::uint64_t next_id = 1;
  std::vector<std::pair<std::uint64_t, Call>> queued;  // calls not yet adopted

  std::map<std::uint64_t, Call> calls;  // loop thread only
  std::thread thread;

  void enqueue(Call call) {
    {
      const std::lock_guard<std::mutex> lock(mutex);
      queued.emplace_back(next_id++, std::move(call));
    }
    transport->wakeup();
  }

  // Moves queued calls into `calls`; true when the loop must stop.
  bool adopt() {
    std::vector<std::pair<std::uint64_t, Call>> fresh;
    bool stop = false;
    {
      const std::lock_guard<std::mutex> lock(mutex);
      fresh.swap(queued);
      stop = stopping;
    }
    for (auto& [id, call] : fresh) {
      calls.emplace(id, std::move(call));
    }
    return stop;
  }

  void finish(std::uint64_t id, detail::Outcome outcome) {
    const auto it = calls.find(id);
    detail::Completion done = std::move(it->second.done);
    calls.erase(it);
    done(std::move(outcome));
  }

  void end_cancelled() {
    std::vector<std::uint64_t> ended;
    for (auto& [id, call] : calls) {
      if (call.request.cancel.cancelled()) {
        ended.push_back(id);
      }
    }
    for (const std::uint64_t id : ended) {
      abandon(id, cancelled("the call was cancelled"));
    }
  }

  void abandon(std::uint64_t id, std::exception_ptr error) {
    if (calls.at(id).in_flight) {
      transport->cancel(id);
    }
    finish(id, detail::Outcome{std::nullopt, std::move(error)});
  }

  void start_due(detail::Clock::time_point now) {
    std::vector<std::uint64_t> due;
    for (auto& [id, call] : calls) {
      if (!call.in_flight && call.due <= now) {
        due.push_back(id);
      }
    }
    for (const std::uint64_t id : due) {
      start(id, calls.at(id), now);
    }
  }

  void start(std::uint64_t id, Call& call, detail::Clock::time_point now) {
    const std::optional<milliseconds> timeout = call.budget.attempt_timeout(now);
    if (!timeout) {
      // A retry reports what its previous attempt got; a first attempt
      // that never started reports the deadline.
      finish(id, call.attempt > 0
                     ? std::move(call.last)
                     : detail::Outcome{std::nullopt,
                                       std::make_exception_ptr(detail::deadline_exceeded())});
      return;
    }
    call.request.timeout = *timeout;
    ++call.attempt;
    try {
      transport->start(id, call.request);
      call.in_flight = true;
    } catch (const TransportError&) {
      ended(TransferResult{id, std::nullopt, std::current_exception()});
    }
  }

  // The wait for the next delay, or nullopt when the result is final.
  std::optional<milliseconds> retry_delay(const Call& call, const TransferResult& result) const {
    const RetryOptions& retry = settings.options.retry;
    if (result.response) {
      return detail::delay_after_response(call.attempt, *result.response, retry, call.idempotent);
    }
    try {
      std::rethrow_exception(result.error);
    } catch (const CancelledError&) {
      return std::nullopt;
    } catch (...) {
      return detail::delay_after_error(call.attempt, retry, call.idempotent);
    }
  }

  void ended(TransferResult result) {
    const auto it = calls.find(result.id);
    // A transport reports nothing after cancel(); this guards a custom
    // one that does, whose call has already ended.
    if (it == calls.end()) {
      return;
    }
    Call& call = it->second;
    call.in_flight = false;
    const auto now = detail::Clock::now();
    const std::optional<milliseconds> delay = retry_delay(call, result);
    call.last = detail::Outcome{std::move(result.response), result.error};
    if (!delay || !call.budget.fits(now, *delay)) {
      finish(result.id, settle(std::move(call.last)));
      return;
    }
    call.due = now + *delay;
  }

  // A final response that is a redirect becomes an error: never followed.
  static detail::Outcome settle(detail::Outcome outcome) {
    try {
      if (outcome.response) {
        detail::refuse_redirect(*outcome.response);
      }
    } catch (const TransportError&) {
      return detail::Outcome{std::nullopt, std::current_exception()};
    }
    return outcome;
  }

  milliseconds wait_time(detail::Clock::time_point now) const {
    milliseconds wait = kIdlePoll;
    for (const auto& [id, call] : calls) {
      if (!call.in_flight) {
        wait = std::min(wait, std::chrono::duration_cast<milliseconds>(call.due - now));
      }
      if (call.request.cancel.cancellable()) {
        wait = std::min(wait, kCancelPoll);
      }
    }
    return std::max(wait, milliseconds(0));
  }

  void run() {
    while (!adopt()) {
      end_cancelled();
      start_due(detail::Clock::now());
      for (TransferResult& result : transport->poll(wait_time(detail::Clock::now()))) {
        ended(std::move(result));
      }
    }
    std::vector<std::uint64_t> left;
    left.reserve(calls.size());
    for (const auto& [id, call] : calls) {
      left.push_back(id);
    }
    for (const std::uint64_t id : left) {
      abandon(id, cancelled("the AsyncClient was destroyed"));
    }
  }
};

AsyncClient::AsyncClient(ClientOptions options)
    : AsyncClient(std::move(options), make_curl_multi_transport()) {}

AsyncClient::AsyncClient(ClientOptions options, std::unique_ptr<AsyncTransport> transport) {
  if (!transport) {
    throw std::invalid_argument("transport must not be null");
  }
  loop_ = std::make_unique<Loop>(detail::settle(std::move(options)), std::move(transport));
  loop_->thread = std::thread([loop = loop_.get()] { loop->run(); });
}

AsyncClient::~AsyncClient() {
  {
    const std::lock_guard<std::mutex> lock(loop_->mutex);
    loop_->stopping = true;
  }
  loop_->transport->wakeup();
  loop_->thread.join();
}

void AsyncClient::submit(const detail::Route& route, std::optional<std::string> body,
                         const std::vector<std::pair<std::string, std::string>>& extra,
                         const CallOptions& call, detail::Completion done) {
  const detail::Settings& settings = loop_->settings;
  Call queued{detail::build(settings, route, std::move(body), extra, call.cancel),
              detail::is_idempotent(route.method, route.path),
              0,
              detail::Budget(settings, detail::Clock::now()),
              detail::Clock::now(),
              false,
              {},
              std::move(done)};
  loop_->enqueue(std::move(queued));
}

std::future<RawResponse> AsyncClient::request(const RawRequest& request, const CallOptions& call) {
  auto promise = std::make_shared<std::promise<RawResponse>>();
  std::future<RawResponse> future = promise->get_future();
  const detail::Route route{request.method, request.path, false, false};
  submit(route, request.body, request.headers, call, [promise](detail::Outcome outcome) {
    if (!outcome.response) {
      promise->set_exception(outcome.error);
      return;
    }
    HttpResponse& response = *outcome.response;
    promise->set_value(
        RawResponse{response.status, std::move(response.body), std::move(response.headers)});
  });
  return future;
}

}  // namespace crypto_service
