// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Transport doubles: they record every request and answer from a
// script, so client behaviour is tested without a server. FakeAsync is
// thread-safe where AsyncTransport requires it (wakeup) and lets a test
// hold a transfer open until it is cancelled.

#ifndef CRYPTO_SERVICE_TESTS_SUPPORT_FAKE_TRANSPORT_HPP
#define CRYPTO_SERVICE_TESTS_SUPPORT_FAKE_TRANSPORT_HPP

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "crypto_service/crypto_service.hpp"

namespace crypto_service::kit {

/// One scripted answer.
struct Reply {
  std::optional<HttpResponse> response;  ///< Answer with this...
  std::exception_ptr error;              ///< ...or fail with this...
  bool hang = false;                     ///< ...or never answer (until cancelled).
  bool refuse_start = false;             ///< AsyncTransport::start throws.
  std::chrono::milliseconds delay{0};    ///< Wait before answering (or starting).
};

/// A 2xx/4xx/5xx reply with `body` and optional headers.
inline Reply reply(long status, std::string body,
                   std::vector<std::pair<std::string, std::string>> headers = {}) {
  return Reply{
      HttpResponse{status, std::move(body), std::move(headers)}, nullptr, false, false, {}};
}

/// A reply that fails with `error`.
template <typename E>
Reply failing(E error) {
  return Reply{std::nullopt, std::make_exception_ptr(std::move(error)), false, false, {}};
}

/// `answer`, delivered after `delay`; FakeAsyncTransport blocks its
/// caller (the loop thread) in start() for that long.
inline Reply slow(Reply answer, std::chrono::milliseconds delay) {
  answer.delay = delay;
  return answer;
}

/// What a fake saw and what it will answer; shared with the test.
struct FakeState {
  std::mutex mutex;
  std::vector<HttpRequest> requests;
  std::deque<Reply> script;
  std::vector<std::uint64_t> cancelled;
  int wakeups = 0;

  void push(Reply next) {
    const std::lock_guard<std::mutex> lock(mutex);
    script.push_back(std::move(next));
  }
  Reply next(const HttpRequest& request) {
    const std::lock_guard<std::mutex> lock(mutex);
    requests.push_back(request);
    if (script.empty()) {
      return failing(TransportError("fake transport: nothing scripted"));
    }
    Reply out = std::move(script.front());
    script.pop_front();
    return out;
  }
  std::vector<HttpRequest> seen() {
    const std::lock_guard<std::mutex> lock(mutex);
    return requests;
  }
};

/// A blocking Transport double.
class FakeTransport final : public Transport {
 public:
  explicit FakeTransport(std::shared_ptr<FakeState> state) : state_(std::move(state)) {}

  HttpResponse send(const HttpRequest& request) override {
    Reply answer = state_->next(request);
    std::this_thread::sleep_for(answer.delay);
    if (answer.response) {
      return *answer.response;
    }
    std::rethrow_exception(answer.error);
  }

 private:
  std::shared_ptr<FakeState> state_;
};

/// An AsyncTransport double: answers in the next poll(), or holds a
/// `hang` transfer until cancel(). With `late`, it breaks the contract
/// on purpose: a cancelled transfer is still reported, as a
/// TransportError, by the next poll().
class FakeAsyncTransport final : public AsyncTransport {
 public:
  explicit FakeAsyncTransport(std::shared_ptr<FakeState> state, bool late = false)
      : state_(std::move(state)), late_(late) {}

  void start(std::uint64_t id, const HttpRequest& request) override {
    Reply answer = state_->next(request);
    std::this_thread::sleep_for(answer.delay);  // holds the loop thread
    if (answer.refuse_start) {
      throw TransportError("fake transport: refused to start");
    }
    if (!answer.hang) {
      ready_.push_back(TransferResult{id, std::move(answer.response), answer.error});
    }
  }

  void cancel(std::uint64_t id) override {
    if (late_) {
      ready_.push_back(TransferResult{
          id, std::nullopt, std::make_exception_ptr(TransportError("fake transport: late"))});
    }
    const std::lock_guard<std::mutex> lock(state_->mutex);
    state_->cancelled.push_back(id);
  }

  std::vector<TransferResult> poll(std::chrono::milliseconds max_wait) override {
    if (ready_.empty()) {
      std::unique_lock<std::mutex> lock(mutex_);
      woken_.wait_for(lock, max_wait, [this] { return awake_; });
      awake_ = false;
    }
    std::vector<TransferResult> out;
    out.swap(ready_);
    return out;
  }

  void wakeup() override {
    {
      const std::lock_guard<std::mutex> lock(mutex_);
      awake_ = true;
    }
    {
      const std::lock_guard<std::mutex> lock(state_->mutex);
      ++state_->wakeups;
    }
    woken_.notify_all();
  }

 private:
  std::shared_ptr<FakeState> state_;
  bool late_ = false;
  std::vector<TransferResult> ready_;  // loop thread only
  std::mutex mutex_;
  std::condition_variable woken_;
  bool awake_ = false;
};

/// Options for a client of `http://crypto.test/` with an API key.
inline ClientOptions fake_options() {
  ClientOptions options;
  options.base_url = "http://crypto.test/";
  options.api_key = "synthetic-test-key";
  return options;
}

}  // namespace crypto_service::kit

#endif  // CRYPTO_SERVICE_TESTS_SUPPORT_FAKE_TRANSPORT_HPP
