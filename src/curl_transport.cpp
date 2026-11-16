// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The libcurl transports. CurlTransport keeps one easy handle, reset
// between requests so its connection is reused. CurlMultiTransport keeps
// one multi handle (shared connection cache, HTTP/2 multiplexing) and a
// pool of idle easy handles; it is driven by AsyncClient's loop thread.

#include <curl/curl.h>

#include <chrono>
#include <cstdint>
#include <exception>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "crypto_service/transport.hpp"
#include "curl_common.hpp"

namespace crypto_service {
namespace {

using detail::EasyHandle;
using detail::Exchange;

class CurlTransport final : public Transport {
 public:
  CurlTransport() : handle_(detail::new_easy_handle()) {}

  HttpResponse send(const HttpRequest& request) override {
    Exchange exchange;
    detail::prepare(handle_.get(), request, exchange);
    const CURLcode code = curl_easy_perform(handle_.get());
    if (code != CURLE_OK) {
      std::rethrow_exception(detail::failure(code, exchange));
    }
    return detail::response_of(handle_.get(), exchange);
  }

 private:
  EasyHandle handle_;
};

struct MultiDeleter {
  void operator()(CURLM* multi) const noexcept { curl_multi_cleanup(multi); }
};

// One transfer in flight: its own copy of the request (libcurl points
// into it) and its buffers, at a fixed address.
struct Transfer {
  std::uint64_t id = 0;
  HttpRequest request;
  EasyHandle handle;
  Exchange exchange;
};

class CurlMultiTransport final : public AsyncTransport {
 public:
  CurlMultiTransport() {
    detail::ensure_curl_global();
    multi_.reset(detail::curl_calls().multi_init());
    // curl_multi_init fails only when memory is exhausted.
    detail::require_curl(multi_ != nullptr, "libcurl could not create a multi handle");
    curl_multi_setopt(multi_.get(), CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  }

  CurlMultiTransport(const CurlMultiTransport&) = delete;
  CurlMultiTransport& operator=(const CurlMultiTransport&) = delete;
  CurlMultiTransport(CurlMultiTransport&&) = delete;
  CurlMultiTransport& operator=(CurlMultiTransport&&) = delete;

  ~CurlMultiTransport() override {
    for (auto& [handle, transfer] : active_) {
      curl_multi_remove_handle(multi_.get(), handle);
    }
  }

  void start(std::uint64_t id, const HttpRequest& request) override {
    auto transfer = std::make_unique<Transfer>();
    transfer->id = id;
    transfer->request = request;
    transfer->handle = idle_handle();
    detail::prepare(transfer->handle.get(), transfer->request, transfer->exchange);
    CURL* handle = transfer->handle.get();
    detail::require_curl(curl_multi_add_handle(multi_.get(), handle) == CURLM_OK,
                         "libcurl could not start a transfer");
    active_.emplace(handle, std::move(transfer));
  }

  void cancel(std::uint64_t id) override {
    for (auto it = active_.begin(); it != active_.end(); ++it) {
      if (it->second->id == id) {
        retire(it);
        return;
      }
    }
  }

  std::vector<TransferResult> poll(std::chrono::milliseconds max_wait) override {
    int running = 0;
    curl_multi_perform(multi_.get(), &running);
    std::vector<TransferResult> done = collect();
    if (done.empty()) {
      curl_multi_poll(multi_.get(), nullptr, 0, static_cast<int>(max_wait.count()), nullptr);
      curl_multi_perform(multi_.get(), &running);
      done = collect();
    }
    return done;
  }

  void wakeup() override { curl_multi_wakeup(multi_.get()); }

 private:
  using Active = std::map<CURL*, std::unique_ptr<Transfer>>;

  EasyHandle idle_handle() {
    if (idle_.empty()) {
      return detail::new_easy_handle();
    }
    EasyHandle handle = std::move(idle_.back());
    idle_.pop_back();
    return handle;
  }

  // Removes a transfer from the multi handle and keeps its easy handle
  // for the next one.
  void retire(Active::iterator it) {
    curl_multi_remove_handle(multi_.get(), it->first);
    idle_.push_back(std::move(it->second->handle));
    active_.erase(it);
  }

  std::vector<TransferResult> collect() {
    std::vector<TransferResult> done;
    int queued = 0;
    while (CURLMsg* message = detail::curl_calls().multi_info_read(multi_.get(), &queued)) {
      const auto it = active_.find(message->easy_handle);
      // Every handle on the multi handle is in active_, and libcurl
      // queues CURLMSG_DONE only; anything else is skipped, not trusted.
      if (message->msg != CURLMSG_DONE || it == active_.end()) {
        continue;
      }
      done.push_back(outcome(*it->second, message->data.result));
      retire(it);
    }
    return done;
  }

  static TransferResult outcome(Transfer& transfer, CURLcode code) {
    TransferResult result;
    result.id = transfer.id;
    if (code == CURLE_OK) {
      result.response = detail::response_of(transfer.handle.get(), transfer.exchange);
    } else {
      result.error = detail::failure(code, transfer.exchange);
    }
    return result;
  }

  std::unique_ptr<CURLM, MultiDeleter> multi_;
  Active active_;
  std::vector<EasyHandle> idle_;
};

}  // namespace

std::unique_ptr<Transport> make_curl_transport() { return std::make_unique<CurlTransport>(); }

std::unique_ptr<AsyncTransport> make_curl_multi_transport() {
  return std::make_unique<CurlMultiTransport>();
}

}  // namespace crypto_service
