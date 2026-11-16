// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The HTTP seam. Client sends through a Transport (blocking, one request
// at a time); AsyncClient drives an AsyncTransport from its event-loop
// thread. The defaults are libcurl (an easy handle, a multi handle);
// tests and custom HTTP stacks substitute their own.
//
// Every libcurl transport refuses redirects, verifies TLS peers and host
// names (there is no option to turn that off), speaks HTTP and HTTPS
// only, and keeps connections alive for reuse.

#ifndef CRYPTO_SERVICE_TRANSPORT_HPP
#define CRYPTO_SERVICE_TRANSPORT_HPP

#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "crypto_service/options.hpp"

namespace crypto_service {

/// One HTTP exchange, as a client hands it to a transport.
struct HttpRequest {
  std::string method;                                        ///< `GET` or `POST`.
  std::string url;                                           ///< The absolute URL.
  std::vector<std::pair<std::string, std::string>> headers;  ///< Name and value, in order.
  std::optional<std::string> body;                           ///< The body, when any.
  std::chrono::milliseconds timeout{0};                      ///< This attempt's timeout.
  CancelToken cancel{};                                      ///< Abort when cancelled.
};

/// The status, raw body and headers of an HTTP response.
struct HttpResponse {
  long status = 0;   ///< The HTTP status code.
  std::string body;  ///< The raw body.
  /// Response headers in the order received.
  std::vector<std::pair<std::string, std::string>> headers{};

  /// The value of the first header named `name` (ASCII
  /// case-insensitive), or nullopt.
  [[nodiscard]] std::optional<std::string> header(std::string_view name) const;
};

/// Sends one request at a time, blocking.
class Transport {
 public:
  Transport() = default;
  Transport(const Transport&) = delete;
  Transport& operator=(const Transport&) = delete;
  Transport(Transport&&) = delete;
  Transport& operator=(Transport&&) = delete;
  virtual ~Transport() = default;

  /// Sends `request` and returns the response, whatever its status.
  /// Throws TransportError when no response arrives (with `timed_out`
  /// set on a timeout) and CancelledError when `request.cancel` fires.
  virtual HttpResponse send(const HttpRequest& request) = 0;
};

/// A Transport on one reusable libcurl easy handle, so consecutive
/// requests reuse the connection. Not thread-safe.
[[nodiscard]] std::unique_ptr<Transport> make_curl_transport();

/// How one asynchronous transfer ended: a response or an error.
struct TransferResult {
  std::uint64_t id = 0;                  ///< The id given to start().
  std::optional<HttpResponse> response;  ///< Set when a response arrived.
  std::exception_ptr error;              ///< Otherwise a TransportError.
};

/// Runs many transfers at once, driven by one event-loop thread. Every
/// member except wakeup() is called from that thread only.
class AsyncTransport {
 public:
  AsyncTransport() = default;
  AsyncTransport(const AsyncTransport&) = delete;
  AsyncTransport& operator=(const AsyncTransport&) = delete;
  AsyncTransport(AsyncTransport&&) = delete;
  AsyncTransport& operator=(AsyncTransport&&) = delete;
  virtual ~AsyncTransport() = default;

  /// Starts sending `request` (the transport keeps its own copy) under
  /// `id`, unique among the transfers in flight. Throws TransportError
  /// when the transfer cannot be started.
  virtual void start(std::uint64_t id, const HttpRequest& request) = 0;
  /// Abandons the transfer `id`; poll() reports nothing more for it.
  virtual void cancel(std::uint64_t id) = 0;
  /// Makes progress for up to `max_wait` (returning early on activity
  /// or wakeup()) and returns the transfers that ended.
  virtual std::vector<TransferResult> poll(std::chrono::milliseconds max_wait) = 0;
  /// Makes a poll() in progress, or the next one, return early. Safe
  /// from any thread.
  virtual void wakeup() = 0;
};

/// An AsyncTransport on one libcurl multi handle: HTTP/2 multiplexing
/// over TLS where the server offers it, and a shared connection cache.
[[nodiscard]] std::unique_ptr<AsyncTransport> make_curl_multi_transport();

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_TRANSPORT_HPP
