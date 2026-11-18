// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// The blocking client.
//
// Thread safety: a Client is thread-compatible, not thread-safe. It owns
// one Transport (by default one libcurl easy handle, whose connection is
// reused between calls), so use one Client per thread or guard a shared
// one with your own mutex. Distinct Client objects may be used
// concurrently. CancelSource::cancel() may be called from any thread.
// For concurrent calls from many threads, share one AsyncClient instead.

#ifndef CRYPTO_SERVICE_CLIENT_HPP
#define CRYPTO_SERVICE_CLIENT_HPP

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "crypto_service/detail/wire.hpp"
#include "crypto_service/operations.hpp"
#include "crypto_service/options.hpp"
#include "crypto_service/transport.hpp"

namespace crypto_service {

/// A request to any path, for routes without a typed method and for
/// sending deliberately malformed input.
struct RawRequest {
  std::string method = "GET";       ///< `GET` or `POST`.
  std::string path = "/";           ///< The path, from `/`, without a query string.
  std::optional<std::string> body;  ///< Sent as it is.
  /// Extra headers (e.g. a Content-Type for `body`; the default for a
  /// body is `application/json`). Credentials are set by the client.
  std::vector<std::pair<std::string, std::string>> headers;
};

/// The status, headers and body of a raw request's final response.
struct RawResponse {
  long status = 0;                                           ///< The HTTP status code.
  std::string body;                                          ///< The raw body.
  std::vector<std::pair<std::string, std::string>> headers;  ///< Response headers.

  /// The body parsed as JSON; null when the body is empty or not JSON.
  [[nodiscard]] nlohmann::json json() const;
};

namespace detail {
/// Ret<T> for the blocking client: the result itself.
template <typename T>
using Same = T;
}  // namespace detail

/// A blocking client for one crypto-server. Movable, not copyable.
class Client : public Operations<Client, detail::Same> {
 public:
  /// Uses libcurl. Throws std::invalid_argument when an option is
  /// outside its documented range (see ClientOptions).
  explicit Client(ClientOptions options);
  /// Uses `transport` (tests, custom HTTP stacks).
  Client(ClientOptions options, std::unique_ptr<Transport> transport);

  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;
  /// Takes over the other client's transport and connection.
  Client(Client&&) noexcept;
  /// Takes over the other client's transport and connection.
  Client& operator=(Client&&) noexcept;
  ~Client();

  /// Sends `request` with the client's credentials, retries and
  /// deadline, and returns the final response whatever its status.
  /// Throws TransportError when no response arrives.
  [[nodiscard]] RawResponse request(const RawRequest& request, const CallOptions& call = {});

 private:
  friend class Operations<Client, detail::Same>;

  template <typename Result>
  Result dispatch(const detail::Route& route, std::optional<std::string> body,
                  const CallOptions& call) {
    HttpResponse response = execute(route, std::move(body), {}, call);
    detail::require_success(response);
    return detail::decode<Result>(response, route.wrapped);
  }

  HttpResponse execute(const detail::Route& route, std::optional<std::string> body,
                       const std::vector<std::pair<std::string, std::string>>& extra,
                       const CallOptions& call);

  struct State;
  std::unique_ptr<State> state_;
};

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_CLIENT_HPP
