// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Internal to the SDK, public only because the client templates use it:
// a route's method, path and shape, and the JSON encoders and decoders
// of the request and result structs (defined and explicitly
// instantiated in src/wire.cpp). Not part of the supported API.

#ifndef CRYPTO_SERVICE_DETAIL_WIRE_HPP
#define CRYPTO_SERVICE_DETAIL_WIRE_HPP

#include <string>
#include <string_view>

#include "crypto_service/transport.hpp"

namespace crypto_service::detail {

/// One operation of the API.
struct Route {
  std::string_view method;  ///< `GET` or `POST`.
  std::string_view path;    ///< The path, from `/`.
  bool wrapped = true;      ///< The result is the response's `data` member.
  bool anonymous = false;   ///< A probe: no credentials are sent.
};

/// The JSON body for `request`.
template <typename Request>
std::string encode(const Request& request);

/// The result in a 2xx `response`; TransportError when the body does
/// not have the documented shape.
template <typename Result>
Result decode(const HttpResponse& response, bool wrapped);

/// Throws ApiError unless `response` has a 2xx status.
void require_success(const HttpResponse& response);

}  // namespace crypto_service::detail

#endif  // CRYPTO_SERVICE_DETAIL_WIRE_HPP
