// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Runs one conformance vector through the SDK: the typed method for its
// route when the vector's body is one the typed request can express
// exactly, a raw request otherwise (malformed input, deprecated v1
// routes, /metrics, unknown routes).

#ifndef CRYPTO_SERVICE_TESTS_SUPPORT_DISPATCH_HPP
#define CRYPTO_SERVICE_TESTS_SUPPORT_DISPATCH_HPP

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "crypto_service/crypto_service.hpp"

namespace crypto_service::kit {

using nlohmann::json;

/// A Transport that remembers the last response, so a typed call's
/// status, media type and raw body can be checked too.
class RecordingTransport final : public Transport {
 public:
  explicit RecordingTransport(std::shared_ptr<std::optional<HttpResponse>> last);
  HttpResponse send(const HttpRequest& request) override;

 private:
  std::unique_ptr<Transport> inner_;
  std::shared_ptr<std::optional<HttpResponse>> last_;
};

/// What a vector got back.
struct VectorOutcome {
  long status = 0;         ///< The HTTP status.
  json body;               ///< As the SDK decoded it (typed) or parsed (raw).
  json raw_body;           ///< The response body as the server sent it.
  std::string media_type;  ///< Content-Type without parameters.
  std::vector<std::pair<std::string, std::string>> headers;  ///< Response headers.
  bool typed = false;                                        ///< Whether a typed method ran.
  std::string route;  ///< Why the raw path was taken, when it was.
};

/// Sends the vector's `request` (already substituted) with `options`.
VectorOutcome run_vector(const ClientOptions& options, const json& request);

/// A problem as JSON, the way the server sent it.
json problem_json(const Problem& problem);

}  // namespace crypto_service::kit

#endif  // CRYPTO_SERVICE_TESTS_SUPPORT_DISPATCH_HPP
