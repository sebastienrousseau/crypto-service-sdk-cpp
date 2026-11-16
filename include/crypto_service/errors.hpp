// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The error model: every exception the SDK throws derives from Error.
// ApiError carries the server's RFC 9457 problem; TransportError means
// no usable HTTP response arrived. Messages name the HTTP status, the
// problem type or the transport failure only: never credentials, keys,
// plaintexts or bodies (docs/adr/0003-error-model.md).

#ifndef CRYPTO_SERVICE_ERRORS_HPP
#define CRYPTO_SERVICE_ERRORS_HPP

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace crypto_service {

/// One field that failed request validation (`validation-failed`).
struct FieldError {
  std::string field;    ///< The field, as a JSON pointer or a body member name.
  std::string message;  ///< What is wrong with it.
};

/// An RFC 9457 problem details object, as the server sends it with
/// `application/problem+json`. A non-2xx body that is not a problem
/// (an HTML page from a proxy, an empty body) becomes an `about:blank`
/// problem for the status code.
struct Problem {
  std::string type = "about:blank";     ///< `urn:crypto-service:problem:<slug>`.
  std::string title;                    ///< Summary of the problem type.
  long status = 0;                      ///< The HTTP status code.
  std::string detail;                   ///< Explanation of this occurrence.
  std::optional<std::string> instance;  ///< The request path, when sent.
  std::optional<std::string> code;      ///< crypto-lib or key-store code, e.g. `KEY_NOT_FOUND`.
  std::vector<FieldError> errors;       ///< Validation errors (`validation-failed`).
  /// Every other member of the problem object (quota fields such as
  /// `limit` and `resetSeconds`), unchanged.
  nlohmann::json extensions = nlohmann::json::object();
};

/// Base class of every error this SDK throws.
class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

/// The server answered with a non-2xx status. `what()` names the status
/// and the problem type; the problem itself is in `problem()`.
class ApiError : public Error {
 public:
  /// An error for `problem`, whose `status` is the HTTP status.
  explicit ApiError(Problem problem);

  /// The HTTP status code.
  [[nodiscard]] long status() const noexcept { return problem_.status; }
  /// The RFC 9457 problem the server sent (or the `about:blank` one).
  [[nodiscard]] const Problem& problem() const noexcept { return problem_; }

 private:
  Problem problem_;
};

/// No usable HTTP response: the connection failed, the attempt or the
/// overall deadline timed out, TLS failed, a redirect was refused, or a
/// 2xx body did not have the documented shape.
class TransportError : public Error {
 public:
  /// An error with `message`; `timed_out` is true when a timeout or the
  /// deadline ended the request.
  explicit TransportError(const std::string& message, bool timed_out = false);

  /// Whether the per-attempt timeout or the overall deadline ended the
  /// request.
  [[nodiscard]] bool timed_out() const noexcept { return timed_out_; }

 private:
  bool timed_out_;
};

/// The request was cancelled through its CancelToken, or its AsyncClient
/// was destroyed while it was in flight.
class CancelledError : public TransportError {
 public:
  using TransportError::TransportError;
};

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_ERRORS_HPP
