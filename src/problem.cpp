// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// The error types, and the RFC 9457 problem of a non-2xx response: the
// server's problem body when it is one, else an `about:blank` problem
// for the status (an HTML page from a proxy, an empty body).

#include "problem.hpp"

#include <array>
#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "crypto_service/client.hpp"
#include "crypto_service/errors.hpp"
#include "crypto_service/transport.hpp"

namespace crypto_service {
namespace {

using nlohmann::json;

// The problem type as it goes into what(): control characters (CR, LF
// and NUL included) become '?', so a hostile server or proxy cannot
// split a log line or cut the message short.
std::string printable(std::string text) {
  for (char& c : text) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte < 0x20U || byte == 0x7FU) {
      c = '?';
    }
  }
  return text;
}

bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

// Reason phrases for the statuses an API client meets; others get a
// generic title.
std::string reason_phrase(long status) {
  static constexpr std::array<std::pair<long, std::string_view>, 13> kPhrases{{
      {400, "Bad Request"},
      {401, "Unauthorized"},
      {403, "Forbidden"},
      {404, "Not Found"},
      {405, "Method Not Allowed"},
      {413, "Payload Too Large"},
      {415, "Unsupported Media Type"},
      {429, "Too Many Requests"},
      {500, "Internal Server Error"},
      {501, "Not Implemented"},
      {502, "Bad Gateway"},
      {503, "Service Unavailable"},
      {504, "Gateway Timeout"},
  }};
  for (const auto& [code, phrase] : kPhrases) {
    if (code == status) {
      return std::string(phrase);
    }
  }
  return "HTTP error";
}

std::string string_member(const json& body, const char* name, std::string fallback) {
  const auto found = body.find(name);
  return found != body.end() && found->is_string() ? found->get<std::string>()
                                                   : std::move(fallback);
}

std::optional<std::string> optional_member(const json& body, const char* name) {
  const auto found = body.find(name);
  if (found == body.end() || !found->is_string()) {
    return std::nullopt;
  }
  return found->get<std::string>();
}

// The `errors` member's entries that have a string field and message.
std::vector<FieldError> field_errors(const json& body) {
  std::vector<FieldError> out;
  const auto found = body.find("errors");
  if (found == body.end() || !found->is_array()) {
    return out;
  }
  for (const json& entry : *found) {
    if (entry.is_object() && entry.value("field", json()).is_string() &&
        entry.value("message", json()).is_string()) {
      out.push_back(
          FieldError{entry.at("field").get<std::string>(), entry.at("message").get<std::string>()});
    }
  }
  return out;
}

Problem from_body(json body, long status) {
  Problem problem;
  problem.type = string_member(body, "type", "about:blank");
  problem.title = string_member(body, "title", reason_phrase(status));
  problem.status = status;
  problem.detail = body.at("detail").get<std::string>();
  problem.instance = optional_member(body, "instance");
  problem.code = optional_member(body, "code");
  problem.errors = field_errors(body);
  for (const char* known : {"type", "title", "status", "detail", "instance", "code", "errors"}) {
    body.erase(known);
  }
  problem.extensions = std::move(body);
  return problem;
}

}  // namespace

std::optional<std::string> HttpResponse::header(std::string_view name) const {
  for (const auto& [key, value] : headers) {
    if (iequals(key, name)) {
      return value;
    }
  }
  return std::nullopt;
}

nlohmann::json RawResponse::json() const {
  nlohmann::json parsed = nlohmann::json::parse(body, nullptr, false);
  return parsed.is_discarded() ? nlohmann::json() : parsed;
}

ApiError::ApiError(Problem problem)
    : Error("crypto-service: HTTP " + std::to_string(problem.status) + " (" +
            printable(problem.type) + ")"),
      problem_(std::move(problem)) {}

TransportError::TransportError(const std::string& message, bool timed_out)
    : Error(message), timed_out_(timed_out) {}

namespace detail {

Problem problem_of(const HttpResponse& response) {
  json body = json::parse(response.body, nullptr, false);
  if (body.is_object() && body.value("detail", json()).is_string()) {
    return from_body(std::move(body), response.status);
  }
  Problem problem;
  problem.title = reason_phrase(response.status);
  problem.status = response.status;
  problem.detail =
      "The server answered " + std::to_string(response.status) + " without a problem body";
  return problem;
}

void require_success(const HttpResponse& response) {
  if (response.status < 200 || response.status >= 300) {
    throw ApiError(problem_of(response));
  }
}

}  // namespace detail
}  // namespace crypto_service
