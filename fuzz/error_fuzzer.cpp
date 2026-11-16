// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// libFuzzer target: any status and body, so mostly error replies. The
// first three bytes are the status as decimal digits (each byte taken
// modulo 10 after subtracting '0', so "404" reads as 404 and any byte
// still gives a digit); the rest is the body. Covers the RFC 9457
// problem parsing, the about:blank fallback, ApiError, and the promise
// that ApiError::what() names only the status and problem type.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "crypto_service/crypto_service.hpp"
#include "problem.hpp"

namespace {

constexpr std::size_t kStatusDigits = 3;

long status_from(const std::uint8_t* digits) {
  long status = 0;
  for (std::size_t i = 0; i < kStatusDigits; ++i) {
    status = status * 10 + static_cast<unsigned char>(digits[i] - '0') % 10;
  }
  return status;
}

void check_message(const crypto_service::ApiError& error) {
  std::string type = error.problem().type;
  for (char& c : type) {
    const auto byte = static_cast<unsigned char>(c);
    c = byte < 0x20U || byte == 0x7FU ? '?' : c;  // control characters are replaced
  }
  const std::string expected =
      "crypto-service: HTTP " + std::to_string(error.status()) + " (" + type + ")";
  if (expected != error.what()) {
    std::abort();
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < kStatusDigits) {
    return 0;
  }
  const crypto_service::HttpResponse response{
      status_from(data),
      std::string(reinterpret_cast<const char*>(data) + kStatusDigits, size - kStatusDigits),
      {}};
  const crypto_service::Problem problem = crypto_service::detail::problem_of(response);
  if (problem.status != response.status) {
    std::abort();
  }
  try {
    crypto_service::detail::require_success(response);
  } catch (const crypto_service::ApiError& error) {
    check_message(error);
  }
  (void)crypto_service::RawResponse{response.status, response.body, {}}.json();
  return 0;
}
