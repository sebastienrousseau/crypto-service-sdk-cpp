// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// Shared by the examples: client options from the environment.
//   CRYPTO_SERVICE_URL      the server, e.g. http://127.0.0.1:3104
//   CRYPTO_SERVICE_API_KEY  the server's CRYPTO_API_KEY (synthetic in tests)

#ifndef CRYPTO_SERVICE_EXAMPLES_EXAMPLE_SUPPORT_HPP
#define CRYPTO_SERVICE_EXAMPLES_EXAMPLE_SUPPORT_HPP

#include <chrono>
#include <cstdlib>
#include <stdexcept>
#include <string>

#include "crypto_service/crypto_service.hpp"

namespace example {

inline std::string env(const char* name) {
  const char* value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    throw std::runtime_error(std::string("set ") + name);
  }
  return value;
}

/// Options for the server in the environment, with retries that absorb
/// the server's per-tenant quota (HTTP 429 with Retry-After).
inline crypto_service::ClientOptions options() {
  crypto_service::ClientOptions options;
  options.base_url = env("CRYPTO_SERVICE_URL");
  options.api_key = env("CRYPTO_SERVICE_API_KEY");
  options.retry.max_retries = 3;
  options.retry.max_delay = std::chrono::seconds(60);
  return options;
}

}  // namespace example

#endif  // CRYPTO_SERVICE_EXAMPLES_EXAMPLE_SUPPORT_HPP
