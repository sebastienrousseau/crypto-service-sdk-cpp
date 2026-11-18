// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// Error handling: the server's RFC 9457 problem details (ApiError) for
// an unknown key and for a request that fails validation, and a
// TransportError for a server that is not there.

#include <chrono>
#include <exception>
#include <iostream>

#include "crypto_service/crypto_service.hpp"
#include "example_support.hpp"

int main() {
  try {
    crypto_service::Client client(example::options());
    try {
      (void)client.sign({"k_AAAAAAAAAAAAAAAAAAAAAA", "m"});
    } catch (const crypto_service::ApiError& error) {
      std::cout << "1. ApiError " << error.status() << " " << error.problem().type
                << " code=" << error.problem().code.value_or("-") << "\n";
    }
    try {
      (void)client.hash({"md5", "abc"});
    } catch (const crypto_service::ApiError& error) {
      for (const auto& field : error.problem().errors) {
        std::cout << "2. ApiError " << error.status() << " field " << field.field << ": "
                  << field.message << "\n";
      }
    }
    crypto_service::ClientOptions nowhere;
    nowhere.base_url = "http://127.0.0.1:9";
    nowhere.timeout = std::chrono::seconds(2);
    try {
      (void)crypto_service::Client(nowhere).health();
    } catch (const crypto_service::TransportError& error) {
      std::cout << "3. TransportError (timed out: " << std::boolalpha << error.timed_out() << ")\n";
    }
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << "\n";
    return 1;
  }
}
