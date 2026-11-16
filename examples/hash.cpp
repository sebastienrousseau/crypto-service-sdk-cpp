// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// SHA-256 and BLAKE3 digests of a text, computed by the server.

#include <exception>
#include <iostream>

#include "crypto_service/crypto_service.hpp"
#include "example_support.hpp"

int main() {
  try {
    crypto_service::Client client(example::options());
    for (const char* algorithm : {"sha256", "blake3"}) {
      const auto result = client.hash({algorithm, "abc"});
      std::cout << result.algorithm << ": " << crypto_service::to_hex(result.digest) << "\n";
    }
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << "\n";
    return 1;
  }
}
