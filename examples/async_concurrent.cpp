// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Concurrent calls with the AsyncClient: queue several requests at
// once, then wait for the futures. One event-loop thread and one
// connection pool serve them all.

#include <exception>
#include <future>
#include <iostream>
#include <string>
#include <vector>

#include "crypto_service/crypto_service.hpp"
#include "example_support.hpp"

int main() {
  try {
    crypto_service::AsyncClient client(example::options());
    std::vector<std::future<crypto_service::HashResult>> digests;
    digests.reserve(8);
    for (int i = 0; i < 8; ++i) {
      digests.push_back(client.hash({"sha256", "message " + std::to_string(i)}));
    }
    auto algorithms = client.algorithms();
    for (auto& digest : digests) {
      std::cout << crypto_service::to_hex(digest.get().digest).substr(0, 16) << "...\n";
    }
    std::cout << algorithms.get().post_quantum.size() << " post-quantum algorithms\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << "\n";
    return 1;
  }
}
