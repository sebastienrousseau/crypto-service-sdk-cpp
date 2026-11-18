// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// Builds against the installed package and uses it without a server:
// the version, the encodings, option validation and both clients.

#include <iostream>
#include <stdexcept>

#include "crypto_service/crypto_service.hpp"

int main() {
  if (crypto_service::to_hex(crypto_service::to_bytes("ab")) != "6162") {
    return 1;
  }
  crypto_service::ClientOptions options;
  options.base_url = "http://127.0.0.1:9";
  const crypto_service::Client client(options);
  const crypto_service::AsyncClient async_client(options);
  options.base_url = "not a url";
  bool rejected = false;
  try {
    const crypto_service::Client invalid(options);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  if (!rejected) {
    return 1;
  }
  std::cout << "crypto-service-sdk-cpp " << crypto_service::kSdkVersion << " installed\n";
  return 0;
}
