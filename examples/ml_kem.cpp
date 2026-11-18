// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// ML-KEM-768 with a server-held key: generate it, encapsulate a shared
// secret to its public key, decapsulate by key id, compare.

#include <exception>
#include <iostream>

#include "crypto_service/crypto_service.hpp"
#include "example_support.hpp"

int main() {
  try {
    crypto_service::Client client(example::options());
    const auto key = client.ml_kem_generate_key_pair();
    const auto sent = client.ml_kem_encapsulate({key.public_key});
    const auto received = client.ml_kem_decapsulate({sent.ciphertext, key.key_id});
    const bool same = sent.shared_secret == received.shared_secret;
    std::cout << key.algorithm << ": " << sent.ciphertext.size() << "-byte ciphertext, "
              << "shared secrets " << (same ? "match" : "differ") << "\n";
    (void)client.keys_delete({key.key_id});
    return same ? 0 : 1;
  } catch (const std::exception& error) {
    std::cerr << error.what() << "\n";
    return 1;
  }
}
