// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// Ed25519 with a server-held key: generate it (the private key stays on
// the server), sign by key id, verify with the public key, then delete
// the key.

#include <exception>
#include <iostream>

#include "crypto_service/crypto_service.hpp"
#include "example_support.hpp"

int main() {
  try {
    crypto_service::Client client(example::options());
    crypto_service::GenerateKeyPairRequest request;
    request.algorithm = "ed25519";
    const auto key = client.generate_key_pair(request);
    std::cout << "key " << key.key_id << " (" << key.algorithm << ")\n";
    const auto signed_message = client.sign({key.key_id, "pay 100 EUR"});
    const auto check = client.verify({key.public_key, "pay 100 EUR", signed_message.signature});
    const auto tampered = client.verify({key.public_key, "pay 900 EUR", signed_message.signature});
    std::cout << "valid: " << std::boolalpha << check.valid
              << ", tampered valid: " << tampered.valid << "\n";
    (void)client.keys_delete({key.key_id});
    return check.valid && !tampered.valid ? 0 : 1;
  } catch (const std::exception& error) {
    std::cerr << error.what() << "\n";
    return 1;
  }
}
