// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// XChaCha20-Poly1305 round trip: encrypt a text under a 256-bit key,
// then decrypt the ciphertext. The key here is a synthetic test value;
// a real key comes from your key management, never from source code.

#include <exception>
#include <iostream>

#include "crypto_service/crypto_service.hpp"
#include "example_support.hpp"

int main() {
  try {
    crypto_service::Client client(example::options());
    const crypto_service::Bytes key(32, 0x42);  // synthetic
    const auto sealed = client.encrypt({key, "attack at dawn"});
    std::cout << sealed.algorithm << " ciphertext: " << sealed.ciphertext.size() << " bytes\n";
    const auto opened = client.decrypt({key, sealed.ciphertext});
    std::cout << "decrypted: " << opened.plaintext << "\n";
    return opened.plaintext == "attack at dawn" ? 0 : 1;
  } catch (const std::exception& error) {
    std::cerr << error.what() << "\n";
    return 1;
  }
}
