// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// Typed round trips against a live crypto-server that the kit does not
// cover: binary HPKE and KMS plaintexts, the async client under
// concurrency, and the problem of an unknown key. Skips without
// CRYPTO_SERVICE_URL and CRYPTO_SERVICE_API_KEY.

#include <gtest/gtest.h>

#include <cstdlib>
#include <future>
#include <string>
#include <vector>

#include "crypto_service/crypto_service.hpp"

namespace crypto_service {
namespace {

std::optional<ClientOptions> live_options() {
  const char* url = std::getenv("CRYPTO_SERVICE_URL");
  const char* key = std::getenv("CRYPTO_SERVICE_API_KEY");
  if (url == nullptr || key == nullptr || *url == '\0' || *key == '\0') {
    return std::nullopt;
  }
  ClientOptions options;
  options.base_url = url;
  options.api_key = key;
  options.retry.max_retries = 3;
  return options;
}

#define LIVE_OPTIONS(name)                                               \
  const auto name = live_options();                                      \
  if (!(name)) {                                                         \
    GTEST_SKIP() << "set CRYPTO_SERVICE_URL and CRYPTO_SERVICE_API_KEY"; \
  }

TEST(Live, AsyncClientRunsConcurrentCalls) {
  LIVE_OPTIONS(options)
  AsyncClient client(*options);
  std::vector<std::future<HashResult>> futures;
  futures.reserve(16);
  for (int i = 0; i < 16; ++i) {
    futures.push_back(client.hash({"sha256", "abc"}));
  }
  for (auto& future : futures) {
    EXPECT_EQ(to_hex(future.get().digest),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  }
}

TEST(Live, HpkeCarriesBinaryPlaintext) {
  LIVE_OPTIONS(options)
  Client client(*options);
  const ServerKeyPair key = client.hpke_generate_key_pair({std::string("x25519")});
  HpkeSealRequest seal;
  seal.recipient_public_key = key.public_key;
  seal.kem = "x25519";
  seal.plaintext = Bytes{0x00, 0xff, 0x41};
  seal.info = to_bytes("app");
  const HpkeSealResult sealed = client.hpke_seal(seal);
  HpkeOpenRequest open;
  open.key_id = key.key_id;
  open.ciphertext = sealed.ciphertext;
  open.encapsulated_key = sealed.encapsulated_key;
  open.info = to_bytes("app");
  EXPECT_EQ(client.hpke_open(open).hex, (Bytes{0x00, 0xff, 0x41}));
  (void)client.keys_delete({key.key_id});
}

TEST(Live, KmsCarriesBinaryPlaintext) {
  LIVE_OPTIONS(options)
  Client client(*options);
  const KmsKey key = client.kms_create_key();
  KmsEncryptRequest encrypt;
  encrypt.key_id = key.key_id;
  encrypt.plaintext = Bytes{0x00, 0xff};
  const KmsEncryptResult sealed = client.kms_encrypt(encrypt);
  KmsDecryptRequest decrypt;
  decrypt.ciphertext = sealed.ciphertext;
  decrypt.key_id = key.key_id;
  const KmsDecryptResult opened = client.kms_decrypt(decrypt);
  EXPECT_EQ(opened.hex, (Bytes{0x00, 0xff}));
}

TEST(Live, UnknownKeyIsAProblem) {
  LIVE_OPTIONS(options)
  Client client(*options);
  try {
    (void)client.sign({"k_AAAAAAAAAAAAAAAAAAAAAA", "m"});
    FAIL() << "no error";
  } catch (const ApiError& e) {
    EXPECT_EQ(e.status(), 404);
    EXPECT_EQ(e.problem().type, "urn:crypto-service:problem:key-not-found");
    EXPECT_EQ(e.problem().code, "KEY_NOT_FOUND");
  }
}

}  // namespace
}  // namespace crypto_service
