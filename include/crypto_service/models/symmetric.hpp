// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Requests and results of the symmetric routes: AEAD, secretbox,
// password encryption and AES key wrap. Binary fields are Bytes; the
// client sends keys as hex and ciphertexts as base64, as the API expects.

#ifndef CRYPTO_SERVICE_MODELS_SYMMETRIC_HPP
#define CRYPTO_SERVICE_MODELS_SYMMETRIC_HPP

#include <optional>
#include <string>

#include "crypto_service/encoding.hpp"

namespace crypto_service {

/// `POST /v2/encrypt`: XChaCha20-Poly1305 under a 256-bit key.
struct EncryptRequest {
  Bytes key;              ///< The 32-byte key (sent as hex).
  std::string plaintext;  ///< UTF-8 text to encrypt.
};

/// What `POST /v2/encrypt` returns.
struct EncryptResult {
  std::string algorithm;  ///< `xchacha20-poly1305`.
  Bytes ciphertext;       ///< nonce || ciphertext || tag (base64 on the wire).
};

/// `POST /v2/decrypt`.
struct DecryptRequest {
  Bytes key;         ///< The 32-byte key (sent as hex).
  Bytes ciphertext;  ///< What encrypt returned (sent as base64).
};

/// What `POST /v2/decrypt` returns.
struct DecryptResult {
  std::string plaintext;  ///< The recovered text (invalid UTF-8 becomes U+FFFD).
};

/// `POST /v2/secretbox/seal`.
struct SecretboxSealRequest {
  Bytes key;                       ///< The 32-byte key (sent as hex).
  std::string plaintext;           ///< UTF-8 text to seal.
  std::optional<std::string> aad;  ///< Associated data, UTF-8 text.
};

/// The result of every sealing route: secretbox, sealed box, hybrid
/// sealed box.
struct SealResult {
  std::string algorithm;  ///< The construction, e.g. `xchacha20-poly1305`.
  Bytes sealed;           ///< The sealed box (base64 on the wire).
};

/// `POST /v2/secretbox/open`.
struct SecretboxOpenRequest {
  Bytes key;                       ///< The 32-byte key (sent as hex).
  Bytes ciphertext;                ///< What secretbox_seal returned in `sealed`.
  std::optional<std::string> aad;  ///< The associated data used to seal.
};

/// The result of the opening routes whose `data` is a bare string:
/// secretbox, sealed box, hybrid sealed box and password decryption.
struct OpenedText {
  std::string plaintext;  ///< The recovered text (invalid UTF-8 becomes U+FFFD).
};

/// `POST /v2/password/encrypt`: Argon2id plus XChaCha20-Poly1305.
struct PasswordEncryptRequest {
  std::string password;   ///< The password.
  std::string plaintext;  ///< UTF-8 text to encrypt.
};

/// What `POST /v2/password/encrypt` returns.
struct PasswordEncryptResult {
  std::string algorithm;  ///< `argon2id-xchacha20-poly1305`.
  Bytes encrypted;        ///< The envelope (base64 on the wire).
};

/// `POST /v2/password/decrypt`.
struct PasswordDecryptRequest {
  std::string password;  ///< The password.
  Bytes ciphertext;      ///< What password_encrypt returned in `encrypted`.
};

/// `POST /v2/keys/wrap`: AES key wrap (RFC 3394) or with padding (RFC 5649).
struct KeyWrapRequest {
  Bytes kek;                             ///< The key-encryption key (sent as hex).
  Bytes key_to_wrap;                     ///< The key to wrap (sent as hex).
  std::optional<std::string> algorithm;  ///< `aes-kw` (default) or `aes-kwp`.
};

/// What `POST /v2/keys/wrap` returns.
struct KeyWrapResult {
  std::string algorithm;  ///< `aes-kw` or `aes-kwp`.
  Bytes wrapped;          ///< The wrapped key (base64 on the wire).
};

/// `POST /v2/keys/unwrap`.
struct KeyUnwrapRequest {
  Bytes kek;                             ///< The key-encryption key (sent as hex).
  Bytes wrapped_key;                     ///< What key_wrap returned (sent as base64).
  std::optional<std::string> algorithm;  ///< `aes-kw` (default) or `aes-kwp`.
};

/// What `POST /v2/keys/unwrap` returns (`data` is a bare hex string).
struct KeyUnwrapResult {
  Bytes key;  ///< The unwrapped key.
};

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_MODELS_SYMMETRIC_HPP
