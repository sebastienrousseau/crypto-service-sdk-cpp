// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Requests and results of hashing, HMAC, key derivation and Argon2id
// password hashing.

#ifndef CRYPTO_SERVICE_MODELS_HASHING_HPP
#define CRYPTO_SERVICE_MODELS_HASHING_HPP

#include <cstdint>
#include <optional>
#include <string>

#include "crypto_service/encoding.hpp"

namespace crypto_service {

/// `POST /v2/hash`.
struct HashRequest {
  /// `sha256`, `sha384`, `sha512`, `sha3-256`, `sha3-512`, `blake2b` or `blake3`.
  std::string algorithm;
  std::string data;  ///< UTF-8 text to hash.
};

/// What `POST /v2/hash` returns.
struct HashResult {
  std::string algorithm;    ///< The algorithm used.
  Bytes digest;             ///< The digest (hex on the wire).
  std::int64_t length = 0;  ///< The digest length in bytes.
};

/// `POST /v2/hmac`.
struct HmacRequest {
  /// `sha256`, `sha384`, `sha512`, `sha3-256` or `sha3-512`.
  std::string algorithm;
  Bytes key;         ///< At least 16 bytes (sent as hex).
  std::string data;  ///< UTF-8 text to authenticate.
};

/// What `POST /v2/hmac` returns.
struct HmacResult {
  std::string algorithm;  ///< The algorithm used.
  Bytes mac;              ///< The tag (hex on the wire).
};

/// `POST /v2/hmac/verify`.
struct HmacVerifyRequest {
  std::string algorithm;  ///< As for HmacRequest.
  Bytes key;              ///< The key (sent as hex).
  std::string data;       ///< The authenticated text.
  Bytes mac;              ///< The tag to check (sent as hex).
};

/// What `POST /v2/hmac/verify` returns.
struct HmacVerifyResult {
  std::string algorithm;  ///< The algorithm used.
  bool valid = false;     ///< Whether the tag matches (compared in constant time).
};

/// Cost parameters of `POST /v2/kdf`; the server enforces OWASP floors.
struct KdfParams {
  std::optional<std::int64_t> n;           ///< scrypt cost `N` (only 131072).
  std::optional<std::int64_t> r;           ///< scrypt block size (only 8).
  std::optional<std::int64_t> p;           ///< scrypt parallelism (1 to 4).
  std::optional<std::int64_t> iterations;  ///< PBKDF2 iterations (600000 to 1000000).
  std::optional<std::string> info;         ///< HKDF info, UTF-8 text.
};

/// `POST /v2/kdf`.
struct KdfRequest {
  std::string algorithm;                   ///< `scrypt`, `hkdf-sha256` or `pbkdf2-sha256`.
  std::string password;                    ///< The input secret, UTF-8 text.
  std::optional<Bytes> salt;               ///< Up to 64 bytes (sent as hex); random if unset.
  std::optional<std::int64_t> key_length;  ///< Output length in bytes (16 to 64).
  std::optional<KdfParams> params;         ///< Algorithm parameters.
};

/// What `POST /v2/kdf` returns.
struct KdfResult {
  std::string algorithm;        ///< The algorithm used.
  Bytes derived_key;            ///< The derived key (hex on the wire).
  std::int64_t key_length = 0;  ///< Its length in bytes.
  Bytes salt;                   ///< The salt used.
};

/// Argon2id parameters, as `password_hash` returns and `password_verify`
/// takes them.
struct Argon2Params {
  std::int64_t m = 0;  ///< Memory cost in KiB.
  std::int64_t p = 0;  ///< Parallelism.
  std::int64_t t = 0;  ///< Passes.
};

/// `POST /v2/password/hash`.
struct PasswordHashRequest {
  std::string password;                     ///< The password.
  std::optional<std::int64_t> time_cost;    ///< Passes (2 to 10).
  std::optional<std::int64_t> memory_cost;  ///< KiB (19456 to 262144).
  std::optional<std::int64_t> parallelism;  ///< Lanes (1 to 8).
};

/// What `POST /v2/password/hash` returns.
struct PasswordHashResult {
  std::string algorithm;  ///< `argon2id`.
  Bytes hash;             ///< The 32-byte hash.
  Argon2Params params;    ///< The parameters used.
  std::string phc;        ///< The same hash as a PHC string.
  Bytes salt;             ///< The random 16-byte salt.
};

/// `POST /v2/password/verify`.
struct PasswordVerifyRequest {
  std::string password;  ///< The password to check.
  Bytes hash;            ///< The stored hash (sent as hex).
  Bytes salt;            ///< The stored salt (sent as hex).
  Argon2Params params;   ///< The stored parameters.
};

/// What `POST /v2/password/verify` returns.
struct PasswordVerifyResult {
  bool valid = false;  ///< Whether the password matches.
};

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_MODELS_HASHING_HPP
