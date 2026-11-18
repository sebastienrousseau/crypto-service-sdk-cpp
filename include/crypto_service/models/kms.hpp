// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// KMS routes (managed keys on a provider) and the OPAQUE (RFC 9807)
// password-authenticated key exchange. KMS ciphertexts and wrapped keys
// are opaque provider strings, passed back unchanged.

#ifndef CRYPTO_SERVICE_MODELS_KMS_HPP
#define CRYPTO_SERVICE_MODELS_KMS_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "crypto_service/encoding.hpp"

namespace crypto_service {

/// String-to-string map: KMS key metadata and encryption context.
using StringMap = std::map<std::string, std::string>;

/// `POST /v2/kms/create-key`.
struct KmsCreateKeyRequest {
  std::optional<std::string> algorithm;  ///< Provider algorithm; provider default if unset.
  std::optional<StringMap> metadata;     ///< Tags stored with the key.
  std::optional<std::string> provider;   ///< `local` (default), `aws`, `gcp`, `vault`, ...
  std::optional<std::string> usage;      ///< `encrypt` (default), `sign` or `wrap`.
};

/// What `POST /v2/kms/create-key` returns.
struct KmsKey {
  std::string algorithm;                        ///< E.g. `aes-256-gcm`.
  std::string created_at;                       ///< RFC 3339 timestamp.
  std::optional<std::int64_t> current_version;  ///< The key version, when versioned.
  bool enabled = false;                         ///< Whether the key can be used.
  std::string key_id;                           ///< The provider's key id.
  std::string provider;                         ///< The provider.
  std::string usage;                            ///< `encrypt`, `sign` or `wrap`.
};

/// `POST /v2/kms/encrypt`. The plaintext is always sent as hex with
/// `encoding: "hex"`, so text and binary data round-trip unchanged.
struct KmsEncryptRequest {
  std::optional<StringMap> context;     ///< Encryption context (AAD).
  std::string key_id;                   ///< The managed key.
  Bytes plaintext;                      ///< The data to encrypt.
  std::optional<std::string> provider;  ///< The provider (default `local`).
};

/// What `POST /v2/kms/encrypt` returns.
struct KmsEncryptResult {
  std::string ciphertext;                   ///< Opaque provider string.
  std::optional<StringMap> context;         ///< The context, when echoed.
  std::string key_id;                       ///< The key used.
  std::optional<std::int64_t> key_version;  ///< The key version used.
  std::string provider;                     ///< The provider.
};

/// `POST /v2/kms/decrypt`.
struct KmsDecryptRequest {
  std::string ciphertext;               ///< What kms_encrypt returned.
  std::optional<StringMap> context;     ///< The context used to encrypt.
  std::string key_id;                   ///< The managed key.
  std::optional<std::string> provider;  ///< The provider.
};

/// What `POST /v2/kms/decrypt` returns: the plaintext as bytes and text.
struct KmsDecryptResult {
  Bytes hex;              ///< The plaintext bytes.
  std::string key_id;     ///< The key used.
  std::string plaintext;  ///< The same, decoded as UTF-8 (invalid bytes become U+FFFD).
  std::string provider;   ///< The provider.
};

/// `POST /v2/kms/generate-data-key`.
struct KmsGenerateDataKeyRequest {
  std::string key_id;                   ///< The managed key that wraps the DEK.
  std::optional<std::string> key_spec;  ///< E.g. `AES_256`.
  std::optional<std::string> provider;  ///< The provider.
};

/// What `POST /v2/kms/generate-data-key` returns.
struct KmsDataKey {
  std::string ciphertext;  ///< The wrapped DEK, an opaque provider string.
  std::string key_id;      ///< The wrapping key.
  Bytes plaintext;         ///< The DEK (hex on the wire).
  std::string provider;    ///< The provider.
};

/// `POST /v2/kms/wrap`.
struct KmsWrapRequest {
  std::optional<StringMap> context;     ///< Wrapping context.
  std::string key_id;                   ///< The wrapping key.
  std::optional<std::string> provider;  ///< The provider.
  Bytes unwrapped_key;                  ///< The key bytes to wrap (sent as hex).
};

/// What `POST /v2/kms/wrap` returns.
struct KmsWrapResult {
  std::string key_id;       ///< The wrapping key.
  std::string provider;     ///< The provider.
  std::string wrapped_key;  ///< Opaque provider string.
};

/// `POST /v2/kms/unwrap`.
struct KmsUnwrapRequest {
  std::optional<StringMap> context;     ///< The context used to wrap.
  std::string key_id;                   ///< The wrapping key.
  std::optional<std::string> provider;  ///< The provider.
  std::string wrapped_key;              ///< What kms_wrap returned.
};

/// What `POST /v2/kms/unwrap` returns.
struct KmsUnwrapResult {
  std::string key_id;    ///< The wrapping key.
  std::string provider;  ///< The provider.
  Bytes unwrapped_key;   ///< The key bytes.
};

/// `POST /v2/opaque/register/init`.
struct OpaqueRegisterInitRequest {
  std::string credential_identifier;  ///< The credential's identifier (the token's subject).
  Bytes request;                      ///< The client's registration request.
  std::optional<std::string> suite;   ///< `P256-SHA256` or `ristretto255-SHA512`.
};

/// What `POST /v2/opaque/register/init` returns.
struct OpaqueRegisterInitResult {
  Bytes response;  ///< The server's registration response.
};

/// `POST /v2/opaque/register/finish`.
struct OpaqueRegisterFinishRequest {
  std::string credential_identifier;  ///< As for init.
  Bytes record;                       ///< The client's registration record.
  std::optional<std::string> suite;   ///< As for init.
};

/// What `POST /v2/opaque/register/finish` returns.
struct OpaqueRegisterFinishResult {
  std::string credential_identifier;  ///< The registered credential.
  std::string status;                 ///< `registered`.
};

/// `POST /v2/opaque/login/init`.
struct OpaqueLoginInitRequest {
  std::string credential_identifier;  ///< The credential.
  Bytes ke1;                          ///< The client's KE1 message.
  std::optional<std::string> suite;   ///< As for registration.
};

/// What `POST /v2/opaque/login/init` returns.
struct OpaqueLoginInitResult {
  Bytes ke2;               ///< The server's KE2 message.
  std::string session_id;  ///< Names the login for finish.
};

/// `POST /v2/opaque/login/finish`.
struct OpaqueLoginFinishRequest {
  Bytes ke3;               ///< The client's KE3 message.
  std::string session_id;  ///< From login init.
};

/// What `POST /v2/opaque/login/finish` returns.
struct OpaqueLoginFinishResult {
  Bytes session_key;  ///< The shared session key.
};

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_MODELS_KMS_HPP
