// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// Server-held keys and classical signatures: generation, export,
// deletion, Ed25519 signing and verification, batch signing and the
// ISO 20022 dual-signature check.

#ifndef CRYPTO_SERVICE_MODELS_KEYS_HPP
#define CRYPTO_SERVICE_MODELS_KEYS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "crypto_service/encoding.hpp"

namespace crypto_service {

/// JWK-style metadata of a server-held key.
struct KeyMetadata {
  std::optional<std::string> exp;  ///< Expiry, as the caller chose to write it.
  std::optional<std::string> kid;  ///< Key identifier.
  std::optional<std::string> use;  ///< `sig` or `enc`.
};

/// `POST /v2/keys/generate`.
struct GenerateKeyPairRequest {
  /// `ed25519` (the server's default), `x25519`, `ed448`, `x448`,
  /// `p256`, `p384`, `ml-kem-512|768|1024` or `ml-dsa-44|65|87`.
  std::optional<std::string> algorithm;
  std::optional<KeyMetadata> metadata;  ///< Metadata to store with the key.
};

/// What `POST /v2/keys/generate` returns. The private key stays on the
/// server under `key_id`.
struct GenerateKeyPairResult {
  std::string algorithm;  ///< The key's algorithm.
  std::string key_id;     ///< `k_` plus 22 characters.
  std::string kid;        ///< The metadata kid, or one derived from the public key.
  KeyMetadata metadata;   ///< The stored metadata.
  Bytes public_key;       ///< The public key (hex on the wire).
};

/// A request naming one server-held key (`keys/export`, `keys/delete`).
struct KeyIdRequest {
  std::string key_id;  ///< `k_` plus 22 characters.
};

/// What `POST /v2/keys/export` returns: the key, private parts included.
/// Which members are set depends on the algorithm.
struct ExportKeyResult {
  std::string algorithm;                    ///< The key's algorithm.
  std::string key_id;                       ///< The key's id.
  std::optional<Bytes> ml_kem_public_key;   ///< Hybrid keys: ML-KEM public key.
  std::optional<Bytes> ml_kem_secret_key;   ///< Hybrid keys: ML-KEM secret key.
  std::optional<Bytes> private_key;         ///< Single keys: private key.
  std::optional<Bytes> public_key;          ///< Single keys: public key.
  std::optional<Bytes> secret_key;          ///< KEM keys: secret key.
  std::optional<Bytes> x25519_private_key;  ///< Hybrid keys: X25519 private key.
  std::optional<Bytes> x25519_public_key;   ///< Hybrid keys: X25519 public key.
};

/// What `POST /v2/keys/delete` returns.
struct DeleteKeyResult {
  bool deleted = false;  ///< Always true on success.
  std::string key_id;    ///< The deleted key's id.
};

/// Signing with a server-held key (`sign`, `pq/dsa/sign`, `pq/slh-dsa/sign`).
struct SignRequest {
  std::string key_id;   ///< The key to sign with.
  std::string message;  ///< UTF-8 text to sign.
};

/// What every signing route returns.
struct SignResult {
  std::string algorithm;  ///< E.g. `ed25519`, `ml-dsa-65`, `slh-dsa-sha2-128f`.
  Bytes signature;        ///< The signature (hex on the wire).
};

/// `POST /v2/verify`: an Ed25519 signature.
struct VerifyRequest {
  Bytes public_key;     ///< The 32-byte public key (sent as hex).
  std::string message;  ///< The signed text.
  Bytes signature;      ///< The 64-byte signature (sent as hex).
};

/// What every verification route returns.
struct VerifyResult {
  std::string algorithm;  ///< The algorithm used.
  bool valid = false;     ///< Whether the signature is valid.
};

/// One message of `POST /v2/stream/sign`.
struct StreamSignItem {
  std::string id;       ///< Caller's identifier, echoed back.
  std::string key_id;   ///< The Ed25519 key to sign with.
  std::string message;  ///< UTF-8 text to sign.
};

/// `POST /v2/stream/sign`: several Ed25519 signatures in one request.
struct StreamSignRequest {
  std::vector<StreamSignItem> items;  ///< The messages.
};

/// One signature of a StreamSignResult.
struct StreamSignature {
  std::string algorithm;  ///< `ed25519`.
  std::string id;         ///< The item's id.
  Bytes signature;        ///< The signature (hex on the wire).
};

/// What `POST /v2/stream/sign` returns.
struct StreamSignResult {
  std::int64_t count = 0;                   ///< Signatures made.
  std::vector<StreamSignature> signatures;  ///< One per item, in order.
};

/// One signature of `POST /v2/stream/verify`.
struct StreamVerifyItem {
  std::string id;       ///< Caller's identifier, echoed back.
  std::string message;  ///< The signed text.
  Bytes public_key;     ///< The Ed25519 public key (sent as hex).
  Bytes signature;      ///< The signature (sent as hex).
};

/// `POST /v2/stream/verify`.
struct StreamVerifyRequest {
  std::vector<StreamVerifyItem> items;  ///< The signatures to check.
};

/// One outcome of a StreamVerifyResult.
struct StreamVerifyOutcome {
  std::string id;      ///< The item's id.
  bool valid = false;  ///< Whether its signature is valid.
};

/// What `POST /v2/stream/verify` returns.
struct StreamVerifyResult {
  bool all_valid = false;                    ///< Whether every signature is valid.
  std::int64_t count = 0;                    ///< Signatures checked.
  std::vector<StreamVerifyOutcome> results;  ///< One per item, in order.
  std::int64_t valid_count = 0;              ///< Valid signatures.
};

/// One signature of an ISO 20022 envelope.
struct Iso20022Signature {
  std::string algorithm;  ///< `ed25519` (classical) or `ml-dsa-44|65|87`.
  Bytes public_key;       ///< The signer's public key (sent as hex).
  Bytes signature;        ///< The signature (sent as hex).
};

/// A dual-signed ISO 20022 envelope.
struct Iso20022Envelope {
  Iso20022Signature classical;     ///< The classical signature.
  std::string digest_algorithm;    ///< `sha256`, `sha384` or `sha512`.
  std::string message_id;          ///< The message id.
  std::string message_type;        ///< `pacs.008`, `pain.001`, `camt.053` or `generic`.
  Bytes payload_digest;            ///< Digest of the payload (sent as hex).
  Iso20022Signature post_quantum;  ///< The post-quantum signature.
  std::string timestamp;           ///< When it was signed (RFC 3339).
};

/// The public keys the caller trusts for an ISO 20022 check.
struct Iso20022TrustedKeys {
  Bytes classical_public_key;     ///< Sent as hex.
  Bytes post_quantum_public_key;  ///< Sent as hex.
};

/// `POST /v2/stream/iso20022`: verify both signatures of an envelope.
struct Iso20022VerifyRequest {
  Iso20022Envelope envelope;                          ///< The envelope.
  nlohmann::json payload = nlohmann::json::object();  ///< The signed payload, any JSON value.
  Iso20022TrustedKeys trusted_keys;                   ///< Keys the signatures must come from.
};

/// What `POST /v2/stream/iso20022` returns.
struct Iso20022VerifyResult {
  bool classical_valid = false;     ///< The classical signature verifies.
  bool digest_matches = false;      ///< The payload matches its digest.
  std::string message_id;           ///< The envelope's message id.
  bool post_quantum_valid = false;  ///< The post-quantum signature verifies.
  bool valid = false;               ///< All three checks pass.
};

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_MODELS_KEYS_HPP
