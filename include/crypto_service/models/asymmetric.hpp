// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Public-key routes: ML-KEM and hybrid X25519 + ML-KEM key exchange,
// ML-DSA and SLH-DSA signatures, sealed boxes, post-quantum STREAM
// encryption, multi-recipient encryption and HPKE (RFC 9180).

#ifndef CRYPTO_SERVICE_MODELS_ASYMMETRIC_HPP
#define CRYPTO_SERVICE_MODELS_ASYMMETRIC_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "crypto_service/encoding.hpp"

namespace crypto_service {

/// A key pair the server generated and holds: its id and public key
/// (`pq/keygen`, `pq/dsa/keygen`, `pq/slh-dsa/keygen`, `hpke/keygen`).
struct ServerKeyPair {
  std::string algorithm;  ///< E.g. `ml-kem-768`, `ml-dsa-65`, `x-wing`.
  std::string key_id;     ///< `k_` plus 22 characters.
  Bytes public_key;       ///< The public key (hex on the wire).
};

/// `POST /v2/pq/encapsulate`: ML-KEM-768.
struct MlKemEncapsulateRequest {
  Bytes public_key;  ///< The recipient's ML-KEM public key (sent as hex).
};

/// What `POST /v2/pq/encapsulate` returns.
struct MlKemEncapsulateResult {
  std::string algorithm;  ///< `ml-kem-768`.
  Bytes ciphertext;       ///< The KEM ciphertext.
  Bytes shared_secret;    ///< The 32-byte shared secret.
};

/// `POST /v2/pq/decapsulate`.
struct MlKemDecapsulateRequest {
  Bytes ciphertext;    ///< The KEM ciphertext (sent as hex).
  std::string key_id;  ///< The server-held ML-KEM key.
};

/// What `POST /v2/pq/decapsulate` returns.
struct SharedSecretResult {
  std::string algorithm;  ///< `ml-kem-768`.
  Bytes shared_secret;    ///< The 32-byte shared secret.
};

/// What `POST /v2/pq/hybrid/keygen` returns.
struct HybridKeyPair {
  std::string algorithm;    ///< `x25519-ml-kem-768`.
  std::string key_id;       ///< The server-held key's id.
  Bytes ml_kem_public_key;  ///< The ML-KEM-768 public key.
  Bytes x25519_public_key;  ///< The X25519 public key.
};

/// `POST /v2/pq/hybrid/encapsulate`.
struct HybridEncapsulateRequest {
  Bytes ml_kem_public_key;  ///< Sent as hex.
  Bytes x25519_public_key;  ///< 32 bytes, sent as hex.
};

/// What `POST /v2/pq/hybrid/encapsulate` returns.
struct HybridEncapsulateResult {
  std::string algorithm;          ///< `x25519-ml-kem-768`.
  std::string combiner;           ///< `crypto-service/hybrid-kem/v2`.
  Bytes ml_kem_ciphertext;        ///< The ML-KEM ciphertext.
  Bytes shared_secret;            ///< The combined shared secret.
  Bytes x25519_ephemeral_public;  ///< The ephemeral X25519 public key.
};

/// `POST /v2/pq/hybrid/decapsulate`.
struct HybridDecapsulateRequest {
  std::string key_id;             ///< The server-held hybrid key.
  Bytes ml_kem_ciphertext;        ///< Sent as hex.
  Bytes x25519_ephemeral_public;  ///< 32 bytes, sent as hex.
};

/// What `POST /v2/pq/hybrid/decapsulate` returns.
struct HybridDecapsulateResult {
  std::string algorithm;  ///< `x25519-ml-kem-768`.
  std::string combiner;   ///< `crypto-service/hybrid-kem/v2`.
  Bytes shared_secret;    ///< The combined shared secret.
};

/// `POST /v2/pq/dsa/keygen`.
struct MlDsaKeygenRequest {
  std::int64_t level = 65;  ///< 44, 65 or 87.
};

/// `POST /v2/pq/dsa/verify`.
struct MlDsaVerifyRequest {
  std::int64_t level = 65;  ///< 44, 65 or 87.
  std::string message;      ///< The signed text.
  Bytes public_key;         ///< Sent as hex.
  Bytes signature;          ///< Sent as hex.
};

/// `POST /v2/pq/slh-dsa/keygen`.
struct SlhDsaKeygenRequest {
  /// `sha2-128f`, `sha2-128s`, ... `shake-256s` (FIPS 205 parameter sets).
  std::string variant;
};

/// `POST /v2/pq/slh-dsa/verify`.
struct SlhDsaVerifyRequest {
  std::string message;  ///< The signed text.
  Bytes public_key;     ///< Sent as hex.
  Bytes signature;      ///< Sent as hex.
  std::string variant;  ///< The parameter set, as for keygen.
};

/// `POST /v2/sealedbox/seal`: anonymous sender, X25519 recipient.
struct SealedboxSealRequest {
  std::string plaintext;       ///< UTF-8 text to seal.
  Bytes recipient_public_key;  ///< The recipient's X25519 key (sent as hex).
};

/// `POST /v2/sealedbox/open` and `/v2/sealedbox/open-pq`.
struct SealedboxOpenRequest {
  std::string key_id;  ///< The server-held recipient key.
  Bytes sealed;        ///< The sealed box (sent as base64).
};

/// `POST /v2/sealedbox/seal-pq`: hybrid X25519 + ML-KEM-768 recipient.
struct SealedboxSealPqRequest {
  Bytes ml_kem_public_key;  ///< Sent as hex.
  std::string plaintext;    ///< UTF-8 text to seal.
  Bytes x25519_public_key;  ///< Sent as hex.
};

/// `POST /v2/stream/pq-encrypt`.
struct StreamPqEncryptRequest {
  std::optional<std::int64_t> chunk_size;  ///< 64 to 1048576 bytes.
  Bytes ml_kem_public_key;                 ///< Sent as hex.
  std::string plaintext;                   ///< UTF-8 text to encrypt.
  Bytes x25519_public_key;                 ///< Sent as hex.
};

/// What `POST /v2/stream/pq-encrypt` returns.
struct StreamPqEncryptResult {
  std::string algorithm;  ///< `x25519-ml-kem-768-xchacha20-poly1305-stream`.
  Bytes ciphertext;       ///< The STREAM ciphertext (base64 on the wire).
};

/// `POST /v2/stream/pq-decrypt`.
struct StreamPqDecryptRequest {
  std::optional<std::int64_t> chunk_size;  ///< The chunk size used to encrypt.
  Bytes ciphertext;                        ///< Sent as base64.
  std::string key_id;                      ///< The server-held hybrid key.
};

/// What `POST /v2/stream/pq-decrypt` returns.
struct StreamPqDecryptResult {
  std::string plaintext;  ///< The recovered text.
};

/// One recipient of `POST /v2/stream/multi-pq-encrypt`.
struct StreamRecipient {
  Bytes ml_kem_public_key;   ///< Sent as hex.
  std::string recipient_id;  ///< Caller's identifier for the recipient.
  Bytes x25519_public_key;   ///< Sent as hex.
};

/// `POST /v2/stream/multi-pq-encrypt`.
struct StreamMultiPqEncryptRequest {
  std::optional<std::int64_t> chunk_size;   ///< 1024 to 16777216 bytes.
  std::string plaintext;                    ///< UTF-8 text to encrypt.
  std::vector<StreamRecipient> recipients;  ///< Who can decrypt.
};

/// What `POST /v2/stream/multi-pq-encrypt` returns.
struct StreamMultiPqEncryptResult {
  std::string algorithm;             ///< The construction's name.
  Bytes ciphertext;                  ///< Base64 on the wire.
  std::int64_t recipient_count = 0;  ///< Recipients included.
};

/// `POST /v2/stream/multi-pq-decrypt`.
struct StreamMultiPqDecryptRequest {
  std::optional<std::int64_t> chunk_size;   ///< The chunk size used to encrypt.
  Bytes ciphertext;                         ///< Sent as base64.
  std::string key_id;                       ///< The server-held hybrid key.
  std::optional<std::string> recipient_id;  ///< Which recipient entry to try.
};

/// What `POST /v2/stream/multi-pq-decrypt` returns.
struct StreamMultiPqDecryptResult {
  std::string plaintext;     ///< The recovered text.
  std::string recipient_id;  ///< The recipient entry that matched.
};

/// One recipient of `POST /v2/multi-recipient/encrypt`.
struct MultiRecipient {
  std::optional<Bytes> ml_kem_public_key;  ///< For `pq` recipients (sent as hex).
  Bytes public_key;                        ///< X25519 public key (sent as hex).
  std::string type;                        ///< `classical` or `pq`.
};

/// `POST /v2/multi-recipient/encrypt`.
struct MultiRecipientEncryptRequest {
  std::string plaintext;                   ///< UTF-8 text to encrypt.
  std::vector<MultiRecipient> recipients;  ///< Who can decrypt.
};

/// The content key, wrapped for one recipient.
struct WrappedRecipientKey {
  Bytes ephemeral_public_key;              ///< Hex on the wire.
  std::optional<Bytes> ml_kem_ciphertext;  ///< For hybrid recipients.
  std::string type;                        ///< `x25519` or `x25519-ml-kem-768`.
  Bytes wrapped_key;                       ///< Base64 on the wire.
};

/// What `POST /v2/multi-recipient/encrypt` returns.
struct MultiRecipientEncryptResult {
  std::string algorithm;                        ///< `multi-recipient-secretbox`.
  Bytes ciphertext;                             ///< Base64 on the wire.
  std::vector<WrappedRecipientKey> recipients;  ///< One per recipient, in order.
};

/// `POST /v2/hpke/keygen`.
struct HpkeKeygenRequest {
  /// `x25519`, `p256`, `x-wing` (the server's default) or `x25519-ml-kem-768`.
  std::optional<std::string> kem;
};

/// `POST /v2/hpke/seal`. Every binary member is sent as hex, so the
/// server never has to guess whether a string is hex or text.
struct HpkeSealRequest {
  std::optional<Bytes> aad;         ///< Associated data.
  std::optional<std::string> aead;  ///< `chacha20-poly1305` (default) or `aes-128-gcm`.
  std::optional<Bytes> info;        ///< Application info.
  std::optional<std::string> kem;   ///< The recipient key's KEM (default `x-wing`).
  Bytes plaintext;                  ///< The message.
  std::optional<Bytes> psk;         ///< Pre-shared key (PSK mode, with psk_id).
  std::optional<Bytes> psk_id;      ///< Pre-shared key id.
  Bytes recipient_public_key;       ///< The recipient's public key.
};

/// What `POST /v2/hpke/seal` returns.
struct HpkeSealResult {
  Bytes ciphertext;        ///< The ciphertext (hex on the wire).
  Bytes encapsulated_key;  ///< The KEM output `enc`.
};

/// `POST /v2/hpke/open`.
struct HpkeOpenRequest {
  std::optional<Bytes> aad;         ///< The associated data used to seal.
  std::optional<std::string> aead;  ///< The AEAD used to seal.
  Bytes ciphertext;                 ///< Sent as hex.
  Bytes encapsulated_key;           ///< Sent as hex.
  std::optional<Bytes> info;        ///< The info used to seal.
  std::string key_id;               ///< The server-held recipient key.
  std::optional<Bytes> psk;         ///< Pre-shared key (PSK mode).
  std::optional<Bytes> psk_id;      ///< Pre-shared key id.
};

/// What `POST /v2/hpke/open` returns: the plaintext as text and as bytes.
struct HpkeOpenResult {
  Bytes hex;              ///< The plaintext bytes.
  std::string plaintext;  ///< The same, decoded as UTF-8 (invalid bytes become U+FFFD).
};

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_MODELS_ASYMMETRIC_HPP
