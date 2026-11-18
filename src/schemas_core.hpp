// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// Internal: the wire schema of the symmetric, hashing and key structs.
// Names and encodings follow openapi/crypto-service.openapi.yaml at the
// pinned server commit (ci/server.ref).

#ifndef CRYPTO_SERVICE_SRC_SCHEMAS_CORE_HPP
#define CRYPTO_SERVICE_SRC_SCHEMAS_CORE_HPP

#include <tuple>

#include "codec.hpp"
#include "crypto_service/models/hashing.hpp"
#include "crypto_service/models/keys.hpp"
#include "crypto_service/models/symmetric.hpp"
#include "crypto_service/operations.hpp"

namespace crypto_service::detail::codec {

inline constexpr Enc kHex = Enc::kHex;
inline constexpr Enc kB64 = Enc::kBase64;

template <>
struct Schema<EmptyRequest> {
  static auto fields() { return std::make_tuple(); }
};

// --- Symmetric ---

template <>
struct Schema<EncryptRequest> {
  static auto fields() {
    using T = EncryptRequest;
    return std::make_tuple(field("key", &T::key, kHex), field("plaintext", &T::plaintext));
  }
};
template <>
struct Schema<EncryptResult> {
  static auto fields() {
    using T = EncryptResult;
    return std::make_tuple(field("algorithm", &T::algorithm),
                           field("ciphertext", &T::ciphertext, kB64));
  }
};
template <>
struct Schema<DecryptRequest> {
  static auto fields() {
    using T = DecryptRequest;
    return std::make_tuple(field("key", &T::key, kHex), field("ciphertext", &T::ciphertext, kB64));
  }
};
template <>
struct Schema<DecryptResult> {
  static auto fields() { return std::make_tuple(field("plaintext", &DecryptResult::plaintext)); }
};
template <>
struct Schema<SecretboxSealRequest> {
  static auto fields() {
    using T = SecretboxSealRequest;
    return std::make_tuple(field("key", &T::key, kHex), field("plaintext", &T::plaintext),
                           field("aad", &T::aad));
  }
};
template <>
struct Schema<SealResult> {
  static auto fields() {
    return std::make_tuple(field("algorithm", &SealResult::algorithm),
                           field("sealed", &SealResult::sealed, kB64));
  }
};
template <>
struct Schema<SecretboxOpenRequest> {
  static auto fields() {
    using T = SecretboxOpenRequest;
    return std::make_tuple(field("key", &T::key, kHex), field("ciphertext", &T::ciphertext, kB64),
                           field("aad", &T::aad));
  }
};
template <>
struct Schema<OpenedText> {
  static auto fields() { return std::make_tuple(field("", &OpenedText::plaintext)); }
};
template <>
struct Schema<PasswordEncryptRequest> {
  static auto fields() {
    using T = PasswordEncryptRequest;
    return std::make_tuple(field("password", &T::password), field("plaintext", &T::plaintext));
  }
};
template <>
struct Schema<PasswordEncryptResult> {
  static auto fields() {
    using T = PasswordEncryptResult;
    return std::make_tuple(field("algorithm", &T::algorithm),
                           field("encrypted", &T::encrypted, kB64));
  }
};
template <>
struct Schema<PasswordDecryptRequest> {
  static auto fields() {
    using T = PasswordDecryptRequest;
    return std::make_tuple(field("password", &T::password),
                           field("ciphertext", &T::ciphertext, kB64));
  }
};
template <>
struct Schema<KeyWrapRequest> {
  static auto fields() {
    using T = KeyWrapRequest;
    return std::make_tuple(field("kek", &T::kek, kHex), field("keyToWrap", &T::key_to_wrap, kHex),
                           field("algorithm", &T::algorithm));
  }
};
template <>
struct Schema<KeyWrapResult> {
  static auto fields() {
    return std::make_tuple(field("algorithm", &KeyWrapResult::algorithm),
                           field("wrapped", &KeyWrapResult::wrapped, kB64));
  }
};
template <>
struct Schema<KeyUnwrapRequest> {
  static auto fields() {
    using T = KeyUnwrapRequest;
    return std::make_tuple(field("kek", &T::kek, kHex), field("wrappedKey", &T::wrapped_key, kB64),
                           field("algorithm", &T::algorithm));
  }
};
template <>
struct Schema<KeyUnwrapResult> {
  static auto fields() { return std::make_tuple(field("", &KeyUnwrapResult::key, kHex)); }
};

// --- Hashing, MAC, KDF, password hashing ---

template <>
struct Schema<HashRequest> {
  static auto fields() {
    return std::make_tuple(field("algorithm", &HashRequest::algorithm),
                           field("data", &HashRequest::data));
  }
};
template <>
struct Schema<HashResult> {
  static auto fields() {
    using T = HashResult;
    return std::make_tuple(field("algorithm", &T::algorithm), field("digest", &T::digest, kHex),
                           field("length", &T::length));
  }
};
template <>
struct Schema<HmacRequest> {
  static auto fields() {
    using T = HmacRequest;
    return std::make_tuple(field("algorithm", &T::algorithm), field("key", &T::key, kHex),
                           field("data", &T::data));
  }
};
template <>
struct Schema<HmacResult> {
  static auto fields() {
    return std::make_tuple(field("algorithm", &HmacResult::algorithm),
                           field("mac", &HmacResult::mac, kHex));
  }
};
template <>
struct Schema<HmacVerifyRequest> {
  static auto fields() {
    using T = HmacVerifyRequest;
    return std::make_tuple(field("algorithm", &T::algorithm), field("key", &T::key, kHex),
                           field("data", &T::data), field("mac", &T::mac, kHex));
  }
};
template <>
struct Schema<HmacVerifyResult> {
  static auto fields() {
    return std::make_tuple(field("algorithm", &HmacVerifyResult::algorithm),
                           field("valid", &HmacVerifyResult::valid));
  }
};
template <>
struct Schema<KdfParams> {
  static auto fields() {
    using T = KdfParams;
    return std::make_tuple(field("N", &T::n), field("r", &T::r), field("p", &T::p),
                           field("iterations", &T::iterations), field("info", &T::info));
  }
};
template <>
struct Schema<KdfRequest> {
  static auto fields() {
    using T = KdfRequest;
    return std::make_tuple(field("algorithm", &T::algorithm), field("password", &T::password),
                           field("salt", &T::salt, kHex), field("keyLength", &T::key_length),
                           field("params", &T::params));
  }
};
template <>
struct Schema<KdfResult> {
  static auto fields() {
    using T = KdfResult;
    return std::make_tuple(field("algorithm", &T::algorithm),
                           field("derivedKey", &T::derived_key, kHex),
                           field("keyLength", &T::key_length), field("salt", &T::salt, kHex));
  }
};
template <>
struct Schema<Argon2Params> {
  static auto fields() {
    return std::make_tuple(field("m", &Argon2Params::m), field("p", &Argon2Params::p),
                           field("t", &Argon2Params::t));
  }
};
template <>
struct Schema<PasswordHashRequest> {
  static auto fields() {
    using T = PasswordHashRequest;
    return std::make_tuple(field("password", &T::password), field("timeCost", &T::time_cost),
                           field("memoryCost", &T::memory_cost),
                           field("parallelism", &T::parallelism));
  }
};
template <>
struct Schema<PasswordHashResult> {
  static auto fields() {
    using T = PasswordHashResult;
    return std::make_tuple(field("algorithm", &T::algorithm), field("hash", &T::hash, kHex),
                           field("params", &T::params), field("phc", &T::phc),
                           field("salt", &T::salt, kHex));
  }
};
template <>
struct Schema<PasswordVerifyRequest> {
  static auto fields() {
    using T = PasswordVerifyRequest;
    return std::make_tuple(field("password", &T::password), field("hash", &T::hash, kHex),
                           field("salt", &T::salt, kHex), field("params", &T::params));
  }
};
template <>
struct Schema<PasswordVerifyResult> {
  static auto fields() { return std::make_tuple(field("valid", &PasswordVerifyResult::valid)); }
};

// --- Keys and classical signatures ---

template <>
struct Schema<KeyMetadata> {
  static auto fields() {
    return std::make_tuple(field("exp", &KeyMetadata::exp), field("kid", &KeyMetadata::kid),
                           field("use", &KeyMetadata::use));
  }
};
template <>
struct Schema<GenerateKeyPairRequest> {
  static auto fields() {
    return std::make_tuple(field("algorithm", &GenerateKeyPairRequest::algorithm),
                           field("metadata", &GenerateKeyPairRequest::metadata));
  }
};
template <>
struct Schema<GenerateKeyPairResult> {
  static auto fields() {
    using T = GenerateKeyPairResult;
    return std::make_tuple(field("algorithm", &T::algorithm), field("keyId", &T::key_id),
                           field("kid", &T::kid), field("metadata", &T::metadata),
                           field("publicKey", &T::public_key, kHex));
  }
};
template <>
struct Schema<KeyIdRequest> {
  static auto fields() { return std::make_tuple(field("keyId", &KeyIdRequest::key_id)); }
};
template <>
struct Schema<ExportKeyResult> {
  static auto fields() {
    using T = ExportKeyResult;
    return std::make_tuple(field("algorithm", &T::algorithm), field("keyId", &T::key_id),
                           field("mlKemPublicKey", &T::ml_kem_public_key, kHex),
                           field("mlKemSecretKey", &T::ml_kem_secret_key, kHex),
                           field("privateKey", &T::private_key, kHex),
                           field("publicKey", &T::public_key, kHex),
                           field("secretKey", &T::secret_key, kHex),
                           field("x25519PrivateKey", &T::x25519_private_key, kHex),
                           field("x25519PublicKey", &T::x25519_public_key, kHex));
  }
};
template <>
struct Schema<DeleteKeyResult> {
  static auto fields() {
    return std::make_tuple(field("deleted", &DeleteKeyResult::deleted),
                           field("keyId", &DeleteKeyResult::key_id));
  }
};
template <>
struct Schema<SignRequest> {
  static auto fields() {
    return std::make_tuple(field("keyId", &SignRequest::key_id),
                           field("message", &SignRequest::message));
  }
};
template <>
struct Schema<SignResult> {
  static auto fields() {
    return std::make_tuple(field("algorithm", &SignResult::algorithm),
                           field("signature", &SignResult::signature, kHex));
  }
};
template <>
struct Schema<VerifyRequest> {
  static auto fields() {
    using T = VerifyRequest;
    return std::make_tuple(field("publicKey", &T::public_key, kHex), field("message", &T::message),
                           field("signature", &T::signature, kHex));
  }
};
template <>
struct Schema<VerifyResult> {
  static auto fields() {
    return std::make_tuple(field("algorithm", &VerifyResult::algorithm),
                           field("valid", &VerifyResult::valid));
  }
};
template <>
struct Schema<StreamSignItem> {
  static auto fields() {
    using T = StreamSignItem;
    return std::make_tuple(field("id", &T::id), field("keyId", &T::key_id),
                           field("message", &T::message));
  }
};
template <>
struct Schema<StreamSignRequest> {
  static auto fields() { return std::make_tuple(field("items", &StreamSignRequest::items)); }
};
template <>
struct Schema<StreamSignature> {
  static auto fields() {
    using T = StreamSignature;
    return std::make_tuple(field("algorithm", &T::algorithm), field("id", &T::id),
                           field("signature", &T::signature, kHex));
  }
};
template <>
struct Schema<StreamSignResult> {
  static auto fields() {
    return std::make_tuple(field("count", &StreamSignResult::count),
                           field("signatures", &StreamSignResult::signatures));
  }
};
template <>
struct Schema<StreamVerifyItem> {
  static auto fields() {
    using T = StreamVerifyItem;
    return std::make_tuple(field("id", &T::id), field("message", &T::message),
                           field("publicKey", &T::public_key, kHex),
                           field("signature", &T::signature, kHex));
  }
};
template <>
struct Schema<StreamVerifyRequest> {
  static auto fields() { return std::make_tuple(field("items", &StreamVerifyRequest::items)); }
};
template <>
struct Schema<StreamVerifyOutcome> {
  static auto fields() {
    return std::make_tuple(field("id", &StreamVerifyOutcome::id),
                           field("valid", &StreamVerifyOutcome::valid));
  }
};
template <>
struct Schema<StreamVerifyResult> {
  static auto fields() {
    using T = StreamVerifyResult;
    return std::make_tuple(field("allValid", &T::all_valid), field("count", &T::count),
                           field("results", &T::results), field("validCount", &T::valid_count));
  }
};
template <>
struct Schema<Iso20022Signature> {
  static auto fields() {
    using T = Iso20022Signature;
    return std::make_tuple(field("algorithm", &T::algorithm),
                           field("publicKey", &T::public_key, kHex),
                           field("signature", &T::signature, kHex));
  }
};
template <>
struct Schema<Iso20022Envelope> {
  static auto fields() {
    using T = Iso20022Envelope;
    return std::make_tuple(
        field("classical", &T::classical), field("digestAlgorithm", &T::digest_algorithm),
        field("messageId", &T::message_id), field("messageType", &T::message_type),
        field("payloadDigest", &T::payload_digest, kHex), field("postQuantum", &T::post_quantum),
        field("timestamp", &T::timestamp));
  }
};
template <>
struct Schema<Iso20022TrustedKeys> {
  static auto fields() {
    using T = Iso20022TrustedKeys;
    return std::make_tuple(field("classicalPublicKey", &T::classical_public_key, kHex),
                           field("postQuantumPublicKey", &T::post_quantum_public_key, kHex));
  }
};
template <>
struct Schema<Iso20022VerifyRequest> {
  static auto fields() {
    using T = Iso20022VerifyRequest;
    return std::make_tuple(field("envelope", &T::envelope), field("payload", &T::payload),
                           field("trustedKeys", &T::trusted_keys));
  }
};
template <>
struct Schema<Iso20022VerifyResult> {
  static auto fields() {
    using T = Iso20022VerifyResult;
    return std::make_tuple(
        field("classicalValid", &T::classical_valid), field("digestMatches", &T::digest_matches),
        field("messageId", &T::message_id), field("postQuantumValid", &T::post_quantum_valid),
        field("valid", &T::valid));
  }
};

}  // namespace crypto_service::detail::codec

#endif  // CRYPTO_SERVICE_SRC_SCHEMAS_CORE_HPP
