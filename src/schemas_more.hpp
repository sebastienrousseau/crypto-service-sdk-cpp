// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// Internal: the wire schema of the public-key, KMS, OPAQUE and service
// structs (see schemas_core.hpp).

#ifndef CRYPTO_SERVICE_SRC_SCHEMAS_MORE_HPP
#define CRYPTO_SERVICE_SRC_SCHEMAS_MORE_HPP

#include <tuple>

#include "codec.hpp"
#include "crypto_service/models/asymmetric.hpp"
#include "schemas_core.hpp"

namespace crypto_service::detail::codec {

// --- Post-quantum key exchange and signatures ---

template <>
struct Schema<ServerKeyPair> {
  static auto fields() {
    using T = ServerKeyPair;
    return std::make_tuple(field("algorithm", &T::algorithm), field("keyId", &T::key_id),
                           field("publicKey", &T::public_key, kHex));
  }
};
template <>
struct Schema<MlKemEncapsulateRequest> {
  static auto fields() {
    return std::make_tuple(field("publicKey", &MlKemEncapsulateRequest::public_key, kHex));
  }
};
template <>
struct Schema<MlKemEncapsulateResult> {
  static auto fields() {
    using T = MlKemEncapsulateResult;
    return std::make_tuple(field("algorithm", &T::algorithm),
                           field("ciphertext", &T::ciphertext, kHex),
                           field("sharedSecret", &T::shared_secret, kHex));
  }
};
template <>
struct Schema<MlKemDecapsulateRequest> {
  static auto fields() {
    using T = MlKemDecapsulateRequest;
    return std::make_tuple(field("ciphertext", &T::ciphertext, kHex), field("keyId", &T::key_id));
  }
};
template <>
struct Schema<SharedSecretResult> {
  static auto fields() {
    return std::make_tuple(field("algorithm", &SharedSecretResult::algorithm),
                           field("sharedSecret", &SharedSecretResult::shared_secret, kHex));
  }
};
template <>
struct Schema<HybridKeyPair> {
  static auto fields() {
    using T = HybridKeyPair;
    return std::make_tuple(field("algorithm", &T::algorithm), field("keyId", &T::key_id),
                           field("mlKemPublicKey", &T::ml_kem_public_key, kHex),
                           field("x25519PublicKey", &T::x25519_public_key, kHex));
  }
};
template <>
struct Schema<HybridEncapsulateRequest> {
  static auto fields() {
    using T = HybridEncapsulateRequest;
    return std::make_tuple(field("mlKemPublicKey", &T::ml_kem_public_key, kHex),
                           field("x25519PublicKey", &T::x25519_public_key, kHex));
  }
};
template <>
struct Schema<HybridEncapsulateResult> {
  static auto fields() {
    using T = HybridEncapsulateResult;
    return std::make_tuple(field("algorithm", &T::algorithm), field("combiner", &T::combiner),
                           field("mlKemCiphertext", &T::ml_kem_ciphertext, kHex),
                           field("sharedSecret", &T::shared_secret, kHex),
                           field("x25519EphemeralPublic", &T::x25519_ephemeral_public, kHex));
  }
};
template <>
struct Schema<HybridDecapsulateRequest> {
  static auto fields() {
    using T = HybridDecapsulateRequest;
    return std::make_tuple(field("keyId", &T::key_id),
                           field("mlKemCiphertext", &T::ml_kem_ciphertext, kHex),
                           field("x25519EphemeralPublic", &T::x25519_ephemeral_public, kHex));
  }
};
template <>
struct Schema<HybridDecapsulateResult> {
  static auto fields() {
    using T = HybridDecapsulateResult;
    return std::make_tuple(field("algorithm", &T::algorithm), field("combiner", &T::combiner),
                           field("sharedSecret", &T::shared_secret, kHex));
  }
};
template <>
struct Schema<MlDsaKeygenRequest> {
  static auto fields() { return std::make_tuple(field("level", &MlDsaKeygenRequest::level)); }
};
template <>
struct Schema<MlDsaVerifyRequest> {
  static auto fields() {
    using T = MlDsaVerifyRequest;
    return std::make_tuple(field("level", &T::level), field("message", &T::message),
                           field("publicKey", &T::public_key, kHex),
                           field("signature", &T::signature, kHex));
  }
};
template <>
struct Schema<SlhDsaKeygenRequest> {
  static auto fields() { return std::make_tuple(field("variant", &SlhDsaKeygenRequest::variant)); }
};
template <>
struct Schema<SlhDsaVerifyRequest> {
  static auto fields() {
    using T = SlhDsaVerifyRequest;
    return std::make_tuple(field("message", &T::message), field("publicKey", &T::public_key, kHex),
                           field("signature", &T::signature, kHex), field("variant", &T::variant));
  }
};

// --- Boxes, streams and multi-recipient encryption ---

template <>
struct Schema<SealedboxSealRequest> {
  static auto fields() {
    using T = SealedboxSealRequest;
    return std::make_tuple(field("plaintext", &T::plaintext),
                           field("recipientPublicKey", &T::recipient_public_key, kHex));
  }
};
template <>
struct Schema<SealedboxOpenRequest> {
  static auto fields() {
    return std::make_tuple(field("keyId", &SealedboxOpenRequest::key_id),
                           field("sealed", &SealedboxOpenRequest::sealed, kB64));
  }
};
template <>
struct Schema<SealedboxSealPqRequest> {
  static auto fields() {
    using T = SealedboxSealPqRequest;
    return std::make_tuple(field("mlKemPublicKey", &T::ml_kem_public_key, kHex),
                           field("plaintext", &T::plaintext),
                           field("x25519PublicKey", &T::x25519_public_key, kHex));
  }
};
template <>
struct Schema<StreamPqEncryptRequest> {
  static auto fields() {
    using T = StreamPqEncryptRequest;
    return std::make_tuple(
        field("chunkSize", &T::chunk_size), field("mlKemPublicKey", &T::ml_kem_public_key, kHex),
        field("plaintext", &T::plaintext), field("x25519PublicKey", &T::x25519_public_key, kHex));
  }
};
template <>
struct Schema<StreamPqEncryptResult> {
  static auto fields() {
    return std::make_tuple(field("algorithm", &StreamPqEncryptResult::algorithm),
                           field("ciphertext", &StreamPqEncryptResult::ciphertext, kB64));
  }
};
template <>
struct Schema<StreamPqDecryptRequest> {
  static auto fields() {
    using T = StreamPqDecryptRequest;
    return std::make_tuple(field("chunkSize", &T::chunk_size),
                           field("ciphertext", &T::ciphertext, kB64), field("keyId", &T::key_id));
  }
};
template <>
struct Schema<StreamPqDecryptResult> {
  static auto fields() {
    return std::make_tuple(field("plaintext", &StreamPqDecryptResult::plaintext));
  }
};
template <>
struct Schema<StreamRecipient> {
  static auto fields() {
    using T = StreamRecipient;
    return std::make_tuple(field("mlKemPublicKey", &T::ml_kem_public_key, kHex),
                           field("recipientId", &T::recipient_id),
                           field("x25519PublicKey", &T::x25519_public_key, kHex));
  }
};
template <>
struct Schema<StreamMultiPqEncryptRequest> {
  static auto fields() {
    using T = StreamMultiPqEncryptRequest;
    return std::make_tuple(field("chunkSize", &T::chunk_size), field("plaintext", &T::plaintext),
                           field("recipients", &T::recipients));
  }
};
template <>
struct Schema<StreamMultiPqEncryptResult> {
  static auto fields() {
    using T = StreamMultiPqEncryptResult;
    return std::make_tuple(field("algorithm", &T::algorithm),
                           field("ciphertext", &T::ciphertext, kB64),
                           field("recipientCount", &T::recipient_count));
  }
};
template <>
struct Schema<StreamMultiPqDecryptRequest> {
  static auto fields() {
    using T = StreamMultiPqDecryptRequest;
    return std::make_tuple(field("chunkSize", &T::chunk_size),
                           field("ciphertext", &T::ciphertext, kB64), field("keyId", &T::key_id),
                           field("recipientId", &T::recipient_id));
  }
};
template <>
struct Schema<StreamMultiPqDecryptResult> {
  static auto fields() {
    return std::make_tuple(field("plaintext", &StreamMultiPqDecryptResult::plaintext),
                           field("recipientId", &StreamMultiPqDecryptResult::recipient_id));
  }
};
template <>
struct Schema<MultiRecipient> {
  static auto fields() {
    using T = MultiRecipient;
    return std::make_tuple(field("mlKemPublicKey", &T::ml_kem_public_key, kHex),
                           field("publicKey", &T::public_key, kHex), field("type", &T::type));
  }
};
template <>
struct Schema<MultiRecipientEncryptRequest> {
  static auto fields() {
    return std::make_tuple(field("plaintext", &MultiRecipientEncryptRequest::plaintext),
                           field("recipients", &MultiRecipientEncryptRequest::recipients));
  }
};
template <>
struct Schema<WrappedRecipientKey> {
  static auto fields() {
    using T = WrappedRecipientKey;
    return std::make_tuple(field("ephemeralPublicKey", &T::ephemeral_public_key, kHex),
                           field("mlKemCiphertext", &T::ml_kem_ciphertext, kHex),
                           field("type", &T::type), field("wrappedKey", &T::wrapped_key, kB64));
  }
};
template <>
struct Schema<MultiRecipientEncryptResult> {
  static auto fields() {
    using T = MultiRecipientEncryptResult;
    return std::make_tuple(field("algorithm", &T::algorithm),
                           field("ciphertext", &T::ciphertext, kB64),
                           field("recipients", &T::recipients));
  }
};

// --- HPKE ---

template <>
struct Schema<HpkeKeygenRequest> {
  static auto fields() { return std::make_tuple(field("kem", &HpkeKeygenRequest::kem)); }
};
template <>
struct Schema<HpkeSealRequest> {
  static auto fields() {
    using T = HpkeSealRequest;
    return std::make_tuple(field("aad", &T::aad, kHex), field("aead", &T::aead),
                           field("info", &T::info, kHex), field("kem", &T::kem),
                           field("plaintext", &T::plaintext, kHex), field("psk", &T::psk, kHex),
                           field("pskId", &T::psk_id, kHex),
                           field("recipientPublicKey", &T::recipient_public_key, kHex));
  }
};
template <>
struct Schema<HpkeSealResult> {
  static auto fields() {
    return std::make_tuple(field("ciphertext", &HpkeSealResult::ciphertext, kHex),
                           field("encapsulatedKey", &HpkeSealResult::encapsulated_key, kHex));
  }
};
template <>
struct Schema<HpkeOpenRequest> {
  static auto fields() {
    using T = HpkeOpenRequest;
    return std::make_tuple(field("aad", &T::aad, kHex), field("aead", &T::aead),
                           field("ciphertext", &T::ciphertext, kHex),
                           field("encapsulatedKey", &T::encapsulated_key, kHex),
                           field("info", &T::info, kHex), field("keyId", &T::key_id),
                           field("psk", &T::psk, kHex), field("pskId", &T::psk_id, kHex));
  }
};
template <>
struct Schema<HpkeOpenResult> {
  static auto fields() {
    return std::make_tuple(field("hex", &HpkeOpenResult::hex, kHex),
                           field("plaintext", &HpkeOpenResult::plaintext));
  }
};

}  // namespace crypto_service::detail::codec

#endif  // CRYPTO_SERVICE_SRC_SCHEMAS_MORE_HPP
