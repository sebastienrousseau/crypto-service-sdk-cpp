// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// Every operation of the crypto-server v2 API, once, for both clients:
// Client returns each result (Ret<T> = T), AsyncClient returns a
// std::future of it. Method names follow the TypeScript SDK in
// snake_case, or the OpenAPI operationId where it has none.
//
// Each call sends one HTTP request (more with retries), checks the
// status, and decodes the result: ApiError for a non-2xx status,
// TransportError when no usable response arrives, CancelledError when
// CallOptions::cancel fires. No cryptography runs in the client.

#ifndef CRYPTO_SERVICE_OPERATIONS_HPP
#define CRYPTO_SERVICE_OPERATIONS_HPP

#include <optional>
#include <string>

#include "crypto_service/detail/wire.hpp"
#include "crypto_service/models/asymmetric.hpp"
#include "crypto_service/models/hashing.hpp"
#include "crypto_service/models/keys.hpp"
#include "crypto_service/models/kms.hpp"
#include "crypto_service/models/service.hpp"
#include "crypto_service/models/symmetric.hpp"
#include "crypto_service/options.hpp"

namespace crypto_service {

namespace detail {
/// The body of the POST routes that take no members: `{}`.
struct EmptyRequest {};
}  // namespace detail

/// The operations, mixed into Client and AsyncClient.
template <typename Derived, template <typename> class Ret>
class Operations {
 public:
  // --- Service and probes ---

  /// `GET /`: service metadata.
  Ret<ServiceInfo> root(const CallOptions& call = {}) {
    return get<ServiceInfo>({"GET", "/", false}, call);
  }
  /// `GET /health` (no credentials sent).
  Ret<HealthStatus> health(const CallOptions& call = {}) {
    return get<HealthStatus>({"GET", "/health", false, true}, call);
  }
  /// `GET /live` (no credentials sent).
  Ret<LiveStatus> live(const CallOptions& call = {}) {
    return get<LiveStatus>({"GET", "/live", false, true}, call);
  }
  /// `GET /ready` (no credentials sent); a server that is not ready answers 503.
  Ret<ReadyStatus> ready(const CallOptions& call = {}) {
    return get<ReadyStatus>({"GET", "/ready", false, true}, call);
  }
  /// `GET /v2/algorithms`: supported algorithms by category.
  Ret<Algorithms> algorithms(const CallOptions& call = {}) {
    return get<Algorithms>({"GET", "/v2/algorithms"}, call);
  }
  /// `GET /v2/compliance/dora`: the DORA self-assessment.
  Ret<DoraScorecard> get_dora_compliance(const CallOptions& call = {}) {
    return get<DoraScorecard>({"GET", "/v2/compliance/dora"}, call);
  }
  /// `GET /v2/compliance/cbom`: the CycloneDX 1.6 CBOM.
  Ret<Cbom> get_cbom(const CallOptions& call = {}) {
    return get<Cbom>({"GET", "/v2/compliance/cbom", false}, call);
  }

  // --- Symmetric ---

  /// `POST /v2/encrypt`: XChaCha20-Poly1305.
  Ret<EncryptResult> encrypt(const EncryptRequest& request, const CallOptions& call = {}) {
    return post<EncryptResult>({"POST", "/v2/encrypt"}, request, call);
  }
  /// `POST /v2/decrypt`.
  Ret<DecryptResult> decrypt(const DecryptRequest& request, const CallOptions& call = {}) {
    return post<DecryptResult>({"POST", "/v2/decrypt"}, request, call);
  }
  /// `POST /v2/secretbox/seal`.
  Ret<SealResult> secretbox_seal(const SecretboxSealRequest& request,
                                 const CallOptions& call = {}) {
    return post<SealResult>({"POST", "/v2/secretbox/seal"}, request, call);
  }
  /// `POST /v2/secretbox/open`.
  Ret<OpenedText> secretbox_open(const SecretboxOpenRequest& request,
                                 const CallOptions& call = {}) {
    return post<OpenedText>({"POST", "/v2/secretbox/open"}, request, call);
  }
  /// `POST /v2/password/encrypt`: Argon2id plus XChaCha20-Poly1305.
  Ret<PasswordEncryptResult> password_encrypt(const PasswordEncryptRequest& request,
                                              const CallOptions& call = {}) {
    return post<PasswordEncryptResult>({"POST", "/v2/password/encrypt"}, request, call);
  }
  /// `POST /v2/password/decrypt`.
  Ret<OpenedText> password_decrypt(const PasswordDecryptRequest& request,
                                   const CallOptions& call = {}) {
    return post<OpenedText>({"POST", "/v2/password/decrypt"}, request, call);
  }
  /// `POST /v2/keys/wrap`: AES-KW or AES-KWP.
  Ret<KeyWrapResult> key_wrap(const KeyWrapRequest& request, const CallOptions& call = {}) {
    return post<KeyWrapResult>({"POST", "/v2/keys/wrap"}, request, call);
  }
  /// `POST /v2/keys/unwrap`.
  Ret<KeyUnwrapResult> key_unwrap(const KeyUnwrapRequest& request, const CallOptions& call = {}) {
    return post<KeyUnwrapResult>({"POST", "/v2/keys/unwrap"}, request, call);
  }

  // --- Hashing, MAC, KDF, password hashing ---

  /// `POST /v2/hash`.
  Ret<HashResult> hash(const HashRequest& request, const CallOptions& call = {}) {
    return post<HashResult>({"POST", "/v2/hash"}, request, call);
  }
  /// `POST /v2/hmac`.
  Ret<HmacResult> mac(const HmacRequest& request, const CallOptions& call = {}) {
    return post<HmacResult>({"POST", "/v2/hmac"}, request, call);
  }
  /// `POST /v2/hmac/verify`.
  Ret<HmacVerifyResult> mac_verify(const HmacVerifyRequest& request, const CallOptions& call = {}) {
    return post<HmacVerifyResult>({"POST", "/v2/hmac/verify"}, request, call);
  }
  /// `POST /v2/kdf`: scrypt, HKDF or PBKDF2.
  Ret<KdfResult> kdf(const KdfRequest& request, const CallOptions& call = {}) {
    return post<KdfResult>({"POST", "/v2/kdf"}, request, call);
  }
  /// `POST /v2/password/hash`: Argon2id.
  Ret<PasswordHashResult> password_hash(const PasswordHashRequest& request,
                                        const CallOptions& call = {}) {
    return post<PasswordHashResult>({"POST", "/v2/password/hash"}, request, call);
  }
  /// `POST /v2/password/verify`.
  Ret<PasswordVerifyResult> password_verify(const PasswordVerifyRequest& request,
                                            const CallOptions& call = {}) {
    return post<PasswordVerifyResult>({"POST", "/v2/password/verify"}, request, call);
  }

  // --- Server-held keys and classical signatures ---

  /// `POST /v2/keys/generate`: a server-held key pair (stateful).
  Ret<GenerateKeyPairResult> generate_key_pair(const GenerateKeyPairRequest& request = {},
                                               const CallOptions& call = {}) {
    return post<GenerateKeyPairResult>({"POST", "/v2/keys/generate"}, request, call);
  }
  /// `POST /v2/keys/export`: needs the `crypto:keys:export` scope.
  Ret<ExportKeyResult> export_key(const KeyIdRequest& request, const CallOptions& call = {}) {
    return post<ExportKeyResult>({"POST", "/v2/keys/export"}, request, call);
  }
  /// `POST /v2/keys/delete` (stateful).
  Ret<DeleteKeyResult> keys_delete(const KeyIdRequest& request, const CallOptions& call = {}) {
    return post<DeleteKeyResult>({"POST", "/v2/keys/delete"}, request, call);
  }
  /// `POST /v2/sign`: Ed25519 with a server-held key.
  Ret<SignResult> sign(const SignRequest& request, const CallOptions& call = {}) {
    return post<SignResult>({"POST", "/v2/sign"}, request, call);
  }
  /// `POST /v2/verify`: an Ed25519 signature.
  Ret<VerifyResult> verify(const VerifyRequest& request, const CallOptions& call = {}) {
    return post<VerifyResult>({"POST", "/v2/verify"}, request, call);
  }
  /// `POST /v2/stream/sign`: several Ed25519 signatures.
  Ret<StreamSignResult> stream_sign(const StreamSignRequest& request,
                                    const CallOptions& call = {}) {
    return post<StreamSignResult>({"POST", "/v2/stream/sign"}, request, call);
  }
  /// `POST /v2/stream/verify`: several Ed25519 signatures.
  Ret<StreamVerifyResult> stream_verify(const StreamVerifyRequest& request,
                                        const CallOptions& call = {}) {
    return post<StreamVerifyResult>({"POST", "/v2/stream/verify"}, request, call);
  }
  /// `POST /v2/stream/iso20022`: an ISO 20022 dual-signature envelope.
  Ret<Iso20022VerifyResult> stream_iso20022(const Iso20022VerifyRequest& request,
                                            const CallOptions& call = {}) {
    return post<Iso20022VerifyResult>({"POST", "/v2/stream/iso20022"}, request, call);
  }

  // --- Post-quantum key exchange and signatures ---

  /// `POST /v2/pq/keygen`: a server-held ML-KEM-768 key (stateful).
  Ret<ServerKeyPair> ml_kem_generate_key_pair(const CallOptions& call = {}) {
    return post<ServerKeyPair>({"POST", "/v2/pq/keygen"}, detail::EmptyRequest{}, call);
  }
  /// `POST /v2/pq/encapsulate`.
  Ret<MlKemEncapsulateResult> ml_kem_encapsulate(const MlKemEncapsulateRequest& request,
                                                 const CallOptions& call = {}) {
    return post<MlKemEncapsulateResult>({"POST", "/v2/pq/encapsulate"}, request, call);
  }
  /// `POST /v2/pq/decapsulate`.
  Ret<SharedSecretResult> ml_kem_decapsulate(const MlKemDecapsulateRequest& request,
                                             const CallOptions& call = {}) {
    return post<SharedSecretResult>({"POST", "/v2/pq/decapsulate"}, request, call);
  }
  /// `POST /v2/pq/hybrid/keygen`: X25519 + ML-KEM-768 (stateful).
  Ret<HybridKeyPair> pq_generate_key_pair(const CallOptions& call = {}) {
    return post<HybridKeyPair>({"POST", "/v2/pq/hybrid/keygen"}, detail::EmptyRequest{}, call);
  }
  /// `POST /v2/pq/hybrid/encapsulate`.
  Ret<HybridEncapsulateResult> pq_encapsulate(const HybridEncapsulateRequest& request,
                                              const CallOptions& call = {}) {
    return post<HybridEncapsulateResult>({"POST", "/v2/pq/hybrid/encapsulate"}, request, call);
  }
  /// `POST /v2/pq/hybrid/decapsulate`.
  Ret<HybridDecapsulateResult> pq_decapsulate(const HybridDecapsulateRequest& request,
                                              const CallOptions& call = {}) {
    return post<HybridDecapsulateResult>({"POST", "/v2/pq/hybrid/decapsulate"}, request, call);
  }
  /// `POST /v2/pq/dsa/keygen`: a server-held ML-DSA key (stateful).
  Ret<ServerKeyPair> pq_sign_keygen(const MlDsaKeygenRequest& request,
                                    const CallOptions& call = {}) {
    return post<ServerKeyPair>({"POST", "/v2/pq/dsa/keygen"}, request, call);
  }
  /// `POST /v2/pq/dsa/sign`: ML-DSA (FIPS 204).
  Ret<SignResult> pq_sign(const SignRequest& request, const CallOptions& call = {}) {
    return post<SignResult>({"POST", "/v2/pq/dsa/sign"}, request, call);
  }
  /// `POST /v2/pq/dsa/verify`.
  Ret<VerifyResult> pq_verify(const MlDsaVerifyRequest& request, const CallOptions& call = {}) {
    return post<VerifyResult>({"POST", "/v2/pq/dsa/verify"}, request, call);
  }
  /// `POST /v2/pq/slh-dsa/keygen`: a server-held SLH-DSA key (stateful).
  Ret<ServerKeyPair> pq_hash_sign_keygen(const SlhDsaKeygenRequest& request,
                                         const CallOptions& call = {}) {
    return post<ServerKeyPair>({"POST", "/v2/pq/slh-dsa/keygen"}, request, call);
  }
  /// `POST /v2/pq/slh-dsa/sign`: SLH-DSA (FIPS 205).
  Ret<SignResult> pq_hash_sign(const SignRequest& request, const CallOptions& call = {}) {
    return post<SignResult>({"POST", "/v2/pq/slh-dsa/sign"}, request, call);
  }
  /// `POST /v2/pq/slh-dsa/verify`.
  Ret<VerifyResult> pq_hash_verify(const SlhDsaVerifyRequest& request,
                                   const CallOptions& call = {}) {
    return post<VerifyResult>({"POST", "/v2/pq/slh-dsa/verify"}, request, call);
  }

  // --- Boxes, streams and multi-recipient encryption ---

  /// `POST /v2/sealedbox/seal`.
  Ret<SealResult> sealedbox_seal(const SealedboxSealRequest& request,
                                 const CallOptions& call = {}) {
    return post<SealResult>({"POST", "/v2/sealedbox/seal"}, request, call);
  }
  /// `POST /v2/sealedbox/open`: with a server-held X25519 key.
  Ret<OpenedText> sealedbox_open(const SealedboxOpenRequest& request,
                                 const CallOptions& call = {}) {
    return post<OpenedText>({"POST", "/v2/sealedbox/open"}, request, call);
  }
  /// `POST /v2/sealedbox/seal-pq`.
  Ret<SealResult> sealedbox_seal_pq(const SealedboxSealPqRequest& request,
                                    const CallOptions& call = {}) {
    return post<SealResult>({"POST", "/v2/sealedbox/seal-pq"}, request, call);
  }
  /// `POST /v2/sealedbox/open-pq`: with a server-held hybrid key.
  Ret<OpenedText> sealedbox_open_pq(const SealedboxOpenRequest& request,
                                    const CallOptions& call = {}) {
    return post<OpenedText>({"POST", "/v2/sealedbox/open-pq"}, request, call);
  }
  /// `POST /v2/stream/pq-encrypt`.
  Ret<StreamPqEncryptResult> stream_pq_encrypt(const StreamPqEncryptRequest& request,
                                               const CallOptions& call = {}) {
    return post<StreamPqEncryptResult>({"POST", "/v2/stream/pq-encrypt"}, request, call);
  }
  /// `POST /v2/stream/pq-decrypt`.
  Ret<StreamPqDecryptResult> stream_pq_decrypt(const StreamPqDecryptRequest& request,
                                               const CallOptions& call = {}) {
    return post<StreamPqDecryptResult>({"POST", "/v2/stream/pq-decrypt"}, request, call);
  }
  /// `POST /v2/stream/multi-pq-encrypt`.
  Ret<StreamMultiPqEncryptResult> stream_multi_pq_encrypt(
      const StreamMultiPqEncryptRequest& request, const CallOptions& call = {}) {
    return post<StreamMultiPqEncryptResult>({"POST", "/v2/stream/multi-pq-encrypt"}, request, call);
  }
  /// `POST /v2/stream/multi-pq-decrypt`.
  Ret<StreamMultiPqDecryptResult> stream_multi_pq_decrypt(
      const StreamMultiPqDecryptRequest& request, const CallOptions& call = {}) {
    return post<StreamMultiPqDecryptResult>({"POST", "/v2/stream/multi-pq-decrypt"}, request, call);
  }
  /// `POST /v2/multi-recipient/encrypt`.
  Ret<MultiRecipientEncryptResult> multi_recipient_encrypt(
      const MultiRecipientEncryptRequest& request, const CallOptions& call = {}) {
    return post<MultiRecipientEncryptResult>({"POST", "/v2/multi-recipient/encrypt"}, request,
                                             call);
  }

  // --- HPKE (RFC 9180) ---

  /// `POST /v2/hpke/keygen`: a server-held HPKE key (stateful).
  Ret<ServerKeyPair> hpke_generate_key_pair(const HpkeKeygenRequest& request = {},
                                            const CallOptions& call = {}) {
    return post<ServerKeyPair>({"POST", "/v2/hpke/keygen"}, request, call);
  }
  /// `POST /v2/hpke/seal`.
  Ret<HpkeSealResult> hpke_seal(const HpkeSealRequest& request, const CallOptions& call = {}) {
    return post<HpkeSealResult>({"POST", "/v2/hpke/seal"}, request, call);
  }
  /// `POST /v2/hpke/open`: with a server-held key.
  Ret<HpkeOpenResult> hpke_open(const HpkeOpenRequest& request, const CallOptions& call = {}) {
    return post<HpkeOpenResult>({"POST", "/v2/hpke/open"}, request, call);
  }

  // --- KMS ---

  /// `POST /v2/kms/create-key` (stateful).
  Ret<KmsKey> kms_create_key(const KmsCreateKeyRequest& request = {},
                             const CallOptions& call = {}) {
    return post<KmsKey>({"POST", "/v2/kms/create-key"}, request, call);
  }
  /// `POST /v2/kms/encrypt`.
  Ret<KmsEncryptResult> kms_encrypt(const KmsEncryptRequest& request,
                                    const CallOptions& call = {}) {
    return post<KmsEncryptResult>({"POST", "/v2/kms/encrypt"}, request, call);
  }
  /// `POST /v2/kms/decrypt`.
  Ret<KmsDecryptResult> kms_decrypt(const KmsDecryptRequest& request,
                                    const CallOptions& call = {}) {
    return post<KmsDecryptResult>({"POST", "/v2/kms/decrypt"}, request, call);
  }
  /// `POST /v2/kms/generate-data-key`.
  Ret<KmsDataKey> kms_generate_data_key(const KmsGenerateDataKeyRequest& request,
                                        const CallOptions& call = {}) {
    return post<KmsDataKey>({"POST", "/v2/kms/generate-data-key"}, request, call);
  }
  /// `POST /v2/kms/wrap`.
  Ret<KmsWrapResult> kms_wrap(const KmsWrapRequest& request, const CallOptions& call = {}) {
    return post<KmsWrapResult>({"POST", "/v2/kms/wrap"}, request, call);
  }
  /// `POST /v2/kms/unwrap`.
  Ret<KmsUnwrapResult> kms_unwrap(const KmsUnwrapRequest& request, const CallOptions& call = {}) {
    return post<KmsUnwrapResult>({"POST", "/v2/kms/unwrap"}, request, call);
  }

  // --- OPAQUE ---

  /// `POST /v2/opaque/register/init` (stateful).
  Ret<OpaqueRegisterInitResult> opaque_register_init(const OpaqueRegisterInitRequest& request,
                                                     const CallOptions& call = {}) {
    return post<OpaqueRegisterInitResult>({"POST", "/v2/opaque/register/init"}, request, call);
  }
  /// `POST /v2/opaque/register/finish` (stateful).
  Ret<OpaqueRegisterFinishResult> opaque_register_finish(const OpaqueRegisterFinishRequest& request,
                                                         const CallOptions& call = {}) {
    return post<OpaqueRegisterFinishResult>({"POST", "/v2/opaque/register/finish"}, request, call);
  }
  /// `POST /v2/opaque/login/init`.
  Ret<OpaqueLoginInitResult> opaque_login_init(const OpaqueLoginInitRequest& request,
                                               const CallOptions& call = {}) {
    return post<OpaqueLoginInitResult>({"POST", "/v2/opaque/login/init"}, request, call);
  }
  /// `POST /v2/opaque/login/finish`.
  Ret<OpaqueLoginFinishResult> opaque_login_finish(const OpaqueLoginFinishRequest& request,
                                                   const CallOptions& call = {}) {
    return post<OpaqueLoginFinishResult>({"POST", "/v2/opaque/login/finish"}, request, call);
  }

 private:
  friend Derived;
  Operations() = default;

  template <typename Result, typename Request>
  Ret<Result> post(const detail::Route& route, const Request& request, const CallOptions& call) {
    return static_cast<Derived*>(this)->template dispatch<Result>(route, detail::encode(request),
                                                                  call);
  }

  template <typename Result>
  Ret<Result> get(const detail::Route& route, const CallOptions& call) {
    return static_cast<Derived*>(this)->template dispatch<Result>(route, std::nullopt, call);
  }
};

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_OPERATIONS_HPP
