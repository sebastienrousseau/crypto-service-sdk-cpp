// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// detail::encode and detail::decode for every request and result
// struct, explicitly instantiated so the public templates link against
// them. A 2xx body that does not have the documented shape is a
// TransportError naming the member, never its value.

#include <stdexcept>
#include <string>
#include <string_view>

#include "codec.hpp"
#include "crypto_service/detail/wire.hpp"
#include "crypto_service/errors.hpp"
#include "schemas.hpp"

namespace crypto_service::detail {
namespace {

using nlohmann::json;

// The parsed body, or its `data` member for a wrapped route.
json document_of(const HttpResponse& response, bool wrapped) {
  json body = json::parse(response.body, nullptr, false);
  if (body.is_discarded()) {
    throw TransportError("crypto-service: HTTP " + std::to_string(response.status) +
                         " response body is not JSON");
  }
  if (!wrapped) {
    return body;
  }
  if (!body.is_object() || body.find("data") == body.end()) {
    throw TransportError("crypto-service: response has no `data` member");
  }
  return std::move(body["data"]);
}

}  // namespace

template <typename Request>
std::string encode(const Request& request) {
  try {
    return codec::to_json(request).dump();
  } catch (const json::type_error&) {
    throw std::invalid_argument("crypto-service: request text is not valid UTF-8");
  }
}

template <typename Result>
Result decode(const HttpResponse& response, bool wrapped) {
  const json document = document_of(response, wrapped);
  try {
    return codec::from_json<Result>(document, "data");
  } catch (const codec::DecodeError& e) {
    throw TransportError(std::string("crypto-service: unexpected response shape: ") + e.what());
  }
}

// Every request struct a method sends.
template std::string encode(const EmptyRequest&);
template std::string encode(const EncryptRequest&);
template std::string encode(const DecryptRequest&);
template std::string encode(const SecretboxSealRequest&);
template std::string encode(const SecretboxOpenRequest&);
template std::string encode(const PasswordEncryptRequest&);
template std::string encode(const PasswordDecryptRequest&);
template std::string encode(const KeyWrapRequest&);
template std::string encode(const KeyUnwrapRequest&);
template std::string encode(const HashRequest&);
template std::string encode(const HmacRequest&);
template std::string encode(const HmacVerifyRequest&);
template std::string encode(const KdfRequest&);
template std::string encode(const PasswordHashRequest&);
template std::string encode(const PasswordVerifyRequest&);
template std::string encode(const GenerateKeyPairRequest&);
template std::string encode(const KeyIdRequest&);
template std::string encode(const SignRequest&);
template std::string encode(const VerifyRequest&);
template std::string encode(const StreamSignRequest&);
template std::string encode(const StreamVerifyRequest&);
template std::string encode(const Iso20022VerifyRequest&);
template std::string encode(const MlKemEncapsulateRequest&);
template std::string encode(const MlKemDecapsulateRequest&);
template std::string encode(const HybridEncapsulateRequest&);
template std::string encode(const HybridDecapsulateRequest&);
template std::string encode(const MlDsaKeygenRequest&);
template std::string encode(const MlDsaVerifyRequest&);
template std::string encode(const SlhDsaKeygenRequest&);
template std::string encode(const SlhDsaVerifyRequest&);
template std::string encode(const SealedboxSealRequest&);
template std::string encode(const SealedboxOpenRequest&);
template std::string encode(const SealedboxSealPqRequest&);
template std::string encode(const StreamPqEncryptRequest&);
template std::string encode(const StreamPqDecryptRequest&);
template std::string encode(const StreamMultiPqEncryptRequest&);
template std::string encode(const StreamMultiPqDecryptRequest&);
template std::string encode(const MultiRecipientEncryptRequest&);
template std::string encode(const HpkeKeygenRequest&);
template std::string encode(const HpkeSealRequest&);
template std::string encode(const HpkeOpenRequest&);
template std::string encode(const KmsCreateKeyRequest&);
template std::string encode(const KmsEncryptRequest&);
template std::string encode(const KmsDecryptRequest&);
template std::string encode(const KmsGenerateDataKeyRequest&);
template std::string encode(const KmsWrapRequest&);
template std::string encode(const KmsUnwrapRequest&);
template std::string encode(const OpaqueRegisterInitRequest&);
template std::string encode(const OpaqueRegisterFinishRequest&);
template std::string encode(const OpaqueLoginInitRequest&);
template std::string encode(const OpaqueLoginFinishRequest&);

// Every result struct a method returns.
template ServiceInfo decode(const HttpResponse&, bool);
template HealthStatus decode(const HttpResponse&, bool);
template LiveStatus decode(const HttpResponse&, bool);
template ReadyStatus decode(const HttpResponse&, bool);
template Algorithms decode(const HttpResponse&, bool);
template DoraScorecard decode(const HttpResponse&, bool);
template Cbom decode(const HttpResponse&, bool);
template EncryptResult decode(const HttpResponse&, bool);
template DecryptResult decode(const HttpResponse&, bool);
template SealResult decode(const HttpResponse&, bool);
template OpenedText decode(const HttpResponse&, bool);
template PasswordEncryptResult decode(const HttpResponse&, bool);
template KeyWrapResult decode(const HttpResponse&, bool);
template KeyUnwrapResult decode(const HttpResponse&, bool);
template HashResult decode(const HttpResponse&, bool);
template HmacResult decode(const HttpResponse&, bool);
template HmacVerifyResult decode(const HttpResponse&, bool);
template KdfResult decode(const HttpResponse&, bool);
template PasswordHashResult decode(const HttpResponse&, bool);
template PasswordVerifyResult decode(const HttpResponse&, bool);
template GenerateKeyPairResult decode(const HttpResponse&, bool);
template ExportKeyResult decode(const HttpResponse&, bool);
template DeleteKeyResult decode(const HttpResponse&, bool);
template SignResult decode(const HttpResponse&, bool);
template VerifyResult decode(const HttpResponse&, bool);
template StreamSignResult decode(const HttpResponse&, bool);
template StreamVerifyResult decode(const HttpResponse&, bool);
template Iso20022VerifyResult decode(const HttpResponse&, bool);
template ServerKeyPair decode(const HttpResponse&, bool);
template MlKemEncapsulateResult decode(const HttpResponse&, bool);
template SharedSecretResult decode(const HttpResponse&, bool);
template HybridKeyPair decode(const HttpResponse&, bool);
template HybridEncapsulateResult decode(const HttpResponse&, bool);
template HybridDecapsulateResult decode(const HttpResponse&, bool);
template StreamPqEncryptResult decode(const HttpResponse&, bool);
template StreamPqDecryptResult decode(const HttpResponse&, bool);
template StreamMultiPqEncryptResult decode(const HttpResponse&, bool);
template StreamMultiPqDecryptResult decode(const HttpResponse&, bool);
template MultiRecipientEncryptResult decode(const HttpResponse&, bool);
template HpkeSealResult decode(const HttpResponse&, bool);
template HpkeOpenResult decode(const HttpResponse&, bool);
template KmsKey decode(const HttpResponse&, bool);
template KmsEncryptResult decode(const HttpResponse&, bool);
template KmsDecryptResult decode(const HttpResponse&, bool);
template KmsDataKey decode(const HttpResponse&, bool);
template KmsWrapResult decode(const HttpResponse&, bool);
template KmsUnwrapResult decode(const HttpResponse&, bool);
template OpaqueRegisterInitResult decode(const HttpResponse&, bool);
template OpaqueRegisterFinishResult decode(const HttpResponse&, bool);
template OpaqueLoginInitResult decode(const HttpResponse&, bool);
template OpaqueLoginFinishResult decode(const HttpResponse&, bool);

}  // namespace crypto_service::detail
