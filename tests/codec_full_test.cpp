// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Every request and result struct, with every member set (optionals
// present, arrays with one element), encoded and decoded back: each
// schema entry is exercised in both directions.

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include "codec.hpp"
#include "crypto_service/crypto_service.hpp"
#include "schemas.hpp"

namespace crypto_service {
namespace {

using detail::codec::Const;
using detail::codec::Field;
using detail::codec::Schema;
using nlohmann::json;

template <typename T>
struct Maker;

template <typename T>
T make() {
  return Maker<T>::make();
}

template <typename S, typename M>
void fill_field(S& value, const Field<S, M>& f) {
  value.*(f.member) = make<M>();
}

template <typename S>
void fill_field(S& /*value*/, const Const& /*c*/) {}

template <typename T>
struct Maker {
  static T make() {
    T value{};
    std::apply([&](const auto&... f) { (fill_field(value, f), ...); }, Schema<T>::fields());
    return value;
  }
};
template <>
struct Maker<std::string> {
  static std::string make() { return "s"; }
};
template <>
struct Maker<Bytes> {
  static Bytes make() { return Bytes{0x01, 0xfe}; }
};
template <>
struct Maker<std::int64_t> {
  static std::int64_t make() { return 7; }
};
template <>
struct Maker<double> {
  static double make() { return 1.5; }
};
template <>
struct Maker<bool> {
  static bool make() { return true; }
};
template <>
struct Maker<json> {
  static json make() { return json{{"k", 1}}; }
};
template <>
struct Maker<StringMap> {
  static StringMap make() { return StringMap{{"a", "b"}}; }
};
template <typename T>
struct Maker<std::vector<T>> {
  static std::vector<T> make() { return {crypto_service::make<T>()}; }
};
template <typename T>
struct Maker<std::optional<T>> {
  static std::optional<T> make() { return crypto_service::make<T>(); }
};

template <typename... Ts>
void round_trip_all() {
  (
      [] {
        const json full = detail::codec::to_json(make<Ts>());
        const json empty = detail::codec::to_json(Ts{});
        EXPECT_EQ(detail::codec::to_json(detail::codec::from_json<Ts>(full, "data")), full);
        EXPECT_EQ(detail::codec::to_json(detail::codec::from_json<Ts>(empty, "data")), empty);
      }(),
      ...);
}

TEST(CodecFull, Requests) {
  round_trip_all<
      EncryptRequest, DecryptRequest, SecretboxSealRequest, SecretboxOpenRequest,
      PasswordEncryptRequest, PasswordDecryptRequest, KeyWrapRequest, KeyUnwrapRequest, HashRequest,
      HmacRequest, HmacVerifyRequest, KdfRequest, PasswordHashRequest, PasswordVerifyRequest,
      GenerateKeyPairRequest, KeyIdRequest, SignRequest, VerifyRequest, StreamSignRequest,
      StreamVerifyRequest, Iso20022VerifyRequest, MlKemEncapsulateRequest, MlKemDecapsulateRequest,
      HybridEncapsulateRequest, HybridDecapsulateRequest, MlDsaKeygenRequest, MlDsaVerifyRequest,
      SlhDsaKeygenRequest, SlhDsaVerifyRequest, SealedboxSealRequest, SealedboxOpenRequest,
      SealedboxSealPqRequest, StreamPqEncryptRequest, StreamPqDecryptRequest,
      StreamMultiPqEncryptRequest, StreamMultiPqDecryptRequest, MultiRecipientEncryptRequest,
      HpkeKeygenRequest, HpkeSealRequest, HpkeOpenRequest, KmsCreateKeyRequest, KmsEncryptRequest,
      KmsDecryptRequest, KmsGenerateDataKeyRequest, KmsWrapRequest, KmsUnwrapRequest,
      OpaqueRegisterInitRequest, OpaqueRegisterFinishRequest, OpaqueLoginInitRequest,
      OpaqueLoginFinishRequest>();
}

TEST(CodecFull, Results) {
  round_trip_all<
      ServiceInfo, HealthStatus, LiveStatus, ReadyStatus, Algorithms, DoraScorecard, Cbom,
      EncryptResult, DecryptResult, SealResult, OpenedText, PasswordEncryptResult, KeyWrapResult,
      KeyUnwrapResult, HashResult, HmacResult, HmacVerifyResult, KdfResult, PasswordHashResult,
      PasswordVerifyResult, GenerateKeyPairResult, ExportKeyResult, DeleteKeyResult, SignResult,
      VerifyResult, StreamSignResult, StreamVerifyResult, Iso20022VerifyResult, ServerKeyPair,
      MlKemEncapsulateResult, SharedSecretResult, HybridKeyPair, HybridEncapsulateResult,
      HybridDecapsulateResult, StreamPqEncryptResult, StreamPqDecryptResult,
      StreamMultiPqEncryptResult, StreamMultiPqDecryptResult, MultiRecipientEncryptResult,
      HpkeSealResult, HpkeOpenResult, KmsKey, KmsEncryptResult, KmsDecryptResult, KmsDataKey,
      KmsWrapResult, KmsUnwrapResult, OpaqueRegisterInitResult, OpaqueRegisterFinishResult,
      OpaqueLoginInitResult, OpaqueLoginFinishResult>();
}

}  // namespace
}  // namespace crypto_service
