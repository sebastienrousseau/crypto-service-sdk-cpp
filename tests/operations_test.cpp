// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// Every typed operation, on both clients, against a fake transport: the
// method and path sent, credentials (none for probes), the body and the
// result decoded from a canned response.

#include <gtest/gtest.h>

#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "codec.hpp"
#include "crypto_service/crypto_service.hpp"
#include "schemas.hpp"
#include "support/fake_transport.hpp"

namespace crypto_service {
namespace {

using kit::FakeState;
using nlohmann::json;

template <typename T>
T resolve(T value) {
  return value;
}

template <typename T>
T resolve(std::future<T> future) {
  return future.get();
}

// The canned body for Result: its default value encoded, wrapped in
// `data` unless the route is unwrapped.
template <typename Result>
std::string canned(bool wrapped) {
  const json value = detail::codec::to_json(Result{});
  return wrapped ? json{{"data", value}}.dump() : value.dump();
}

struct Expect {
  std::string_view method;
  std::string_view path;
  bool wrapped = true;
  bool anonymous = false;
};

void check_request(const HttpRequest& request, const Expect& expect) {
  EXPECT_EQ(request.method, expect.method);
  EXPECT_EQ(request.url, "http://crypto.test" + std::string(expect.path));
  const auto key = HttpResponse{0, "", request.headers}.header("x-api-key");
  EXPECT_EQ(key.has_value(), !expect.anonymous) << expect.path;
  EXPECT_EQ(request.body.has_value(), expect.method == "POST") << expect.path;
}

template <typename Result, typename Call>
void check(const Expect& expect, Call call) {
  SCOPED_TRACE(std::string(expect.path));
  auto state = std::make_shared<FakeState>();
  state->push(kit::reply(200, canned<Result>(expect.wrapped)));
  state->push(kit::reply(200, canned<Result>(expect.wrapped)));
  {
    Client client(kit::fake_options(), std::make_unique<kit::FakeTransport>(state));
    const Result result = resolve(call(client));
    EXPECT_EQ(detail::codec::to_json(result), detail::codec::to_json(Result{}));
  }
  {
    AsyncClient client(kit::fake_options(), std::make_unique<kit::FakeAsyncTransport>(state));
    const Result result = resolve(call(client));
    EXPECT_EQ(detail::codec::to_json(result), detail::codec::to_json(Result{}));
  }
  const auto requests = state->seen();
  ASSERT_EQ(requests.size(), 2U);
  check_request(requests[0], expect);
  check_request(requests[1], expect);
  EXPECT_EQ(requests[0].body, requests[1].body);
}

TEST(Operations, Service) {
  check<ServiceInfo>({"GET", "/", false}, [](auto& c) { return c.root(); });
  check<HealthStatus>({"GET", "/health", false, true}, [](auto& c) { return c.health(); });
  check<LiveStatus>({"GET", "/live", false, true}, [](auto& c) { return c.live(); });
  check<ReadyStatus>({"GET", "/ready", false, true}, [](auto& c) { return c.ready(); });
  check<Algorithms>({"GET", "/v2/algorithms"}, [](auto& c) { return c.algorithms(); });
  check<DoraScorecard>({"GET", "/v2/compliance/dora"},
                       [](auto& c) { return c.get_dora_compliance(); });
  check<Cbom>({"GET", "/v2/compliance/cbom", false}, [](auto& c) { return c.get_cbom(); });
}

TEST(Operations, Symmetric) {
  check<EncryptResult>({"POST", "/v2/encrypt"}, [](auto& c) { return c.encrypt({}); });
  check<DecryptResult>({"POST", "/v2/decrypt"}, [](auto& c) { return c.decrypt({}); });
  check<SealResult>({"POST", "/v2/secretbox/seal"}, [](auto& c) { return c.secretbox_seal({}); });
  check<OpenedText>({"POST", "/v2/secretbox/open"}, [](auto& c) { return c.secretbox_open({}); });
  check<PasswordEncryptResult>({"POST", "/v2/password/encrypt"},
                               [](auto& c) { return c.password_encrypt({}); });
  check<OpenedText>({"POST", "/v2/password/decrypt"},
                    [](auto& c) { return c.password_decrypt({}); });
  check<KeyWrapResult>({"POST", "/v2/keys/wrap"}, [](auto& c) { return c.key_wrap({}); });
  check<KeyUnwrapResult>({"POST", "/v2/keys/unwrap"}, [](auto& c) { return c.key_unwrap({}); });
}

TEST(Operations, Hashing) {
  check<HashResult>({"POST", "/v2/hash"}, [](auto& c) { return c.hash({}); });
  check<HmacResult>({"POST", "/v2/hmac"}, [](auto& c) { return c.mac({}); });
  check<HmacVerifyResult>({"POST", "/v2/hmac/verify"}, [](auto& c) { return c.mac_verify({}); });
  check<KdfResult>({"POST", "/v2/kdf"}, [](auto& c) { return c.kdf({}); });
  check<PasswordHashResult>({"POST", "/v2/password/hash"},
                            [](auto& c) { return c.password_hash({}); });
  check<PasswordVerifyResult>({"POST", "/v2/password/verify"},
                              [](auto& c) { return c.password_verify({}); });
}

TEST(Operations, Keys) {
  check<GenerateKeyPairResult>({"POST", "/v2/keys/generate"},
                               [](auto& c) { return c.generate_key_pair(); });
  check<ExportKeyResult>({"POST", "/v2/keys/export"}, [](auto& c) { return c.export_key({}); });
  check<DeleteKeyResult>({"POST", "/v2/keys/delete"}, [](auto& c) { return c.keys_delete({}); });
  check<SignResult>({"POST", "/v2/sign"}, [](auto& c) { return c.sign({}); });
  check<VerifyResult>({"POST", "/v2/verify"}, [](auto& c) { return c.verify({}); });
  check<StreamSignResult>({"POST", "/v2/stream/sign"}, [](auto& c) { return c.stream_sign({}); });
  check<StreamVerifyResult>({"POST", "/v2/stream/verify"},
                            [](auto& c) { return c.stream_verify({}); });
  check<Iso20022VerifyResult>({"POST", "/v2/stream/iso20022"},
                              [](auto& c) { return c.stream_iso20022({}); });
}

TEST(Operations, PostQuantum) {
  check<ServerKeyPair>({"POST", "/v2/pq/keygen"},
                       [](auto& c) { return c.ml_kem_generate_key_pair(); });
  check<MlKemEncapsulateResult>({"POST", "/v2/pq/encapsulate"},
                                [](auto& c) { return c.ml_kem_encapsulate({}); });
  check<SharedSecretResult>({"POST", "/v2/pq/decapsulate"},
                            [](auto& c) { return c.ml_kem_decapsulate({}); });
  check<HybridKeyPair>({"POST", "/v2/pq/hybrid/keygen"},
                       [](auto& c) { return c.pq_generate_key_pair(); });
  check<HybridEncapsulateResult>({"POST", "/v2/pq/hybrid/encapsulate"},
                                 [](auto& c) { return c.pq_encapsulate({}); });
  check<HybridDecapsulateResult>({"POST", "/v2/pq/hybrid/decapsulate"},
                                 [](auto& c) { return c.pq_decapsulate({}); });
  check<ServerKeyPair>({"POST", "/v2/pq/dsa/keygen"}, [](auto& c) { return c.pq_sign_keygen({}); });
  check<SignResult>({"POST", "/v2/pq/dsa/sign"}, [](auto& c) { return c.pq_sign({}); });
  check<VerifyResult>({"POST", "/v2/pq/dsa/verify"}, [](auto& c) { return c.pq_verify({}); });
  check<ServerKeyPair>({"POST", "/v2/pq/slh-dsa/keygen"},
                       [](auto& c) { return c.pq_hash_sign_keygen({}); });
  check<SignResult>({"POST", "/v2/pq/slh-dsa/sign"}, [](auto& c) { return c.pq_hash_sign({}); });
  check<VerifyResult>({"POST", "/v2/pq/slh-dsa/verify"},
                      [](auto& c) { return c.pq_hash_verify({}); });
}

TEST(Operations, BoxesAndStreams) {
  check<SealResult>({"POST", "/v2/sealedbox/seal"}, [](auto& c) { return c.sealedbox_seal({}); });
  check<OpenedText>({"POST", "/v2/sealedbox/open"}, [](auto& c) { return c.sealedbox_open({}); });
  check<SealResult>({"POST", "/v2/sealedbox/seal-pq"},
                    [](auto& c) { return c.sealedbox_seal_pq({}); });
  check<OpenedText>({"POST", "/v2/sealedbox/open-pq"},
                    [](auto& c) { return c.sealedbox_open_pq({}); });
  check<StreamPqEncryptResult>({"POST", "/v2/stream/pq-encrypt"},
                               [](auto& c) { return c.stream_pq_encrypt({}); });
  check<StreamPqDecryptResult>({"POST", "/v2/stream/pq-decrypt"},
                               [](auto& c) { return c.stream_pq_decrypt({}); });
  check<StreamMultiPqEncryptResult>({"POST", "/v2/stream/multi-pq-encrypt"},
                                    [](auto& c) { return c.stream_multi_pq_encrypt({}); });
  check<StreamMultiPqDecryptResult>({"POST", "/v2/stream/multi-pq-decrypt"},
                                    [](auto& c) { return c.stream_multi_pq_decrypt({}); });
  check<MultiRecipientEncryptResult>({"POST", "/v2/multi-recipient/encrypt"},
                                     [](auto& c) { return c.multi_recipient_encrypt({}); });
}

TEST(Operations, HpkeKmsOpaque) {
  check<ServerKeyPair>({"POST", "/v2/hpke/keygen"},
                       [](auto& c) { return c.hpke_generate_key_pair(); });
  check<HpkeSealResult>({"POST", "/v2/hpke/seal"}, [](auto& c) { return c.hpke_seal({}); });
  check<HpkeOpenResult>({"POST", "/v2/hpke/open"}, [](auto& c) { return c.hpke_open({}); });
  check<KmsKey>({"POST", "/v2/kms/create-key"}, [](auto& c) { return c.kms_create_key(); });
  check<KmsEncryptResult>({"POST", "/v2/kms/encrypt"}, [](auto& c) { return c.kms_encrypt({}); });
  check<KmsDecryptResult>({"POST", "/v2/kms/decrypt"}, [](auto& c) { return c.kms_decrypt({}); });
  check<KmsDataKey>({"POST", "/v2/kms/generate-data-key"},
                    [](auto& c) { return c.kms_generate_data_key({}); });
  check<KmsWrapResult>({"POST", "/v2/kms/wrap"}, [](auto& c) { return c.kms_wrap({}); });
  check<KmsUnwrapResult>({"POST", "/v2/kms/unwrap"}, [](auto& c) { return c.kms_unwrap({}); });
  check<OpaqueRegisterInitResult>({"POST", "/v2/opaque/register/init"},
                                  [](auto& c) { return c.opaque_register_init({}); });
  check<OpaqueRegisterFinishResult>({"POST", "/v2/opaque/register/finish"},
                                    [](auto& c) { return c.opaque_register_finish({}); });
  check<OpaqueLoginInitResult>({"POST", "/v2/opaque/login/init"},
                               [](auto& c) { return c.opaque_login_init({}); });
  check<OpaqueLoginFinishResult>({"POST", "/v2/opaque/login/finish"},
                                 [](auto& c) { return c.opaque_login_finish({}); });
}

TEST(Operations, BodiesUseTheWireNames) {
  auto state = std::make_shared<FakeState>();
  state->push(kit::reply(200, canned<HashResult>(true)));
  Client client(kit::fake_options(), std::make_unique<kit::FakeTransport>(state));
  (void)client.hash({"sha256", "abc"});
  EXPECT_EQ(json::parse(state->seen().at(0).body.value_or("")),
            json({{"algorithm", "sha256"}, {"data", "abc"}}));
}

TEST(Operations, EmptyPostBodyIsAnObject) {
  auto state = std::make_shared<FakeState>();
  state->push(kit::reply(200, canned<HybridKeyPair>(true)));
  Client client(kit::fake_options(), std::make_unique<kit::FakeTransport>(state));
  (void)client.pq_generate_key_pair();
  EXPECT_EQ(state->seen().at(0).body.value_or(""), "{}");
}

}  // namespace
}  // namespace crypto_service
