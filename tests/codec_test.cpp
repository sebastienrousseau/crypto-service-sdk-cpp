// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The table-driven codec: every value type in both directions, optional
// members present and absent, bare `data` values, the constant KMS
// encoding member, and every decode failure. The wire names of each
// struct are checked by the conformance kit against a live server.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "codec.hpp"
#include "crypto_service/crypto_service.hpp"
#include "schemas.hpp"

namespace crypto_service {
namespace {

using detail::codec::DecodeError;
// Qualified calls: an unqualified one also finds nlohmann::from_json by
// ADL, which GCC 16 rejects when given an explicit template argument.
namespace codec = detail::codec;
using detail::codec::to_json;
using nlohmann::json;

template <typename T>
void round_trip(const json& wire) {
  const T decoded = codec::from_json<T>(wire, "body");
  EXPECT_EQ(to_json(decoded), wire) << wire.dump();
}

TEST(Codec, ScalarsBytesAndOptionalMembers) {
  round_trip<KdfRequest>(
      {{"algorithm", "hkdf-sha256"},
       {"password", "pw"},
       {"salt", "0001"},
       {"keyLength", 32},
       {"params", {{"N", 131072}, {"r", 8}, {"p", 1}, {"iterations", 1}, {"info", "i"}}}});
  round_trip<KdfRequest>({{"algorithm", "scrypt"}, {"password", "pw"}});
  round_trip<HealthStatus>({{"status", "ok"}, {"statusCode", 200}, {"uptime", 1.5}});
  round_trip<HmacVerifyResult>({{"algorithm", "sha256"}, {"valid", true}});
  round_trip<EncryptResult>({{"algorithm", "xchacha20-poly1305"}, {"ciphertext", "AAEC"}});
}

TEST(Codec, ArraysMapsJsonAndNestedOptionals) {
  round_trip<Algorithms>({{"encryption", {"a"}},
                          {"hashing", json::array()},
                          {"kdf", {"k"}},
                          {"keyExchange", {"x"}},
                          {"mac", {"m"}},
                          {"postQuantum", {"p"}},
                          {"signing", {"s"}}});
  round_trip<KmsCreateKeyRequest>({{"metadata", {{"team", "a"}}}, {"usage", "wrap"}});
  round_trip<Cbom>(
      {{"bomFormat", "CycloneDX"},
       {"components",
        {{{"name", "n"}, {"properties", {{{"name", "a"}, {"value", "b"}}}}}, json::object()}},
       {"metadata", {{"tools", json::array()}}},
       {"serialNumber", "urn:uuid:0"},
       {"specVersion", "1.6"},
       {"version", 1}});
  round_trip<GenerateKeyPairRequest>({{"metadata", {{"kid", "k"}, {"use", "sig"}}}});
  round_trip<MultiRecipientEncryptResult>({{"algorithm", "a"},
                                           {"ciphertext", ""},
                                           {"recipients",
                                            {{{"ephemeralPublicKey", "00"},
                                              {"mlKemCiphertext", "01"},
                                              {"type", "t"},
                                              {"wrappedKey", "AA=="}}}}});
}

TEST(Codec, BareDataValues) {
  EXPECT_EQ(codec::from_json<OpenedText>(json("secret"), "data").plaintext, "secret");
  EXPECT_EQ(to_json(OpenedText{"secret"}), json("secret"));
  EXPECT_EQ(codec::from_json<KeyUnwrapResult>(json("00ff"), "data").key, (Bytes{0x00, 0xff}));
  EXPECT_THROW(codec::from_json<OpenedText>(json(), "data"), DecodeError);
}

TEST(Codec, KmsEncryptAlwaysSendsHex) {
  KmsEncryptRequest request;
  request.key_id = "local-1";
  request.plaintext = to_bytes("hi");
  EXPECT_EQ(to_json(request),
            json({{"encoding", "hex"}, {"keyId", "local-1"}, {"plaintext", "6869"}}));
  // The constant member is ignored when decoding.
  EXPECT_EQ(
      codec::from_json<KmsEncryptRequest>(json({{"keyId", "k"}, {"plaintext", "00"}}), "b").key_id,
      "k");
}

TEST(Codec, NullOptionalIsAbsent) {
  const auto metadata = codec::from_json<KeyMetadata>(json({{"kid", nullptr}}), "metadata");
  EXPECT_FALSE(metadata.kid);
}

TEST(Codec, DecodeFailuresNameTheMember) {
  const auto fails = [](const json& wire, const char* member) {
    try {
      (void)codec::from_json<HashResult>(wire, "data");
      ADD_FAILURE() << "decoded " << wire.dump();
    } catch (const DecodeError& e) {
      EXPECT_NE(std::string(e.what()).find(member), std::string::npos) << e.what();
    }
  };
  const json good = {{"algorithm", "sha256"}, {"digest", "00"}, {"length", 1}};
  fails(json::array(), "algorithm");
  for (const char* name : {"algorithm", "digest", "length"}) {
    json missing = good;
    missing.erase(name);
    fails(missing, name);
  }
  fails({{"algorithm", 1}, {"digest", "00"}, {"length", 1}}, "algorithm");
  fails({{"algorithm", "a"}, {"digest", 1}, {"length", 1}}, "digest");
  fails({{"algorithm", "a"}, {"digest", "0"}, {"length", 1}}, "digest");
  fails({{"algorithm", "a"}, {"digest", "00"}, {"length", 1.5}}, "length");
  fails({{"algorithm", "a"}, {"digest", "00"}, {"length", 18446744073709551615ULL}}, "length");
}

TEST(Codec, OtherDecodeFailures) {
  EXPECT_THROW(codec::from_json<EncryptResult>({{"algorithm", "a"}, {"ciphertext", "!"}}, "d"),
               DecodeError);
  EXPECT_THROW(
      codec::from_json<HealthStatus>({{"status", "ok"}, {"statusCode", 1}, {"uptime", "1"}}, "d"),
      DecodeError);
  EXPECT_THROW(codec::from_json<HmacVerifyResult>({{"algorithm", "a"}, {"valid", 1}}, "d"),
               DecodeError);
  EXPECT_THROW(codec::from_json<KmsCreateKeyRequest>({{"metadata", json::array()}}, "d"),
               DecodeError);
  EXPECT_THROW(codec::from_json<KmsCreateKeyRequest>({{"metadata", {{"a", 1}}}}, "d"), DecodeError);
  EXPECT_THROW(codec::from_json<Algorithms>({{"encryption", "a"}}, "d"), DecodeError);
}

TEST(Codec, JsonMembersPassThrough) {
  Iso20022VerifyRequest request;
  request.payload = {{"Amt", 1}};
  const json wire = to_json(request);
  EXPECT_EQ(wire.at("payload"), json({{"Amt", 1}}));
  EXPECT_EQ(codec::from_json<Iso20022VerifyRequest>(wire, "body").payload, request.payload);
}

}  // namespace
}  // namespace crypto_service
