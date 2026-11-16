// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The kit runner itself, without a server: the vendored kit is intact
// (SHA256SUMS), the pinned server commit is recorded, and the template
// matcher, pattern subset, substitution, captures and token minting
// behave as conformance/README.md says.

#include <gtest/gtest.h>

#include <fstream>
#include <string>

#include "support/kit.hpp"
#include "support/pattern.hpp"
#include "support/sha256.hpp"

namespace crypto_service {
namespace {

using kit::json;

TEST(Kit, VendoredFilesMatchTheirChecksums) {
  EXPECT_TRUE(kit::checksum_mismatches().empty());
  for (const std::string& name : kit::vector_files()) {
    EXPECT_NO_THROW((void)kit::read_kit_file(name)) << name;
  }
  EXPECT_THROW((void)kit::read_kit_file("absent.json"), std::runtime_error);
}

TEST(Kit, ServerRefIsAFullCommit) {
  std::ifstream in(kit::kit_dir() + "/../ci/server.ref");
  std::string ref;
  in >> ref;
  EXPECT_EQ(ref.size(), 40U);
  EXPECT_EQ(ref.find_first_not_of("0123456789abcdef"), std::string::npos);
}

TEST(Kit, TemplatesMatchExactly) {
  std::string why;
  EXPECT_TRUE(
      kit::matches(json({{"a", 1}, {"b", {1, "x"}}}), json({{"b", {1, "x"}}, {"a", 1}}), why));
  EXPECT_FALSE(kit::matches(json({{"a", 1}}), json({{"a", 1}, {"b", 2}}), why));
  EXPECT_EQ(why, "/: has extra member b");
  EXPECT_FALSE(kit::matches(json({{"a", 1}}), json::object(), why));
  EXPECT_FALSE(kit::matches(json({1, 2}), json({1}), why));
  EXPECT_FALSE(kit::matches(json({1, 2}), json({1, 3}), why));
  EXPECT_FALSE(kit::matches(json("x"), json({{"x", 1}}), why));
  EXPECT_TRUE(kit::matches(json(200), json(200.0), why));
}

TEST(Kit, ShapesUseTheSchemaSubset) {
  std::string why;
  const json shape = {
      {"$shape",
       {{"type", "object"},
        {"required", {"id"}},
        {"properties", {{"id", {{"type", "string"}, {"format", "uuid"}}}}},
        {"additionalProperties", {{"type", "array"}, {"items", {{"type", "integer"}}}}}}}};
  EXPECT_TRUE(kit::matches(
      shape, json({{"id", "0b8e6f1a-3c2d-4e5f-8a9b-0c1d2e3f4a5b"}, {"n", {1, 2}}}), why));
  EXPECT_FALSE(kit::matches(shape, json({{"id", "nope"}}), why));
  EXPECT_FALSE(kit::matches(shape, json({{"n", {1}}}), why));
  EXPECT_FALSE(kit::matches(
      shape, json({{"id", "0b8e6f1a-3c2d-4e5f-8a9b-0c1d2e3f4a5b"}, {"n", {"x"}}}), why));
  EXPECT_TRUE(kit::schema_matches({{"format", "date-time"}}, "2026-11-15T11:03:17.270Z", why));
  EXPECT_FALSE(kit::schema_matches({{"format", "date-time"}}, "yesterday", why));
  EXPECT_TRUE(kit::schema_matches({{"const", "1.6"}}, "1.6", why));
  EXPECT_FALSE(kit::schema_matches({{"const", "1.6"}}, "1.5", why));
  EXPECT_FALSE(kit::schema_matches(false, 1, why));
  const std::pair<const char*, json> typed[] = {
      {"string", "x"}, {"integer", 1},    {"number", 1.5},  {"object", json::object()},
      {"array", {1}},  {"boolean", true}, {"null", nullptr}};
  for (const auto& [type, value] : typed) {
    EXPECT_TRUE(kit::schema_matches({{"type", type}}, value, why)) << type;
    EXPECT_FALSE(
        kit::schema_matches({{"type", type}}, json("x") == value ? json(2) : json("x"), why))
        << type;
  }
}

TEST(Kit, PatternSubset) {
  EXPECT_TRUE(kit::pattern_matches("^[0-9a-f]{4}$", "0a9f"));
  EXPECT_FALSE(kit::pattern_matches("^[0-9a-f]{4}$", "0a9"));
  EXPECT_FALSE(kit::pattern_matches("^[0-9a-f]{4}$", "0a9fe"));
  EXPECT_TRUE(kit::pattern_matches("^([0-9a-f]{2})*$", ""));
  EXPECT_FALSE(kit::pattern_matches("^([0-9a-f]{2})*$", "abc"));
  EXPECT_TRUE(kit::pattern_matches("^[A-Za-z0-9+/]*={0,2}$", "Zm8="));
  EXPECT_FALSE(kit::pattern_matches("^[A-Za-z0-9+/]*={0,2}$", "Zm8==="));
  EXPECT_TRUE(kit::pattern_matches("^\\$argon2id\\$v=19\\$", "$argon2id$v=19$m=1"));
  EXPECT_TRUE(kit::pattern_matches("^\"[0-9]+\\.[0-9]+\"$", "\"1.20\""));
  EXPECT_TRUE(kit::pattern_matches("^urn:uuid:", "urn:uuid:x"));
  EXPECT_TRUE(kit::pattern_matches("^a?b+$", "bb"));
  EXPECT_TRUE(kit::pattern_matches("^k_[A-Za-z0-9_-]{22}$", "k_AAAAAAAAAAAAAAAAAAAAAA"));
  EXPECT_TRUE(kit::pattern_matches("^[0-9a-f]{34176}$", std::string(34176, 'a')));
  EXPECT_THROW(kit::pattern_matches("abc", "abc"), std::invalid_argument);
  EXPECT_THROW(kit::pattern_matches("^(ab", "ab"), std::invalid_argument);
  EXPECT_THROW(kit::pattern_matches("^a{2", "aa"), std::invalid_argument);
}

TEST(Kit, SubstitutionAndCaptures) {
  const kit::Captures captures = {{"key", "k_1"}, {"n", "2"}};
  EXPECT_EQ(kit::substitute(json({{"a", "${key}/${key}"}, {"b", {"${n}"}}, {"c", 3}}), captures),
            json({{"a", "k_1/k_1"}, {"b", {"2"}}, {"c", 3}}));
  const json body = {{"data", {{"keyId", "k_9"}, {"count", 4}}}};
  EXPECT_EQ(kit::capture(body, "/data/keyId"), "k_9");
  EXPECT_EQ(kit::capture(body, "/data/count"), "4");
  EXPECT_FALSE(kit::capture(body, "/data/none"));
}

TEST(Kit, TokensAreHs256) {
  // RFC 4231 test case 2.
  EXPECT_EQ(kit::base64url(kit::hmac_sha256("Jefe", "what do ya want for nothing?")),
            "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM");
  EXPECT_EQ(kit::base64url("f"), "Zg");
  EXPECT_EQ(kit::base64url("fo"), "Zm8");
  const json claims = kit::token_claims("conformance-hash", {"crypto:hash"}, 1000, "iss", "aud");
  EXPECT_EQ(claims.at("exp"), 1300);
  EXPECT_EQ(claims.at("aud"), "aud");
  const std::string token = kit::mint_token("secret", claims);
  EXPECT_EQ(token.substr(0, token.find('.')), kit::base64url(R"({"alg":"HS256","typ":"JWT"})"));
  EXPECT_EQ(kit::sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

}  // namespace
}  // namespace crypto_service
