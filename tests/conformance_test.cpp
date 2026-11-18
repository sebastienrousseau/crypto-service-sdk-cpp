// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// The conformance kit against a live crypto-server, one test per vector
// file, vectors in order with captures carried forward. Typed methods
// run wherever the vector's body is one they can express; their decoded
// result must match the template exactly (no missing or extra members),
// so a gap in a result struct fails here.
//
// Environment: CRYPTO_SERVICE_URL (skips without it), and for the vectors
// that need tokens with given scopes, CRYPTO_SERVICE_JWT_SECRET (the
// server's JWT_SECRET; CRYPTO_SERVICE_JWT_ISSUER/_AUDIENCE when the
// server sets JWT_ISSUER/JWT_AUDIENCE). With the secret every file runs
// as its own principal (`conformance-<group>`), as the kit requires;
// without it, admin vectors use CRYPTO_SERVICE_API_KEY and the others
// skip. `make conformance` fails on any skip.

#include <gtest/gtest.h>

#include <cstdlib>
#include <ctime>
#include <exception>
#include <iostream>
#include <optional>
#include <string>

#include "support/dispatch.hpp"
#include "support/kit.hpp"

namespace crypto_service {
namespace {

using kit::json;

std::optional<std::string> env(const char* name) {
  const char* value = std::getenv(name);
  return value != nullptr && *value != '\0' ? std::optional<std::string>(value) : std::nullopt;
}

// Client options for a vector's `auth`, or nullopt when it needs a
// token and no JWT secret is set.
std::optional<ClientOptions> options_for(const json& auth, const std::string& group) {
  ClientOptions options;
  options.base_url = env("CRYPTO_SERVICE_URL").value_or("");
  options.timeout = std::chrono::seconds(60);
  // Some routes have their own per-address limit in a one-minute window
  // (password hash and verify: 5; SLH-DSA keygen and sign: 10). A 429
  // was not processed, so waiting out its Retry-After (up to the whole
  // window) keeps back-to-back runs, and the other SDKs' runs against
  // the same server, from failing.
  options.retry.max_retries = 3;
  options.retry.max_delay = std::chrono::seconds(60);
  if (auth == "none") {
    return options;
  }
  const json scopes = auth.is_object() ? auth.at("scopes") : json::array({"crypto:admin"});
  if (const auto secret = env("CRYPTO_SERVICE_JWT_SECRET")) {
    const json claims =
        kit::token_claims("conformance-" + group, scopes, std::time(nullptr),
                          env("CRYPTO_SERVICE_JWT_ISSUER"), env("CRYPTO_SERVICE_JWT_AUDIENCE"));
    options.token = kit::mint_token(*secret, claims);
    return options;
  }
  if (auth.is_object()) {
    return std::nullopt;
  }
  options.api_key = env("CRYPTO_SERVICE_API_KEY");
  return options;
}

void check_headers(const json& expect, const kit::VectorOutcome& got) {
  const json headers = expect.value("headers", json::object());
  for (const auto& [name, value] : headers.items()) {
    const auto header = HttpResponse{0, "", got.headers}.header(name);
    EXPECT_EQ(header.value_or("<absent>"), value.get<std::string>()) << name;
  }
}

void check_outcome(const json& expect, const kit::VectorOutcome& got, std::string& why) {
  EXPECT_EQ(got.status, expect.at("status").get<long>()) << got.raw_body.dump().substr(0, 400);
  if (expect.contains("mediaType")) {
    EXPECT_EQ(got.media_type, expect["mediaType"].get<std::string>());
  }
  check_headers(expect, got);
  if (expect.contains("body")) {
    EXPECT_TRUE(kit::matches(expect["body"], got.body, why)) << why;
    EXPECT_TRUE(kit::matches(expect["body"], got.raw_body, why)) << "server body: " << why;
  }
}

class Conformance : public ::testing::TestWithParam<std::string> {};

TEST_P(Conformance, Vectors) {
  if (!env("CRYPTO_SERVICE_URL")) {
    GTEST_SKIP() << "set CRYPTO_SERVICE_URL to run the conformance kit";
  }
  const json file = json::parse(kit::read_kit_file(GetParam()));
  const std::string group = file.at("group").get<std::string>();
  kit::Captures captures;
  int typed = 0;
  int raw = 0;
  int skipped = 0;
  for (const json& vector : file.at("vectors")) {
    const std::string id = vector.at("id").get<std::string>();
    SCOPED_TRACE(id);
    const auto options = options_for(vector.value("auth", json("admin")), group);
    if (!options) {
      ++skipped;
      continue;
    }
    const json request = kit::substitute(vector.at("request"), captures);
    kit::VectorOutcome got;
    try {
      got = kit::run_vector(*options, request);
    } catch (const std::exception& e) {
      ADD_FAILURE() << id << ": " << e.what();
      continue;
    }
    (got.typed ? typed : raw) += 1;
    std::string why;
    check_outcome(kit::substitute(vector.at("expect"), captures), got, why);
    const json wanted = vector.value("capture", json::object());
    for (const auto& [name, pointer] : wanted.items()) {
      const auto value = kit::capture(got.raw_body, pointer.get<std::string>());
      ASSERT_TRUE(value.has_value()) << "capture " << name;
      captures[name] = value.value_or("");
    }
    if (!got.typed) {
      std::cout << "  [raw] " << id << ": " << got.route.substr(0, 120) << "\n";
    }
  }
  std::cout << "  " << GetParam() << ": " << typed << " typed, " << raw << " raw, " << skipped
            << " skipped\n";
  if (skipped > 0) {
    GTEST_SKIP() << skipped << " vectors need CRYPTO_SERVICE_JWT_SECRET";
  }
}

INSTANTIATE_TEST_SUITE_P(Kit, Conformance, ::testing::ValuesIn(kit::vector_files()),
                         [](const auto& info) {
                           std::string name = info.param.substr(0, info.param.find('.'));
                           for (char& c : name) {
                             c = c == '-' ? '_' : c;
                           }
                           return name;
                         });

}  // namespace
}  // namespace crypto_service
