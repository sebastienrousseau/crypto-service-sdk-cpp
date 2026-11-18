// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// RFC 9457 problems from error responses, the about:blank fallback, the
// error types, response helpers and the decoding of 2xx bodies.

#include <gtest/gtest.h>

#include <string>

#include "crypto_service/crypto_service.hpp"
#include "problem.hpp"

namespace crypto_service {
namespace {

using nlohmann::json;

HttpResponse response(long status, const std::string& body) {
  return HttpResponse{status, body, {}};
}

TEST(Problem, ServerProblemIsKeptWithExtensions) {
  const json body = {{"type", "urn:crypto-service:problem:validation-failed"},
                     {"title", "Validation failed"},
                     {"status", 400},
                     {"detail", "body must have required property 'data'"},
                     {"instance", "/v2/hash"},
                     {"code", "X"},
                     {"errors",
                      {{{"field", "/data"}, {"message", "is required"}},
                       {{"field", 1}},
                       {{"field", "/x"}, {"message", 1}},
                       "not an object"}},
                     {"limit", 60}};
  const Problem problem = detail::problem_of(response(400, body.dump()));
  EXPECT_EQ(problem.type, "urn:crypto-service:problem:validation-failed");
  EXPECT_EQ(problem.title, "Validation failed");
  EXPECT_EQ(problem.status, 400);
  EXPECT_EQ(problem.detail, "body must have required property 'data'");
  EXPECT_EQ(problem.instance, "/v2/hash");
  EXPECT_EQ(problem.code, "X");
  ASSERT_EQ(problem.errors.size(), 1U);
  EXPECT_EQ(problem.errors[0].field, "/data");
  EXPECT_EQ(problem.extensions, json({{"limit", 60}}));
}

TEST(Problem, MissingMembersGetDefaults) {
  const Problem problem = detail::problem_of(response(
      429, json({{"detail", "slow down"}, {"type", 7}, {"errors", "x"}, {"instance", 5}}).dump()));
  EXPECT_EQ(problem.type, "about:blank");
  EXPECT_EQ(problem.title, "Too Many Requests");
  EXPECT_FALSE(problem.instance);
  EXPECT_TRUE(problem.errors.empty());
}

TEST(Problem, NonProblemBodiesBecomeAboutBlank) {
  for (const std::string body : {"<html>bad gateway</html>", "", "[]", R"({"detail":1})"}) {
    const Problem problem = detail::problem_of(response(502, body));
    EXPECT_EQ(problem.type, "about:blank");
    EXPECT_EQ(problem.title, "Bad Gateway");
    EXPECT_EQ(problem.status, 502);
    EXPECT_EQ(problem.detail, "The server answered 502 without a problem body");
  }
  EXPECT_EQ(detail::problem_of(response(418, "")).title, "HTTP error");
}

TEST(Problem, ApiErrorMessageNamesStatusAndTypeOnly) {
  Problem problem;
  problem.status = 404;
  problem.type = "urn:crypto-service:problem:key-not-found";
  problem.detail = "secret detail";
  const ApiError error(problem);
  EXPECT_EQ(std::string(error.what()),
            "crypto-service: HTTP 404 (urn:crypto-service:problem:key-not-found)");
  EXPECT_EQ(error.status(), 404);
  EXPECT_EQ(error.problem().detail, "secret detail");
}

TEST(Problem, ApiErrorMessageReplacesControlCharactersInTheType) {
  Problem problem;
  problem.status = 400;
  problem.type = std::string("urn:x\r\ny\0z\x7f", 11);
  const ApiError error(problem);
  EXPECT_EQ(std::string(error.what()), "crypto-service: HTTP 400 (urn:x??y?z?)");
  EXPECT_EQ(error.problem().type, problem.type);  // the problem itself is unchanged
}

TEST(Problem, RequireSuccess) {
  EXPECT_NO_THROW(detail::require_success(response(200, "")));
  EXPECT_NO_THROW(detail::require_success(response(299, "")));
  EXPECT_THROW(detail::require_success(response(199, "")), ApiError);
  EXPECT_THROW(detail::require_success(response(300, "")), ApiError);
}

TEST(Problem, TransportErrorFlags) {
  EXPECT_FALSE(TransportError("x").timed_out());
  EXPECT_TRUE(TransportError("x", true).timed_out());
  const CancelledError cancelled("c");
  const TransportError& base = cancelled;
  EXPECT_FALSE(base.timed_out());
}

TEST(Response, HeaderLookupIsCaseInsensitive) {
  const HttpResponse r{200, "", {{"Retry-After", "1"}, {"X", "2"}}};
  EXPECT_EQ(r.header("retry-after"), "1");
  EXPECT_EQ(r.header("RETRY-AFTEX"), std::nullopt);
  EXPECT_EQ(r.header("Y"), std::nullopt);
}

TEST(Response, RawJson) {
  EXPECT_EQ((RawResponse{200, R"({"a":1})", {}}.json()), json({{"a", 1}}));
  EXPECT_TRUE((RawResponse{200, "not json", {}}.json()).is_null());
}

TEST(Decode, ShapeErrorsAreTransportErrors) {
  const auto decode = [](const std::string& body, bool wrapped) {
    return detail::decode<HashResult>(response(200, body), wrapped);
  };
  EXPECT_THROW(decode("not json", true), TransportError);
  EXPECT_THROW(decode("[]", true), TransportError);
  EXPECT_THROW(decode(R"({"other":1})", true), TransportError);
  EXPECT_THROW(decode(R"({"data":{"algorithm":1}})", true), TransportError);
  EXPECT_EQ(decode(R"({"algorithm":"a","digest":"00","length":1})", false).length, 1);
}

TEST(Encode, InvalidUtf8IsRejected) {
  HashRequest request;
  request.data = std::string("\xff\xfe", 2);
  EXPECT_THROW((void)detail::encode(request), std::invalid_argument);
}

}  // namespace
}  // namespace crypto_service
