// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Hex and base64 against RFC 4648 section 10 test vectors, and every
// malformed-input branch.

#include <gtest/gtest.h>

#include <string>

#include "crypto_service/encoding.hpp"

namespace crypto_service {
namespace {

TEST(Encoding, HexRoundTrip) {
  EXPECT_EQ(to_hex(to_bytes("")), "");
  EXPECT_EQ(to_hex(Bytes{0x00, 0x0f, 0xa5, 0xff}), "000fa5ff");
  EXPECT_EQ(from_hex("000FA5ff"), (Bytes{0x00, 0x0f, 0xa5, 0xff}));
  EXPECT_EQ(from_hex(""), Bytes{});
}

TEST(Encoding, HexRejectsMalformedInput) {
  EXPECT_FALSE(from_hex("abc"));  // odd length
  EXPECT_FALSE(from_hex("zz"));   // high digit
  EXPECT_FALSE(from_hex("0g"));   // low digit
}

TEST(Encoding, Base64Rfc4648Vectors) {
  const std::pair<const char*, const char*> vectors[] = {
      {"", ""},
      {"f", "Zg=="},
      {"fo", "Zm8="},
      {"foo", "Zm9v"},
      {"foob", "Zm9vYg=="},
      {"fooba", "Zm9vYmE="},
      {"foobar", "Zm9vYmFy"},
  };
  for (const auto& [plain, encoded] : vectors) {
    EXPECT_EQ(to_base64(to_bytes(plain)), encoded);
    EXPECT_EQ(from_base64(encoded), to_bytes(plain)) << encoded;
  }
  EXPECT_EQ(to_base64(Bytes{0xfb, 0xff}), "+/8=");
}

TEST(Encoding, Base64RejectsMalformedInput) {
  EXPECT_FALSE(from_base64("Zg="));   // length not a multiple of four
  EXPECT_FALSE(from_base64("===="));  // only padding
  EXPECT_FALSE(from_base64("Z==="));  // three padding characters
  EXPECT_FALSE(from_base64("Zg=a"));  // padding inside
  EXPECT_FALSE(from_base64("Zm9*"));  // outside the alphabet
  EXPECT_FALSE(from_base64("Zh=="));  // non-zero trailing bits
  EXPECT_FALSE(from_base64("Zm9="));  // non-zero trailing bits
}

}  // namespace
}  // namespace crypto_service
