// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// A small FIPS 180-4 SHA-256 and HMAC-SHA256, so the kit checksum test
// and the conformance tokens need no crypto library. Test support only:
// the SDK itself does no cryptography.

#ifndef CRYPTO_SERVICE_TESTS_SUPPORT_SHA256_HPP
#define CRYPTO_SERVICE_TESTS_SUPPORT_SHA256_HPP

#include <string>
#include <string_view>

namespace crypto_service::kit {

/// The 32-byte SHA-256 digest of the bytes.
std::string sha256_raw(std::string_view bytes);

/// Lower-case hex SHA-256 of the bytes.
std::string sha256_hex(std::string_view bytes);

/// HMAC-SHA256 (RFC 2104) of `message` under `key`: 32 raw bytes. Used
/// to mint the conformance kit's HS256 test tokens.
std::string hmac_sha256(std::string_view key, std::string_view message);

}  // namespace crypto_service::kit

#endif  // CRYPTO_SERVICE_TESTS_SUPPORT_SHA256_HPP
