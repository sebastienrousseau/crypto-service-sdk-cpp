// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The conformance kit's rules (conformance/README.md): template
// matching with `$shape` JSON Schemas, `${name}` substitution, captures
// by JSON pointer, the SHA256SUMS pin, and HS256 test tokens.

#ifndef CRYPTO_SERVICE_TESTS_SUPPORT_KIT_HPP
#define CRYPTO_SERVICE_TESTS_SUPPORT_KIT_HPP

#include <ctime>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace crypto_service::kit {

using nlohmann::json;
using Captures = std::map<std::string, std::string>;

/// The kit directory (conformance/).
std::string kit_dir();

/// The contents of `name` in the kit directory.
std::string read_kit_file(const std::string& name);

/// The vector files in the order the README lists them.
std::vector<std::string> vector_files();

/// Files whose SHA-256 differs from SHA256SUMS (empty when the kit is
/// intact).
std::vector<std::string> checksum_mismatches();

/// Whether `value` matches `expected`; on a mismatch `why` says where.
bool matches(const json& expected, const json& value, std::string& why,
             const std::string& where = "");

/// Whether `value` is valid under the `$shape` schema (the keywords the
/// kit uses: type, const, pattern, format, required, properties,
/// additionalProperties, items).
bool schema_matches(const json& schema, const json& value, std::string& why,
                    const std::string& where = "");

/// `value` with every `${name}` in its strings replaced.
json substitute(const json& value, const Captures& captures);

/// The value at JSON pointer `pointer` in `body`, as a string (strings
/// as they are, other values as JSON text); nullopt when absent.
std::optional<std::string> capture(const json& body, const std::string& pointer);

/// Base64url without padding (RFC 4648 section 5), for JWTs.
std::string base64url(const std::string& bytes);

/// An HS256 JWT signed with `secret` carrying `claims`.
std::string mint_token(const std::string& secret, const json& claims);

/// The kit's claims for a file run as `sub` with `scopes`, issued at
/// `now`: iat, exp (now + 300 s), and iss/aud when given.
json token_claims(const std::string& sub, const json& scopes, std::time_t now,
                  const std::optional<std::string>& issuer,
                  const std::optional<std::string>& audience);

}  // namespace crypto_service::kit

#endif  // CRYPTO_SERVICE_TESTS_SUPPORT_KIT_HPP
