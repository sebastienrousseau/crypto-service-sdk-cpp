// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The subset of ECMAScript regular expressions the conformance kit's
// `$shape` patterns use: anchored (`^`, optional `$`), literals and
// escapes, character classes with ranges, groups, and the quantifiers
// `*`, `+`, `?`, `{n}` and `{n,m}`, matched greedily. std::regex is not
// used: libstdc++'s recursive matcher overflows the stack on the kit's
// 34 KB signatures.

#ifndef CRYPTO_SERVICE_TESTS_SUPPORT_PATTERN_HPP
#define CRYPTO_SERVICE_TESTS_SUPPORT_PATTERN_HPP

#include <string_view>

namespace crypto_service::kit {

/// Whether `text` matches `pattern`. Throws std::invalid_argument for a
/// pattern outside the subset.
bool pattern_matches(std::string_view pattern, std::string_view text);

}  // namespace crypto_service::kit

#endif  // CRYPTO_SERVICE_TESTS_SUPPORT_PATTERN_HPP
