// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// The byte type and the two text encodings the API uses for binary
// values: lowercase hex (keys, signatures, digests, shared secrets) and
// standard padded base64 (AEAD, secretbox, sealed-box, stream and
// key-wrap output). The client encodes and decodes them for you; these
// are exposed for printing and storing values.

#ifndef CRYPTO_SERVICE_ENCODING_HPP
#define CRYPTO_SERVICE_ENCODING_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace crypto_service {

/// Binary data, as the client hands it to and receives it from the API.
using Bytes = std::vector<std::uint8_t>;

/// The bytes of a UTF-8 (or any) string, unchanged.
[[nodiscard]] Bytes to_bytes(std::string_view text);

/// Lowercase hex of `bytes`.
[[nodiscard]] std::string to_hex(const Bytes& bytes);

/// The bytes of a hex string (either case), or nullopt when `hex` has an
/// odd length or a character that is not a hex digit.
[[nodiscard]] std::optional<Bytes> from_hex(std::string_view hex);

/// Standard base64 (RFC 4648, section 4) of `bytes`, with padding.
[[nodiscard]] std::string to_base64(const Bytes& bytes);

/// The bytes of a padded standard base64 string, or nullopt when it is
/// not one (wrong length, a character outside the alphabet, or padding
/// anywhere but the end).
[[nodiscard]] std::optional<Bytes> from_base64(std::string_view text);

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_ENCODING_HPP
