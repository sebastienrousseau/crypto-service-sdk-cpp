// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Hex and base64 text encodings of binary values. Not cryptography: the
// API carries bytes as text, and these convert between the two.

#include "crypto_service/encoding.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace crypto_service {
namespace {

constexpr std::string_view kHexDigits = "0123456789abcdef";
constexpr std::string_view kBase64Alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr int kInvalid = -1;
constexpr unsigned kNotHex = 16;

unsigned hex_value(char c) {
  const auto pos = std::string_view("0123456789abcdefABCDEF").find(c);
  if (pos == std::string_view::npos) {
    return kNotHex;
  }
  return static_cast<unsigned>(pos < 16 ? pos : pos - 6);
}

// The 6-bit value of a base64 character, or kInvalid.
int base64_value(char c) {
  const auto pos = kBase64Alphabet.find(c);
  return pos == std::string_view::npos ? kInvalid : static_cast<int>(pos);
}

// The number of '=' at the end of `text` (a multiple of four long), or
// kInvalid when there are more than two.
int padding(std::string_view text) {
  const auto last = text.find_last_not_of('=');
  const std::size_t pad = last == std::string_view::npos ? text.size() : text.size() - last - 1;
  return pad > 2 ? kInvalid : static_cast<int>(pad);
}

// Decodes `text` (base64 without its padding) into `out`; false on a
// character outside the alphabet or non-zero trailing bits.
bool decode_groups(std::string_view text, Bytes& out) {
  std::uint32_t buffer = 0;
  int bits = 0;
  for (const char c : text) {
    const int value = base64_value(c);
    if (value == kInvalid) {
      return false;
    }
    buffer = (buffer << 6U) | static_cast<std::uint32_t>(value);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((buffer >> static_cast<unsigned>(bits)) & 0xFFU));
    }
  }
  // Canonical encodings leave the unused low bits of the last character
  // zero. (With the length a multiple of four, those are 2 * pad bits.)
  const std::uint32_t leftover = buffer & ((1U << static_cast<unsigned>(bits)) - 1U);
  return leftover == 0;
}

// Appends the four characters for the (up to) three bytes at `at`,
// padding with '=' when fewer than three remain.
void append_group(std::string& out, const Bytes& bytes, std::size_t at) {
  const std::size_t count = std::min<std::size_t>(3, bytes.size() - at);
  std::uint32_t group = 0;
  for (std::size_t k = 0; k < 3; ++k) {
    group = (group << 8U) | (k < count ? static_cast<std::uint32_t>(bytes[at + k]) : 0U);
  }
  for (std::size_t k = 0; k < 4; ++k) {
    const auto shift = static_cast<unsigned>(18 - 6 * k);
    out.push_back(k <= count ? kBase64Alphabet[(group >> shift) & 0x3FU] : '=');
  }
}

}  // namespace

Bytes to_bytes(std::string_view text) { return Bytes(text.begin(), text.end()); }

std::string to_hex(const Bytes& bytes) {
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const std::uint8_t byte : bytes) {
    out.push_back(kHexDigits[byte >> 4U]);
    out.push_back(kHexDigits[byte & 0x0FU]);
  }
  return out;
}

std::optional<Bytes> from_hex(std::string_view hex) {
  if (hex.size() % 2 != 0) {
    return std::nullopt;
  }
  Bytes out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const unsigned high = hex_value(hex[i]);
    const unsigned low = hex_value(hex[i + 1]);
    if (high == kNotHex || low == kNotHex) {
      return std::nullopt;
    }
    out.push_back(static_cast<std::uint8_t>((high << 4U) | low));
  }
  return out;
}

std::string to_base64(const Bytes& bytes) {
  std::string out;
  out.reserve((bytes.size() + 2) / 3 * 4);
  for (std::size_t i = 0; i < bytes.size(); i += 3) {
    append_group(out, bytes, i);
  }
  return out;
}

std::optional<Bytes> from_base64(std::string_view text) {
  if (text.size() % 4 != 0) {
    return std::nullopt;
  }
  const int pad = padding(text);
  if (pad == kInvalid) {
    return std::nullopt;
  }
  Bytes out;
  out.reserve(text.size() / 4 * 3);
  const auto unpadded = text.substr(0, text.size() - static_cast<std::size_t>(pad));
  if (!decode_groups(unpadded, out)) {
    return std::nullopt;
  }
  return out;
}

}  // namespace crypto_service
