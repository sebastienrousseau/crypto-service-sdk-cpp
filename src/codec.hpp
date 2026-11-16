// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Internal: a table-driven JSON codec. Each request and result struct
// has a Schema listing its members (wire name, member pointer, text
// encoding); write() and read() walk that list. Branching lives in the
// non-template helpers (codec.cpp) or in templates instantiated once
// per value type, never once per struct, so the code stays small and
// every branch is reachable from a handful of tests.

#ifndef CRYPTO_SERVICE_SRC_CODEC_HPP
#define CRYPTO_SERVICE_SRC_CODEC_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "crypto_service/encoding.hpp"

namespace crypto_service::detail::codec {

using nlohmann::json;

/// How a string member carries its value.
enum class Enc : std::uint8_t { kPlain, kHex, kBase64 };

/// A response member is missing or has the wrong type or encoding. The
/// message names the member, never its value.
class DecodeError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

/// One member: its wire name ("" for a route whose `data` is the bare
/// value), the struct member and its text encoding.
template <typename S, typename M>
struct Field {
  std::string_view name;
  M S::*member;
  Enc enc;
};

/// A member always written with a fixed value and ignored when read.
struct Const {
  std::string_view name;
  std::string_view value;
};

template <typename S, typename M>
constexpr Field<S, M> field(std::string_view name, M S::*member, Enc enc = Enc::kPlain) {
  return Field<S, M>{name, member, enc};
}

/// Specialised for every struct (schemas.hpp) with a static fields().
template <typename T>
struct Schema {};

template <typename T, typename = void>
struct has_schema : std::false_type {};
template <typename T>
struct has_schema<T, std::void_t<decltype(Schema<T>::fields())>> : std::true_type {};

// --- Non-template helpers (codec.cpp) ---

/// The slot for member `name` of `object` (the object itself for "").
json& slot(json& object, std::string_view name);
/// Member `name` of `object` (the object itself for ""), or nullptr when
/// it is absent or null. DecodeError when `object` is not an object.
const json* member(const json& object, std::string_view name);
/// As member(), but DecodeError when the member is absent or null.
const json& required(const json& object, std::string_view name);

json encode_bytes(const Bytes& bytes, Enc enc);
void read_value(const json& value, std::string& out, Enc enc, std::string_view name);
void read_value(const json& value, Bytes& out, Enc enc, std::string_view name);
void read_value(const json& value, std::int64_t& out, Enc enc, std::string_view name);
void read_value(const json& value, double& out, Enc enc, std::string_view name);
void read_value(const json& value, bool& out, Enc enc, std::string_view name);
void read_value(const json& value, json& out, Enc enc, std::string_view name);
void read_value(const json& value, std::map<std::string, std::string>& out, Enc enc,
                std::string_view name);
/// The elements of an array member; DecodeError when it is not one.
const json::array_t& elements(const json& value, std::string_view name);

// --- Writing ---

inline void write_value(json& out, const std::string& value, Enc /*enc*/) { out = value; }
inline void write_value(json& out, const Bytes& value, Enc enc) { out = encode_bytes(value, enc); }
inline void write_value(json& out, std::int64_t value, Enc /*enc*/) { out = value; }
inline void write_value(json& out, double value, Enc /*enc*/) { out = value; }
inline void write_value(json& out, bool value, Enc /*enc*/) { out = value; }
inline void write_value(json& out, const json& value, Enc /*enc*/) { out = value; }
inline void write_value(json& out, const std::map<std::string, std::string>& value, Enc /*enc*/) {
  out = value;
}

template <typename T, std::enable_if_t<has_schema<T>::value, int> = 0>
void write_value(json& out, const T& value, Enc enc);

template <typename T>
void write_value(json& out, const std::vector<T>& values, Enc enc) {
  out = json::array();
  for (const T& value : values) {
    write_value(out.emplace_back(), value, enc);
  }
}

template <typename T>
void put(json& object, std::string_view name, const T& value, Enc enc) {
  write_value(slot(object, name), value, enc);
}

template <typename T>
void put(json& object, std::string_view name, const std::optional<T>& value, Enc enc) {
  if (value) {
    write_value(slot(object, name), *value, enc);
  }
}

template <typename S, typename M>
void write_field(json& object, const S& value, const Field<S, M>& f) {
  put(object, f.name, value.*(f.member), f.enc);
}

template <typename S>
void write_field(json& object, const S& /*value*/, const Const& c) {
  slot(object, c.name) = c.value;
}

template <typename T, std::enable_if_t<has_schema<T>::value, int>>
void write_value(json& out, const T& value, Enc /*enc*/) {
  out = json::object();
  std::apply([&](const auto&... f) { (write_field(out, value, f), ...); }, Schema<T>::fields());
}

// --- Reading ---

template <typename T, std::enable_if_t<has_schema<T>::value, int> = 0>
void read_value(const json& value, T& out, Enc enc, std::string_view name);

template <typename T>
void read_value(const json& value, std::vector<T>& out, Enc enc, std::string_view name) {
  const json::array_t& items = elements(value, name);
  out.clear();
  out.reserve(items.size());
  for (const json& item : items) {
    read_value(item, out.emplace_back(), enc, name);
  }
}

template <typename T>
void take(const json& object, std::string_view name, T& out, Enc enc) {
  read_value(required(object, name), out, enc, name);
}

template <typename T>
void take(const json& object, std::string_view name, std::optional<T>& out, Enc enc) {
  const json* found = member(object, name);
  if (found == nullptr) {
    out.reset();
    return;
  }
  read_value(*found, out.emplace(), enc, name);
}

template <typename S, typename M>
void read_field(const json& object, S& value, const Field<S, M>& f) {
  take(object, f.name, value.*(f.member), f.enc);
}

template <typename S>
void read_field(const json& /*object*/, S& /*value*/, const Const& /*c*/) {}

template <typename T, std::enable_if_t<has_schema<T>::value, int>>
void read_value(const json& value, T& out, Enc /*enc*/, std::string_view /*name*/) {
  std::apply([&](const auto&... f) { (read_field(value, out, f), ...); }, Schema<T>::fields());
}

/// `value` encoded as a JSON document.
template <typename T>
json to_json(const T& value) {
  json out;
  write_value(out, value, Enc::kPlain);
  return out;
}

/// `document` decoded; DecodeError when it does not have T's shape.
template <typename T>
T from_json(const json& document, std::string_view name) {
  T out{};
  read_value(document, out, Enc::kPlain, name);
  return out;
}

}  // namespace crypto_service::detail::codec

#endif  // CRYPTO_SERVICE_SRC_CODEC_HPP
