// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The non-template half of the codec: member lookup, scalar decoding
// and the hex and base64 conversion of byte members.

#include "codec.hpp"

#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>

#include "crypto_service/encoding.hpp"

namespace crypto_service::detail::codec {
namespace {

[[noreturn]] void fail(std::string_view name, std::string_view expected) {
  throw DecodeError("member `" + std::string(name) + "` is not " + std::string(expected));
}

}  // namespace

json& slot(json& object, std::string_view name) {
  return name.empty() ? object : object[std::string(name)];
}

const json* member(const json& object, std::string_view name) {
  if (name.empty()) {
    return object.is_null() ? nullptr : &object;
  }
  if (!object.is_object()) {
    throw DecodeError("expected an object holding `" + std::string(name) + "`");
  }
  const auto found = object.find(std::string(name));
  return found == object.end() || found->is_null() ? nullptr : &*found;
}

const json& required(const json& object, std::string_view name) {
  const json* found = member(object, name);
  if (found == nullptr) {
    fail(name, "present");
  }
  return *found;
}

json encode_bytes(const Bytes& bytes, Enc enc) {
  return enc == Enc::kBase64 ? to_base64(bytes) : to_hex(bytes);
}

void read_value(const json& value, std::string& out, Enc /*enc*/, std::string_view name) {
  if (!value.is_string()) {
    fail(name, "a string");
  }
  out = value.get_ref<const std::string&>();
}

void read_value(const json& value, Bytes& out, Enc enc, std::string_view name) {
  if (!value.is_string()) {
    fail(name, "a string");
  }
  const auto& text = value.get_ref<const std::string&>();
  std::optional<Bytes> bytes = enc == Enc::kBase64 ? from_base64(text) : from_hex(text);
  if (!bytes) {
    fail(name, enc == Enc::kBase64 ? "valid base64" : "valid hex");
  }
  out = std::move(*bytes);
}

void read_value(const json& value, std::int64_t& out, Enc /*enc*/, std::string_view name) {
  if (value.is_number_unsigned() &&
      value.get<std::uint64_t>() >
          static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
    fail(name, "a 64-bit integer");
  }
  if (!value.is_number_integer()) {
    fail(name, "an integer");
  }
  out = value.get<std::int64_t>();
}

void read_value(const json& value, double& out, Enc /*enc*/, std::string_view name) {
  if (!value.is_number()) {
    fail(name, "a number");
  }
  out = value.get<double>();
}

void read_value(const json& value, bool& out, Enc /*enc*/, std::string_view name) {
  if (!value.is_boolean()) {
    fail(name, "a boolean");
  }
  out = value.get<bool>();
}

void read_value(const json& value, json& out, Enc /*enc*/, std::string_view /*name*/) {
  out = value;
}

void read_value(const json& value, std::map<std::string, std::string>& out, Enc enc,
                std::string_view name) {
  if (!value.is_object()) {
    fail(name, "an object");
  }
  out.clear();
  for (const auto& [key, item] : value.items()) {
    read_value(item, out[key], enc, name);
  }
}

const json::array_t& elements(const json& value, std::string_view name) {
  if (!value.is_array()) {
    fail(name, "an array");
  }
  return value.get_ref<const json::array_t&>();
}

}  // namespace crypto_service::detail::codec
