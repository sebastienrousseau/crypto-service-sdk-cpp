// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau

#include "kit.hpp"

#include <cctype>
#include <cstddef>
#include <ctime>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto_service/encoding.hpp"
#include "pattern.hpp"
#include "sha256.hpp"

namespace crypto_service::kit {
namespace {

bool fail(std::string& why, const std::string& where, const std::string& what) {
  why = (where.empty() ? std::string("/") : where) + ": " + what;
  return false;
}

bool type_matches(const std::string& type, const json& value) {
  if (type == "string") return value.is_string();
  if (type == "integer") return value.is_number_integer();
  if (type == "number") return value.is_number();
  if (type == "object") return value.is_object();
  if (type == "array") return value.is_array();
  if (type == "boolean") return value.is_boolean();
  return type == "null" && value.is_null();
}

bool uuid(const std::string& text) {
  return pattern_matches(
      "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", text);
}

bool date_time(const std::string& text) {
  return pattern_matches("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}", text);
}

bool string_rules(const json& schema, const json& value, std::string& why,
                  const std::string& where) {
  if (!value.is_string()) {
    return true;
  }
  const auto& text = value.get_ref<const std::string&>();
  if (schema.contains("pattern") && !pattern_matches(schema["pattern"].get<std::string>(), text)) {
    return fail(why, where, "does not match " + schema["pattern"].get<std::string>());
  }
  const std::string format = schema.value("format", "");
  if ((format == "uuid" && !uuid(text)) || (format == "date-time" && !date_time(text))) {
    return fail(why, where, "is not a " + format);
  }
  return true;
}

bool object_rules(const json& schema, const json& value, std::string& why,
                  const std::string& where) {
  if (!value.is_object()) {
    return true;
  }
  for (const auto& name : schema.value("required", json::array())) {
    if (!value.contains(name.get<std::string>())) {
      return fail(why, where, "lacks " + name.get<std::string>());
    }
  }
  const json properties = schema.value("properties", json::object());
  for (const auto& [name, member] : value.items()) {
    const std::string at = where + "/" += name;
    if (properties.contains(name)) {
      if (!schema_matches(properties[name], member, why, at)) return false;
    } else if (schema.contains("additionalProperties") &&
               !schema_matches(schema["additionalProperties"], member, why, at)) {
      return false;
    }
  }
  return true;
}

bool scalar_rules(const json& schema, const json& value, std::string& why,
                  const std::string& where) {
  if (schema.contains("const") && schema["const"] != value) {
    return fail(why, where, "is not " + schema["const"].dump());
  }
  if (schema.contains("type") && !type_matches(schema["type"].get<std::string>(), value)) {
    return fail(why, where, "is not of type " + schema["type"].get<std::string>());
  }
  return true;
}

bool item_rules(const json& schema, const json& value, std::string& why, const std::string& where) {
  if (!schema.contains("items") || !value.is_array()) {
    return true;
  }
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (!schema_matches(schema["items"], value[i], why, where + "/" + std::to_string(i))) {
      return false;
    }
  }
  return true;
}

bool objects_match(const json& expected, const json& value, std::string& why,
                   const std::string& where) {
  for (const auto& [name, member] : value.items()) {
    if (!expected.contains(name)) {
      return fail(why, where, "has extra member " + name);
    }
  }
  for (const auto& [name, member] : expected.items()) {
    if (!value.contains(name)) {
      return fail(why, where, "lacks " + name);
    }
    if (!matches(member, value[name], why, std::string(where).append("/").append(name))) {
      return false;
    }
  }
  return true;
}

bool arrays_match(const json& expected, const json& value, std::string& why,
                  const std::string& where) {
  if (expected.size() != value.size()) {
    return fail(why, where, "array length differs");
  }
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (!matches(expected[i], value[i], why, where + "/" + std::to_string(i))) {
      return false;
    }
  }
  return true;
}

std::string replace_all(std::string text, const Captures& captures) {
  for (const auto& [name, value] : captures) {
    const std::string marker = "${" + name + "}";
    for (auto pos = text.find(marker); pos != std::string::npos;
         pos = text.find(marker, pos + value.size())) {
      text.replace(pos, marker.size(), value);
    }
  }
  return text;
}

}  // namespace

std::string kit_dir() { return CRYPTO_SERVICE_KIT_DIR; }

std::string read_kit_file(const std::string& name) {
  std::ifstream in(kit_dir() + "/" + name, std::ios::binary);
  if (!in) {
    throw std::runtime_error("cannot read conformance/" + name);
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

std::vector<std::string> vector_files() {
  return {"meta.json",      "probes.json",  "hash.json",       "mac.json",     "kdf.json",
          "symmetric.json", "signing.json", "asymmetric.json", "pq-sign.json", "hpke.json",
          "kms.json",       "opaque.json",  "errors.json",     "v1.json"};
}

std::vector<std::string> checksum_mismatches() {
  std::vector<std::string> bad;
  std::istringstream sums(read_kit_file("SHA256SUMS"));
  std::string digest;
  std::string name;
  while (sums >> digest >> name) {
    if (sha256_hex(read_kit_file(name)) != digest) {
      bad.push_back(name);
    }
  }
  return bad;
}

bool schema_matches(const json& schema, const json& value, std::string& why,
                    const std::string& where) {
  if (schema.is_boolean()) {
    return schema.get<bool>() || fail(why, where, "is not allowed");
  }
  return scalar_rules(schema, value, why, where) && string_rules(schema, value, why, where) &&
         object_rules(schema, value, why, where) && item_rules(schema, value, why, where);
}

bool matches(const json& expected, const json& value, std::string& why, const std::string& where) {
  if (expected.is_object() && expected.size() == 1 && expected.contains("$shape")) {
    return schema_matches(expected["$shape"], value, why, where);
  }
  if (expected.is_object() != value.is_object() || expected.is_array() != value.is_array()) {
    return fail(why, where, "expected " + expected.dump() + ", got " + value.dump());
  }
  if (expected.is_object()) {
    return objects_match(expected, value, why, where);
  }
  if (expected.is_array()) {
    return arrays_match(expected, value, why, where);
  }
  return expected == value ||
         fail(why, where, "expected " + expected.dump() + ", got " + value.dump().substr(0, 200));
}

json substitute(const json& value, const Captures& captures) {
  if (value.is_string()) {
    return replace_all(value.get<std::string>(), captures);
  }
  json out = value;
  if (value.is_structured()) {
    for (auto& member : out) {
      member = substitute(member, captures);
    }
  }
  return out;
}

std::optional<std::string> capture(const json& body, const std::string& pointer) {
  const json::json_pointer at(pointer);
  if (!body.contains(at)) {
    return std::nullopt;
  }
  const json& value = body.at(at);
  return value.is_string() ? value.get<std::string>() : value.dump();
}

std::string base64url(const std::string& bytes) {
  std::string out = to_base64(Bytes(bytes.begin(), bytes.end()));
  out.erase(out.find_last_not_of('=') + 1);
  for (char& c : out) {
    c = c == '+' ? '-' : (c == '/' ? '_' : c);
  }
  return out;
}

std::string mint_token(const std::string& secret, const json& claims) {
  const std::string input =
      base64url(json({{"alg", "HS256"}, {"typ", "JWT"}}).dump()) + "." + base64url(claims.dump());
  return input + "." + base64url(hmac_sha256(secret, input));
}

json token_claims(const std::string& sub, const json& scopes, std::time_t now,
                  const std::optional<std::string>& issuer,
                  const std::optional<std::string>& audience) {
  json claims = {{"sub", sub}, {"scopes", scopes}, {"iat", now}, {"exp", now + 300}};
  if (issuer) claims["iss"] = *issuer;
  if (audience) claims["aud"] = *audience;
  return claims;
}

}  // namespace crypto_service::kit
