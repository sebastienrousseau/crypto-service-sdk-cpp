// SPDX-License-Identifier: Apache-2.0 OR MIT

#include "dispatch.hpp"

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "codec.hpp"
#include "schemas.hpp"

namespace crypto_service::kit {
namespace {

// Qualified calls: an unqualified one also finds nlohmann::from_json by
// ADL, which GCC 16 rejects when given an explicit template argument.
namespace codec = detail::codec;
using detail::codec::to_json;

// The vector's body cannot be expressed exactly by the typed request.
class NotExpressible : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

using Typed = std::function<json(Client&, const json&)>;

template <typename Base, typename Request, typename Result>
Typed op(Result (Base::*method)(const Request&, const CallOptions&), bool wrapped = true) {
  return [method, wrapped](Client& client, const json& body) {
    Request request;
    try {
      request = codec::from_json<Request>(body, "body");
    } catch (const detail::codec::DecodeError& e) {
      throw NotExpressible(e.what());
    }
    if (to_json(request) != body) {
      throw NotExpressible("the typed request encodes differently: " + to_json(request).dump());
    }
    const json result = to_json((client.*method)(request, {}));
    return wrapped ? json{{"data", result}} : result;
  };
}

template <typename Base, typename Result>
Typed op(Result (Base::*method)(const CallOptions&), bool wrapped = true) {
  return [method, wrapped](Client& client, const json& body) {
    if (!body.is_null() && body != json::object()) {
      throw NotExpressible("the typed method takes no body");
    }
    const json result = to_json((client.*method)({}));
    return wrapped ? json{{"data", result}} : result;
  };
}

void add_service_and_symmetric(std::map<std::string, Typed>& table) {
  using C = Client;
  table.insert({
      {"GET /", op(&C::root, false)},
      {"GET /health", op(&C::health, false)},
      {"GET /live", op(&C::live, false)},
      {"GET /ready", op(&C::ready, false)},
      {"GET /v2/algorithms", op(&C::algorithms)},
      {"GET /v2/compliance/dora", op(&C::get_dora_compliance)},
      {"GET /v2/compliance/cbom", op(&C::get_cbom, false)},
      {"POST /v2/encrypt", op(&C::encrypt)},
      {"POST /v2/decrypt", op(&C::decrypt)},
      {"POST /v2/secretbox/seal", op(&C::secretbox_seal)},
      {"POST /v2/secretbox/open", op(&C::secretbox_open)},
      {"POST /v2/password/encrypt", op(&C::password_encrypt)},
      {"POST /v2/password/decrypt", op(&C::password_decrypt)},
      {"POST /v2/keys/wrap", op(&C::key_wrap)},
      {"POST /v2/keys/unwrap", op(&C::key_unwrap)},
      {"POST /v2/hash", op(&C::hash)},
      {"POST /v2/hmac", op(&C::mac)},
      {"POST /v2/hmac/verify", op(&C::mac_verify)},
      {"POST /v2/kdf", op(&C::kdf)},
      {"POST /v2/password/hash", op(&C::password_hash)},
      {"POST /v2/password/verify", op(&C::password_verify)},
      {"POST /v2/keys/generate", op(&C::generate_key_pair)},
      {"POST /v2/keys/export", op(&C::export_key)},
      {"POST /v2/keys/delete", op(&C::keys_delete)},
      {"POST /v2/sign", op(&C::sign)},
      {"POST /v2/verify", op(&C::verify)},
      {"POST /v2/stream/sign", op(&C::stream_sign)},
      {"POST /v2/stream/verify", op(&C::stream_verify)},
      {"POST /v2/stream/iso20022", op(&C::stream_iso20022)},
      {"POST /v2/pq/keygen", op(&C::ml_kem_generate_key_pair)},
      {"POST /v2/pq/encapsulate", op(&C::ml_kem_encapsulate)},
  });
}

void add_public_key(std::map<std::string, Typed>& table) {
  using C = Client;
  table.insert({
      {"POST /v2/pq/decapsulate", op(&C::ml_kem_decapsulate)},
      {"POST /v2/pq/hybrid/keygen", op(&C::pq_generate_key_pair)},
      {"POST /v2/pq/hybrid/encapsulate", op(&C::pq_encapsulate)},
      {"POST /v2/pq/hybrid/decapsulate", op(&C::pq_decapsulate)},
      {"POST /v2/pq/dsa/keygen", op(&C::pq_sign_keygen)},
      {"POST /v2/pq/dsa/sign", op(&C::pq_sign)},
      {"POST /v2/pq/dsa/verify", op(&C::pq_verify)},
      {"POST /v2/pq/slh-dsa/keygen", op(&C::pq_hash_sign_keygen)},
      {"POST /v2/pq/slh-dsa/sign", op(&C::pq_hash_sign)},
      {"POST /v2/pq/slh-dsa/verify", op(&C::pq_hash_verify)},
      {"POST /v2/sealedbox/seal", op(&C::sealedbox_seal)},
      {"POST /v2/sealedbox/open", op(&C::sealedbox_open)},
      {"POST /v2/sealedbox/seal-pq", op(&C::sealedbox_seal_pq)},
      {"POST /v2/sealedbox/open-pq", op(&C::sealedbox_open_pq)},
      {"POST /v2/stream/pq-encrypt", op(&C::stream_pq_encrypt)},
      {"POST /v2/stream/pq-decrypt", op(&C::stream_pq_decrypt)},
      {"POST /v2/stream/multi-pq-encrypt", op(&C::stream_multi_pq_encrypt)},
      {"POST /v2/stream/multi-pq-decrypt", op(&C::stream_multi_pq_decrypt)},
      {"POST /v2/multi-recipient/encrypt", op(&C::multi_recipient_encrypt)},
      {"POST /v2/hpke/keygen", op(&C::hpke_generate_key_pair)},
      {"POST /v2/hpke/seal", op(&C::hpke_seal)},
      {"POST /v2/hpke/open", op(&C::hpke_open)},
      {"POST /v2/kms/create-key", op(&C::kms_create_key)},
      {"POST /v2/kms/encrypt", op(&C::kms_encrypt)},
      {"POST /v2/kms/decrypt", op(&C::kms_decrypt)},
      {"POST /v2/kms/generate-data-key", op(&C::kms_generate_data_key)},
      {"POST /v2/kms/wrap", op(&C::kms_wrap)},
      {"POST /v2/kms/unwrap", op(&C::kms_unwrap)},
      {"POST /v2/opaque/register/init", op(&C::opaque_register_init)},
      {"POST /v2/opaque/register/finish", op(&C::opaque_register_finish)},
      {"POST /v2/opaque/login/init", op(&C::opaque_login_init)},
      {"POST /v2/opaque/login/finish", op(&C::opaque_login_finish)},
  });
}

const std::map<std::string, Typed>& routes() {
  static const std::map<std::string, Typed> table = [] {
    std::map<std::string, Typed> out;
    add_service_and_symmetric(out);
    add_public_key(out);
    return out;
  }();
  return table;
}

// The server's /v2/hpke rule: an even-length hex string is hex, any
// other string is UTF-8 text (hpke.ts ensureHex).
std::string ensure_hex(const std::string& text) {
  const bool hex =
      text.size() % 2 == 0 && text.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
  return hex ? text : to_hex(to_bytes(text));
}

// The vector's body in the form the server reads it, for routes whose
// typed request removes an ambiguity: HPKE text-or-hex members, and KMS
// plaintexts, which the SDK always sends as hex.
json canonical(const std::string& path, json body) {
  if (path == "/v2/hpke/seal" || path == "/v2/hpke/open") {
    for (const char* name : {"plaintext", "info", "aad"}) {
      if (body.contains(name)) body[name] = ensure_hex(body[name].get<std::string>());
    }
  }
  if (path == "/v2/kms/encrypt" && body.value("encoding", "utf8") != "hex") {
    body["plaintext"] = to_hex(to_bytes(body["plaintext"].get<std::string>()));
    body["encoding"] = "hex";
  }
  return body;
}

std::string media_type(const HttpResponse& response) {
  const std::string type = response.header("Content-Type").value_or("");
  return type.substr(0, type.find(';'));
}

RawRequest raw_request(const json& request) {
  RawRequest raw;
  raw.method = request.at("method").get<std::string>();
  raw.path = request.at("path").get<std::string>();
  if (request.contains("rawBody")) {
    raw.body = request["rawBody"].get<std::string>();
  } else if (request.contains("body")) {
    raw.body = request["body"].dump();
  }
  const json headers = request.value("headers", json::object());
  for (const auto& [name, value] : headers.items()) {
    raw.headers.emplace_back(name, value.get<std::string>());
  }
  return raw;
}

// The typed result, or nullopt with `why` when the raw path must be taken.
std::optional<json> try_typed(Client& client, const json& request, std::string& why) {
  const std::string path = request.at("path").get<std::string>();
  const auto found = routes().find(request.at("method").get<std::string>() + " " + path);
  if (found == routes().end() || request.contains("rawBody") || request.contains("headers")) {
    why = "no typed method for this request";
    return std::nullopt;
  }
  try {
    return found->second(client, canonical(path, request.value("body", json())));
  } catch (const ApiError& e) {
    return problem_json(e.problem());
  } catch (const NotExpressible& e) {
    why = e.what();
    return std::nullopt;
  }
}

}  // namespace

RecordingTransport::RecordingTransport(std::shared_ptr<std::optional<HttpResponse>> last)
    : inner_(make_curl_transport()), last_(std::move(last)) {}

HttpResponse RecordingTransport::send(const HttpRequest& request) {
  HttpResponse response = inner_->send(request);
  *last_ = response;
  return response;
}

json problem_json(const Problem& problem) {
  json out = problem.extensions;
  out["type"] = problem.type;
  out["title"] = problem.title;
  out["status"] = problem.status;
  out["detail"] = problem.detail;
  if (problem.instance) out["instance"] = *problem.instance;
  if (problem.code) out["code"] = *problem.code;
  if (!problem.errors.empty()) {
    out["errors"] = json::array();
    for (const FieldError& error : problem.errors) {
      out["errors"].push_back({{"field", error.field}, {"message", error.message}});
    }
  }
  return out;
}

VectorOutcome run_vector(const ClientOptions& options, const json& request) {
  auto last = std::make_shared<std::optional<HttpResponse>>();
  Client client(options, std::make_unique<RecordingTransport>(last));
  VectorOutcome out;
  if (std::optional<json> typed = try_typed(client, request, out.route)) {
    out.body = std::move(*typed);
    out.typed = true;
  } else {
    out.body = client.request(raw_request(request)).json();
  }
  const HttpResponse response = last->value_or(HttpResponse{});
  out.status = response.status;
  out.raw_body = json::parse(response.body, nullptr, false);
  out.media_type = media_type(response);
  out.headers = response.headers;
  return out;
}

}  // namespace crypto_service::kit
