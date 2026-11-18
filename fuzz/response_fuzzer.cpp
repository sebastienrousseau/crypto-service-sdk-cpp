// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// libFuzzer target: any bytes as the body of a 200 response, decoded as
// a spread of result types (wrapped in `data`, bare string data, nested
// arrays and optionals, unwrapped documents). Decoding must either
// succeed or throw TransportError, whose message never repeats the body.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include "crypto_service/crypto_service.hpp"

namespace {

using crypto_service::HttpResponse;
using crypto_service::TransportError;

// The SDK builds its messages from fixed text, the HTTP status and
// schema member names: none holds a JSON bracket or brace, a double
// quote or a byte outside printable ASCII. A body holding one of them
// (every JSON object, array or string does) is in a message only if it
// leaked; a plain-text body may match the fixed text by chance.
bool marked(const std::string& body) {
  for (const char c : body) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte < 0x20U || byte >= 0x7FU ||
        std::string_view("{}[]\"").find(c) != std::string_view::npos) {
      return true;
    }
  }
  return false;
}

template <typename Result>
void decode(const HttpResponse& response, bool wrapped) {
  try {
    (void)crypto_service::detail::decode<Result>(response, wrapped);
  } catch (const TransportError& error) {
    const std::string message = error.what();
    if (marked(response.body) && message.find(response.body) != std::string::npos) {
      std::abort();  // the body leaked into an error message
    }
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const HttpResponse response{200, std::string(reinterpret_cast<const char*>(data), size), {}};
  decode<crypto_service::HashResult>(response, true);
  decode<crypto_service::EncryptResult>(response, true);
  decode<crypto_service::OpenedText>(response, true);
  decode<crypto_service::KeyUnwrapResult>(response, true);
  decode<crypto_service::KdfResult>(response, true);
  decode<crypto_service::GenerateKeyPairResult>(response, true);
  decode<crypto_service::ExportKeyResult>(response, true);
  decode<crypto_service::StreamVerifyResult>(response, true);
  decode<crypto_service::MultiRecipientEncryptResult>(response, true);
  decode<crypto_service::KmsKey>(response, true);
  decode<crypto_service::DoraScorecard>(response, true);
  decode<crypto_service::HealthStatus>(response, false);
  decode<crypto_service::Cbom>(response, false);
  return 0;
}
