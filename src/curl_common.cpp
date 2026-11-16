// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// One libcurl transfer's setup and outcome, for both transports. The
// security options are set on every transfer and have no off switch:
// redirects are not followed, TLS peers and host names are verified, and
// only HTTP and HTTPS are spoken.

#include "curl_common.hpp"

#include <cstddef>
#include <exception>
#include <string>
#include <string_view>
#include <utility>

#include "crypto_service/errors.hpp"

namespace crypto_service::detail {
namespace {

// curl_global_init at first use, curl_global_cleanup at exit. A
// function-local static is initialised once, even across threads.
class CurlGlobal {
 public:
  CurlGlobal() {
    require_curl(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK,
                 "libcurl global initialisation failed");
  }
  CurlGlobal(const CurlGlobal&) = delete;
  CurlGlobal& operator=(const CurlGlobal&) = delete;
  CurlGlobal(CurlGlobal&&) = delete;
  CurlGlobal& operator=(CurlGlobal&&) = delete;
  ~CurlGlobal() { curl_global_cleanup(); }
};

std::size_t write_body(char* data, std::size_t size, std::size_t count, void* user) {
  static_cast<std::string*>(user)->append(data, size * count);
  return size * count;
}

std::string_view trim(std::string_view text) {
  const auto first = text.find_first_not_of(" \t\r\n");
  if (first == std::string_view::npos) {
    return {};
  }
  return text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
}

// One header line per call. A status line starts a new response (after
// an interim 100 Continue), so the headers collected so far are dropped;
// the blank line ending the block has no colon and is skipped.
std::size_t write_header(char* data, std::size_t size, std::size_t count, void* user) {
  auto* out = static_cast<std::vector<std::pair<std::string, std::string>>*>(user);
  const std::string_view line(data, size * count);
  const auto colon = line.find(':');
  if (line.substr(0, 5) == "HTTP/") {
    out->clear();
  } else if (colon != std::string_view::npos) {
    out->emplace_back(std::string(line.substr(0, colon)),
                      std::string(trim(line.substr(colon + 1))));
  }
  return size * count;
}

// Aborts the transfer (CURLE_ABORTED_BY_CALLBACK) once cancelled.
int on_progress(void* user, curl_off_t /*dltotal*/, curl_off_t /*dlnow*/, curl_off_t /*ultotal*/,
                curl_off_t /*ulnow*/) {
  return static_cast<const CancelToken*>(user)->cancelled() ? 1 : 0;
}

template <typename T>
void set(CURL* handle, CURLoption option, T value) {
  require_curl(curl_easy_setopt(handle, option, value) == CURLE_OK,
               "libcurl rejected a request option");
}

HeaderList header_list(const HttpRequest& request) {
  HeaderList list;
  // An empty Expect stops libcurl waiting for 100 Continue on large bodies.
  std::vector<std::string> lines{"Expect:"};
  for (const auto& [name, value] : request.headers) {
    std::string line = name;
    line.append(": ").append(value);
    lines.push_back(std::move(line));
  }
  for (const std::string& line : lines) {
    curl_slist* head = curl_slist_append(list.get(), line.c_str());
    require_curl(head != nullptr, "out of memory building request headers");
    if (!list) {
      list.reset(head);  // the first append creates the list
    }
  }
  return list;
}

void set_method(CURL* handle, const HttpRequest& request) {
  if (request.method == "GET") {
    set(handle, CURLOPT_HTTPGET, 1L);
    return;
  }
  // libcurl keeps the pointer until the transfer ends: it points into the
  // request, which outlives the transfer.
  const char* data = request.body ? request.body->c_str() : "";
  const std::size_t size = request.body ? request.body->size() : 0;
  set(handle, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(size));
  set(handle, CURLOPT_POSTFIELDS, data);
  if (request.method != "POST") {
    set(handle, CURLOPT_CUSTOMREQUEST, request.method.c_str());
  }
}

void set_security(CURL* handle) {
  set(handle, CURLOPT_FOLLOWLOCATION, 0L);
  set(handle, CURLOPT_SSL_VERIFYPEER, 1L);
  set(handle, CURLOPT_SSL_VERIFYHOST, 2L);
  set(handle, CURLOPT_PROTOCOLS_STR, "http,https");
}

void set_cancel(CURL* handle, const HttpRequest& request) {
  if (!request.cancel.cancellable()) {
    return;
  }
  set(handle, CURLOPT_NOPROGRESS, 0L);
  set(handle, CURLOPT_XFERINFOFUNCTION, &on_progress);
  set(handle, CURLOPT_XFERINFODATA, static_cast<const void*>(&request.cancel));
}

}  // namespace

void require_curl(bool ok, const char* what) {
  if (!ok) {
    throw TransportError(std::string("crypto-service: ") + what);
  }
}

void ensure_curl_global() { static const CurlGlobal global; }

CurlCalls& curl_calls() {
  static CurlCalls calls;
  return calls;
}

EasyHandle new_easy_handle() {
  ensure_curl_global();
  EasyHandle handle(curl_calls().easy_init());
  // curl_easy_init fails only when memory is exhausted.
  require_curl(handle != nullptr, "libcurl could not create a handle");
  return handle;
}

void prepare(CURL* handle, const HttpRequest& request, Exchange& exchange) {
  curl_easy_reset(handle);
  exchange.headers = header_list(request);
  set(handle, CURLOPT_URL, request.url.c_str());
  set(handle, CURLOPT_ERRORBUFFER, exchange.error.data());
  set(handle, CURLOPT_NOSIGNAL, 1L);
  set(handle, CURLOPT_TIMEOUT_MS, static_cast<long>(request.timeout.count()));
  set(handle, CURLOPT_ACCEPT_ENCODING, "");
  set(handle, CURLOPT_TCP_KEEPALIVE, 1L);
  set(handle, CURLOPT_HTTP_VERSION, static_cast<long>(CURL_HTTP_VERSION_2TLS));
  set(handle, CURLOPT_PIPEWAIT, 1L);
  set_security(handle);
  set_method(handle, request);
  set_cancel(handle, request);
  set(handle, CURLOPT_HTTPHEADER, exchange.headers.get());
  set(handle, CURLOPT_WRITEFUNCTION, &write_body);
  set(handle, CURLOPT_WRITEDATA, static_cast<void*>(&exchange.body));
  set(handle, CURLOPT_HEADERFUNCTION, &write_header);
  set(handle, CURLOPT_HEADERDATA, static_cast<void*>(&exchange.received));
}

HttpResponse response_of(CURL* handle, Exchange& exchange) {
  long status = 0;
  curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
  return HttpResponse{status, std::move(exchange.body), std::move(exchange.received)};
}

std::exception_ptr failure(CURLcode code, const Exchange& exchange) {
  if (code == CURLE_ABORTED_BY_CALLBACK) {
    return std::make_exception_ptr(CancelledError("crypto-service: the call was cancelled"));
  }
  // libcurl fills the error buffer on every failed transfer; the
  // fallback to the code's description is defensive.
  const std::string reason =
      exchange.error[0] != '\0' ? exchange.error.data() : curl_easy_strerror(code);
  const bool timed_out = code == CURLE_OPERATION_TIMEDOUT;
  return std::make_exception_ptr(
      TransportError(std::string("crypto-service: ") +
                         (timed_out ? "request timed out: " : "request failed: ") + reason,
                     timed_out));
}

}  // namespace crypto_service::detail
