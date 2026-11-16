// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Internal: what the easy-handle and multi-handle transports share: the
// libcurl global state, handle ownership, and one transfer's setup,
// buffers and outcome.

#ifndef CRYPTO_SERVICE_SRC_CURL_COMMON_HPP
#define CRYPTO_SERVICE_SRC_CURL_COMMON_HPP

#include <curl/curl.h>

#include <array>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "crypto_service/transport.hpp"

namespace crypto_service::detail {

/// Throws TransportError(`what`) unless `ok`.
void require_curl(bool ok, const char* what);

/// curl_global_init once per process (thread-safe).
void ensure_curl_global();

/// The libcurl calls whose failure or output the SDK cannot provoke
/// through libcurl itself: the two handle constructors (they fail only
/// when memory is exhausted) and the multi handle's message queue. Each
/// defaults to libcurl's own function.
///
/// Test-only seam. Production code never changes it. A test swaps a call
/// in to reach the path that handles its failure, and restores the
/// defaults, while no transport or AsyncClient is in use on another
/// thread: the pointers are read without synchronisation.
struct CurlCalls {
  CURL* (*easy_init)() = &curl_easy_init;                             ///< curl_easy_init.
  CURLM* (*multi_init)() = &curl_multi_init;                          ///< curl_multi_init.
  CURLMsg* (*multi_info_read)(CURLM*, int*) = &curl_multi_info_read;  ///< curl_multi_info_read.
};

/// The process-wide CurlCalls the transports go through.
CurlCalls& curl_calls();

struct EasyDeleter {
  void operator()(CURL* handle) const noexcept { curl_easy_cleanup(handle); }
};
struct SlistDeleter {
  void operator()(curl_slist* list) const noexcept { curl_slist_free_all(list); }
};
using EasyHandle = std::unique_ptr<CURL, EasyDeleter>;
using HeaderList = std::unique_ptr<curl_slist, SlistDeleter>;

/// A new easy handle; TransportError when libcurl cannot make one.
EasyHandle new_easy_handle();

/// The buffers of one transfer. It must stay at one address, and the
/// request it was prepared with must outlive it, until the transfer ends.
struct Exchange {
  HeaderList headers;                                         ///< The request header list.
  std::array<char, CURL_ERROR_SIZE> error{};                  ///< libcurl's message.
  std::string body;                                           ///< The response body.
  std::vector<std::pair<std::string, std::string>> received;  ///< Response headers.
};

/// Resets `handle` and sets every option for `request`: URL, method,
/// body, headers, timeout, cancellation, no redirects, TLS verification,
/// HTTP and HTTPS only, keep-alive, HTTP/2 over TLS.
void prepare(CURL* handle, const HttpRequest& request, Exchange& exchange);

/// The response of a completed transfer.
HttpResponse response_of(CURL* handle, Exchange& exchange);

/// The exception for a failed transfer: CancelledError when the cancel
/// token aborted it, TransportError (timed_out when it timed out)
/// otherwise.
std::exception_ptr failure(CURLcode code, const Exchange& exchange);

}  // namespace crypto_service::detail

#endif  // CRYPTO_SERVICE_SRC_CURL_COMMON_HPP
