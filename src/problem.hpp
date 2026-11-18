// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// Internal: the problem of a non-2xx response.

#ifndef CRYPTO_SERVICE_SRC_PROBLEM_HPP
#define CRYPTO_SERVICE_SRC_PROBLEM_HPP

#include "crypto_service/errors.hpp"
#include "crypto_service/transport.hpp"

namespace crypto_service::detail {

/// The RFC 9457 problem in `response`'s body, or an `about:blank`
/// problem for its status when the body is not one (TypeScript SDK
/// rule: a JSON object whose `detail` is a string). `status` is always
/// the HTTP status.
Problem problem_of(const HttpResponse& response);

}  // namespace crypto_service::detail

#endif  // CRYPTO_SERVICE_SRC_PROBLEM_HPP
