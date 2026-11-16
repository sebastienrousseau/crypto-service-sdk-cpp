// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Internal: the wire schema of the KMS, OPAQUE and service structs (see
// schemas_core.hpp).

#ifndef CRYPTO_SERVICE_SRC_SCHEMAS_SERVICE_HPP
#define CRYPTO_SERVICE_SRC_SCHEMAS_SERVICE_HPP

#include <tuple>

#include "codec.hpp"
#include "crypto_service/models/kms.hpp"
#include "crypto_service/models/service.hpp"
#include "schemas_core.hpp"

namespace crypto_service::detail::codec {

// --- KMS ---

template <>
struct Schema<KmsCreateKeyRequest> {
  static auto fields() {
    using T = KmsCreateKeyRequest;
    return std::make_tuple(field("algorithm", &T::algorithm), field("metadata", &T::metadata),
                           field("provider", &T::provider), field("usage", &T::usage));
  }
};
template <>
struct Schema<KmsKey> {
  static auto fields() {
    using T = KmsKey;
    return std::make_tuple(field("algorithm", &T::algorithm), field("createdAt", &T::created_at),
                           field("currentVersion", &T::current_version),
                           field("enabled", &T::enabled), field("keyId", &T::key_id),
                           field("provider", &T::provider), field("usage", &T::usage));
  }
};
template <>
struct Schema<KmsEncryptRequest> {
  static auto fields() {
    using T = KmsEncryptRequest;
    return std::make_tuple(field("context", &T::context), Const{"encoding", "hex"},
                           field("keyId", &T::key_id), field("plaintext", &T::plaintext, kHex),
                           field("provider", &T::provider));
  }
};
template <>
struct Schema<KmsEncryptResult> {
  static auto fields() {
    using T = KmsEncryptResult;
    return std::make_tuple(field("ciphertext", &T::ciphertext), field("context", &T::context),
                           field("keyId", &T::key_id), field("keyVersion", &T::key_version),
                           field("provider", &T::provider));
  }
};
template <>
struct Schema<KmsDecryptRequest> {
  static auto fields() {
    using T = KmsDecryptRequest;
    return std::make_tuple(field("ciphertext", &T::ciphertext), field("context", &T::context),
                           field("keyId", &T::key_id), field("provider", &T::provider));
  }
};
template <>
struct Schema<KmsDecryptResult> {
  static auto fields() {
    using T = KmsDecryptResult;
    return std::make_tuple(field("hex", &T::hex, kHex), field("keyId", &T::key_id),
                           field("plaintext", &T::plaintext), field("provider", &T::provider));
  }
};
template <>
struct Schema<KmsGenerateDataKeyRequest> {
  static auto fields() {
    using T = KmsGenerateDataKeyRequest;
    return std::make_tuple(field("keyId", &T::key_id), field("keySpec", &T::key_spec),
                           field("provider", &T::provider));
  }
};
template <>
struct Schema<KmsDataKey> {
  static auto fields() {
    using T = KmsDataKey;
    return std::make_tuple(field("ciphertext", &T::ciphertext), field("keyId", &T::key_id),
                           field("plaintext", &T::plaintext, kHex),
                           field("provider", &T::provider));
  }
};
template <>
struct Schema<KmsWrapRequest> {
  static auto fields() {
    using T = KmsWrapRequest;
    return std::make_tuple(field("context", &T::context), field("keyId", &T::key_id),
                           field("provider", &T::provider),
                           field("unwrappedKey", &T::unwrapped_key, kHex));
  }
};
template <>
struct Schema<KmsWrapResult> {
  static auto fields() {
    using T = KmsWrapResult;
    return std::make_tuple(field("keyId", &T::key_id), field("provider", &T::provider),
                           field("wrappedKey", &T::wrapped_key));
  }
};
template <>
struct Schema<KmsUnwrapRequest> {
  static auto fields() {
    using T = KmsUnwrapRequest;
    return std::make_tuple(field("context", &T::context), field("keyId", &T::key_id),
                           field("provider", &T::provider), field("wrappedKey", &T::wrapped_key));
  }
};
template <>
struct Schema<KmsUnwrapResult> {
  static auto fields() {
    using T = KmsUnwrapResult;
    return std::make_tuple(field("keyId", &T::key_id), field("provider", &T::provider),
                           field("unwrappedKey", &T::unwrapped_key, kHex));
  }
};

// --- OPAQUE ---

template <>
struct Schema<OpaqueRegisterInitRequest> {
  static auto fields() {
    using T = OpaqueRegisterInitRequest;
    return std::make_tuple(field("credentialIdentifier", &T::credential_identifier),
                           field("request", &T::request, kHex), field("suite", &T::suite));
  }
};
template <>
struct Schema<OpaqueRegisterInitResult> {
  static auto fields() {
    return std::make_tuple(field("response", &OpaqueRegisterInitResult::response, kHex));
  }
};
template <>
struct Schema<OpaqueRegisterFinishRequest> {
  static auto fields() {
    using T = OpaqueRegisterFinishRequest;
    return std::make_tuple(field("credentialIdentifier", &T::credential_identifier),
                           field("record", &T::record, kHex), field("suite", &T::suite));
  }
};
template <>
struct Schema<OpaqueRegisterFinishResult> {
  static auto fields() {
    using T = OpaqueRegisterFinishResult;
    return std::make_tuple(field("credentialIdentifier", &T::credential_identifier),
                           field("status", &T::status));
  }
};
template <>
struct Schema<OpaqueLoginInitRequest> {
  static auto fields() {
    using T = OpaqueLoginInitRequest;
    return std::make_tuple(field("credentialIdentifier", &T::credential_identifier),
                           field("ke1", &T::ke1, kHex), field("suite", &T::suite));
  }
};
template <>
struct Schema<OpaqueLoginInitResult> {
  static auto fields() {
    return std::make_tuple(field("ke2", &OpaqueLoginInitResult::ke2, kHex),
                           field("sessionId", &OpaqueLoginInitResult::session_id));
  }
};
template <>
struct Schema<OpaqueLoginFinishRequest> {
  static auto fields() {
    return std::make_tuple(field("ke3", &OpaqueLoginFinishRequest::ke3, kHex),
                           field("sessionId", &OpaqueLoginFinishRequest::session_id));
  }
};
template <>
struct Schema<OpaqueLoginFinishResult> {
  static auto fields() {
    return std::make_tuple(field("sessionKey", &OpaqueLoginFinishResult::session_key, kHex));
  }
};

// --- Service and compliance ---

template <>
struct Schema<ServiceInfo> {
  static auto fields() {
    using T = ServiceInfo;
    return std::make_tuple(field("description", &T::description), field("details", &T::details),
                           field("id", &T::id), field("license", &T::license),
                           field("title", &T::title), field("url", &T::url),
                           field("version", &T::version));
  }
};
template <>
struct Schema<HealthStatus> {
  static auto fields() {
    return std::make_tuple(field("status", &HealthStatus::status),
                           field("statusCode", &HealthStatus::status_code),
                           field("uptime", &HealthStatus::uptime));
  }
};
template <>
struct Schema<LiveStatus> {
  static auto fields() {
    return std::make_tuple(field("status", &LiveStatus::status),
                           field("uptime", &LiveStatus::uptime));
  }
};
template <>
struct Schema<ReadyChecks> {
  static auto fields() {
    return std::make_tuple(field("accepting", &ReadyChecks::accepting),
                           field("keyStore", &ReadyChecks::key_store));
  }
};
template <>
struct Schema<ReadyStatus> {
  static auto fields() {
    return std::make_tuple(field("checks", &ReadyStatus::checks),
                           field("status", &ReadyStatus::status));
  }
};
template <>
struct Schema<Algorithms> {
  static auto fields() {
    using T = Algorithms;
    return std::make_tuple(field("encryption", &T::encryption), field("hashing", &T::hashing),
                           field("kdf", &T::kdf), field("keyExchange", &T::key_exchange),
                           field("mac", &T::mac), field("postQuantum", &T::post_quantum),
                           field("signing", &T::signing));
  }
};
template <>
struct Schema<DoraDeprecation> {
  static auto fields() {
    using T = DoraDeprecation;
    return std::make_tuple(field("algorithm", &T::algorithm), field("category", &T::category),
                           field("recommendedMigration", &T::recommended_migration),
                           field("sunsetDate", &T::sunset_date));
  }
};
template <>
struct Schema<DoraInventoryEntry> {
  static auto fields() {
    using T = DoraInventoryEntry;
    return std::make_tuple(field("fipsCompliance", &T::fips_compliance),
                           field("package", &T::package), field("status", &T::status),
                           field("version", &T::version));
  }
};
template <>
struct Schema<DoraScorecard> {
  static auto fields() {
    using T = DoraScorecard;
    return std::make_tuple(
        field("activePrimitivesCount", &T::active_primitives_count),
        field("algorithmDeprecationSchedule", &T::algorithm_deprecation_schedule),
        field("article", &T::article), field("cryptographicInventory", &T::cryptographic_inventory),
        field("disclaimer", &T::disclaimer),
        field("postQuantumPrimitivesCount", &T::post_quantum_primitives_count),
        field("quantumResistanceRatio", &T::quantum_resistance_ratio),
        field("standard", &T::standard), field("status", &T::status),
        field("timestamp", &T::timestamp));
  }
};
template <>
struct Schema<CbomProperty> {
  static auto fields() {
    return std::make_tuple(field("name", &CbomProperty::name),
                           field("value", &CbomProperty::value));
  }
};
template <>
struct Schema<CbomComponent> {
  static auto fields() {
    using T = CbomComponent;
    return std::make_tuple(field("name", &T::name), field("properties", &T::properties),
                           field("type", &T::type), field("version", &T::version));
  }
};
template <>
struct Schema<Cbom> {
  static auto fields() {
    using T = Cbom;
    return std::make_tuple(field("bomFormat", &T::bom_format), field("components", &T::components),
                           field("metadata", &T::metadata),
                           field("serialNumber", &T::serial_number),
                           field("specVersion", &T::spec_version), field("version", &T::version));
  }
};

}  // namespace crypto_service::detail::codec

#endif  // CRYPTO_SERVICE_SRC_SCHEMAS_SERVICE_HPP
