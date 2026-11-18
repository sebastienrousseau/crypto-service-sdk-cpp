// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
//
// Service metadata, probes, the algorithm catalogue and the compliance
// documents (DORA self-assessment, CycloneDX CBOM).

#ifndef CRYPTO_SERVICE_MODELS_SERVICE_HPP
#define CRYPTO_SERVICE_MODELS_SERVICE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace crypto_service {

/// What `GET /` returns (not wrapped in `data`).
struct ServiceInfo {
  std::string description;  ///< What the service is.
  std::string details;      ///< Further details.
  std::string id;           ///< This server instance (a UUID, new at each start).
  std::string license;      ///< The server's licence.
  std::string title;        ///< The service title.
  std::string url;          ///< The project URL.
  /// The library version as a JSON string literal, quotes included
  /// (`"1.2.3"` with the quotes), exactly as the server sends it.
  std::string version;
};

/// What `GET /health` returns.
struct HealthStatus {
  std::string status;            ///< `ok`.
  std::int64_t status_code = 0;  ///< 200.
  double uptime = 0.0;           ///< Seconds since start.
};

/// What `GET /live` returns.
struct LiveStatus {
  std::string status;       ///< `alive`.
  std::int64_t uptime = 0;  ///< Whole seconds since start.
};

/// The checks behind `GET /ready`.
struct ReadyChecks {
  bool accepting = false;  ///< The server accepts requests.
  bool key_store = false;  ///< The key store is usable.
};

/// What `GET /ready` returns while ready. A server that is not ready
/// answers 503, which the client raises as ApiError.
struct ReadyStatus {
  ReadyChecks checks;  ///< The individual checks.
  std::string status;  ///< `ready`.
};

/// What `GET /v2/algorithms` returns: algorithm names by category.
struct Algorithms {
  std::vector<std::string> encryption;    ///< AEAD and box constructions.
  std::vector<std::string> hashing;       ///< Hash functions.
  std::vector<std::string> kdf;           ///< Key derivation functions.
  std::vector<std::string> key_exchange;  ///< Key agreement and KEMs.
  std::vector<std::string> mac;           ///< MACs.
  std::vector<std::string> post_quantum;  ///< Post-quantum primitives.
  std::vector<std::string> signing;       ///< Signature schemes.
};

/// One planned algorithm sunset in the DORA scorecard.
struct DoraDeprecation {
  std::string algorithm;              ///< The algorithm.
  std::string category;               ///< `symmetric` or `asymmetric`.
  std::string recommended_migration;  ///< What to move to.
  std::string sunset_date;            ///< When.
};

/// One package of the DORA cryptographic inventory.
struct DoraInventoryEntry {
  std::string fips_compliance;  ///< The FIPS statement for the package.
  std::string package;          ///< The package name.
  std::string status;           ///< `implemented`, `partial` or `placeholder`.
  std::string version;          ///< The package version.
};

/// What `GET /v2/compliance/dora` returns: a DORA Article 9 and 13
/// self-assessment, not a certification.
struct DoraScorecard {
  std::int64_t active_primitives_count = 0;                     ///< Primitives in use.
  std::vector<DoraDeprecation> algorithm_deprecation_schedule;  ///< Planned sunsets.
  std::string article;                                          ///< `Article 9 & Article 13`.
  std::vector<DoraInventoryEntry> cryptographic_inventory;      ///< Packages.
  std::string disclaimer;                                       ///< Scope of the assessment.
  std::int64_t post_quantum_primitives_count = 0;               ///< Post-quantum primitives.
  double quantum_resistance_ratio = 0.0;                        ///< Their share.
  std::string standard;                                         ///< `DORA (EU 2022/2554)`.
  std::string status;                                           ///< Overall status.
  std::string timestamp;                                        ///< When it was computed.
};

/// One `name`/`value` property of a CBOM component.
struct CbomProperty {
  std::string name;   ///< The property name.
  std::string value;  ///< Its value.
};

/// One component of the CBOM.
struct CbomComponent {
  std::optional<std::string> name;                      ///< Component name.
  std::optional<std::vector<CbomProperty>> properties;  ///< Its properties.
  std::optional<std::string> type;                      ///< CycloneDX component type.
  std::optional<std::string> version;                   ///< Component version.
};

/// What `GET /v2/compliance/cbom` returns: a CycloneDX 1.6
/// Cryptographic Bill of Materials (not wrapped in `data`).
struct Cbom {
  std::string bom_format;                              ///< `CycloneDX`.
  std::vector<CbomComponent> components;               ///< The components.
  nlohmann::json metadata = nlohmann::json::object();  ///< CycloneDX metadata, unchanged.
  std::string serial_number;                           ///< `urn:uuid:...`.
  std::string spec_version;                            ///< `1.6`.
  std::int64_t version = 0;                            ///< The BOM version.
};

}  // namespace crypto_service

#endif  // CRYPTO_SERVICE_MODELS_SERVICE_HPP
