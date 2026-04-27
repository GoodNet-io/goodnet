/// @file   core/config/config.hpp
/// @brief  Config holder + JSON load + lookup for the kernel and plugins.
///
/// Per `limits.md` §2 / `host-api.md` §2 (config slots): the kernel
/// owns one Config instance loaded from JSON at startup; plugins
/// query it through `host_api->config_get_string` /
/// `config_get_int64`. Top-level keys are flat strings; nested values
/// addressable through dotted paths (e.g. `"limits.max_connections"`).

#pragma once

#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include <sdk/limits.h>
#include <sdk/types.h>

namespace gn::core {

/// JSON-backed config holder. Thread-safe for concurrent reads;
/// reload is exclusive.
class Config {
public:
    /// Default-constructed config carries the canonical default
    /// limits and an empty JSON object — every key lookup misses.
    Config();

    /// Load a JSON document from raw text. Replaces the current
    /// state on success; leaves the existing state unchanged on
    /// parse failure (returns `GN_ERR_INVALID_ENVELOPE` repurposed
    /// as parse-failure indicator until a dedicated drop reason
    /// lands).
    [[nodiscard]] gn_result_t load_json(std::string_view json);

    /// Validate cross-field invariants from `limits.md` §3. Returns
    /// `GN_ERR_LIMIT_REACHED` when any invariant fails; the offending
    /// field name is appended to @p out_reason if non-null.
    [[nodiscard]] gn_result_t validate(std::string* out_reason = nullptr) const;

    /// Lookup a string value by dotted path. Returns `GN_ERR_UNKNOWN_RECEIVER`
    /// when the key is missing.
    [[nodiscard]] gn_result_t get_string(std::string_view key,
                                         std::string& out) const;

    /// Lookup an integer value by dotted path.
    [[nodiscard]] gn_result_t get_int64(std::string_view key,
                                        std::int64_t& out) const;

    /// Snapshot of the parsed limits. Read-side accessors hold a
    /// shared lock for the duration of the call.
    [[nodiscard]] gn_limits_t limits() const noexcept;

private:
    [[nodiscard]] static gn_limits_t parse_limits(const nlohmann::json& root);

    /// Resolve a dotted path against the JSON root. Returns nullopt
    /// when any segment is missing or not an object on the way.
    [[nodiscard]] std::optional<nlohmann::json>
    resolve(std::string_view dotted_key) const;

    mutable std::shared_mutex mu_;
    nlohmann::json            json_;
    gn_limits_t               limits_;
};

} // namespace gn::core
