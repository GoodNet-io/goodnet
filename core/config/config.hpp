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
    /// parse failure (returns `GN_ERR_INVALID_ENVELOPE`) or on
    /// invariant-failure (`GN_ERR_LIMIT_REACHED`).
    ///
    /// The JSON parser tolerates `//`-style and `/* */` comments
    /// in the document — operators routinely annotate config files
    /// with rationale, and a strict parser turns the convenience
    /// into hostility.
    [[nodiscard]] gn_result_t load_json(std::string_view json);

    /// Convenience: read the file at @p path off the filesystem,
    /// then hand the bytes to `load_json`. The kernel itself is
    /// linkable as a library and does not assume an embedding
    /// application; this entry exists for the common case where
    /// the deployment is a single binary that picks its config
    /// off disk at startup.
    ///
    /// Returns `GN_ERR_UNKNOWN_RECEIVER` if the file cannot be
    /// opened (missing path, permission denied), the same parse /
    /// invariant codes `load_json` would return otherwise. Failure
    /// leaves the existing state unchanged in every case.
    [[nodiscard]] gn_result_t load_file(const std::string& path);

    /// Validate cross-field invariants from `limits.md` §3. Returns
    /// `GN_ERR_LIMIT_REACHED` when any invariant fails; the offending
    /// field name is appended to @p out_reason if non-null.
    ///
    /// `load_json` runs this implicitly on the new limits before
    /// installing them, so a successful load is necessarily a
    /// validated load — the kernel never executes against an
    /// invariant-violating limits set. Callers retain access to the
    /// public `validate` for paths that re-check after a manual
    /// `set_limits`.
    [[nodiscard]] gn_result_t validate(std::string* out_reason = nullptr) const;

    /// Validate a free-standing `gn_limits_t` against the same
    /// invariants. Used by `load_json` to gate the install of newly
    /// parsed limits without going through the lock once for parse
    /// and again for validate.
    [[nodiscard]] static gn_result_t validate_limits(
        const gn_limits_t& limits,
        std::string*       out_reason);

    /// Lookup a string value by dotted path. Returns `GN_ERR_UNKNOWN_RECEIVER`
    /// when the key is missing.
    [[nodiscard]] gn_result_t get_string(std::string_view key,
                                         std::string& out) const;

    /// Lookup an integer value by dotted path.
    [[nodiscard]] gn_result_t get_int64(std::string_view key,
                                        std::int64_t& out) const;

    /// Lookup a boolean value by dotted path.
    [[nodiscard]] gn_result_t get_bool(std::string_view key,
                                        bool& out) const;

    /// Lookup a floating-point value by dotted path. Accepts both
    /// JSON `number` (integer literal) and `number` (float literal)
    /// — operators that write `0.5` and operators that write `1`
    /// both reach the same configurable knob without surprise.
    [[nodiscard]] gn_result_t get_double(std::string_view key,
                                          double& out) const;

    /// Lookup the size of an array at @p key. Returns
    /// `GN_ERR_UNKNOWN_RECEIVER` when the key is missing,
    /// `GN_ERR_INVALID_ENVELOPE` when the value is not an array,
    /// `GN_OK` and writes the element count to @p out otherwise.
    [[nodiscard]] gn_result_t get_array_size(std::string_view key,
                                              std::size_t& out) const;

    /// Read the string element at @p index of the array at @p key.
    /// Out-of-bounds @p index returns `GN_ERR_UNKNOWN_RECEIVER`.
    /// Element-type mismatch returns `GN_ERR_INVALID_ENVELOPE`.
    [[nodiscard]] gn_result_t get_array_string(std::string_view key,
                                                std::size_t      index,
                                                std::string&     out) const;

    /// Read the integer element at @p index of the array at @p key.
    /// Same error contract as `get_array_string`.
    [[nodiscard]] gn_result_t get_array_int64(std::string_view key,
                                               std::size_t      index,
                                               std::int64_t&    out) const;

    /// Snapshot of the parsed limits. Read-side accessors hold a
    /// shared lock for the duration of the call.
    [[nodiscard]] gn_limits_t limits() const noexcept;

    /// Serialise the live document back to JSON text. Used by
    /// debugging tooling, by audit pipelines that diff effective
    /// config against the on-disk source, and by tests that pin
    /// round-trip behaviour.
    ///
    /// `indent < 0` produces compact output (no whitespace);
    /// `indent >= 0` pretty-prints with that many spaces per level.
    /// The kernel does not run the result through `validate` again
    /// — `dump` is a read-only observation of state already
    /// validated at load time.
    [[nodiscard]] std::string dump(int indent = -1) const;

    /// Named tuning profile. Selects a baseline `gn_limits_t` —
    /// the JSON document's `limits` block then overrides individual
    /// fields on top of the chosen baseline. The default profile is
    /// `Server` and matches the historical hard-coded canonical
    /// values; `Embedded` shrinks every bound for resource-
    /// constrained IoT or single-board deployments; `Desktop`
    /// picks a middle ground.
    enum class Profile {
        Server,    ///< canonical defaults — large memory, many conns
        Embedded,  ///< small device — tight bounds across the board
        Desktop    ///< single-user — between Server and Embedded
    };

    /// Parse a profile name string into the enum. Recognises
    /// `"server"` / `"embedded"` / `"desktop"` (lowercase). Returns
    /// `Profile::Server` on any other input — the
    /// canonical-defaults baseline is the safe fallback.
    [[nodiscard]] static Profile parse_profile_name(std::string_view name) noexcept;

    /// Return the baseline `gn_limits_t` for @p profile. Identical
    /// to `parse_limits` against an empty JSON document with the
    /// matching profile.
    [[nodiscard]] static gn_limits_t profile_defaults(Profile profile) noexcept;

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
