// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/config.hpp
/// @brief  Typed C++ wrappers over `host_api->config_get`.
///
/// One-expression typed config pulls returning `std::optional<T>`,
/// collapsing the C ABI's three-state ("absent" / "wrong type" /
/// "value retrieved") signal into the option's empty state plus
/// the C ABI's NULL-argument diagnostics. The C path stays
/// available for callers that need the raw error code; this
/// wrapper is for the common branchless pull.
///
/// @code
/// const bool verify =
///     gn::sdk::config_bool(api, "links.tls.verify_peer").value_or(true);
/// @endcode
///
/// All helpers return `std::nullopt` when the key is absent OR the
/// stored value type doesn't match (the C ABI returns
/// `GN_ERR_INVALID_ENVELOPE` on type mismatch). The discriminator
/// "absent vs type mismatch" lives behind a raw `config_get_err`
/// variant for callers that care.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::sdk {

[[nodiscard]] inline std::optional<std::int64_t>
config_int(const host_api_t* api, std::string_view key) noexcept {
    if (!api || !api->config_get || key.empty()) return std::nullopt;
    const std::string z(key);
    std::int64_t out = 0;
    const gn_result_t rc = api->config_get(
        api->host_ctx, z.c_str(),
        GN_CONFIG_VALUE_INT64, GN_CONFIG_NO_INDEX,
        &out, nullptr, nullptr);
    if (rc != GN_OK) return std::nullopt;
    return out;
}

[[nodiscard]] inline std::optional<bool>
config_bool(const host_api_t* api, std::string_view key) noexcept {
    if (!api || !api->config_get || key.empty()) return std::nullopt;
    const std::string z(key);
    bool out = false;
    const gn_result_t rc = api->config_get(
        api->host_ctx, z.c_str(),
        GN_CONFIG_VALUE_BOOL, GN_CONFIG_NO_INDEX,
        &out, nullptr, nullptr);
    if (rc != GN_OK) return std::nullopt;
    return out;
}

[[nodiscard]] inline std::optional<double>
config_double(const host_api_t* api, std::string_view key) noexcept {
    if (!api || !api->config_get || key.empty()) return std::nullopt;
    const std::string z(key);
    double out = 0.0;
    const gn_result_t rc = api->config_get(
        api->host_ctx, z.c_str(),
        GN_CONFIG_VALUE_DOUBLE, GN_CONFIG_NO_INDEX,
        &out, nullptr, nullptr);
    if (rc != GN_OK) return std::nullopt;
    return out;
}

/// String config keys return an opaque malloc'd buffer through the
/// `out_user_data` / `out_free` pair — we wrap that here so the
/// caller gets a plain `std::string` and the underlying allocation
/// is freed before this function returns.
[[nodiscard]] inline std::optional<std::string>
config_string(const host_api_t* api, std::string_view key) {
    if (!api || !api->config_get || key.empty()) return std::nullopt;
    const std::string z(key);
    const char* raw   = nullptr;
    void*       owner = nullptr;
    void (*freefn)(void* user_data, void* bytes) = nullptr;
    const gn_result_t rc = api->config_get(
        api->host_ctx, z.c_str(),
        GN_CONFIG_VALUE_STRING, GN_CONFIG_NO_INDEX,
        static_cast<void*>(&raw), &owner, &freefn);
    if (rc != GN_OK || !raw) {
        if (freefn) (*freefn)(owner, const_cast<char*>(raw));
        return std::nullopt;
    }
    std::string copy(raw);
    if (freefn) (*freefn)(owner, const_cast<char*>(raw));
    return copy;
}

}  // namespace gn::sdk
