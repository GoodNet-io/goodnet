// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/config.hpp
/// @brief  Typed C++ wrappers over `host_api->config_get`.
///
/// ## Scalar helpers (return `std::optional<T>`)
///
/// ```cpp
/// const bool verify =
///     gn::sdk::config_get<bool>(api, "links.tls.verify_peer").value_or(true);
/// // or the named aliases:
/// const bool verify = gn::sdk::config_bool(api, "links.tls.verify_peer").value_or(true);
/// ```
///
/// Both "key absent" and "type mismatch" collapse to `std::nullopt`.
/// Use `config_get_or_err<T>` when you need to distinguish the two.
///
/// ## Zero-copy string access
///
/// ```cpp
/// auto s = gn::sdk::config_string_raw(api, "links.tls.cert_path");
/// if (s) use(s->view());   // no heap copy; buffer freed when s goes out of scope
/// ```

#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <sdk/host_api.h>
#include <sdk/types.h>
#include <sdk/cpp/contract.hpp>

namespace gn::sdk {

// ── ConfigString ─────────────────────────────────────────────────────────────

/// RAII owner for the malloc'd buffer returned by STRING config queries.
/// Move-only; freed via the kernel-supplied destructor on destruction.
struct ConfigString {
    const char* data   = nullptr;
    void*       owner  = nullptr;
    void (*freefn)(void* owner, void* bytes) = nullptr;

    ConfigString() noexcept = default;
    ConfigString(const char* d, void* o,
                 void (*f)(void*, void*)) noexcept
        : data(d), owner(o), freefn(f) {}

    ~ConfigString() noexcept {
        if (freefn && data) (*freefn)(owner, const_cast<char*>(data));
    }

    ConfigString(ConfigString&& o) noexcept
        : data(o.data), owner(o.owner), freefn(o.freefn) {
        o.data = nullptr; o.freefn = nullptr;
    }
    ConfigString& operator=(ConfigString&& o) noexcept {
        if (this != &o) {
            if (freefn && data) (*freefn)(owner, const_cast<char*>(data));
            data = o.data; owner = o.owner; freefn = o.freefn;
            o.data = nullptr; o.freefn = nullptr;
        }
        return *this;
    }
    ConfigString(const ConfigString&)            = delete;
    ConfigString& operator=(const ConfigString&) = delete;

    std::string_view view()  const noexcept { return data ? std::string_view(data) : ""; }
    explicit operator bool() const noexcept { return data != nullptr; }
};

// ── Internal helpers ──────────────────────────────────────────────────────────

namespace detail {

// NUL-terminated copy of a string_view for C API calls.
// In C++26, std::string is constexpr — the compiler may elide the allocation
// when key is a string literal known at compile time.
inline std::string to_cstr(std::string_view key) { return std::string(key); }

} // namespace detail

// ── config_get<T> — primary template ─────────────────────────────────────────

/// Returns the config value at @p key as `std::optional<T>`, or `std::nullopt`
/// when the key is absent or the stored type doesn't match T.
template <typename T>
[[nodiscard]] std::optional<T>
config_get(const host_api_t* api, std::string_view key) noexcept;

// ── Specializations ───────────────────────────────────────────────────────────

template <>
[[nodiscard]] inline std::optional<std::int64_t>
config_get<std::int64_t>(const host_api_t* api, std::string_view key) noexcept
{
    if (!api || !api->config_get || key.empty()) return std::nullopt;
    const auto z = detail::to_cstr(key);
    std::int64_t out = 0;
    if (api->config_get(api->host_ctx, z.c_str(),
                        GN_CONFIG_VALUE_INT64, GN_CONFIG_NO_INDEX,
                        &out, nullptr, nullptr) != GN_OK)
        return std::nullopt;
    return out;
}

template <>
[[nodiscard]] inline std::optional<bool>
config_get<bool>(const host_api_t* api, std::string_view key) noexcept
{
    if (!api || !api->config_get || key.empty()) return std::nullopt;
    const auto z = detail::to_cstr(key);
    bool out = false;
    if (api->config_get(api->host_ctx, z.c_str(),
                        GN_CONFIG_VALUE_BOOL, GN_CONFIG_NO_INDEX,
                        &out, nullptr, nullptr) != GN_OK)
        return std::nullopt;
    return out;
}

template <>
[[nodiscard]] inline std::optional<double>
config_get<double>(const host_api_t* api, std::string_view key) noexcept
{
    if (!api || !api->config_get || key.empty()) return std::nullopt;
    const auto z = detail::to_cstr(key);
    double out = 0.0;
    if (api->config_get(api->host_ctx, z.c_str(),
                        GN_CONFIG_VALUE_DOUBLE, GN_CONFIG_NO_INDEX,
                        &out, nullptr, nullptr) != GN_OK)
        return std::nullopt;
    return out;
}

template <>
[[nodiscard]] inline std::optional<std::string>
config_get<std::string>(const host_api_t* api, std::string_view key)
{
    if (!api || !api->config_get || key.empty()) return std::nullopt;
    const auto z = detail::to_cstr(key);
    const char* raw  = nullptr;
    void*       own  = nullptr;
    void (*fn)(void*, void*) = nullptr;
    if (api->config_get(api->host_ctx, z.c_str(),
                        GN_CONFIG_VALUE_STRING, GN_CONFIG_NO_INDEX,
                        static_cast<void*>(&raw), &own, &fn) != GN_OK || !raw) {
        if (fn && raw) (*fn)(own, const_cast<char*>(raw));
        return std::nullopt;
    }
    std::string copy(raw);
    (*fn)(own, const_cast<char*>(raw));
    return copy;
}

// ── Zero-copy string variant ──────────────────────────────────────────────────

/// Like `config_get<std::string>` but returns a `ConfigString` — no heap copy.
/// The caller accesses the value via `.view()` and the buffer is freed on
/// destruction of the returned object.
[[nodiscard]] inline std::optional<ConfigString>
config_string_raw(const host_api_t* api, std::string_view key)
{
    if (!api || !api->config_get || key.empty()) return std::nullopt;
    const auto z = detail::to_cstr(key);
    const char* raw  = nullptr;
    void*       own  = nullptr;
    void (*fn)(void*, void*) = nullptr;
    if (api->config_get(api->host_ctx, z.c_str(),
                        GN_CONFIG_VALUE_STRING, GN_CONFIG_NO_INDEX,
                        static_cast<void*>(&raw), &own, &fn) != GN_OK || !raw) {
        if (fn && raw) (*fn)(own, const_cast<char*>(raw));
        return std::nullopt;
    }
    return ConfigString{raw, own, fn};
}

// ── Error-discriminating variant ──────────────────────────────────────────────

/// Like `config_get<T>` but returns `std::expected<T, gn_result_t>` so the
/// caller can tell `GN_ERR_NOT_FOUND` (key absent) from
/// `GN_ERR_INVALID_ENVELOPE` (type mismatch).
template <typename T>
[[nodiscard]] std::expected<T, gn_result_t>
config_get_or_err(const host_api_t* api, std::string_view key) noexcept;

template <>
[[nodiscard]] inline std::expected<std::int64_t, gn_result_t>
config_get_or_err<std::int64_t>(const host_api_t* api, std::string_view key) noexcept
{
    if (!api || !api->config_get || key.empty())
        return std::unexpected(GN_ERR_NULL_ARG);
    const auto z = detail::to_cstr(key);
    std::int64_t out = 0;
    const gn_result_t rc = api->config_get(api->host_ctx, z.c_str(),
                                           GN_CONFIG_VALUE_INT64, GN_CONFIG_NO_INDEX,
                                           &out, nullptr, nullptr);
    if (rc != GN_OK) return std::unexpected(rc);
    return out;
}

template <>
[[nodiscard]] inline std::expected<bool, gn_result_t>
config_get_or_err<bool>(const host_api_t* api, std::string_view key) noexcept
{
    if (!api || !api->config_get || key.empty())
        return std::unexpected(GN_ERR_NULL_ARG);
    const auto z = detail::to_cstr(key);
    bool out = false;
    const gn_result_t rc = api->config_get(api->host_ctx, z.c_str(),
                                           GN_CONFIG_VALUE_BOOL, GN_CONFIG_NO_INDEX,
                                           &out, nullptr, nullptr);
    if (rc != GN_OK) return std::unexpected(rc);
    return out;
}

template <>
[[nodiscard]] inline std::expected<double, gn_result_t>
config_get_or_err<double>(const host_api_t* api, std::string_view key) noexcept
{
    if (!api || !api->config_get || key.empty())
        return std::unexpected(GN_ERR_NULL_ARG);
    const auto z = detail::to_cstr(key);
    double out = 0.0;
    const gn_result_t rc = api->config_get(api->host_ctx, z.c_str(),
                                           GN_CONFIG_VALUE_DOUBLE, GN_CONFIG_NO_INDEX,
                                           &out, nullptr, nullptr);
    if (rc != GN_OK) return std::unexpected(rc);
    return out;
}

// ── Named aliases (backward-compat) ──────────────────────────────────────────

[[nodiscard]] inline std::optional<std::int64_t>
config_int(const host_api_t* api, std::string_view key) noexcept {
    return config_get<std::int64_t>(api, key);
}

[[nodiscard]] inline std::optional<bool>
config_bool(const host_api_t* api, std::string_view key) noexcept {
    return config_get<bool>(api, key);
}

[[nodiscard]] inline std::optional<double>
config_double(const host_api_t* api, std::string_view key) noexcept {
    return config_get<double>(api, key);
}

[[nodiscard]] inline std::optional<std::string>
config_string(const host_api_t* api, std::string_view key) {
    return config_get<std::string>(api, key);
}

} // namespace gn::sdk
