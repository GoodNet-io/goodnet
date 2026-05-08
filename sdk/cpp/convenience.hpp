/// @file   sdk/cpp/convenience.hpp
/// @brief  Inline-function wrappers around the host_api vtable —
///         the C++ analog of `sdk/convenience.h`.
///
/// `sdk/convenience.h` builds its register-meta arguments through C99
/// compound literals (`&(gn_register_meta_t){ .api_size = …, .name =
/// …, … }`). GCC and clang accept compound literals in C++ as a
/// documented extension; MSVC does not. C++ plugins built with MSVC
/// therefore cannot use the C macros for `register_handler` /
/// `register_link` directly — they have to declare a named local of
/// `gn_register_meta_t`, fill it field by field, and call
/// `register_vtable` themselves.
///
/// This header gives MSVC C++ plugin authors the same one-liner shape
/// without compound literals: `gn::register_handler(api, "gnet-v1",
/// 0xBEEF, /*priority*/128, vtable, self, &out_id)` packs the meta
/// struct on the caller's stack with a named temporary, then calls
/// the vtable. GCC and clang miss nothing — the inline call collapses
/// to the same machine code as the macro expansion.
///
/// Logging stays in `sdk/cpp/log.hpp` — the printf vs std::format
/// split there is more than a syntactic difference and would not
/// belong in a "convenience" header.
///
/// Include order: any time after `sdk/host_api.h`.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>

#include <sdk/host_api.h>

namespace gn {

// ── Messaging ────────────────────────────────────────────────────────────

/// `api->send(api->host_ctx, conn, msg_id, payload, size)` without
/// the host_ctx ceremony.
[[nodiscard]] inline gn_result_t send(
    const host_api_t* api,
    gn_conn_id_t conn,
    std::uint32_t msg_id,
    std::span<const std::uint8_t> payload) noexcept {
    return api->send(api->host_ctx, conn, msg_id,
                     payload.data(), payload.size());
}

[[nodiscard]] inline gn_result_t disconnect(
    const host_api_t* api, gn_conn_id_t conn) noexcept {
    return api->disconnect(api->host_ctx, conn);
}

// ── Handler / link / extension registration ───────────────────────────────

/// Pack the `gn_register_meta_t` struct as a named local and route
/// through `register_vtable`. The local lives for the duration of
/// the call — `register_vtable` is documented to copy or borrow
/// `meta->name` per its contract on `gn_register_meta_t`, so a
/// stack temporary is enough.
[[nodiscard]] inline gn_result_t register_handler(
    const host_api_t* api,
    const char* protocol_id,
    std::uint32_t msg_id,
    std::uint8_t priority,
    const gn_handler_vtable_t* vtable,
    void* self,
    gn_handler_id_t* out_id) noexcept {
    gn_register_meta_t meta{};
    meta.api_size = sizeof(meta);
    meta.name     = protocol_id;
    meta.msg_id   = msg_id;
    meta.priority = priority;
    return api->register_vtable(api->host_ctx, GN_REGISTER_HANDLER,
                                 &meta, vtable, self,
                                 reinterpret_cast<std::uint64_t*>(out_id));
}

[[nodiscard]] inline gn_result_t unregister_handler(
    const host_api_t* api, gn_handler_id_t id) noexcept {
    return api->unregister_vtable(api->host_ctx,
                                   static_cast<std::uint64_t>(id));
}

[[nodiscard]] inline gn_result_t register_link(
    const host_api_t* api,
    const char* scheme,
    const gn_link_vtable_t* vtable,
    void* self,
    gn_link_id_t* out_id) noexcept {
    gn_register_meta_t meta{};
    meta.api_size = sizeof(meta);
    meta.name     = scheme;
    meta.msg_id   = 0;
    meta.priority = 0;
    return api->register_vtable(api->host_ctx, GN_REGISTER_LINK,
                                 &meta, vtable, self,
                                 reinterpret_cast<std::uint64_t*>(out_id));
}

[[nodiscard]] inline gn_result_t unregister_link(
    const host_api_t* api, gn_link_id_t id) noexcept {
    return api->unregister_vtable(api->host_ctx,
                                   static_cast<std::uint64_t>(id));
}

[[nodiscard]] inline gn_result_t register_extension(
    const host_api_t* api,
    const char* name,
    std::uint32_t version,
    const void* vtable) noexcept {
    return api->register_extension(api->host_ctx, name, version, vtable);
}

[[nodiscard]] inline gn_result_t query_extension(
    const host_api_t* api,
    const char* name,
    std::uint32_t version,
    const void** out_vtable) noexcept {
    return api->query_extension_checked(api->host_ctx, name,
                                         version, out_vtable);
}

/// Typed extension query — returns a typed pointer or `nullptr`.
/// `T` is the extension's vtable struct (e.g. `gn_heartbeat_api_t`);
/// the caller passes the matching name + version pair.
template <class T>
[[nodiscard]] inline const T* query_extension_typed(
    const host_api_t* api,
    const char* name,
    std::uint32_t version) noexcept {
    const void* vt = nullptr;
    if (api == nullptr || api->query_extension_checked == nullptr) {
        return nullptr;
    }
    if (api->query_extension_checked(api->host_ctx, name, version, &vt)
            != GN_OK) {
        return nullptr;
    }
    return static_cast<const T*>(vt);
}

// ── Registry queries ──────────────────────────────────────────────────────

[[nodiscard]] inline gn_result_t find_conn_by_pk(
    const host_api_t* api,
    const std::uint8_t pk[GN_PUBLIC_KEY_BYTES],
    gn_conn_id_t* out_conn) noexcept {
    return api->find_conn_by_pk(api->host_ctx, pk, out_conn);
}

[[nodiscard]] inline gn_result_t get_endpoint(
    const host_api_t* api,
    gn_conn_id_t conn,
    gn_endpoint_t* out_endpoint) noexcept {
    return api->get_endpoint(api->host_ctx, conn, out_endpoint);
}

// ── Configuration ─────────────────────────────────────────────────────────

[[nodiscard]] inline gn_result_t config_get_int64(
    const host_api_t* api, const char* key, std::int64_t* out_value) noexcept {
    return api->config_get(api->host_ctx, key,
                           GN_CONFIG_VALUE_INT64, GN_CONFIG_NO_INDEX,
                           out_value, nullptr, nullptr);
}

[[nodiscard]] inline gn_result_t config_get_bool(
    const host_api_t* api, const char* key, std::int32_t* out_value) noexcept {
    return api->config_get(api->host_ctx, key,
                           GN_CONFIG_VALUE_BOOL, GN_CONFIG_NO_INDEX,
                           out_value, nullptr, nullptr);
}

[[nodiscard]] inline gn_result_t config_get_double(
    const host_api_t* api, const char* key, double* out_value) noexcept {
    return api->config_get(api->host_ctx, key,
                           GN_CONFIG_VALUE_DOUBLE, GN_CONFIG_NO_INDEX,
                           out_value, nullptr, nullptr);
}

[[nodiscard]] inline gn_result_t config_get_array_size(
    const host_api_t* api, const char* key, std::size_t* out_size) noexcept {
    return api->config_get(api->host_ctx, key,
                           GN_CONFIG_VALUE_ARRAY_SIZE, GN_CONFIG_NO_INDEX,
                           out_size, nullptr, nullptr);
}

/// `STRING` reads land the malloc'd buffer, the destruction-state
/// pointer, and the destructor in three out-params; the plugin frees
/// through `(*out_free)(*out_user_data, *out_str)`.
[[nodiscard]] inline gn_result_t config_get_string(
    const host_api_t* api,
    const char* key,
    char** out_str,
    void** out_user_data,
    void (**out_free)(void*, void*)) noexcept {
    return api->config_get(api->host_ctx, key,
                           GN_CONFIG_VALUE_STRING, GN_CONFIG_NO_INDEX,
                           static_cast<void*>(out_str),
                           out_user_data, out_free);
}

[[nodiscard]] inline gn_result_t config_get_array_int64(
    const host_api_t* api, const char* key, std::size_t index,
    std::int64_t* out_value) noexcept {
    return api->config_get(api->host_ctx, key,
                           GN_CONFIG_VALUE_INT64, index,
                           out_value, nullptr, nullptr);
}

[[nodiscard]] inline gn_result_t config_get_array_string(
    const host_api_t* api,
    const char* key,
    std::size_t index,
    char** out_str,
    void** out_user_data,
    void (**out_free)(void*, void*)) noexcept {
    return api->config_get(api->host_ctx, key,
                           GN_CONFIG_VALUE_STRING, index,
                           static_cast<void*>(out_str),
                           out_user_data, out_free);
}

// ── Limits ────────────────────────────────────────────────────────────────

[[nodiscard]] inline const gn_limits_t* limits(const host_api_t* api) noexcept {
    return api->limits(api->host_ctx);
}

// ── Foreign-payload injection ─────────────────────────────────────────────

[[nodiscard]] inline gn_result_t inject_external_message(
    const host_api_t* api,
    gn_conn_id_t source,
    std::uint32_t msg_id,
    std::span<const std::uint8_t> payload) noexcept {
    return api->inject(api->host_ctx, GN_INJECT_LAYER_MESSAGE,
                       source, msg_id, payload.data(), payload.size());
}

[[nodiscard]] inline gn_result_t inject_frame(
    const host_api_t* api,
    gn_conn_id_t source,
    std::span<const std::uint8_t> frame) noexcept {
    return api->inject(api->host_ctx, GN_INJECT_LAYER_FRAME,
                       source, 0, frame.data(), frame.size());
}

} // namespace gn
