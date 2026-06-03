// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/send.hpp
/// @brief  Type-safe send helpers for WireSchema-typed messages.
///
/// `GN_SEND(api, conn, Schema, value)` is the canonical outbound send
/// for typed extension messages. It:
///
///   1. Calls `Schema::serialize(value)` to produce a fixed-size frame.
///   2. Reads `Schema::msg_id` to route through the protocol layer.
///   3. Optionally validates against the local topology handler list when
///      the topology has been sealed (pre-seal calls pass through).
///
/// ## Usage
///
/// ```cpp
/// #include <sdk/cpp/send.hpp>
///
/// struct PingSchema {
///     using value_type = PingMessage;
///     static constexpr std::uint32_t msg_id = 0x20;
///     static constexpr std::size_t   size   = sizeof(PingMessage);
///     static std::array<std::uint8_t, size> serialize(const value_type& v) { ... }
///     static std::optional<value_type> parse(std::span<const std::uint8_t>) { ... }
/// };
///
/// gn_result_t rc = GN_SEND(api, conn, PingSchema, ping_value);
/// ```
///
/// When the Schema also provides `static constexpr const char* protocol_id()`
/// and the kernel topology has been sealed, `GN_SEND` verifies that a handler
/// for `(protocol_id, msg_id)` is registered locally. A mismatch returns
/// `GN_ERR_NOT_FOUND` with a diagnostic log line before the first byte is sent.
///
/// Peer-side handler verification (requires Slice 4b full handler-set exchange)
/// is a future extension of this mechanism.

#pragma once

#include <array>
#include <cstdint>
#include <span>

#include <sdk/cpp/convenience.hpp>
#include <sdk/cpp/log.hpp>
#include <sdk/cpp/wire.hpp>
#include <sdk/host_api.h>
#include <sdk/topology.h>
#include <sdk/types.h>

namespace gn::sdk {

namespace detail {

/// Retrieve the sealed topology pointer via the `gn.topology` named
/// extension. Returns nullptr when the topology is not yet available
/// (pre-`gn_core_start`) or when the extension is not registered.
[[nodiscard]] inline const gn_topology_t*
get_local_topology(const host_api_t* api) noexcept {
    if (!api || !api->get_extension) return nullptr;
    const void* ext = api->get_extension(api->host_ctx, GN_EXT_TOPOLOGY);
    if (!ext) return nullptr;
    // The extension vtable's first slot is the topology pointer accessor;
    // for gn.topology the extension IS the topology pointer itself.
    return static_cast<const gn_topology_t*>(ext);
}

/// Returns true when a handler for (@p protocol_id, @p msg_id) is
/// registered in the local topology. Always returns true when the
/// topology is not yet available (pre-seal pass-through).
[[nodiscard]] inline bool
local_handler_exists(const host_api_t* api,
                     const char* protocol_id,
                     std::uint32_t msg_id) noexcept {
    const auto* topo = get_local_topology(api);
    if (!topo) return true;
    for (std::uint32_t i = 0; i < topo->handler_count; ++i) {
        const auto& h = topo->handlers[i];
        if (h.msg_id == msg_id &&
            h.protocol_id != nullptr &&
            protocol_id != nullptr &&
            __builtin_strcmp(h.protocol_id, protocol_id) == 0) {
            return true;
        }
    }
    return false;
}

} // namespace detail

/// Type-safe send for a WireSchema-typed message.
///
/// Serialises @p value via `Schema::serialize`, then calls
/// `gn::send(api, conn, Schema::msg_id, bytes)`.
template <wire::WireSchema Schema>
[[nodiscard]] inline gn_result_t wire_send(
    const host_api_t*              api,
    gn_conn_id_t                   conn,
    const typename Schema::value_type& value) noexcept {
    if (!api) return GN_ERR_NULL_ARG;
    const auto bytes = Schema::serialize(value);
    return gn::send(api, conn, Schema::msg_id,
                    std::span<const std::uint8_t>{bytes.data(), bytes.size()});
}

/// Same as `wire_send` but also validates the local handler topology
/// when the Schema exposes `static constexpr const char* protocol_id()`.
/// Returns `GN_ERR_NOT_FOUND` with a diagnostic when a pre-sealed
/// topology exists and the handler is absent.
template <wire::WireSchema Schema>
[[nodiscard]] inline gn_result_t checked_send(
    const host_api_t*              api,
    gn_conn_id_t                   conn,
    const typename Schema::value_type& value) noexcept {
    if (!api) return GN_ERR_NULL_ARG;

    if constexpr (requires { { Schema::protocol_id() } -> std::convertible_to<const char*>; }) {
        if (!detail::local_handler_exists(api, Schema::protocol_id(), Schema::msg_id)) {
            ::gn::log::warn(
                "GN_SEND: no local handler for protocol={} msg_id={:#x} — "
                "topology sealed without this handler; send aborted",
                Schema::protocol_id(), Schema::msg_id);
            return GN_ERR_NOT_FOUND;
        }
    }

    return wire_send<Schema>(api, conn, value);
}

} // namespace gn::sdk

/// Type-safe send macro. Calls `gn::sdk::checked_send<Schema>`.
///
/// @param api   `const host_api_t*` plugin received in init.
/// @param conn  `gn_conn_id_t` target connection.
/// @param Schema WireSchema type (has `msg_id`, `serialize`, `size`).
/// @param value `Schema::value_type` to send.
#define GN_SEND(api, conn, Schema, value) \
    ::gn::sdk::checked_send<Schema>((api), (conn), (value))
