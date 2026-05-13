/// @file   core/kernel/host_api_builder.cpp
/// @brief  Wire the kernel-side host_api thunks into a `host_api_t`
///         table per `host-api.md`. Slot bodies live in
///         `core/kernel/host_api/*.cpp`; their declarations live in
///         `host_api_internal.hpp`. Each section comment below
///         mirrors the equivalent header section in
///         `sdk/host_api.h` so a reader can follow the same map on
///         both sides of the ABI.

#include "host_api_builder.hpp"
#include "host_api_internal.hpp"

namespace gn::core {

host_api_t build_host_api(PluginContext& ctx) {
    host_api_t a{};
    a.api_size = sizeof(host_api_t);
    a.host_ctx = &ctx;

    // ── Messaging (host_api/messaging.cpp) ──────────────────────────
    a.send                  = &host_api_thunks::send;
    a.disconnect            = &host_api_thunks::disconnect;
    a.send_to               = &host_api_thunks::send_to;

    // ── Universal registration (host_api/control.cpp) ──────────────
    a.register_vtable       = &host_api_thunks::register_vtable;
    a.unregister_vtable     = &host_api_thunks::unregister_vtable;

    // ── Extensions (host_api/control.cpp) ──────────────────────────
    a.query_extension_checked = &host_api_thunks::query_extension_checked;
    a.register_extension      = &host_api_thunks::register_extension;
    a.unregister_extension    = &host_api_thunks::unregister_extension;

    // ── Timers (host_api/control.cpp) ──────────────────────────────
    a.set_timer               = &host_api_thunks::set_timer;
    a.cancel_timer            = &host_api_thunks::cancel_timer;

    // ── Subscriptions (host_api/control.cpp) ───────────────────────
    a.subscribe_conn_state    = &host_api_thunks::subscribe_conn_state;
    a.subscribe_config_reload = &host_api_thunks::subscribe_config_reload;
    a.unsubscribe             = &host_api_thunks::unsubscribe;
    a.for_each_connection     = &host_api_thunks::for_each_connection;
    a.notify_backpressure     = &host_api_thunks::notify_backpressure;

    // ── Limits / config (host_api/control.cpp) ─────────────────────
    a.limits                = &host_api_thunks::limits;
    a.config_get            = &host_api_thunks::config_get;

    // ── Logging (host_api/control.cpp) ─────────────────────────────
    a.log.api_size          = sizeof(gn_log_api_t);
    a.log.should_log        = &host_api_thunks::log_should_log;
    a.log.emit              = &host_api_thunks::log_emit;

    // ── Link notifications (host_api/notifications.cpp) ────────────
    a.notify_connect        = &host_api_thunks::notify_connect;
    a.notify_inbound_bytes  = &host_api_thunks::notify_inbound_bytes;
    a.notify_disconnect     = &host_api_thunks::notify_disconnect;
    a.kick_handshake        = &host_api_thunks::kick_handshake;
    a.inject                = &host_api_thunks::inject;

    // ── Security registry (host_api/control.cpp) ───────────────────
    a.register_security     = &host_api_thunks::register_security;
    a.unregister_security   = &host_api_thunks::unregister_security;

    // ── Registry queries (host_api/control.cpp) ────────────────────
    a.find_conn_by_pk       = &host_api_thunks::find_conn_by_pk;
    a.get_endpoint          = &host_api_thunks::get_endpoint;

    // ── Lifecycle / metrics (host_api/control.cpp) ─────────────────
    a.is_shutdown_requested = &host_api_thunks::is_shutdown_requested;
    a.emit_counter          = &host_api_thunks::emit_counter;
    a.iterate_counters      = &host_api_thunks::iterate_counters;

    // ── Identity (host_api/identity.cpp) ───────────────────────────
    a.register_local_key      = &host_api_thunks::register_local_key;
    a.delete_local_key        = &host_api_thunks::delete_local_key;
    a.list_local_keys         = &host_api_thunks::list_local_keys;
    a.sign_local              = &host_api_thunks::sign_local;
    a.sign_local_by_id        = &host_api_thunks::sign_local_by_id;
    a.get_peer_user_pk        = &host_api_thunks::get_peer_user_pk;
    a.get_peer_device_pk      = &host_api_thunks::get_peer_device_pk;
    a.get_handshake_hash      = &host_api_thunks::get_handshake_hash;
    a.announce_rotation       = &host_api_thunks::announce_rotation;

    // ── Capability blobs (host_api/identity.cpp) ───────────────────
    a.present_capability_blob   = &host_api_thunks::present_capability_blob;
    a.subscribe_capability_blob = &host_api_thunks::subscribe_capability_blob;

    /// Other slots remain NULL; plugins guard with GN_API_HAS.
    return a;
}

}  // namespace gn::core
