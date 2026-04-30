/**
 * @file   tests/abi/test_layout.c
 * @brief  Compile-time pin of every public C ABI struct's layout.
 *
 * Per `docs/contracts/abi-evolution.md` §7, every SDK MINOR ships a
 * `tests/abi/layout` binary that records the size of every public C ABI
 * struct and the offset of every named field. The file is compiled but
 * never executed: the assertions fire at compile time. Any future patch
 * that reorders, resizes, or renames a v1.0 struct fails to link this
 * compilation unit before reaching merge.
 *
 * The numbers were measured on x86_64 Linux gcc15 against the release
 * snapshot of `sdk/`. Grouping below mirrors the header layout. New
 * fields land before each header's `_reserved[]` slot — the reserved
 * trailer absorbs additive evolution per `abi-evolution.md` §3 without
 * shifting any earlier offset.
 *
 * To regenerate after an ABI bump:
 *   1. Bump `GN_SDK_VERSION_MAJOR` in `sdk/types.h`.
 *   2. Compile and run `tests/abi/measure_layout.c` (the producer of
 *      these numbers; it lives next to this file).
 *   3. Paste the updated values below; this file is the new pin.
 */

#include <stddef.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/connection.h>
#include <sdk/conn_events.h>
#include <sdk/endpoint.h>
#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/limits.h>
#include <sdk/log.h>
#include <sdk/metrics.h>
#include <sdk/plugin.h>
#include <sdk/protocol.h>
#include <sdk/security.h>
#include <sdk/transport.h>
#include <sdk/trust.h>
#include <sdk/types.h>

#include <sdk/extensions/heartbeat.h>
#include <sdk/extensions/transport.h>

/* ── sdk/types.h ───────────────────────────────────────────────────────────── */

_Static_assert(sizeof(gn_message_t) == 120,
               "gn_message_t size pinned at 120");
_Static_assert(offsetof(gn_message_t, sender_pk) == 0,
               "gn_message_t::sender_pk offset pinned at 0");
_Static_assert(offsetof(gn_message_t, receiver_pk) == 32,
               "gn_message_t::receiver_pk offset pinned at 32");
_Static_assert(offsetof(gn_message_t, msg_id) == 64,
               "gn_message_t::msg_id offset pinned at 64");
_Static_assert(offsetof(gn_message_t, payload) == 72,
               "gn_message_t::payload offset pinned at 72");
_Static_assert(offsetof(gn_message_t, payload_size) == 80,
               "gn_message_t::payload_size offset pinned at 80");
_Static_assert(offsetof(gn_message_t, _reserved) == 88,
               "gn_message_t::_reserved offset pinned at 88");

/* ── sdk/conn_events.h ─────────────────────────────────────────────────────── */

_Static_assert(sizeof(gn_conn_event_t) == 96,
               "gn_conn_event_t size pinned at 96");
_Static_assert(offsetof(gn_conn_event_t, api_size) == 0,
               "gn_conn_event_t::api_size offset pinned at 0");
_Static_assert(offsetof(gn_conn_event_t, kind) == 4,
               "gn_conn_event_t::kind offset pinned at 4");
_Static_assert(offsetof(gn_conn_event_t, conn) == 8,
               "gn_conn_event_t::conn offset pinned at 8");
_Static_assert(offsetof(gn_conn_event_t, trust) == 16,
               "gn_conn_event_t::trust offset pinned at 16");
_Static_assert(offsetof(gn_conn_event_t, remote_pk) == 20,
               "gn_conn_event_t::remote_pk offset pinned at 20");
_Static_assert(offsetof(gn_conn_event_t, pending_bytes) == 56,
               "gn_conn_event_t::pending_bytes offset pinned at 56");
_Static_assert(offsetof(gn_conn_event_t, _reserved) == 64,
               "gn_conn_event_t::_reserved offset pinned at 64");

/* ── sdk/endpoint.h ────────────────────────────────────────────────────────── */

_Static_assert(sizeof(gn_endpoint_t) == 400,
               "gn_endpoint_t size pinned at 400");
_Static_assert(offsetof(gn_endpoint_t, conn_id) == 0,
               "gn_endpoint_t::conn_id offset pinned at 0");
_Static_assert(offsetof(gn_endpoint_t, remote_pk) == 8,
               "gn_endpoint_t::remote_pk offset pinned at 8");
_Static_assert(offsetof(gn_endpoint_t, trust) == 40,
               "gn_endpoint_t::trust offset pinned at 40");
_Static_assert(offsetof(gn_endpoint_t, uri) == 44,
               "gn_endpoint_t::uri offset pinned at 44");
_Static_assert(offsetof(gn_endpoint_t, transport_scheme) == 300,
               "gn_endpoint_t::transport_scheme offset pinned at 300");
_Static_assert(offsetof(gn_endpoint_t, bytes_in) == 320,
               "gn_endpoint_t::bytes_in offset pinned at 320");
_Static_assert(offsetof(gn_endpoint_t, bytes_out) == 328,
               "gn_endpoint_t::bytes_out offset pinned at 328");
_Static_assert(offsetof(gn_endpoint_t, frames_in) == 336,
               "gn_endpoint_t::frames_in offset pinned at 336");
_Static_assert(offsetof(gn_endpoint_t, frames_out) == 344,
               "gn_endpoint_t::frames_out offset pinned at 344");
_Static_assert(offsetof(gn_endpoint_t, pending_queue_bytes) == 352,
               "gn_endpoint_t::pending_queue_bytes offset pinned at 352");
_Static_assert(offsetof(gn_endpoint_t, last_rtt_us) == 360,
               "gn_endpoint_t::last_rtt_us offset pinned at 360");
_Static_assert(offsetof(gn_endpoint_t, _reserved) == 368,
               "gn_endpoint_t::_reserved offset pinned at 368");

/* ── sdk/handler.h ─────────────────────────────────────────────────────────── */

_Static_assert(sizeof(gn_handler_vtable_t) == 88,
               "gn_handler_vtable_t size pinned at 88");
_Static_assert(offsetof(gn_handler_vtable_t, api_size) == 0,
               "gn_handler_vtable_t::api_size offset pinned at 0");
_Static_assert(offsetof(gn_handler_vtable_t, protocol_id) == 8,
               "gn_handler_vtable_t::protocol_id offset pinned at 8");
_Static_assert(offsetof(gn_handler_vtable_t, supported_msg_ids) == 16,
               "gn_handler_vtable_t::supported_msg_ids offset pinned at 16");
_Static_assert(offsetof(gn_handler_vtable_t, handle_message) == 24,
               "gn_handler_vtable_t::handle_message offset pinned at 24");
_Static_assert(offsetof(gn_handler_vtable_t, on_result) == 32,
               "gn_handler_vtable_t::on_result offset pinned at 32");
_Static_assert(offsetof(gn_handler_vtable_t, on_init) == 40,
               "gn_handler_vtable_t::on_init offset pinned at 40");
_Static_assert(offsetof(gn_handler_vtable_t, on_shutdown) == 48,
               "gn_handler_vtable_t::on_shutdown offset pinned at 48");
_Static_assert(offsetof(gn_handler_vtable_t, _reserved) == 56,
               "gn_handler_vtable_t::_reserved offset pinned at 56");

/* ── sdk/host_api.h ────────────────────────────────────────────────────────── */

_Static_assert(sizeof(host_api_t) == 496,
               "host_api_t size pinned at 496");
_Static_assert(offsetof(host_api_t, api_size) == 0,
               "host_api_t::api_size offset pinned at 0");
_Static_assert(offsetof(host_api_t, host_ctx) == 8,
               "host_api_t::host_ctx offset pinned at 8");
_Static_assert(offsetof(host_api_t, send) == 16,
               "host_api_t::send offset pinned at 16");
_Static_assert(offsetof(host_api_t, send_uri) == 24,
               "host_api_t::send_uri offset pinned at 24");
_Static_assert(offsetof(host_api_t, broadcast) == 32,
               "host_api_t::broadcast offset pinned at 32");
_Static_assert(offsetof(host_api_t, disconnect) == 40,
               "host_api_t::disconnect offset pinned at 40");
_Static_assert(offsetof(host_api_t, register_handler) == 48,
               "host_api_t::register_handler offset pinned at 48");
_Static_assert(offsetof(host_api_t, unregister_handler) == 56,
               "host_api_t::unregister_handler offset pinned at 56");
_Static_assert(offsetof(host_api_t, register_transport) == 64,
               "host_api_t::register_transport offset pinned at 64");
_Static_assert(offsetof(host_api_t, unregister_transport) == 72,
               "host_api_t::unregister_transport offset pinned at 72");
_Static_assert(offsetof(host_api_t, find_conn_by_pk) == 80,
               "host_api_t::find_conn_by_pk offset pinned at 80");
_Static_assert(offsetof(host_api_t, get_endpoint) == 88,
               "host_api_t::get_endpoint offset pinned at 88");
_Static_assert(offsetof(host_api_t, query_extension_checked) == 96,
               "host_api_t::query_extension_checked offset pinned at 96");
_Static_assert(offsetof(host_api_t, register_extension) == 104,
               "host_api_t::register_extension offset pinned at 104");
_Static_assert(offsetof(host_api_t, unregister_extension) == 112,
               "host_api_t::unregister_extension offset pinned at 112");
_Static_assert(offsetof(host_api_t, config_get_string) == 120,
               "host_api_t::config_get_string offset pinned at 120");
_Static_assert(offsetof(host_api_t, config_get_int64) == 128,
               "host_api_t::config_get_int64 offset pinned at 128");
_Static_assert(offsetof(host_api_t, config_get_bool) == 136,
               "host_api_t::config_get_bool offset pinned at 136");
_Static_assert(offsetof(host_api_t, config_get_double) == 144,
               "host_api_t::config_get_double offset pinned at 144");
_Static_assert(offsetof(host_api_t, config_get_array_size) == 152,
               "host_api_t::config_get_array_size offset pinned at 152");
_Static_assert(offsetof(host_api_t, config_get_array_string) == 160,
               "host_api_t::config_get_array_string offset pinned at 160");
_Static_assert(offsetof(host_api_t, config_get_array_int64) == 168,
               "host_api_t::config_get_array_int64 offset pinned at 168");
_Static_assert(offsetof(host_api_t, limits) == 176,
               "host_api_t::limits offset pinned at 176");
_Static_assert(offsetof(host_api_t, log) == 184,
               "host_api_t::log offset pinned at 184");
_Static_assert(offsetof(host_api_t, notify_connect) == 272,
               "host_api_t::notify_connect offset pinned at 272");
_Static_assert(offsetof(host_api_t, notify_inbound_bytes) == 280,
               "host_api_t::notify_inbound_bytes offset pinned at 280");
_Static_assert(offsetof(host_api_t, notify_disconnect) == 288,
               "host_api_t::notify_disconnect offset pinned at 288");
_Static_assert(offsetof(host_api_t, register_security) == 296,
               "host_api_t::register_security offset pinned at 296");
_Static_assert(offsetof(host_api_t, unregister_security) == 304,
               "host_api_t::unregister_security offset pinned at 304");
_Static_assert(offsetof(host_api_t, inject_external_message) == 312,
               "host_api_t::inject_external_message offset pinned at 312");
_Static_assert(offsetof(host_api_t, inject_frame) == 320,
               "host_api_t::inject_frame offset pinned at 320");
_Static_assert(offsetof(host_api_t, kick_handshake) == 328,
               "host_api_t::kick_handshake offset pinned at 328");
_Static_assert(offsetof(host_api_t, set_timer) == 336,
               "host_api_t::set_timer offset pinned at 336");
_Static_assert(offsetof(host_api_t, cancel_timer) == 344,
               "host_api_t::cancel_timer offset pinned at 344");
_Static_assert(offsetof(host_api_t, post_to_executor) == 352,
               "host_api_t::post_to_executor offset pinned at 352");
_Static_assert(offsetof(host_api_t, subscribe_conn_state) == 360,
               "host_api_t::subscribe_conn_state offset pinned at 360");
_Static_assert(offsetof(host_api_t, unsubscribe_conn_state) == 368,
               "host_api_t::unsubscribe_conn_state offset pinned at 368");
_Static_assert(offsetof(host_api_t, for_each_connection) == 376,
               "host_api_t::for_each_connection offset pinned at 376");
_Static_assert(offsetof(host_api_t, notify_backpressure) == 384,
               "host_api_t::notify_backpressure offset pinned at 384");
_Static_assert(offsetof(host_api_t, emit_counter) == 392,
               "host_api_t::emit_counter offset pinned at 392");
_Static_assert(offsetof(host_api_t, iterate_counters) == 400,
               "host_api_t::iterate_counters offset pinned at 400");
_Static_assert(offsetof(host_api_t, subscribe_config_reload) == 408,
               "host_api_t::subscribe_config_reload offset pinned at 408");
_Static_assert(offsetof(host_api_t, unsubscribe_config_reload) == 416,
               "host_api_t::unsubscribe_config_reload offset pinned at 416");
_Static_assert(offsetof(host_api_t, is_shutdown_requested) == 424,
               "host_api_t::is_shutdown_requested offset pinned at 424");
_Static_assert(offsetof(host_api_t, _reserved) == 432,
               "host_api_t::_reserved offset pinned at 432");

/* ── sdk/limits.h ──────────────────────────────────────────────────────────── */

_Static_assert(sizeof(gn_limits_t) == 120,
               "gn_limits_t size pinned at 120");
_Static_assert(offsetof(gn_limits_t, max_connections) == 0,
               "gn_limits_t::max_connections offset pinned at 0");
_Static_assert(offsetof(gn_limits_t, max_outbound_connections) == 4,
               "gn_limits_t::max_outbound_connections offset pinned at 4");
_Static_assert(offsetof(gn_limits_t, pending_queue_bytes_high) == 8,
               "gn_limits_t::pending_queue_bytes_high offset pinned at 8");
_Static_assert(offsetof(gn_limits_t, pending_queue_bytes_low) == 12,
               "gn_limits_t::pending_queue_bytes_low offset pinned at 12");
_Static_assert(offsetof(gn_limits_t, pending_queue_bytes_hard) == 16,
               "gn_limits_t::pending_queue_bytes_hard offset pinned at 16");
_Static_assert(offsetof(gn_limits_t, max_payload_bytes) == 20,
               "gn_limits_t::max_payload_bytes offset pinned at 20");
_Static_assert(offsetof(gn_limits_t, max_frame_bytes) == 24,
               "gn_limits_t::max_frame_bytes offset pinned at 24");
_Static_assert(offsetof(gn_limits_t, max_handlers_per_msg_id) == 28,
               "gn_limits_t::max_handlers_per_msg_id offset pinned at 28");
_Static_assert(offsetof(gn_limits_t, max_relay_ttl) == 32,
               "gn_limits_t::max_relay_ttl offset pinned at 32");
_Static_assert(offsetof(gn_limits_t, max_plugins) == 36,
               "gn_limits_t::max_plugins offset pinned at 36");
_Static_assert(offsetof(gn_limits_t, max_extensions) == 40,
               "gn_limits_t::max_extensions offset pinned at 40");
_Static_assert(offsetof(gn_limits_t, max_timers) == 44,
               "gn_limits_t::max_timers offset pinned at 44");
_Static_assert(offsetof(gn_limits_t, max_pending_tasks) == 48,
               "gn_limits_t::max_pending_tasks offset pinned at 48");
_Static_assert(offsetof(gn_limits_t, max_timers_per_plugin) == 52,
               "gn_limits_t::max_timers_per_plugin offset pinned at 52");
_Static_assert(offsetof(gn_limits_t, inject_rate_per_source) == 56,
               "gn_limits_t::inject_rate_per_source offset pinned at 56");
_Static_assert(offsetof(gn_limits_t, inject_rate_burst) == 60,
               "gn_limits_t::inject_rate_burst offset pinned at 60");
_Static_assert(offsetof(gn_limits_t, inject_rate_lru_cap) == 64,
               "gn_limits_t::inject_rate_lru_cap offset pinned at 64");
_Static_assert(offsetof(gn_limits_t, pending_handshake_bytes) == 68,
               "gn_limits_t::pending_handshake_bytes offset pinned at 68");
_Static_assert(offsetof(gn_limits_t, max_storage_table_entries) == 72,
               "gn_limits_t::max_storage_table_entries offset pinned at 72");
_Static_assert(offsetof(gn_limits_t, max_storage_value_bytes) == 80,
               "gn_limits_t::max_storage_value_bytes offset pinned at 80");
_Static_assert(offsetof(gn_limits_t, _reserved) == 88,
               "gn_limits_t::_reserved offset pinned at 88");

/* ── sdk/log.h ─────────────────────────────────────────────────────────────── */

_Static_assert(sizeof(gn_log_api_t) == 88,
               "gn_log_api_t size pinned at 88");
_Static_assert(offsetof(gn_log_api_t, api_size) == 0,
               "gn_log_api_t::api_size offset pinned at 0");
_Static_assert(offsetof(gn_log_api_t, should_log) == 8,
               "gn_log_api_t::should_log offset pinned at 8");
_Static_assert(offsetof(gn_log_api_t, emit) == 16,
               "gn_log_api_t::emit offset pinned at 16");
_Static_assert(offsetof(gn_log_api_t, _reserved) == 24,
               "gn_log_api_t::_reserved offset pinned at 24");

/* ── sdk/plugin.h ──────────────────────────────────────────────────────────── */

_Static_assert(sizeof(gn_plugin_descriptor_t) == 80,
               "gn_plugin_descriptor_t size pinned at 80");
_Static_assert(offsetof(gn_plugin_descriptor_t, name) == 0,
               "gn_plugin_descriptor_t::name offset pinned at 0");
_Static_assert(offsetof(gn_plugin_descriptor_t, version) == 8,
               "gn_plugin_descriptor_t::version offset pinned at 8");
_Static_assert(offsetof(gn_plugin_descriptor_t, hot_reload_safe) == 16,
               "gn_plugin_descriptor_t::hot_reload_safe offset pinned at 16");
_Static_assert(offsetof(gn_plugin_descriptor_t, ext_requires) == 24,
               "gn_plugin_descriptor_t::ext_requires offset pinned at 24");
_Static_assert(offsetof(gn_plugin_descriptor_t, ext_provides) == 32,
               "gn_plugin_descriptor_t::ext_provides offset pinned at 32");
_Static_assert(offsetof(gn_plugin_descriptor_t, kind) == 40,
               "gn_plugin_descriptor_t::kind offset pinned at 40");
_Static_assert(offsetof(gn_plugin_descriptor_t, _reserved) == 48,
               "gn_plugin_descriptor_t::_reserved offset pinned at 48");

/* ── sdk/protocol.h ────────────────────────────────────────────────────────── */

_Static_assert(sizeof(gn_deframe_result_t) == 56,
               "gn_deframe_result_t size pinned at 56");
_Static_assert(offsetof(gn_deframe_result_t, messages) == 0,
               "gn_deframe_result_t::messages offset pinned at 0");
_Static_assert(offsetof(gn_deframe_result_t, count) == 8,
               "gn_deframe_result_t::count offset pinned at 8");
_Static_assert(offsetof(gn_deframe_result_t, bytes_consumed) == 16,
               "gn_deframe_result_t::bytes_consumed offset pinned at 16");
_Static_assert(offsetof(gn_deframe_result_t, _reserved) == 24,
               "gn_deframe_result_t::_reserved offset pinned at 24");

_Static_assert(sizeof(gn_protocol_layer_vtable_t) == 88,
               "gn_protocol_layer_vtable_t size pinned at 88");
_Static_assert(offsetof(gn_protocol_layer_vtable_t, api_size) == 0,
               "gn_protocol_layer_vtable_t::api_size offset pinned at 0");
_Static_assert(offsetof(gn_protocol_layer_vtable_t, protocol_id) == 8,
               "gn_protocol_layer_vtable_t::protocol_id offset pinned at 8");
_Static_assert(offsetof(gn_protocol_layer_vtable_t, deframe) == 16,
               "gn_protocol_layer_vtable_t::deframe offset pinned at 16");
_Static_assert(offsetof(gn_protocol_layer_vtable_t, frame) == 24,
               "gn_protocol_layer_vtable_t::frame offset pinned at 24");
_Static_assert(offsetof(gn_protocol_layer_vtable_t, max_payload_size) == 32,
               "gn_protocol_layer_vtable_t::max_payload_size offset pinned at 32");
_Static_assert(offsetof(gn_protocol_layer_vtable_t, destroy) == 40,
               "gn_protocol_layer_vtable_t::destroy offset pinned at 40");
_Static_assert(offsetof(gn_protocol_layer_vtable_t, allowed_trust_mask) == 48,
               "gn_protocol_layer_vtable_t::allowed_trust_mask offset pinned at 48");
_Static_assert(offsetof(gn_protocol_layer_vtable_t, _reserved) == 56,
               "gn_protocol_layer_vtable_t::_reserved offset pinned at 56");

/* ── sdk/security.h ────────────────────────────────────────────────────────── */

_Static_assert(sizeof(gn_handshake_keys_t) == 176,
               "gn_handshake_keys_t size pinned at 176");
_Static_assert(offsetof(gn_handshake_keys_t, send_cipher_key) == 0,
               "gn_handshake_keys_t::send_cipher_key offset pinned at 0");
_Static_assert(offsetof(gn_handshake_keys_t, recv_cipher_key) == 32,
               "gn_handshake_keys_t::recv_cipher_key offset pinned at 32");
_Static_assert(offsetof(gn_handshake_keys_t, initial_send_nonce) == 64,
               "gn_handshake_keys_t::initial_send_nonce offset pinned at 64");
_Static_assert(offsetof(gn_handshake_keys_t, initial_recv_nonce) == 72,
               "gn_handshake_keys_t::initial_recv_nonce offset pinned at 72");
_Static_assert(offsetof(gn_handshake_keys_t, handshake_hash) == 80,
               "gn_handshake_keys_t::handshake_hash offset pinned at 80");
_Static_assert(offsetof(gn_handshake_keys_t, peer_static_pk) == 112,
               "gn_handshake_keys_t::peer_static_pk offset pinned at 112");
_Static_assert(offsetof(gn_handshake_keys_t, _reserved) == 144,
               "gn_handshake_keys_t::_reserved offset pinned at 144");

_Static_assert(sizeof(gn_secure_buffer_t) == 24,
               "gn_secure_buffer_t size pinned at 24");
_Static_assert(offsetof(gn_secure_buffer_t, bytes) == 0,
               "gn_secure_buffer_t::bytes offset pinned at 0");
_Static_assert(offsetof(gn_secure_buffer_t, size) == 8,
               "gn_secure_buffer_t::size offset pinned at 8");
_Static_assert(offsetof(gn_secure_buffer_t, free_fn) == 16,
               "gn_secure_buffer_t::free_fn offset pinned at 16");

_Static_assert(sizeof(gn_security_provider_vtable_t) == 128,
               "gn_security_provider_vtable_t size pinned at 128");
_Static_assert(offsetof(gn_security_provider_vtable_t, api_size) == 0,
               "gn_security_provider_vtable_t::api_size offset pinned at 0");
_Static_assert(offsetof(gn_security_provider_vtable_t, provider_id) == 8,
               "gn_security_provider_vtable_t::provider_id offset pinned at 8");
_Static_assert(offsetof(gn_security_provider_vtable_t, handshake_open) == 16,
               "gn_security_provider_vtable_t::handshake_open offset pinned at 16");
_Static_assert(offsetof(gn_security_provider_vtable_t, handshake_step) == 24,
               "gn_security_provider_vtable_t::handshake_step offset pinned at 24");
_Static_assert(offsetof(gn_security_provider_vtable_t, handshake_complete) == 32,
               "gn_security_provider_vtable_t::handshake_complete offset pinned at 32");
_Static_assert(offsetof(gn_security_provider_vtable_t, export_transport_keys) == 40,
               "gn_security_provider_vtable_t::export_transport_keys offset pinned at 40");
_Static_assert(offsetof(gn_security_provider_vtable_t, encrypt) == 48,
               "gn_security_provider_vtable_t::encrypt offset pinned at 48");
_Static_assert(offsetof(gn_security_provider_vtable_t, decrypt) == 56,
               "gn_security_provider_vtable_t::decrypt offset pinned at 56");
_Static_assert(offsetof(gn_security_provider_vtable_t, rekey) == 64,
               "gn_security_provider_vtable_t::rekey offset pinned at 64");
_Static_assert(offsetof(gn_security_provider_vtable_t, handshake_close) == 72,
               "gn_security_provider_vtable_t::handshake_close offset pinned at 72");
_Static_assert(offsetof(gn_security_provider_vtable_t, destroy) == 80,
               "gn_security_provider_vtable_t::destroy offset pinned at 80");
_Static_assert(offsetof(gn_security_provider_vtable_t, allowed_trust_mask) == 88,
               "gn_security_provider_vtable_t::allowed_trust_mask offset pinned at 88");
_Static_assert(offsetof(gn_security_provider_vtable_t, _reserved) == 96,
               "gn_security_provider_vtable_t::_reserved offset pinned at 96");

/* ── sdk/transport.h ───────────────────────────────────────────────────────── */

_Static_assert(sizeof(gn_byte_span_t) == 16,
               "gn_byte_span_t size pinned at 16");
_Static_assert(offsetof(gn_byte_span_t, bytes) == 0,
               "gn_byte_span_t::bytes offset pinned at 0");
_Static_assert(offsetof(gn_byte_span_t, size) == 8,
               "gn_byte_span_t::size offset pinned at 8");

_Static_assert(sizeof(gn_transport_vtable_t) == 112,
               "gn_transport_vtable_t size pinned at 112");
_Static_assert(offsetof(gn_transport_vtable_t, api_size) == 0,
               "gn_transport_vtable_t::api_size offset pinned at 0");
_Static_assert(offsetof(gn_transport_vtable_t, scheme) == 8,
               "gn_transport_vtable_t::scheme offset pinned at 8");
_Static_assert(offsetof(gn_transport_vtable_t, listen) == 16,
               "gn_transport_vtable_t::listen offset pinned at 16");
_Static_assert(offsetof(gn_transport_vtable_t, connect) == 24,
               "gn_transport_vtable_t::connect offset pinned at 24");
_Static_assert(offsetof(gn_transport_vtable_t, send) == 32,
               "gn_transport_vtable_t::send offset pinned at 32");
_Static_assert(offsetof(gn_transport_vtable_t, send_batch) == 40,
               "gn_transport_vtable_t::send_batch offset pinned at 40");
_Static_assert(offsetof(gn_transport_vtable_t, disconnect) == 48,
               "gn_transport_vtable_t::disconnect offset pinned at 48");
_Static_assert(offsetof(gn_transport_vtable_t, extension_name) == 56,
               "gn_transport_vtable_t::extension_name offset pinned at 56");
_Static_assert(offsetof(gn_transport_vtable_t, extension_vtable) == 64,
               "gn_transport_vtable_t::extension_vtable offset pinned at 64");
_Static_assert(offsetof(gn_transport_vtable_t, destroy) == 72,
               "gn_transport_vtable_t::destroy offset pinned at 72");
_Static_assert(offsetof(gn_transport_vtable_t, _reserved) == 80,
               "gn_transport_vtable_t::_reserved offset pinned at 80");

/* ── sdk/extensions/heartbeat.h ────────────────────────────────────────────── */

_Static_assert(sizeof(gn_heartbeat_stats_t) == 16,
               "gn_heartbeat_stats_t size pinned at 16");
_Static_assert(offsetof(gn_heartbeat_stats_t, peer_count) == 0,
               "gn_heartbeat_stats_t::peer_count offset pinned at 0");
_Static_assert(offsetof(gn_heartbeat_stats_t, avg_rtt_us) == 4,
               "gn_heartbeat_stats_t::avg_rtt_us offset pinned at 4");
_Static_assert(offsetof(gn_heartbeat_stats_t, min_rtt_us) == 8,
               "gn_heartbeat_stats_t::min_rtt_us offset pinned at 8");
_Static_assert(offsetof(gn_heartbeat_stats_t, max_rtt_us) == 12,
               "gn_heartbeat_stats_t::max_rtt_us offset pinned at 12");

_Static_assert(sizeof(gn_heartbeat_api_t) == 72,
               "gn_heartbeat_api_t size pinned at 72");
_Static_assert(offsetof(gn_heartbeat_api_t, api_size) == 0,
               "gn_heartbeat_api_t::api_size offset pinned at 0");
_Static_assert(offsetof(gn_heartbeat_api_t, get_stats) == 8,
               "gn_heartbeat_api_t::get_stats offset pinned at 8");
_Static_assert(offsetof(gn_heartbeat_api_t, get_rtt) == 16,
               "gn_heartbeat_api_t::get_rtt offset pinned at 16");
_Static_assert(offsetof(gn_heartbeat_api_t, get_observed_address) == 24,
               "gn_heartbeat_api_t::get_observed_address offset pinned at 24");
_Static_assert(offsetof(gn_heartbeat_api_t, ctx) == 32,
               "gn_heartbeat_api_t::ctx offset pinned at 32");
_Static_assert(offsetof(gn_heartbeat_api_t, _reserved) == 40,
               "gn_heartbeat_api_t::_reserved offset pinned at 40");

/* ── sdk/extensions/transport.h ────────────────────────────────────────────── */

_Static_assert(sizeof(gn_transport_caps_t) == 56,
               "gn_transport_caps_t size pinned at 56");
_Static_assert(offsetof(gn_transport_caps_t, flags) == 0,
               "gn_transport_caps_t::flags offset pinned at 0");
_Static_assert(offsetof(gn_transport_caps_t, max_payload) == 4,
               "gn_transport_caps_t::max_payload offset pinned at 4");
_Static_assert(offsetof(gn_transport_caps_t, _reserved) == 8,
               "gn_transport_caps_t::_reserved offset pinned at 8");

_Static_assert(sizeof(gn_transport_stats_t) == 104,
               "gn_transport_stats_t size pinned at 104");
_Static_assert(offsetof(gn_transport_stats_t, bytes_in) == 0,
               "gn_transport_stats_t::bytes_in offset pinned at 0");
_Static_assert(offsetof(gn_transport_stats_t, bytes_out) == 8,
               "gn_transport_stats_t::bytes_out offset pinned at 8");
_Static_assert(offsetof(gn_transport_stats_t, frames_in) == 16,
               "gn_transport_stats_t::frames_in offset pinned at 16");
_Static_assert(offsetof(gn_transport_stats_t, frames_out) == 24,
               "gn_transport_stats_t::frames_out offset pinned at 24");
_Static_assert(offsetof(gn_transport_stats_t, active_connections) == 32,
               "gn_transport_stats_t::active_connections offset pinned at 32");
_Static_assert(offsetof(gn_transport_stats_t, _reserved) == 40,
               "gn_transport_stats_t::_reserved offset pinned at 40");

_Static_assert(sizeof(gn_transport_api_t) == 136,
               "gn_transport_api_t size pinned at 136");
_Static_assert(offsetof(gn_transport_api_t, api_size) == 0,
               "gn_transport_api_t::api_size offset pinned at 0");
_Static_assert(offsetof(gn_transport_api_t, get_stats) == 8,
               "gn_transport_api_t::get_stats offset pinned at 8");
_Static_assert(offsetof(gn_transport_api_t, get_capabilities) == 16,
               "gn_transport_api_t::get_capabilities offset pinned at 16");
_Static_assert(offsetof(gn_transport_api_t, send) == 24,
               "gn_transport_api_t::send offset pinned at 24");
_Static_assert(offsetof(gn_transport_api_t, send_batch) == 32,
               "gn_transport_api_t::send_batch offset pinned at 32");
_Static_assert(offsetof(gn_transport_api_t, close) == 40,
               "gn_transport_api_t::close offset pinned at 40");
_Static_assert(offsetof(gn_transport_api_t, listen) == 48,
               "gn_transport_api_t::listen offset pinned at 48");
_Static_assert(offsetof(gn_transport_api_t, connect) == 56,
               "gn_transport_api_t::connect offset pinned at 56");
_Static_assert(offsetof(gn_transport_api_t, subscribe_data) == 64,
               "gn_transport_api_t::subscribe_data offset pinned at 64");
_Static_assert(offsetof(gn_transport_api_t, unsubscribe_data) == 72,
               "gn_transport_api_t::unsubscribe_data offset pinned at 72");
_Static_assert(offsetof(gn_transport_api_t, ctx) == 80,
               "gn_transport_api_t::ctx offset pinned at 80");
_Static_assert(offsetof(gn_transport_api_t, _reserved) == 88,
               "gn_transport_api_t::_reserved offset pinned at 88");
