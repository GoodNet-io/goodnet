/// @file   core/kernel/host_api_internal.hpp
/// @brief  Private header tying every `host_api/*.cpp` translation
///         unit together. Public API stays in `host_api_builder.hpp`;
///         this header carries the cross-cutting helpers and thunk
///         declarations so `build_host_api()` can take their
///         addresses without re-parsing 2.5k lines of slot bodies.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include <sdk/host_api.h>
#include <sdk/identity.h>
#include <sdk/types.h>

#include "kernel.hpp"
#include "plugin_context.hpp"

namespace gn::core {

class SecuritySession;
struct PerConnQueue;
struct ConnectionRecord;
struct LinkEntry;

namespace host_api_internal {

/// Liveness check for the `PluginContext*` every host_api thunk
/// reaches through `host_ctx`. The kernel stamps `kMagicDead` in
/// `~PluginContext`; a plugin that retained the `host_api`
/// pointer past its own teardown lands in a thunk with a freed
/// context whose magic field reads as the poison value. The thunk
/// returns before dereferencing any other field.
[[nodiscard]] inline bool ctx_live(PluginContext* pc) noexcept {
    return pc != nullptr && pc->magic == PluginContext::kMagicLive;
}

/// Loader-side host-API entries — `notify_connect` /
/// `notify_inbound_bytes` / `notify_disconnect` / `kick_handshake`
/// — are reserved for transport plugins. A handler / security /
/// protocol plugin attempting to call them is rejected up front.
[[nodiscard]] inline bool link_role(const PluginContext* pc) noexcept {
    if (pc == nullptr) return false;
    return pc->kind == GN_PLUGIN_KIND_LINK ||
           pc->kind == GN_PLUGIN_KIND_UNKNOWN;
}

/// Build a `gn_message_t` from the four pieces every assembly site
/// always has. `payload` is `@borrowed` for the kernel call; the
/// helper does not copy.
[[nodiscard]] gn_message_t build_envelope(
    const PublicKey&   sender_pk,
    const PublicKey&   receiver_pk,
    std::uint32_t      msg_id,
    const std::uint8_t* payload,
    std::size_t        payload_size) noexcept;

/// Propagate the security session's `peer_static_pk` into the
/// connection record's `remote_pk` once the handshake has
/// completed. See the body in `host_api/internal.cpp` for the
/// failure-mode table (collisions → INTEGRITY_FAILED).
[[nodiscard]] gn_result_t propagate_peer_pk_after_handshake(
    const PluginContext* pc,
    gn_conn_id_t conn,
    const SecuritySession& session);

/// Tear down a connection from inside a kernel thunk after a
/// security-level failure (peer pk collision, integrity check).
void kernel_initiated_disconnect(const PluginContext* pc,
                                  gn_conn_id_t conn);

/// Verify the caller's plugin anchor owns the connection's
/// registered link scheme.
[[nodiscard]] bool conn_owned_by_caller(const PluginContext* pc,
                                         const ConnectionRecord& rec);

/// Surface the router's verdict — bumps the `route.outcome.*`
/// metric counter and logs drops at the right level per
/// `metrics.md` §4.
void route_one_envelope(Kernel& kernel,
                         std::string_view protocol_id,
                         const gn_message_t& env);

/// Hand a batch of wire-frame buffers to the link plugin. Falls
/// back to scalar `send` when the link declares no `send_batch`.
[[nodiscard]] gn_result_t send_link_batch(
    PluginContext* pc,
    const LinkEntry& trans,
    gn_conn_id_t conn,
    std::span<const std::vector<std::uint8_t>> batch,
    std::size_t& out_accepted) noexcept;

/// Drain a connection's send queue — claim has already been won
/// via the `PerConnQueue::drain_scheduled` CAS upstream.
void drain_send_queue(PluginContext* pc,
                       const LinkEntry& trans,
                       gn_conn_id_t conn,
                       PerConnQueue& queue,
                       const std::shared_ptr<SecuritySession>& session) noexcept;

/// Send handshake-phase bytes raw via the transport vtable,
/// bypassing the security and protocol layers.
[[nodiscard]] gn_result_t send_raw_via_link(
    PluginContext* pc,
    gn_conn_id_t conn,
    std::string_view scheme,
    std::span<const std::uint8_t> bytes);

/// Kernel-side teardown for a connection the kernel itself closes
/// (no plugin-driven `notify_disconnect` upstream).
void publish_kernel_disconnect(PluginContext* pc, gn_conn_id_t conn);

/// Drain the session's pending-handshake queue once it has
/// reached the Transport phase.
void drain_handshake_pending(PluginContext* pc,
                              gn_conn_id_t conn,
                              SecuritySession& session,
                              std::string_view link_scheme);

/// True iff @p pk has at least one non-zero byte.
[[nodiscard]] bool pk_is_known(const std::uint8_t pk[GN_PUBLIC_KEY_BYTES]) noexcept;

/// 64-bit key for the per-source rate limiter on `inject_*` thunks.
[[nodiscard]] std::uint64_t inject_rate_key(const PublicKey& pk) noexcept;

}  // namespace host_api_internal

/// Thunks live in their own namespace so `build_host_api()` can
/// take addresses across translation-unit boundaries without
/// resorting to `extern "C"` (every signature is already POD-only
/// C ABI). Each `host_api/*.cpp` defines its slice inside this
/// namespace.
namespace host_api_thunks {

// ── Messaging (host_api/messaging.cpp) ─────────────────────────────
gn_result_t send(void* host_ctx, gn_conn_id_t conn, uint32_t msg_id,
                  const uint8_t* payload, size_t payload_size);
gn_result_t send_to(void* host_ctx,
                     const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                     uint32_t msg_id,
                     const uint8_t* payload, size_t payload_size);
gn_result_t disconnect(void* host_ctx, gn_conn_id_t conn);

// ── Connection-lifecycle notifications (host_api/notifications.cpp) ─
gn_result_t notify_connect(void* host_ctx,
                            const uint8_t remote_pk[GN_PUBLIC_KEY_BYTES],
                            const char* uri,
                            gn_trust_class_t trust,
                            gn_handshake_role_t role,
                            gn_conn_id_t* out_conn);
gn_result_t kick_handshake(void* host_ctx, gn_conn_id_t conn);
gn_result_t notify_inbound_bytes(void* host_ctx, gn_conn_id_t conn,
                                  const uint8_t* bytes, size_t size);
gn_result_t notify_disconnect(void* host_ctx, gn_conn_id_t conn,
                               gn_result_t reason);
gn_result_t inject(void* host_ctx,
                    gn_inject_layer_t layer_kind,
                    gn_conn_id_t source,
                    std::uint32_t msg_id,
                    const std::uint8_t* bytes,
                    std::size_t size);

// ── Identity + capability blobs (host_api/identity.cpp) ────────────
gn_result_t register_local_key(void* host_ctx,
                                gn_key_purpose_t purpose,
                                const char* label,
                                gn_key_id_t* out_id);
gn_result_t delete_local_key(void* host_ctx, gn_key_id_t id);
gn_result_t list_local_keys(void* host_ctx,
                             gn_key_descriptor_t* out_array,
                             std::size_t array_cap,
                             std::size_t* out_count);
gn_result_t sign_local(void* host_ctx,
                        gn_key_purpose_t purpose,
                        const std::uint8_t* payload,
                        std::size_t size,
                        std::uint8_t out_sig[64]);
gn_result_t sign_local_by_id(void* host_ctx,
                              gn_key_id_t id,
                              const std::uint8_t* payload,
                              std::size_t size,
                              std::uint8_t out_sig[64]);
gn_result_t get_peer_user_pk(void* host_ctx, gn_conn_id_t conn,
                              std::uint8_t out_pk[GN_PUBLIC_KEY_BYTES]);
gn_result_t get_peer_device_pk(void* host_ctx, gn_conn_id_t conn,
                                std::uint8_t out_pk[GN_PUBLIC_KEY_BYTES]);
gn_result_t get_handshake_hash(void* host_ctx, gn_conn_id_t conn,
                                std::uint8_t out_hash[GN_HASH_BYTES]);
gn_result_t announce_rotation(void* host_ctx,
                               std::int64_t valid_from_unix_ts);
gn_result_t present_capability_blob(void* host_ctx, gn_conn_id_t conn,
                                     const std::uint8_t* blob, std::size_t size,
                                     std::int64_t expires_unix_ts);
gn_result_t subscribe_capability_blob(void* host_ctx,
                                       gn_capability_blob_cb_t cb,
                                       void* user_data,
                                       void (*ud_destroy)(void*),
                                       gn_subscription_id_t* out_id);

// ── Control plane: small thunks (host_api/control.cpp) ─────────────
gn_result_t find_conn_by_pk(void* host_ctx,
                             const std::uint8_t pk[GN_PUBLIC_KEY_BYTES],
                             gn_conn_id_t* out_conn);
gn_result_t get_endpoint(void* host_ctx, gn_conn_id_t conn,
                          gn_endpoint_t* out);
gn_result_t register_security(void* host_ctx,
                               const char* provider_id,
                               const gn_security_provider_vtable_t* vtable,
                               void* security_self);
gn_result_t unregister_security(void* host_ctx, const char* provider_id);
gn_result_t query_extension_checked(void* host_ctx,
                                     const char* name,
                                     uint32_t version,
                                     const void** out_vtable);
gn_result_t register_extension(void* host_ctx, const char* name,
                                uint32_t version, const void* vtable);
gn_result_t unregister_extension(void* host_ctx, const char* name);
gn_result_t set_timer(void* host_ctx, std::uint32_t delay_ms,
                       gn_task_fn_t fn, void* user_data,
                       gn_timer_id_t* out_id);
gn_result_t cancel_timer(void* host_ctx, gn_timer_id_t id);
gn_result_t subscribe_conn_state(void* host_ctx,
                                  gn_conn_state_cb_t cb,
                                  void* user_data,
                                  void (*ud_destroy)(void*),
                                  gn_subscription_id_t* out_id);
gn_result_t subscribe_config_reload(void* host_ctx,
                                     gn_config_reload_cb_t cb,
                                     void* user_data,
                                     void (*ud_destroy)(void*),
                                     gn_subscription_id_t* out_id);
gn_result_t unsubscribe(void* host_ctx, gn_subscription_id_t id);
int32_t     is_shutdown_requested(void* host_ctx);
void        emit_counter(void* host_ctx, const char* name);
std::uint64_t iterate_counters(void* host_ctx,
                                gn_counter_visitor_t visitor,
                                void* user_data);
gn_result_t for_each_connection(void* host_ctx,
                                 gn_conn_visitor_t visitor,
                                 void* user_data);
gn_result_t notify_backpressure(void* host_ctx, gn_conn_id_t conn,
                                 gn_conn_event_kind_t kind,
                                 std::uint64_t pending_bytes);
gn_result_t register_vtable(void* host_ctx,
                             gn_register_kind_t kind,
                             const gn_register_meta_t* meta,
                             const void* vtable,
                             void* self,
                             std::uint64_t* out_id);
gn_result_t unregister_vtable(void* host_ctx, std::uint64_t id);
const gn_limits_t* limits(void* host_ctx);
gn_result_t config_get(void* host_ctx,
                        const char* key,
                        gn_config_value_type_t type,
                        std::size_t index,
                        void* out_value,
                        void** out_user_data,
                        void (**out_free)(void*, void*));
int32_t     log_should_log(void* host_ctx, gn_log_level_t level);
void        log_emit(void* host_ctx, gn_log_level_t level,
                      const char* file, int32_t line, const char* msg);

}  // namespace host_api_thunks

}  // namespace gn::core
