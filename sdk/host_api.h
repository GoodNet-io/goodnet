/**
 * @file   sdk/host_api.h
 * @brief  Public host vtable handed to every plugin at init.
 *
 * Plugins drive the kernel through this single C ABI table. Every
 * operation a plugin can request — sending a message, registering a
 * handler, querying an extension — goes through one of its function
 * pointers.
 *
 * The table is paired with an opaque @c host_ctx pointer that the plugin
 * receives at init time and passes back unchanged on every call. Both
 * `api` and `host_ctx` remain valid from `gn_plugin_init` return until
 * `gn_plugin_shutdown` returns.
 *
 * See `docs/contracts/host-api.md`.
 */
#ifndef GOODNET_SDK_HOST_API_H
#define GOODNET_SDK_HOST_API_H

#include <stdint.h>
#include <stddef.h>

#include <sdk/conn_events.h>
#include <sdk/types.h>
#include <sdk/handler.h>
#include <sdk/limits.h>
#include <sdk/endpoint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations — full vtable types live in their own headers. */
typedef struct gn_handler_vtable_s             gn_handler_vtable_t;
typedef struct gn_transport_vtable_s           gn_transport_vtable_t;
typedef struct gn_security_provider_vtable_s   gn_security_provider_vtable_t;

/**
 * @brief Public host vtable.
 *
 * Begins with @ref api_size for size-prefix evolution. New entries are
 * appended at the tail; consumers gate access through `GN_API_HAS`
 * (`sdk/abi.h`).
 *
 * The @ref host_ctx field is paired with the function pointers: every
 * vtable entry takes `host_ctx` as its first argument, and the kernel
 * sets the field before handing the table to the plugin. Convenience
 * macros in `sdk/convenience.h` read the field through `(api)->host_ctx`
 * so plugin authors call entries without passing it explicitly.
 */
typedef struct host_api_s {
    /** sizeof(host_api_t) at the producer's build time. */
    uint32_t api_size;

    /**
     * @brief Opaque kernel context. Pass back unchanged on every call.
     *
     * Set by the kernel before `gn_plugin_init` returns. Valid for the
     * full plugin lifetime (init through shutdown). The plugin must not
     * inspect it; it is stable, opaque, and identifies the plugin's
     * loader-side state to the kernel.
     */
    void* host_ctx;

    /* ── Messaging ─────────────────────────────────────────────────────── */

    /**
     * @brief Send an envelope on an existing connection.
     * @param payload @borrowed; copied internally before return.
     */
    gn_result_t (*send)(void* host_ctx,
                        gn_conn_id_t conn,
                        uint32_t msg_id,
                        const uint8_t* payload, size_t payload_size);

    /**
     * @brief Send to a peer identified by URI; opens the connection
     *        on first call.
     */
    gn_result_t (*send_uri)(void* host_ctx,
                            const char* uri,
                            uint32_t msg_id,
                            const uint8_t* payload, size_t payload_size);

    /** Broadcast to every currently connected peer. */
    gn_result_t (*broadcast)(void* host_ctx,
                             uint32_t msg_id,
                             const uint8_t* payload, size_t payload_size);

    /** Close a connection. Safe from any thread. */
    gn_result_t (*disconnect)(void* host_ctx, gn_conn_id_t conn);

    /* ── Handler registration ──────────────────────────────────────────── */

    /**
     * @param vtable @borrowed; must remain valid until unregister.
     */
    gn_result_t (*register_handler)(void* host_ctx,
                                    const char* protocol_id,
                                    uint32_t msg_id,
                                    uint8_t priority,
                                    const gn_handler_vtable_t* vtable,
                                    void* handler_self,
                                    gn_handler_id_t* out_id);

    gn_result_t (*unregister_handler)(void* host_ctx, gn_handler_id_t id);

    /* ── Transport registration ────────────────────────────────────────── */

    gn_result_t (*register_transport)(void* host_ctx,
                                      const char* scheme,
                                      const gn_transport_vtable_t* vtable,
                                      void* transport_self,
                                      gn_transport_id_t* out_id);

    gn_result_t (*unregister_transport)(void* host_ctx, gn_transport_id_t id);

    /* ── Registry queries ──────────────────────────────────────────────── */

    /**
     * @return GN_OK and a connection id, or GN_ERR_UNKNOWN_RECEIVER.
     */
    gn_result_t (*find_conn_by_pk)(void* host_ctx,
                                   const uint8_t pk[GN_PUBLIC_KEY_BYTES],
                                   gn_conn_id_t* out_conn);

    /**
     * @param out @in-out; caller allocates, kernel fills.
     */
    gn_result_t (*get_endpoint)(void* host_ctx,
                                gn_conn_id_t conn,
                                gn_endpoint_t* out);

    /* ── Extension API ─────────────────────────────────────────────────── */

    /**
     * @param out_vtable @borrowed; lifetime tied to the extension provider.
     */
    gn_result_t (*query_extension_checked)(void* host_ctx,
                                           const char* name,
                                           uint32_t version,
                                           const void** out_vtable);

    gn_result_t (*register_extension)(void* host_ctx,
                                      const char* name,
                                      uint32_t version,
                                      const void* vtable);

    gn_result_t (*unregister_extension)(void* host_ctx,
                                        const char* name);

    /* ── Configuration ─────────────────────────────────────────────────── */

    /**
     * @param out_str  @owned; caller calls *out_free when done.
     * @param out_free destructor matching @p out_str allocation.
     */
    gn_result_t (*config_get_string)(void* host_ctx,
                                     const char* key,
                                     char** out_str,
                                     void (**out_free)(char*));

    gn_result_t (*config_get_int64)(void* host_ctx,
                                    const char* key,
                                    int64_t* out_value);

    /* ── Limits read access ────────────────────────────────────────────── */

    /**
     * @return @borrowed pointer to the live limits struct; valid for the
     *         plugin's lifetime.
     */
    const gn_limits_t* (*limits)(void* host_ctx);

    /* ── Logging ───────────────────────────────────────────────────────── */

    void (*log)(void* host_ctx,
                gn_log_level_t level,
                const char* fmt, ...);

    /* ── Transport-side notifications ──────────────────────────────────── */

    /**
     * @brief Transport announces a fully-established connection.
     *
     * Allocates a fresh `gn_conn_id_t` inside the kernel and returns
     * it through @p out_conn. The transport stores the id and uses
     * it on every subsequent send / receive / disconnect call.
     *
     * @param remote_pk Peer's Ed25519 public key. Set for outbound
     *                  initiator-side connections that target a known
     *                  pk; all-zero for inbound responder-side
     *                  connections, where the pk is learned from the
     *                  handshake.
     * @param uri       Connection URI as parsed by the transport.
     *                  Borrowed for the call.
     * @param scheme    Transport scheme (`"tcp"`, `"udp"`, …).
     * @param trust     TrustClass computed from observable connection
     *                  properties per `transport.md` §3.
     * @param role      Handshake role: initiator for outbound, responder
     *                  for inbound.
     * @param out_conn  Kernel-allocated connection id on success.
     */
    gn_result_t (*notify_connect)(void* host_ctx,
                                  const uint8_t remote_pk[GN_PUBLIC_KEY_BYTES],
                                  const char* uri,
                                  const char* scheme,
                                  gn_trust_class_t trust,
                                  gn_handshake_role_t role,
                                  gn_conn_id_t* out_conn);

    /**
     * @brief Transport pushes received bytes for kernel processing.
     *
     * The kernel runs the bytes through security decrypt → protocol
     * deframe → router dispatch. `bytes` is `@borrowed` for the
     * duration of the call; the kernel copies before returning if
     * it needs to retain anything.
     */
    gn_result_t (*notify_inbound_bytes)(void* host_ctx,
                                        gn_conn_id_t conn,
                                        const uint8_t* bytes,
                                        size_t size);

    /**
     * @brief Transport announces a connection close.
     *
     * @param reason `GN_OK` for a clean close; otherwise the
     *               `gn_result_t` value that triggered teardown.
     */
    gn_result_t (*notify_disconnect)(void* host_ctx,
                                     gn_conn_id_t conn,
                                     gn_result_t reason);

    /* ── Security registration ─────────────────────────────────────────── */

    /**
     * @brief Register a security provider with the kernel.
     *
     * Stack policy from `security-trust.md` §4: a node uses one
     * default provider per trust class; v1 simplification holds a
     * single active provider total. Plugins register their vtable
     * and self pointer; the kernel calls encrypt / decrypt /
     * handshake entries through it.
     *
     * @param vtable @borrowed; valid until `unregister_security`.
     */
    gn_result_t (*register_security)(void* host_ctx,
                                     const char* provider_id,
                                     const struct gn_security_provider_vtable_s* vtable,
                                     void* security_self);

    gn_result_t (*unregister_security)(void* host_ctx,
                                       const char* provider_id);

    /* ── Foreign-payload injection ─────────────────────────────────────── */

    /**
     * @brief Bridge plugins inject foreign-system payloads into the mesh
     *        under their own identity.
     *
     * Builds an envelope with `sender_pk = source.remote_pk`,
     * `receiver_pk = local_identity`, the supplied `msg_id`, and payload,
     * then routes it through the kernel as if the bytes had arrived
     * from the source connection's transport. Per `host-api.md` §8.
     *
     * @param source        existing connection that originated the foreign payload
     * @param msg_id        envelope routing key; must be non-zero
     * @param payload       @borrowed; copied internally before return
     * @param payload_size  bounded by `limits.max_payload_bytes`
     */
    gn_result_t (*inject_external_message)(void* host_ctx,
                                           gn_conn_id_t source,
                                           uint32_t msg_id,
                                           const uint8_t* payload,
                                           size_t payload_size);

    /**
     * @brief Inject a fully framed wire-side bytes buffer at the
     *        protocol-layer's deframe entry, dispatching the resulting
     *        envelopes through the router.
     *
     * The frame is parsed by the active protocol layer; malformed
     * frames return the deframer's error verbatim. Used by
     * relay-style tunnels that move opaque inner frames between mesh
     * peers. Per `host-api.md` §8.
     */
    gn_result_t (*inject_frame)(void* host_ctx,
                                gn_conn_id_t source,
                                const uint8_t* frame,
                                size_t frame_size);

    /**
     * @brief Drive the local side of a security handshake into action.
     *
     * `notify_connect` allocates the connection record and creates the
     * security session in `Handshake` phase but does **not** generate
     * the initiator's first wire message: doing so synchronously would
     * race the transport, which still needs to register its socket
     * under the freshly-allocated `conn` before bytes can ride out.
     * The transport calls `kick_handshake` once it has registered the
     * connection — the kernel then drives initiator's first message
     * (no-op for a responder, no-op for connections without a
     * security session).
     */
    gn_result_t (*kick_handshake)(void* host_ctx, gn_conn_id_t conn);

    /* ── Service executor (timer.md is the authoritative spec) ─────────── */

    /**
     * @brief Schedule a one-shot callback after @p delay_ms ms.
     *
     * `fn(user_data)` runs on the kernel's single-thread service
     * executor. The kernel pairs every timer with a weak observer
     * of the calling plugin's quiescence sentinel; a callback whose
     * plugin already unloaded is dropped silently (`timer.md` §4).
     *
     * @return `GN_OK` on success, `GN_ERR_NULL_ARG` on null
     *         argument, `GN_ERR_LIMIT_REACHED` when
     *         `gn_limits_t::max_timers` has been exhausted.
     */
    gn_result_t (*set_timer)(void* host_ctx,
                             uint32_t delay_ms,
                             gn_task_fn_t fn,
                             void* user_data,
                             gn_timer_id_t* out_id);

    /**
     * @brief Cancel a pending timer. Idempotent: cancelling an
     *        already-fired or already-cancelled timer is success.
     */
    gn_result_t (*cancel_timer)(void* host_ctx, gn_timer_id_t id);

    /**
     * @brief Run @p fn(user_data) on the service executor at the
     *        next available point. Used to hand work back from a
     *        transport's strand into the kernel's serialised loop.
     */
    gn_result_t (*post_to_executor)(void* host_ctx,
                                    gn_task_fn_t fn,
                                    void* user_data);

    /* ── Connection events (conn-events.md is authoritative) ───────────── */

    /**
     * @brief Subscribe to connection-lifecycle events.
     *
     * The kernel pairs each subscription with a weak observer of
     * the calling plugin's quiescence sentinel; a callback whose
     * plugin already unloaded is dropped silently
     * (`conn-events.md` §3).
     */
    gn_result_t (*subscribe_conn_state)(void* host_ctx,
                                        gn_conn_event_cb_t cb,
                                        void* user_data,
                                        gn_subscription_id_t* out_id);

    /**
     * @brief Remove a subscription. Idempotent: removing an already-
     *        gone id returns @ref GN_OK.
     */
    gn_result_t (*unsubscribe_conn_state)(void* host_ctx,
                                          gn_subscription_id_t id);

    /**
     * @brief Visit every currently-registered connection under a
     *        per-shard read lock. Visitor returns 0 to continue,
     *        non-zero to stop.
     */
    gn_result_t (*for_each_connection)(void* host_ctx,
                                        gn_conn_visitor_t visitor,
                                        void* user_data);

    /**
     * @brief Publish a backpressure transition for @p conn — soft
     *        (queue crossed `pending_queue_bytes_high`) or clear
     *        (queue dropped below `pending_queue_bytes_low`).
     *        Transport plugins call this once per rising / falling
     *        edge per `backpressure.md` §3. Restricted to
     *        transport-role callers; other plugin kinds get
     *        @ref GN_ERR_NOT_IMPLEMENTED.
     *
     * `kind` must be either
     * @ref GN_CONN_EVENT_BACKPRESSURE_SOFT or
     * @ref GN_CONN_EVENT_BACKPRESSURE_CLEAR; any other value is
     * @ref GN_ERR_INVALID_ENVELOPE.
     */
    gn_result_t (*notify_backpressure)(void* host_ctx,
                                        gn_conn_id_t conn,
                                        gn_conn_event_kind_t kind,
                                        uint64_t pending_bytes);

    /* ── Reserved for future extension ─────────────────────────────────── */

    void* _reserved[8];
} host_api_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_HOST_API_H */
