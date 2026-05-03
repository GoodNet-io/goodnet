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
#include <sdk/log.h>
#include <sdk/metrics.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations — full vtable types live in their own headers. */
typedef struct gn_handler_vtable_s             gn_handler_vtable_t;
typedef struct gn_link_vtable_s                gn_link_vtable_t;
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

    /** Close a connection. Safe from any thread. */
    gn_result_t (*disconnect)(void* host_ctx, gn_conn_id_t conn);

    /* ── Handler registration ──────────────────────────────────────────── */

    /* ── Universal handler / link registration ────────────────────────── */

    /**
     * @brief Register a handler or link vtable with the kernel.
     *
     * `kind` selects the family; `meta` carries the per-family
     * fields (see @ref gn_register_kind_t for the per-kind table).
     * `vtable` is `@borrowed` until `unregister(id)` returns;
     * `self` is the per-instance opaque pointer that flows back
     * through every vtable call. The id returned in `*out_id`
     * carries the kind tag in its top 4 bits so `unregister(id)`
     * routes back to the right registry without naming the kind
     * a second time.
     *
     * Failure modes:
     *
     * | Condition | Result |
     * |---|---|
     * | `meta == NULL` / `meta->name == NULL` / `vtable == NULL` / `out_id == NULL` | `GN_ERR_NULL_ARG` |
     * | unknown `kind` enum value | `GN_ERR_INVALID_ENVELOPE` |
     * | `meta->api_size < sizeof(gn_register_meta_t)` (older SDK) | `GN_ERR_VERSION_MISMATCH` |
     * | duplicate name within the family | `GN_ERR_LIMIT_REACHED` |
     */
    gn_result_t (*register_vtable)(void* host_ctx,
                                    gn_register_kind_t kind,
                                    const gn_register_meta_t* meta,
                                    const void* vtable,
                                    void* self,
                                    uint64_t* out_id);

    /**
     * @brief Drop a registration. Idempotent: removing an already-
     *        gone id returns @ref GN_OK. The id encodes the kind
     *        in its top 4 bits; the kernel decodes it internally.
     */
    gn_result_t (*unregister_vtable)(void* host_ctx, uint64_t id);

    /* ── Registry queries ──────────────────────────────────────────────── */

    /**
     * @return GN_OK and a connection id, or GN_ERR_NOT_FOUND.
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
     * @brief Look up an extension vtable by name with a major-version
     *        compatibility check.
     *
     * The compatibility predicate is the SDK's own
     * `gn_version_compatible` (see `sdk/abi.h`): the registered major
     * must equal @p version's major and the registered minor must
     * be at least @p version's minor. Patch is ignored. A consumer
     * built against an older minor of the extension always loads;
     * a consumer that asks for a newer minor than the registered
     * provider is rejected with `GN_ERR_VERSION_MISMATCH`.
     *
     * Failure modes — distinct enough that callers can handle the
     * "extension absent" and "extension too old" cases differently:
     *
     * | Condition | Result |
     * |---|---|
     * | `out_vtable == NULL` | `GN_ERR_NULL_ARG` |
     * | no extension registered under @p name | `GN_ERR_NOT_FOUND` |
     * | registered version is incompatible with @p version | `GN_ERR_VERSION_MISMATCH` |
     * | otherwise | `GN_OK` and `*out_vtable` set |
     *
     * @param out_vtable @borrowed; lifetime tied to the extension provider.
     */
    gn_result_t (*query_extension_checked)(void* host_ctx,
                                           const char* name,
                                           uint32_t version,
                                           const void** out_vtable);

    /**
     * @brief Publish a vtable under @p name with a major.minor
     *        version tag. Other plugins look it up through
     *        `query_extension_checked`.
     *
     * | Condition | Result |
     * |---|---|
     * | `name == NULL` / `vtable == NULL` | `GN_ERR_NULL_ARG` |
     * | another extension already registered under @p name | `GN_ERR_LIMIT_REACHED` |
     * | otherwise | `GN_OK` |
     */
    gn_result_t (*register_extension)(void* host_ctx,
                                      const char* name,
                                      uint32_t version,
                                      const void* vtable);

    /**
     * @brief Drop the registration. Idempotent — removing an
     *        already-absent name returns `GN_ERR_NOT_FOUND`.
     */
    gn_result_t (*unregister_extension)(void* host_ctx,
                                        const char* name);

    /* ── Configuration ─────────────────────────────────────────────────── */

    /**
     * @brief Read a value out of the live config document.
     *
     * The kernel parses the operator's JSON into a typed tree at
     * load and reload. This entry point reads one node out of that
     * tree under a runtime contract — the plugin declares the type
     * it expects through @p type, and the kernel returns
     * `GN_ERR_INVALID_ENVELOPE` if the live value's parse type does
     * not match. Type-validated reads keep config drift visible at
     * the call site instead of silently writing zeros into the
     * plugin's local state.
     *
     * The shape of @p out_value depends on @p type — see the table
     * on @ref gn_config_value_type_t. @p index carries the
     * array-element ordinal for `INT64` / `STRING` reads inside an
     * array; pass @ref GN_CONFIG_NO_INDEX for scalar lookups and
     * for the `ARRAY_SIZE` query.
     *
     * @p out_user_data and @p out_free are meaningful only for the
     * `STRING` reads (scalar and array element); pass `NULL` for the
     * other types. On a successful `STRING` read the kernel writes
     * an opaque destruction-state pointer into `*out_user_data` and
     * a destructor into `*out_free`; the plugin invokes
     * `(*out_free)(*out_user_data, *out_value)` to release the
     * buffer. Splitting destruction state from the function pointer
     * lets a non-C language binding hand back a captured handle
     * (Rust `Box`, Python object) without leaking it through the
     * `void(*)(void*)` form.
     *
     * Failure modes:
     *
     * | Condition | Result |
     * |---|---|
     * | `key == NULL` or `out_value == NULL` | `GN_ERR_NULL_ARG` |
     * | `STRING` read with `out_free == NULL` or `out_user_data == NULL`, or non-`STRING` read with either non-`NULL` | `GN_ERR_NULL_ARG` |
     * | scalar read with `index != GN_CONFIG_NO_INDEX`, or array-element read with `index == GN_CONFIG_NO_INDEX` | `GN_ERR_OUT_OF_RANGE` |
     * | key not present in config | `GN_ERR_NOT_FOUND` |
     * | live value's parse type does not match @p type | `GN_ERR_INVALID_ENVELOPE` |
     * | `ARRAY_SIZE` query against a non-array key | `GN_ERR_INVALID_ENVELOPE` |
     * | `index` past array length | `GN_ERR_OUT_OF_RANGE` |
     * | unknown @p type enum value | `GN_ERR_INVALID_ENVELOPE` |
     *
     * Per `host-api.md` §2 and `config.md` §3.
     *
     * @param key            dotted JSON path (`"foo.bar.baz"`).
     * @param type           expected node type; see @ref gn_config_value_type_t.
     * @param index          array-element ordinal, or @ref GN_CONFIG_NO_INDEX for scalar.
     * @param out_value      typed pointer per @p type.
     * @param out_user_data  on success of a `STRING` read, opaque destruction-
     *                       state pointer; `NULL` for non-`STRING` reads.
     * @param out_free       destructor for `STRING` reads; `NULL` otherwise.
     */
    gn_result_t (*config_get)(void* host_ctx,
                              const char* key,
                              gn_config_value_type_t type,
                              size_t index,
                              void* out_value,
                              void** out_user_data,
                              void (**out_free)(void* user_data, void* bytes));

    /* ── Limits read access ────────────────────────────────────────────── */

    /**
     * @return @borrowed pointer to the live limits struct; valid for the
     *         plugin's lifetime.
     */
    const gn_limits_t* (*limits)(void* host_ctx);

    /* ── Logging (sdk/log.h, host-api.md §11) ──────────────────────────── */

    /**
     * @brief Plugin-facing logging vtable. `should_log` short-
     *        circuits hot-path formatting; `emit` accepts a
     *        pre-formatted message buffer plus the call-site
     *        source location.
     */
    gn_log_api_t log;

    /* ── Link-side notifications ──────────────────────────────────── */

    /**
     * @brief Link announces a fully-established connection.
     *
     * Allocates a fresh `gn_conn_id_t` inside the kernel and returns
     * it through @p out_conn. The link stores the id and uses
     * it on every subsequent send / receive / disconnect call.
     *
     * @param remote_pk Peer's Ed25519 public key. Set for outbound
     *                  initiator-side connections that target a known
     *                  pk; all-zero for inbound responder-side
     *                  connections, where the pk is learned from the
     *                  handshake.
     * @param uri       Connection URI as parsed by the link.
     *                  Borrowed for the call.
     * @param scheme    Link scheme (`"tcp"`, `"udp"`, …).
     * @param trust     TrustClass computed from observable connection
     *                  properties per `link.md` §3.
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
     * @brief Link pushes received bytes for kernel processing.
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
     * @brief Link announces a connection close.
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
     * @brief Bridge plugins inject foreign-system bytes into the mesh
     *        under their own identity.
     *
     * @ref GN_INJECT_LAYER_MESSAGE builds an envelope with
     * `sender_pk = source.remote_pk`, `receiver_pk = local_identity`,
     * the supplied `msg_id`, and `bytes` as payload, then routes it
     * through the kernel as if it had arrived from the source
     * connection's link. `msg_id` must be non-zero. `size` is bounded
     * by `limits.max_payload_bytes`.
     *
     * @ref GN_INJECT_LAYER_FRAME runs the active protocol layer's
     * deframer over `bytes` and dispatches the resulting envelopes
     * through the router. `msg_id` is ignored. `size` is bounded by
     * `limits.max_frame_bytes`. Used by relay-style tunnels that move
     * opaque inner frames between mesh peers.
     *
     * Per `host-api.md` §8.
     *
     * @param layer    @ref GN_INJECT_LAYER_MESSAGE or @ref GN_INJECT_LAYER_FRAME
     * @param source   existing connection that originated the foreign bytes
     * @param msg_id   envelope routing key (MESSAGE only; ignored for FRAME)
     * @param bytes    @borrowed; copied internally before return
     * @param size     length of @p bytes
     */
    gn_result_t (*inject)(void* host_ctx,
                          gn_inject_layer_t layer,
                          gn_conn_id_t source,
                          uint32_t msg_id,
                          const uint8_t* bytes,
                          size_t size);

    /**
     * @brief Drive the local side of a security handshake into action.
     *
     * `notify_connect` allocates the connection record and creates the
     * security session in `Handshake` phase but does **not** generate
     * the initiator's first wire message: doing so synchronously would
     * race the link, which still needs to register its socket
     * under the freshly-allocated `conn` before bytes can ride out.
     * The link calls `kick_handshake` once it has registered the
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
     * of the calling plugin's lifetime anchor; a callback whose
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

    /* ── Channel subscription (conn-events.md / config.md authoritative) ── */

    /**
     * @brief Subscribe to a kernel pub/sub channel.
     *
     * The kernel pairs each subscription with a weak observer of
     * the calling plugin's lifetime anchor; a callback whose
     * plugin already unloaded is dropped silently
     * (`conn-events.md` §3 / `config.md` §2).
     *
     * `cb` runs on the publishing thread and receives a typed
     * payload — see @ref gn_subscribe_cb_t. Per-channel payload
     * shape is documented on the same enum.
     *
     * @p ud_destroy, if non-NULL, is invoked exactly once with
     * @p user_data when the subscription is removed — either
     * through `unsubscribe(out_id)` or because the kernel observed
     * the plugin's lifetime anchor expire. Bindings whose
     * `user_data` captures heap state (Rust `Box::into_raw`,
     * Python `Py_INCREF`'d object) point this slot at their
     * destructor; callers that pass plain pointers leave it NULL.
     */
    gn_result_t (*subscribe)(void* host_ctx,
                              gn_subscribe_channel_t channel,
                              gn_subscribe_cb_t cb,
                              void* user_data,
                              void (*ud_destroy)(void*),
                              gn_subscription_id_t* out_id);

    /**
     * @brief Remove a subscription. Idempotent: removing an already-
     *        gone id returns @ref GN_OK. The id is unique across
     *        every channel; the kernel routes the unsubscribe to
     *        the right channel internally.
     */
    gn_result_t (*unsubscribe)(void* host_ctx,
                                gn_subscription_id_t id);

    /* ── Connection iteration ──────────────────────────────────────────── */

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
     *        Link plugins call this once per rising / falling
     *        edge per `backpressure.md` §3. Restricted to
     *        link-role callers; other plugin kinds get
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

    /* ── Metrics (metrics.md) ──────────────────────────────────────────── */

    /**
     * @brief Bump the kernel-side counter at @p name by one.
     *
     * The kernel store is a flat map of monotonic UTF-8-named
     * 64-bit counters. Plugins emit cross-cutting telemetry
     * (relay forwards, cache hits, retries) through this slot
     * rather than spinning up their own metrics infrastructure;
     * an out-of-tree exporter plugin walks the merged set through
     * `iterate_counters` and serves whatever wire format the
     * operator picks. The kernel itself is wire-format agnostic.
     *
     * Names are convention-only: the kernel does not validate
     * shape or charset. Recommended pattern:
     * `<subsystem>.<event>.<reason>` (e.g. `relay.forward.ok`).
     */
    void (*emit_counter)(void* host_ctx, const char* name);

    /**
     * @brief Walk every registered counter; @p visitor is invoked
     *        once per `(name, value)` pair.
     *
     * The visitor's `name` borrows from the kernel's store and is
     * valid only for the call. A non-zero return from the visitor
     * stops iteration early. The kernel returns the number of
     * counters visited.
     */
    uint64_t (*iterate_counters)(void* host_ctx,
                                  gn_counter_visitor_t visitor,
                                  void* user_data);

    /* ── Cooperative cancellation (plugin-lifetime.md §8) ──────────────── */

    /**
     * @brief Non-zero once the kernel begins teardown for this plugin.
     *
     * Set the moment `PluginManager::rollback` enters the per-plugin
     * teardown path: before `gn_plugin_unregister` is called, before
     * pending timers are cancelled, before the drain wait. Plugins that
     * run long-lived async work — periodic timers that re-arm
     * themselves, multi-step posted tasks — poll this from inside the
     * loop and exit cooperatively rather than relying on the kernel's
     * drain timeout to leak the `dlclose` handle.
     *
     * @return 0 if shutdown has not been requested; non-zero otherwise.
     *         Always 0 for in-tree fixtures whose context has no anchor.
     *
     * Safe to call from any callback dispatched by the kernel for this
     * plugin (timer / posted task / signal subscriber). Calling it
     * after `gn_plugin_shutdown` returns is undefined.
     */
    int32_t (*is_shutdown_requested)(void* host_ctx);

    /* ── Reserved for future extension ───────────────────────────────────
     *
     * The kernel zero-initialises `_reserved` before exposing
     * `host_api_t` to a plugin. A plugin that copies `host_api_t` by
     * value (typically not done; the slot is `@borrowed` for the plugin
     * lifetime) MUST zero the field on copy.
     *
     * Per `abi-evolution.md` §4: the producer zero-initialises every
     * `_reserved` array on every value-type struct in this SDK; the
     * consumer treats unknown reserved contents as undefined and never
     * reads them. New fields are added by promoting a slot to a named
     * field, never by reusing existing reserved bytes.
     */
    void* _reserved[8];
} host_api_t;

GN_VTABLE_API_SIZE_FIRST(host_api_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_HOST_API_H */
