/**
 * @file   sdk/handler.h
 * @brief  C ABI for application-level message handlers.
 *
 * Handlers consume envelopes whose `(protocol_id, msg_id)` pair matches
 * their registration. Multiple handlers may share the same pair; the
 * kernel dispatches in priority order until one returns @ref GN_PROPAGATION_CONSUMED.
 */
#ifndef GOODNET_SDK_HANDLER_H
#define GOODNET_SDK_HANDLER_H

#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Propagation policy returned from `handle_message`.
 *
 * Determines whether subsequent handlers in the dispatch chain see the
 * same envelope.
 */
typedef enum gn_propagation_e {
    GN_PROPAGATION_CONTINUE = 0,  /**< pass envelope to the next handler */
    GN_PROPAGATION_CONSUMED = 1,  /**< stop dispatch chain — handled */
    GN_PROPAGATION_REJECT   = 2   /**< drop envelope and close the connection */
} gn_propagation_t;

/**
 * @brief Vtable for an `IHandler` implementation in C.
 *
 * Begins with `api_size` for size-prefix evolution per
 * `abi-evolution.md` §3.
 *
 * @par Per-instance state via `self`
 * Every callback in this vtable receives a `void* self` as its first
 * argument. That pointer is the one the plugin passed to
 * `host_api->register_vtable(kind, meta, vtable, self, &id)` at
 * registration time and the kernel hands it back unchanged on every
 * subsequent call. Plugin authors put their per-handler state behind
 * `self` and dereference it inside every entry — this is the
 * vtable's equivalent of the `user_data` argument that
 * `set_timer` and `subscribe` carry. There is no separate
 * `user_data` parameter because `self` already serves that role for
 * the entire vtable lifetime.
 *
 * @par Per-envelope state continuity
 * `handle_message` and `on_result` see the same `gn_message_t*`
 * (same address) for one dispatch. Handlers that need to thread
 * state from `handle_message` to `on_result` for the same envelope
 * key on `(envelope->sender_pk, envelope->msg_id)` inside `self`'s
 * own state map — the kernel does not allocate per-envelope storage
 * on the plugin's behalf. The envelope reference itself is borrowed
 * for the full handle + on_result span.
 */
typedef struct gn_handler_vtable_s {
    uint32_t api_size;          /**< sizeof(gn_handler_vtable_t) at producer build time */

    /**
     * @brief Stable identifier of the protocol layer this handler binds to.
     *
     * @return @borrowed pointer; valid for the lifetime of the plugin.
     */
    const char* (*protocol_id)(void* self);

    /**
     * @brief List of message IDs this handler subscribes to.
     *
     * The kernel queries this once at registration.
     *
     * @param out_ids   @borrowed pointer-to-pointer; the array the
     *                  plugin returns through `*out_ids` is
     *                  @borrowed for the lifetime of the handler.
     * @param out_count out parameter; written by the plugin, never read.
     */
    void (*supported_msg_ids)(void* self,
                              const uint32_t** out_ids,
                              size_t* out_count);

    /**
     * @brief Dispatch entry point.
     *
     * Synchronous; runs to completion before the kernel reuses the
     * envelope storage.
     *
     * @param envelope @borrowed for the duration of this call;
     *                 `envelope->payload` shares the same lifetime.
     *                 Handlers that need to retain payload bytes
     *                 past return must copy.
     */
    gn_propagation_t (*handle_message)(void* self,
                                       const gn_message_t* envelope);

    /**
     * @brief Called after every `handle_message` regardless of outcome.
     *
     * Receives the propagation value the handler just returned. Used by
     * relay counters, DHT bucket refresh, and other handlers that need
     * to observe their own dispatch tail. Optional; the slot may be
     * NULL when the handler has nothing to do at completion. The pinned
     * fast-path invokes this slot identically to the slow path.
     *
     * @param envelope @borrowed for the duration of this call.
     */
    void (*on_result)(void* self,
                      const gn_message_t* envelope,
                      gn_propagation_t result);

    /**
     * @brief Optional lifecycle hooks. May be NULL if not used.
     *
     * `on_init` runs once after the handler is admitted to the
     * registry and before the first `handle_message` dispatch.
     * `on_shutdown` runs once before the kernel drops the
     * registration; after it returns the kernel may release every
     * resource tied to `self`.
     */
    void (*on_init)(void* self);
    void (*on_shutdown)(void* self);

    void* _reserved[4];
} gn_handler_vtable_t;

GN_VTABLE_API_SIZE_FIRST(gn_handler_vtable_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_HANDLER_H */
