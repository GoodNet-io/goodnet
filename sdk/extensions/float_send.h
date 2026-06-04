/**
 * @file   sdk/extensions/float_send.h
 * @brief  Extension vtable: `gn.float-send.*` — payload-level send intercept.
 *
 * Float-send plugins sit upstream of the `gn.strategy.*` chain in
 * `send_to`. They receive the full payload and the live candidate set,
 * so they can fan out, duplicate, or reorder across all paths — not
 * just pick one. The kernel walks registered `gn.float-send.*` plugins in
 * registration order; the first one that returns GN_OK "owns" the send
 * (the strategy chain is skipped). A plugin that returns GN_ERR_NOT_FOUND
 * passes the call to the next float-send plugin; if all pass, the kernel
 * falls through to the strategy chain as usual.
 *
 * See `gn.float-send.multipath-bond` for the reference implementation.
 */
#ifndef GOODNET_SDK_EXTENSIONS_FLOAT_SEND_H
#define GOODNET_SDK_EXTENSIONS_FLOAT_SEND_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/extensions/strategy.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Extension family prefix. Per-plugin names extend this
 *  (e.g. `gn.float-send.multipath-bond`). */
#define GN_EXT_FLOAT_SEND_PREFIX  "gn.float-send."

/** v1.0.0 — initial release. */
#define GN_EXT_FLOAT_SEND_VERSION 0x00010000u

/**
 * @brief Float-send extension vtable.
 *
 * Registered by float-send plugins under `gn.float-send.<name>`.
 * Begins with `api_size` for size-prefix evolution per
 * `abi-evolution.en.md` §3.
 */
typedef struct gn_float_send_api_s {
    uint32_t api_size;    /**< sizeof(gn_float_send_api_t) at producer build time */

    /**
     * @brief Intercept a peer-addressed send with full payload.
     *
     * @param ctx              plugin's opaque context (mirrored in `ctx` below).
     * @param peer_pk          @borrowed; destination peer public key.
     * @param msg_id           application message id (non-zero).
     * @param payload          @borrowed; message bytes.
     * @param payload_size     byte count of @p payload.
     * @param candidates       @borrowed; non-empty array of live conns to peer.
     * @param candidate_count  length of @p candidates.
     *
     * @return GN_OK when the plugin handled the send (kernel stops the
     *         float-send + strategy chains and returns this to the caller).
     *         GN_ERR_NOT_FOUND to pass to the next float-send plugin (or
     *         fall through to the strategy chain). Any other error aborts
     *         the chain and surfaces to the `send_to` caller.
     */
    gn_result_t (*float_send)(
        void* ctx,
        const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
        uint32_t msg_id,
        const uint8_t* payload,
        size_t payload_size,
        const gn_path_sample_t* candidates,
        size_t candidate_count);

    /**
     * @brief React to a path-state event (same contract as
     *        `gn_strategy_api_t::on_path_event`).
     *
     * The kernel dispatches CONN_UP, CONN_DOWN, and RTT_UPDATE events to
     * all registered float-send plugins. Always non-null in the vtable —
     * the C++ macro fills a no-op stub when not implemented.
     */
    gn_result_t (*on_path_event)(
        void* ctx,
        const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
        gn_path_event_t ev,
        const gn_path_sample_t* sample);

    void* ctx;
    void* _reserved[4];
} gn_float_send_api_t;

GN_VTABLE_API_SIZE_FIRST(gn_float_send_api_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_FLOAT_SEND_H */
