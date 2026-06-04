/**
 * @file   sdk/extensions/multipath_bond.h
 * @brief  Management API for the `gn.float-send.multipath-bond` plugin.
 *
 * The bond plugin registers this vtable under the name
 * `gn.multipath-bond` so operators can configure per-peer bond strategies
 * at runtime via `host_api->query_extension_checked`.
 */
#ifndef GOODNET_SDK_EXTENSIONS_MULTIPATH_BOND_H
#define GOODNET_SDK_EXTENSIONS_MULTIPATH_BOND_H

#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Name under which the management vtable is registered. */
#define GN_EXT_MULTIPATH_BOND_API  "gn.multipath-bond"

/** v1.0.0 */
#define GN_EXT_MULTIPATH_BOND_VERSION 0x00010000u

/**
 * @brief Fan-out strategy for a bonded peer.
 *
 * `GN_BOND_REDUNDANT` — every `float_send` call copies the payload on
 *   all live conns to the peer. The receiver must deduplicate by msg_id.
 *
 * `GN_BOND_MIN_LATENCY` — pick the single conn with the lowest smoothed
 *   RTT among live candidates, same as `gn.strategy.rtt-optimal` but
 *   applied per-peer inside the bond plugin.
 */
typedef enum gn_bond_strategy_e {
    GN_BOND_REDUNDANT    = 0,
    GN_BOND_MIN_LATENCY  = 1
} gn_bond_strategy_t;

/**
 * @brief Management vtable for `gn.float-send.multipath-bond`.
 *
 * Registered under `GN_EXT_MULTIPATH_BOND_API` by the bond plugin.
 * All slots take a `peer_pk` to allow per-peer configuration.
 */
typedef struct gn_multipath_bond_api_s {
    uint32_t api_size;

    /**
     * @brief Set the fan-out strategy for a peer.
     *
     * Takes effect on the next `float_send` call for @p peer_pk.
     * Default is `GN_BOND_REDUNDANT`.
     */
    gn_result_t (*set_strategy)(
        void* ctx,
        const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
        gn_bond_strategy_t strategy);

    /**
     * @brief Query the current strategy for a peer.
     *
     * @param out_strategy  written on GN_OK.
     */
    gn_result_t (*get_strategy)(
        void* ctx,
        const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
        gn_bond_strategy_t* out_strategy);

    void* ctx;
    void* _reserved[4];
} gn_multipath_bond_api_t;

GN_VTABLE_API_SIZE_FIRST(gn_multipath_bond_api_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_MULTIPATH_BOND_H */
