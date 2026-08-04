/**
 * @file    sdk/extensions/ice.h
 * @brief   Public ICE extension surface — config and signaling vtable.
 *
 * Two independent contracts live here:
 *
 *   1. `gn_ice_config_t` — operator-supplied STUN/TURN parameters.
 *      Passed to `IceLink::set_config()` before `composer_listen`
 *      to override built-in defaults without rebuilding the plugin.
 *      ABI-stable via `api_size` guard (abi-evolution.en.md §3).
 *
 *   2. `gn_link_ice_signal_api_t` — out-of-band ICE signaling vtable.
 *      Registered by IceLink under `"gn.link.ice.signal"`. Handler
 *      plugins that own the signaling channel (heartbeat, future
 *      rendezvous service) call `offer`/`answer` through this vtable
 *      to feed candidate blobs into the ICE FSM.
 *      Version constant: `GN_EXT_ICE_SIGNAL_VERSION`.
 *
 * Both types are pure C so this header can be included from C plugins.
 */

#ifndef GOODNET_SDK_EXTENSIONS_ICE_H
#define GOODNET_SDK_EXTENSIONS_ICE_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── ICE configuration ─────────────────────────────────────────────────── */

/**
 * @brief Operator-supplied ICE configuration.
 *
 * ABI rule: `api_size` MUST be set to `sizeof(gn_ice_config_t)` by the
 * caller.  IceLink guards each field read with an offset check so older
 * callers that allocated a smaller struct still work.
 *
 * String pointer fields are **borrowed**: the caller keeps the buffers
 * alive until after `set_config()` returns; IceLink copies the strings.
 * NULL for any field means "use built-in default".
 */
typedef struct gn_ice_config_s {
    /** sizeof(gn_ice_config_t) at the caller's build time. */
    uint32_t    api_size;

    /** Primary STUN server URL, e.g. "stun:stun.l.google.com:19302".
     *  NULL → built-in default. */
    const char* stun_server;

    /** TURN relay server hostname or IP.  NULL → TURN disabled. */
    const char* turn_server;
    /** TURN server port.  0 → default 3478. */
    uint16_t    turn_port;
    uint8_t     _pad[2];

    /** TURN long-term credentials.  NULL → TURN auth disabled. */
    const char* turn_username;
    const char* turn_password;

    /** ICE session timeout in seconds.  0 → default (10 s). */
    int32_t     session_timeout_s;
    /** STUN keepalive interval in seconds.  0 → default (20 s). */
    int32_t     keepalive_interval_s;
    /** Connectivity-check interval in milliseconds.  0 → default (50 ms). */
    int32_t     check_interval_ms;

    /** 0 = regular nomination (RFC 8445 default), 1 = aggressive. */
    uint8_t     aggressive_nomination;
    uint8_t     _reserved[3];
} gn_ice_config_t;

/* ── ICE signaling extension ───────────────────────────────────────────── */

/** Extension version for `"gn.link.ice.signal"`. */
#define GN_EXT_ICE_SIGNAL_VERSION UINT32_C(0x00020000)

/**
 * @brief ICE signaling vtable — registered under `"gn.link.ice.signal"`.
 *
 * Handler plugins that own the out-of-band signaling channel call
 * `offer`/`answer` through this vtable to feed serialised candidate
 * blobs into the ICE plugin's FSM.
 *
 * @note `peer_pk` is always `GN_PUBLIC_KEY_BYTES` bytes.
 */
typedef struct gn_link_ice_signal_api_s {
    uint32_t api_size;

    /** Deliver a remote offer (peer is ICE controller).
     *  Allocates a new IceSession in responder role. */
    gn_result_t (*offer)(void*               ctx,
                         const uint8_t       peer_pk[GN_PUBLIC_KEY_BYTES],
                         const uint8_t*      blob,
                         size_t              blob_size);

    /** Deliver a remote answer (we are ICE controller).
     *  Feeds the candidate set into the in-flight session. */
    gn_result_t (*answer)(void*               ctx,
                          const uint8_t       peer_pk[GN_PUBLIC_KEY_BYTES],
                          const uint8_t*      blob,
                          size_t              blob_size);

    /** RFC 8838 §10 trickle end-of-candidates for an offer. */
    gn_result_t (*offer_eoc)(void*             ctx,
                              const uint8_t    peer_pk[GN_PUBLIC_KEY_BYTES],
                              const uint8_t*   blob,
                              size_t           blob_size);

    /** RFC 8838 §10 trickle end-of-candidates for an answer. */
    gn_result_t (*answer_eoc)(void*            ctx,
                               const uint8_t   peer_pk[GN_PUBLIC_KEY_BYTES],
                               const uint8_t*  blob,
                               size_t          blob_size);

    /** Drain one pending outbound signal blob for the given peer.
     *  Returns GN_OK + fills kind_out/blob_out/blob_len_out when a
     *  blob is available. Returns GN_ERR_NOT_FOUND when the queue is
     *  empty. `kind_out`: 0=offer 1=answer 2=offer_eoc 3=answer_eoc. */
    gn_result_t (*poll_local)(void*            ctx,
                               const uint8_t   peer_pk[GN_PUBLIC_KEY_BYTES],
                               uint32_t*       kind_out,
                               uint8_t*        blob_out,
                               size_t          blob_cap,
                               size_t*         blob_len_out);

    void* ctx;
    void* _reserved[2];
} gn_link_ice_signal_api_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_ICE_H */
