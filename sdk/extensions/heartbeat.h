/**
 * @file   sdk/extensions/heartbeat.h
 * @brief  Extension vtable: `gn.heartbeat` — RTT and STUN-on-the-wire.
 *
 * The heartbeat handler exchanges PING/PONG envelopes on a known
 * `msg_id` and exports two pieces of information through this
 * extension: the round-trip-time of the most recent PONG, and the
 * peer's view of the local node's external endpoint reflected back in
 * the PONG payload (STUN-on-the-wire — no separate STUN server).
 */
#ifndef GOODNET_SDK_EXTENSIONS_HEARTBEAT_H
#define GOODNET_SDK_EXTENSIONS_HEARTBEAT_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Stable extension identifier. Unchanged across minor releases. */
#define GN_EXT_HEARTBEAT          "gn.heartbeat"

/** v1.0.0 — initial release. */
#define GN_EXT_HEARTBEAT_VERSION  0x00010000u

/**
 * @brief Aggregate RTT statistics across every live peer.
 */
typedef struct gn_heartbeat_stats_s {
    uint32_t peer_count;   /**< number of peers with at least one PONG observed */
    uint32_t avg_rtt_us;   /**< arithmetic mean of last-PONG RTTs across peers */
    uint32_t min_rtt_us;   /**< minimum observed last-PONG RTT */
    uint32_t max_rtt_us;   /**< maximum observed last-PONG RTT */
} gn_heartbeat_stats_t;

/**
 * @brief Vtable surfaced as the `gn.heartbeat` extension.
 *
 * The `ctx` field is the handler's `self` pointer; every entry takes
 * it as its first argument. Versioned with @ref GN_EXT_HEARTBEAT_VERSION.
 */
typedef struct gn_heartbeat_api_s {
    /**
     * @brief Snapshot the aggregate stats. Returns 0 on success, -1
     *        when @p out is NULL.
     */
    int (*get_stats)(void* ctx, gn_heartbeat_stats_t* out);

    /**
     * @brief Latest single-PONG RTT recorded for @p conn, in microseconds.
     *
     * Returns 0 on success, -1 if the connection is unknown or no PONG
     * has yet been observed. The output is the value carried by the
     * most recent PONG arrival.
     */
    int (*get_rtt)(void* ctx, gn_conn_id_t conn, uint64_t* out_rtt_us);

    /**
     * @brief Latest external address the peer reported back in its
     *        PONG payload.
     *
     * @p buf is filled with a NUL-terminated address string (IP literal
     * or hostname) up to @p buf_len bytes; @p port_out receives the
     * matching port. Returns 0 on success, -1 if the connection is
     * unknown, no PONG has yet been observed, or @p buf_len is too
     * small to hold the address (in that case @p buf is left
     * NUL-terminated at the truncation boundary).
     */
    int (*get_observed_address)(void* ctx, gn_conn_id_t conn,
                                 char* buf, size_t buf_len,
                                 uint16_t* port_out);

    void* ctx;
    void* _reserved[4];
} gn_heartbeat_api_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_HEARTBEAT_H */
