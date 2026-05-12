/**
 * @file   sdk/extensions/strategy.h
 * @brief  Extension vtable: `gn.strategy.*` — multi-path routing.
 *
 * Strategy plugins decide which connection an outbound message rides
 * when the kernel has multiple live conns to the same peer (TCP
 * fallback + UDP carrier + NAT-traversed ICE + QUIC stream, etc.).
 * The kernel calls `pick_conn` with a snapshot of all live conns to
 * a destination; the strategy returns the chosen `gn_conn_id_t`.
 *
 * One strategy plugin is active per node (operator config selects
 * which); multiple registrations conflict at plugin load time.
 * Future minors of this contract may add per-class strategies (one
 * per app priority band) — gate on `api_size` to detect.
 *
 * See `docs/architecture/strategies.ru.md` for the design rationale
 * and the `gn.float-send.*` family of strategies built on this
 * surface.
 */
#ifndef GOODNET_SDK_EXTENSIONS_STRATEGY_H
#define GOODNET_SDK_EXTENSIONS_STRATEGY_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Extension family identifier. Per-plugin names extend this prefix
 *  (e.g. `gn.strategy.rtt-optimal`). */
#define GN_EXT_STRATEGY_PREFIX  "gn.strategy."

/** v1.0.0 — initial release. */
#define GN_EXT_STRATEGY_VERSION 0x00010000u

/**
 * @brief Per-path lifecycle events delivered to the strategy.
 *
 * Strategies use these to update internal models (RTT EWMA, loss
 * smoothing, capability deltas) and may choose to reroute in-flight
 * traffic on receipt. The kernel coalesces frequent events into the
 * latest sample so a strategy that takes more than a few hundred
 * microseconds in `on_path_event` does not impose unbounded backlog.
 */
typedef enum gn_path_event_e {
    /** New conn opened to this peer; the strategy may immediately
     *  consider it for outbound routing. `sample.rtt_us` is zero
     *  (unknown) until the first RTT probe lands. */
    GN_PATH_EVENT_CONN_UP            = 1,
    /** Conn closed; the strategy must drop it from its candidate set
     *  and stop returning it from `pick_conn`. */
    GN_PATH_EVENT_CONN_DOWN          = 2,
    /** New RTT sample for an existing conn. */
    GN_PATH_EVENT_RTT_UPDATE         = 3,
    /** Packet-loss spike crossed the threshold tracked by the
     *  kernel's loss detector. `sample.loss_pct_x100` carries the
     *  smoothed loss percentage scaled by 100. */
    GN_PATH_EVENT_LOSS_DETECTED      = 4,
    /** Link plugin re-advertised its capabilities (rare — TLS
     *  handshake completion, QUIC ALPN negotiation, ICE nomination
     *  flip from host to relay, etc.). `sample.caps` carries the new
     *  cap bitmask. */
    GN_PATH_EVENT_CAPABILITY_REFRESH = 5
} gn_path_event_t;

/**
 * @brief Snapshot of one candidate connection passed to `pick_conn`
 *        or `on_path_event`.
 *
 * The kernel fills this struct fresh on every call from its current
 * accounting (RTT EWMA, loss detector, capability snapshot). The
 * strategy must NOT cache pointers to it past the call.
 */
typedef struct gn_path_sample_s {
    /** Connection id valid for the duration of this call. */
    gn_conn_id_t conn;
    /** Smoothed RTT in microseconds; 0 means "no sample yet". */
    uint64_t     rtt_us;
    /** Packet-loss percentage scaled by 100 — `1234` ≈ 12.34 %.
     *  Operators target the smoothed-loss value, not raw counts. */
    uint16_t     loss_pct_x100;
    /** Capability flags from the link plugin's `get_capabilities`. */
    uint32_t     caps;
    /** Padding for future growth without an ABI break. */
    uint16_t     _reserved_pad;
    uint32_t     _reserved[3];
} gn_path_sample_t;

/**
 * @brief Strategy extension vtable.
 *
 * Registered by strategy plugins under `gn.strategy.<plugin-name>`.
 * Begins with `api_size` for size-prefix evolution per
 * `abi-evolution.md` §3. Consumers (the kernel's dispatch path)
 * query the extension through `host_api->query_extension_checked`
 * which validates `api_size` against the consumer's compile-time
 * minimum before any slot fires.
 */
typedef struct gn_strategy_api_s {
    uint32_t api_size;          /**< sizeof(gn_strategy_api_t) at producer build time */

    /**
     * @brief Pick a connection from the candidate set.
     *
     * @param ctx              plugin's `self` pointer (mirrored in `ctx` below).
     * @param peer_pk          @borrowed; peer public key, GN_PUBLIC_KEY_BYTES bytes.
     * @param candidates       @borrowed; non-empty array of live conns.
     * @param candidate_count  length of @p candidates.
     * @param out_chosen       @borrowed caller-allocated; written on success.
     *
     * @return GN_OK and a conn id taken from @p candidates on success.
     *         GN_ERR_NULL_ARG if any pointer is NULL or count is 0.
     *         GN_ERR_NOT_FOUND if every candidate is currently
     *         unsuitable (kernel falls back to lowest-priority conn).
     */
    gn_result_t (*pick_conn)(
        void* ctx,
        const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
        const gn_path_sample_t* candidates,
        size_t candidate_count,
        gn_conn_id_t* out_chosen);

    /**
     * @brief React to a path-state event.
     *
     * Optional in the plugin class but the slot is always non-null in
     * the vtable — the C++ macro fills a no-op stub if the user class
     * does not implement it. Callers can therefore invoke
     * unconditionally without a slot-null check.
     *
     * @param sample @borrowed; nullable for `CONN_DOWN` (no live
     *               sample remains) and `CAPABILITY_REFRESH` (caps
     *               carried via the prior call's snapshot).
     */
    gn_result_t (*on_path_event)(
        void* ctx,
        const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
        gn_path_event_t ev,
        const gn_path_sample_t* sample);

    void* ctx;
    void* _reserved[4];
} gn_strategy_api_t;

GN_VTABLE_API_SIZE_FIRST(gn_strategy_api_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_STRATEGY_H */
