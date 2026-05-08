/**
 * @file   sdk/limits.h
 * @brief  Resource bounds shared by the kernel and every plugin.
 *
 * Every code path that enforces a resource ceiling reads the live
 * `gn_limits_t` reference exposed through `host_api->limits()`. Hard-coded
 * parallel ceilings are forbidden. See `docs/contracts/limits.en.md`.
 */
#ifndef GOODNET_SDK_LIMITS_H
#define GOODNET_SDK_LIMITS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Resource bounds loaded once at startup, read-only thereafter.
 *
 * Loaded from `Config::limits` before the kernel reaches the `Wire` phase.
 * Most fields determine at-startup allocations; runtime reload is not
 * supported in v1.x — operators restart the kernel to change limits.
 */
typedef struct gn_limits_s {
    /* Connections */
    uint32_t max_connections;            /**< total inbound + outbound */
    uint32_t max_outbound_connections;   /**< subset of @ref max_connections */

    /* Per-connection send queue (bytes) */
    uint32_t pending_queue_bytes_high;   /**< backpressure trigger */
    uint32_t pending_queue_bytes_low;    /**< backpressure release */
    uint32_t pending_queue_bytes_hard;   /**< disconnect threshold */

    /* Framing */
    uint32_t max_payload_bytes;          /**< per-message payload ceiling */
    uint32_t max_frame_bytes;            /**< wire-frame ceiling, header+payload */

    /* Handler bounds */
    uint32_t max_handlers_per_msg_id;    /**< dispatch chain length */
    uint32_t max_relay_ttl;              /**< forwarded message hop count */

    /* Plugin bounds */
    uint32_t max_plugins;                /**< dlopen ceiling */
    uint32_t max_extensions;             /**< extension registry size */

    /* Service executor (timer.md §6) */
    uint32_t max_timers;                 /**< active one-shot timers */
    uint32_t max_pending_tasks;          /**< queued service-executor tasks (set_timer fire-and-forget) */
    uint32_t max_timers_per_plugin;      /**< per-anchor timer cap; 0 = no
                                              per-plugin sub-quota, only the
                                              global `max_timers` ceiling
                                              applies. Closes the DoS where a
                                              single misbehaving plugin
                                              exhausts the kernel's global
                                              budget and starves siblings. */

    /* Foreign-payload injection rate limiter (host-api.md §8) */
    uint32_t inject_rate_per_source;     /**< token-bucket refill rate per
                                              source — tokens per second
                                              accrued for the bridge plugin's
                                              `inject(LAYER_MESSAGE)` /
                                              `inject(LAYER_FRAME)` calls
                                              keyed on the source
                                              connection's remote_pk hash */
    uint32_t inject_rate_burst;          /**< token-bucket initial / max
                                              tokens; the rate-limiter accepts
                                              up to this many calls before the
                                              refill rate kicks in */
    uint32_t inject_rate_lru_cap;        /**< maximum number of distinct
                                              source-pk buckets the kernel
                                              tracks; the LRU evicts the
                                              least-recently-used bucket on
                                              cap, so unbounded source-id
                                              growth cannot exhaust memory */

    /* Handshake-phase send buffer (backpressure.md §8) */
    uint32_t pending_handshake_bytes;    /**< per-conn cap on app data
                                              buffered while the security
                                              session is in Handshake phase */

    /* Storage */
    uint64_t max_storage_table_entries;
    uint64_t max_storage_value_bytes;

    /* Metrics cardinality (`metrics.md` §3.1).
     *
     * Hard cap on the number of distinct counter names a single
     * `MetricsRegistry` will hold. The slow path of `increment`
     * rejects new names past this cap and bumps
     * `metrics.cardinality_rejected` so the operator can spot the
     * cliff — the alternative (LRU eviction) silently loses
     * established counters and produces missing-data spikes on
     * every Prometheus scrape. Default 8192 = built-in counters
     * + ~7 plugins × ~50 names + headroom; matches the per-target
     * scrape budget Prometheus's default config tolerates.
     *
     * Slot promoted out of `_reserved[]` per `abi-evolution.md`
     * §4 — the slot count drops by one to keep MINOR-compat
     * bytes-precise. */
    uint32_t max_counter_names;

    /* Per-channel subscription cap (`conn-events.md` §3).
     *
     * Hard cap on the number of live subscriptions a single
     * `SignalChannel` (`GN_SUBSCRIBE_CONN_STATE`,
     * `GN_SUBSCRIBE_CONFIG_RELOAD`) will hold. A `subscribe`
     * call past this cap returns `GN_ERR_LIMIT_REACHED`. The
     * cap is per-channel rather than per-kernel because the two
     * channels carry independent payloads — saturating one with
     * ConnState subscribers must not exhaust the slots the
     * config-reload channel needs. Default 256 matches the
     * extension-registry default and supports the documented
     * pattern of one subscription per plugin instance.
     *
     * Slot promoted out of `_reserved[]` per `abi-evolution.md`
     * §4 — same MINOR-compat shape as `max_counter_names`. */
    uint32_t max_subscriptions;

    /** Hard cap on a capability-blob payload (`identity.en.md` §8).
     * Sender-side `present_capability_blob` rejects with
     * `GN_ERR_PAYLOAD_TOO_LARGE` when set and the blob exceeds the
     * cap; 0 disables the gate. Default 16 KiB. */
    uint32_t max_capability_blob_bytes;

    /* MUST be zero. Slot count `5` (uint32_t) follows the
     * operator-tunable family per `abi-evolution.md` §4 — limits
     * accumulate faster than vtable slots over the platform's
     * lifetime, and the wider tail keeps a MAJOR bump off this
     * surface. */
    uint32_t _reserved[5];
} gn_limits_t;

/* ── Default values ──────────────────────────────────────────────────────── */

#define GN_LIMITS_DEFAULT_MAX_CONNECTIONS              4096u
#define GN_LIMITS_DEFAULT_MAX_OUTBOUND_CONNECTIONS     1024u
#define GN_LIMITS_DEFAULT_PENDING_QUEUE_BYTES_HIGH     (1u  << 20)   /*  1 MiB */
#define GN_LIMITS_DEFAULT_PENDING_QUEUE_BYTES_LOW      (256u << 10)  /* 256 KiB */
#define GN_LIMITS_DEFAULT_PENDING_QUEUE_BYTES_HARD     (4u  << 20)   /*  4 MiB */
#define GN_LIMITS_DEFAULT_MAX_FRAME_BYTES              (64u << 10)   /* 64 KiB */
#define GN_LIMITS_DEFAULT_MAX_HANDLERS_PER_MSG_ID      8u
#define GN_LIMITS_DEFAULT_MAX_RELAY_TTL                4u
#define GN_LIMITS_DEFAULT_MAX_PLUGINS                  64u
#define GN_LIMITS_DEFAULT_MAX_EXTENSIONS               256u
#define GN_LIMITS_DEFAULT_MAX_STORAGE_TABLE_ENTRIES    10000ull
#define GN_LIMITS_DEFAULT_MAX_RELAY_TTL_CEIL           8u
#define GN_LIMITS_DEFAULT_MAX_TIMERS                   4096u
#define GN_LIMITS_DEFAULT_MAX_PENDING_TASKS            4096u
#define GN_LIMITS_DEFAULT_PENDING_HANDSHAKE_BYTES      (256u << 10) /* 256 KiB */
#define GN_LIMITS_DEFAULT_INJECT_RATE_PER_SOURCE       100u
#define GN_LIMITS_DEFAULT_INJECT_RATE_BURST            50u
#define GN_LIMITS_DEFAULT_INJECT_RATE_LRU_CAP          4096u
#define GN_LIMITS_DEFAULT_MAX_COUNTER_NAMES            8192u
#define GN_LIMITS_DEFAULT_MAX_SUBSCRIPTIONS            256u
#define GN_LIMITS_DEFAULT_MAX_CAPABILITY_BLOB_BYTES    (16u << 10)  /* 16 KiB */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_LIMITS_H */
