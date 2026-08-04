/**
 * @file   sdk/conn_events.h
 * @brief  Connection-event publish/subscribe contract.
 *
 * The kernel publishes a typed event for every observable change in
 * a connection's lifecycle. See `docs/contracts/conn-events.en.md` for
 * the authoritative semantics; this header is the C ABI surface.
 */
#ifndef GOODNET_SDK_CONN_EVENTS_H
#define GOODNET_SDK_CONN_EVENTS_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/topology.h>
#include <sdk/trust.h>
#include <sdk/types.h>

/* Forward declaration — full definition in sdk/topology.h (already included above). */
struct gn_topology_s;

#ifdef __cplusplus
extern "C" {
#endif

/** Event categories surfaced through `subscribe(GN_SUBSCRIBE_CONN_STATE)`. */
typedef enum gn_conn_event_kind_e {
    GN_CONN_EVENT_CONNECTED          = 1, /**< notify_connect just fired */
    GN_CONN_EVENT_DISCONNECTED       = 2, /**< notify_disconnect just fired */
    GN_CONN_EVENT_TRUST_UPGRADED     = 3, /**< Untrusted → Peer */
    GN_CONN_EVENT_BACKPRESSURE_SOFT  = 4, /**< pending_queue crossed *_high */
    GN_CONN_EVENT_BACKPRESSURE_CLEAR = 5, /**< pending_queue dropped below *_low */
    /** Peer announced a user_pk rotation (`identity.en.md` §7).
     *  The pinned `user_pk` for `remote_pk` advanced to a new value;
     *  subscribers update their connectivity-graph edges without
     *  disconnecting the live transport.
     *  See `gn_conn_event_t::user_pk_prev`, `user_pk_next`,
     *  `rotation_seq` for the accompanying payload. */
    GN_CONN_EVENT_IDENTITY_ROTATED   = 6,
    /** Peer's topology fingerprint (TLV 0x0004) does not match the
     *  local fingerprint after a topology reload or on first
     *  capability-blob exchange. The connection remains open; the
     *  kernel sets `peer_caps_verified = false` and fires this event
     *  so the embedding application can decide to disconnect or
     *  tolerate the mismatch. `gn_conn_event_t::peer_fingerprint`
     *  carries the 32-byte peer fingerprint (@borrowed for the
     *  callback duration).
     *  See `docs/contracts/topology-reload.en.md` §3. */
    GN_CONN_EVENT_TOPOLOGY_MISMATCH  = 7,
    /** Security provider unregistered — all contours keyed to it are now BROKEN.
     *  `contour_provider_id` names the provider; `contour_trust_mask` is the bitmask
     *  of affected GN_TRUST_* classes. `conn` is GN_INVALID_ID (contour-level event). */
    GN_CONN_EVENT_CONTOUR_BROKEN   = 8,
    /** Provider re-registered or topology reloaded — affected contours are LIVE or PARTIAL.
     *  Same payload shape as CONTOUR_BROKEN. `contour_state` carries the new state. */
    GN_CONN_EVENT_CONTOUR_LIVE     = 9,
    /** Peer's contour fingerprint (TLV 0x0005) does not match the local contour fingerprint.
     *  `peer_fingerprint` carries the 32-byte peer value (borrowed). `conn` is the connection. */
    GN_CONN_EVENT_CONTOUR_MISMATCH = 10
} gn_conn_event_kind_t;

/**
 * @brief One connection event payload.
 *
 * Begins with `api_size` for size-prefix evolution per
 * `abi-evolution.en.md` §3. New fields land before `_reserved`.
 */
typedef struct gn_conn_event_s {
    uint32_t              api_size;       /**< sizeof(gn_conn_event_t) */
    gn_conn_event_kind_t  kind;
    gn_conn_id_t          conn;
    gn_trust_class_t      trust;          /**< current trust at the event */
    uint8_t               remote_pk[GN_PUBLIC_KEY_BYTES];
    uint64_t              pending_bytes;  /**< populated for BACKPRESSURE_*; 0 otherwise */
    /** @name IDENTITY_ROTATED payload — borrowed for the callback duration;
     *  NULL for all other event kinds. */
    /**@{*/
    const uint8_t*        user_pk_prev;     /**< previous user public key (GN_PUBLIC_KEY_BYTES) */
    const uint8_t*        user_pk_next;     /**< new user public key (GN_PUBLIC_KEY_BYTES) */
    const uint64_t*       rotation_seq;     /**< monotone rotation counter */
    /**@}*/
    /** @name TOPOLOGY_MISMATCH payload — borrowed for the callback duration;
     *  NULL for all other event kinds. */
    /**@{*/
    const uint8_t*        peer_fingerprint; /**< 32-byte peer topology SHA-256; NULL otherwise */
    /**@}*/
    /** @name CONTOUR_BROKEN / CONTOUR_LIVE payload — borrowed for callback duration;
     *  NULL / 0 for all other event kinds. */
    /**@{*/
    const char*        contour_provider_id; /**< provider_id string */
    uint32_t           contour_trust_mask;  /**< bitmask of affected GN_TRUST_* */
    gn_contour_state_t contour_state;       /**< new runtime state */
    uint32_t           _pad_contour;        /**< alignment; MUST be zero */
    /**@}*/
    void*                 _reserved[4];     /**< ABI evolution; MUST be zero */
} gn_conn_event_t;

/** Subscription handle returned from `host_api->subscribe`. */
typedef uint64_t gn_subscription_id_t;

/** Sentinel value indicating an unset / invalid subscription id. */
#define GN_INVALID_SUBSCRIPTION_ID ((gn_subscription_id_t)0)

/**
 * @brief Channel selector for `host_api->subscribe`.
 *
 * `CONN_STATE` delivers `gn_conn_event_t` payloads;
 * `CONFIG_RELOAD` fires after every successful `Kernel::reload_config`
 * with a NULL payload.
 */
typedef enum gn_subscribe_channel_e {
    GN_SUBSCRIBE_CONN_STATE       = 0,
    GN_SUBSCRIBE_CONFIG_RELOAD    = 1,
    /* 2 is reserved for the internal capability-blob channel. */
    GN_SUBSCRIBE_TOPOLOGY_RELOAD  = 3
} gn_subscribe_channel_t;

/**
 * @brief Per-channel typed subscriber callbacks.
 *
 * Each kernel pub/sub channel publishes through its own typed
 * callback. The split mirrors the host-side `gn_message_cb_t` /
 * `gn_conn_event_cb_t` split in `sdk/core.h` — a binding writes
 * one strongly-typed signature per channel rather than casting
 * `(const void*, size_t)` to the right shape at every call site.
 *
 * Both run on the publishing thread per `conn-events.en.md` §3 /
 * `config.en.md` §2; the payload borrows for the duration of the
 * call.
 */
typedef void (*gn_conn_state_cb_t)(void* user_data,
                                    const gn_conn_event_t* ev);

typedef void (*gn_config_reload_cb_t)(void* user_data);

/**
 * @brief Callback fired after every `gn_core_reload_topology()`.
 *
 * @param prev  Previous topology snapshot; NULL on the first reload.
 *              Borrowed for the callback duration — MUST NOT be stored.
 * @param next  Freshly built snapshot. Never NULL. Same lifetime rule.
 */
typedef void (*gn_topology_reload_cb_t)(void* user_data,
                                         const struct gn_topology_s* prev,
                                         const struct gn_topology_s* next);

/**
 * @brief Iteration visitor for `for_each_connection`. Returns 0 to
 *        continue, non-zero to stop. `uri` is `@borrowed` for the
 *        duration of the call.
 */
typedef int (*gn_conn_visitor_t)(void* user_data,
                                  gn_conn_id_t conn,
                                  gn_trust_class_t trust,
                                  const uint8_t remote_pk[GN_PUBLIC_KEY_BYTES],
                                  const char* uri);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_CONN_EVENTS_H */
