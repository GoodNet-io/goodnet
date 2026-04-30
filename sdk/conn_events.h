/**
 * @file   sdk/conn_events.h
 * @brief  Connection-event publish/subscribe contract.
 *
 * The kernel publishes a typed event for every observable change in
 * a connection's lifecycle. See `docs/contracts/conn-events.md` for
 * the authoritative semantics; this header is the C ABI surface.
 */
#ifndef GOODNET_SDK_CONN_EVENTS_H
#define GOODNET_SDK_CONN_EVENTS_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/trust.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Event categories surfaced through `subscribe_conn_state`. */
typedef enum gn_conn_event_kind_e {
    GN_CONN_EVENT_CONNECTED          = 1, /**< notify_connect just fired */
    GN_CONN_EVENT_DISCONNECTED       = 2, /**< notify_disconnect just fired */
    GN_CONN_EVENT_TRUST_UPGRADED     = 3, /**< Untrusted → Peer */
    GN_CONN_EVENT_BACKPRESSURE_SOFT  = 4, /**< pending_queue crossed *_high */
    GN_CONN_EVENT_BACKPRESSURE_CLEAR = 5, /**< pending_queue dropped below *_low */
} gn_conn_event_kind_t;

/**
 * @brief One connection event payload.
 *
 * Begins with @ref api_size for size-prefix evolution per
 * `abi-evolution.md` §3. New fields land before `_reserved`.
 */
typedef struct gn_conn_event_s {
    uint32_t              api_size;       /**< sizeof(gn_conn_event_t) */
    gn_conn_event_kind_t  kind;
    gn_conn_id_t          conn;
    gn_trust_class_t      trust;          /**< current trust at the event */
    uint8_t               remote_pk[GN_PUBLIC_KEY_BYTES];
    uint64_t              pending_bytes;  /**< populated for BACKPRESSURE_*; 0 otherwise */
    void*                 _reserved[4];
} gn_conn_event_t;

/** Subscription handle returned from `subscribe_conn_state`. */
typedef uint64_t gn_subscription_id_t;

/** Sentinel value indicating an unset / invalid subscription id. */
#define GN_INVALID_SUBSCRIPTION_ID ((gn_subscription_id_t)0)

/**
 * @brief Subscriber callback. Runs on the publishing thread per
 *        `conn-events.md` §3; the event pointer is `@borrowed`
 *        for the duration of the call.
 */
typedef void (*gn_conn_event_cb_t)(void* user_data,
                                    const gn_conn_event_t* event);

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
