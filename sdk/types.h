/**
 * @file   sdk/types.h
 * @brief  Fundamental C ABI types for GoodNet plugins.
 *
 * The kernel and plugins communicate through this header. Anything wider
 * (transport, security, extensions) builds on top of these types.
 *
 * Stability: stable for v1.0.x. Field additions to gn_message_t require a
 * major ABI bump; @ref _reserved slots permit non-breaking minor evolution.
 */
#ifndef GOODNET_SDK_TYPES_H
#define GOODNET_SDK_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── ABI versioning ─────────────────────────────────────────────────────── */

#define GN_SDK_VERSION_MAJOR 1   /**< incompatible ABI changes */
#define GN_SDK_VERSION_MINOR 4   /**< additive (size-prefix-protected) */
#define GN_SDK_VERSION_PATCH 0   /**< documentation / non-binary fixes */

/* ── Identity sizing ────────────────────────────────────────────────────── */

#define GN_PUBLIC_KEY_BYTES   32  /**< Ed25519 public key */
#define GN_PRIVATE_KEY_BYTES  64  /**< Ed25519 secret key (libsodium layout) */

/* ── Identifier typedefs ────────────────────────────────────────────────── */

/** Stable per-connection handle. Allocated only by the kernel. */
typedef uint64_t gn_conn_id_t;

/** Opaque per-handler-registration handle. Returned by register_handler. */
typedef uint64_t gn_handler_id_t;

/** Opaque per-transport-registration handle. Returned by register_transport. */
typedef uint64_t gn_transport_id_t;

/** Opaque service-executor timer handle. Returned by set_timer. */
typedef uint64_t gn_timer_id_t;

/** Sentinel value indicating an unset / invalid id. */
#define GN_INVALID_ID ((uint64_t)0)

/** Sentinel value indicating an unset / invalid timer id. Aliases
 *  `GN_INVALID_ID` for source-level convenience.
 */
#define GN_INVALID_TIMER_ID ((gn_timer_id_t)0)

/** Service-executor task callback. Runs on the kernel's
 *  single-thread service executor (timer.md §3); `user_data` is
 *  passed back unchanged. */
typedef void (*gn_task_fn_t)(void* user_data);

/* ── Diagnostics enums ──────────────────────────────────────────────────── */

/** Severity levels for the host-API logging entry. */
typedef enum gn_log_level_e {
    GN_LOG_TRACE = 0,
    GN_LOG_DEBUG = 1,
    GN_LOG_INFO  = 2,
    GN_LOG_WARN  = 3,
    GN_LOG_ERROR = 4,
    GN_LOG_FATAL = 5
} gn_log_level_t;

/**
 * @brief Reasons for dropping a frame at any kernel chokepoint.
 *
 * One metric counter exists per value. New reasons may be appended in minor
 * releases; consumers default-handle unknown values rather than enumerate.
 */
typedef enum gn_drop_reason_e {
    GN_DROP_NONE                  = 0,

    GN_DROP_FRAME_TOO_LARGE       = 1,  /**< exceeds max_frame_bytes */
    GN_DROP_PAYLOAD_TOO_LARGE     = 2,  /**< exceeds max_payload_bytes */
    GN_DROP_QUEUE_HARD_CAP        = 3,  /**< per-conn pending queue full */
    GN_DROP_RESERVED_BIT_SET      = 4,  /**< unknown reserved flag in frame */
    GN_DROP_DEFRAME_CORRUPT       = 5,  /**< plugin signalled corruption */
    GN_DROP_ZERO_SENDER           = 6,  /**< envelope sender_pk all zero */
    GN_DROP_UNKNOWN_RECEIVER      = 7,  /**< no local identity matches receiver_pk */
    GN_DROP_RELAY_TTL_EXCEEDED    = 8,
    GN_DROP_RELAY_LOOP_DEDUP      = 9,
    GN_DROP_RATE_LIMITED          = 10,
    GN_DROP_TRUST_CLASS_MISMATCH  = 11
} gn_drop_reason_t;

/**
 * @brief Backpressure signal returned to senders when the queue is loaded.
 *
 * Returned by `host_api->send` and friends. Plugins must branch on the value;
 * ignoring `GN_BP_HARD_LIMIT` and tight-looping on send is a contract
 * violation.
 */
typedef enum gn_backpressure_e {
    GN_BP_OK            = 0,  /**< accepted, no pressure */
    GN_BP_SOFT_LIMIT    = 1,  /**< past low watermark — sender should slow down */
    GN_BP_HARD_LIMIT    = 2,  /**< dropped — back off, do not retry tight */
    GN_BP_DISCONNECT    = 3   /**< connection gone — caller should stop */
} gn_backpressure_t;

/**
 * @brief Policy returned from `IHandler::on_result` to influence dispatch.
 */
typedef enum gn_on_result_policy_e {
    GN_ORP_CONTINUE_CHAIN = 0, /**< default: dispatch continues per `Propagation` */
    GN_ORP_STOP_CHAIN     = 1  /**< stop the chain regardless of `Propagation` */
} gn_on_result_policy_t;

/* ── Result codes ───────────────────────────────────────────────────────── */

/**
 * @brief Result codes returned by C ABI entry points.
 *
 * Zero is success; negative values indicate failure. New codes may be added
 * in minor releases — consumers must default-handle unknown values rather
 * than enumerate.
 */
typedef enum gn_result_e {
    GN_OK                     =  0,

    GN_ERR_NULL_ARG           = -1,  /**< caller passed NULL where required */
    GN_ERR_OUT_OF_MEMORY      = -2,
    GN_ERR_INVALID_ENVELOPE   = -3,  /**< sender_pk == ZERO, msg_id == 0, _reserved non-zero */
    GN_ERR_UNKNOWN_RECEIVER   = -4,  /**< receiver_pk not in local_identities, no relay loaded */
    GN_ERR_PAYLOAD_TOO_LARGE  = -5,  /**< payload_size > plugin.max_payload_size() */
    GN_ERR_DEFRAME_INCOMPLETE = -6,  /**< partial frame — kernel buffers and retries */
    GN_ERR_DEFRAME_CORRUPT    = -7,  /**< magic mismatch / bad version / overflow */
    GN_ERR_NOT_IMPLEMENTED    = -8,
    GN_ERR_VERSION_MISMATCH   = -9,  /**< plugin SDK major != kernel SDK major */
    GN_ERR_LIMIT_REACHED      = -10
} gn_result_t;

/* ── Kernel↔plugin envelope ─────────────────────────────────────────────── */

/**
 * @brief Kernel↔plugin message envelope.
 *
 * Produced by `IProtocolLayer::deframe` on inbound and consumed by
 * `IProtocolLayer::frame` on outbound. Routed by the kernel using
 * `(receiver_pk, msg_id)`. See `docs/contracts/protocol-layer.md` for full
 * semantics.
 *
 * @par Lifetime
 * `payload` is *borrowed* for the duration of the synchronous handler
 * dispatch. Handlers that need to retain the bytes past return — the
 * cross-thread or async-pipeline case — copy them into a buffer they
 * own before yielding. The kernel never extends `payload`'s
 * lifetime past the dispatch return.
 *
 * @par Identity sourcing
 * Plugins populate the public-key fields from either the connection context
 * (direct, mesh-native) or the wire (relay, broadcast). The kernel never
 * synthesises identities itself.
 */
typedef struct gn_message_s {
    uint8_t        sender_pk[GN_PUBLIC_KEY_BYTES];   /**< Ed25519, end-to-end identity */
    uint8_t        receiver_pk[GN_PUBLIC_KEY_BYTES]; /**< ZERO bytes ⇒ broadcast */
    uint32_t       msg_id;                           /**< per-protocol routing key */
    const uint8_t* payload;                          /**< borrowed; opaque application bytes */
    size_t         payload_size;
    void*          _reserved[4];                     /**< must be NULL on init */
} gn_message_t;

/**
 * @brief Returns 1 if `pk` is the all-zero broadcast marker, 0 otherwise.
 *
 * The check folds bits with OR rather than memcmp — short-circuit-free.
 * Hot paths that need constant-time semantics should use
 * `sodium_is_zero(pk, GN_PUBLIC_KEY_BYTES)` instead.
 */
static inline int gn_pk_is_zero(const uint8_t pk[GN_PUBLIC_KEY_BYTES]) {
    uint8_t acc = 0;
    for (size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) acc |= pk[i];
    return acc == 0;
}

/* ── Build-time invariants ──────────────────────────────────────────────── */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(GN_PUBLIC_KEY_BYTES == 32,
               "Ed25519 public key is 32 bytes");
_Static_assert(sizeof(((gn_message_t*)0)->_reserved) == 4 * sizeof(void*),
               "envelope reserved slots must be sized for ABI evolution");
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_TYPES_H */
