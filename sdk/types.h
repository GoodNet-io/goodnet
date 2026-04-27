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
#define GN_SDK_VERSION_MINOR 0   /**< additive (size-prefix-protected) */
#define GN_SDK_VERSION_PATCH 0   /**< documentation / non-binary fixes */

/* ── Identity sizing ────────────────────────────────────────────────────── */

#define GN_PUBLIC_KEY_BYTES   32  /**< Ed25519 public key */
#define GN_PRIVATE_KEY_BYTES  64  /**< Ed25519 secret key (libsodium layout) */

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
 * dispatch. Cross-thread retention requires copying via @ref gn_message_dup
 * (not implemented in this skeleton).
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
