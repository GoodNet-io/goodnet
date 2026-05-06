/**
 * @file   sdk/types.h
 * @brief  Fundamental C ABI types for GoodNet plugins.
 *
 * The kernel and plugins communicate through this header. Anything wider
 * (link, security, extensions) builds on top of these types.
 *
 * Stability: stable for v1.0.x. Field additions to gn_message_t require a
 * major ABI bump; `_reserved` slots permit non-breaking minor evolution.
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

/* ── Identifier typedefs ────────────────────────────────────────────────── */

/** Stable per-connection handle. Allocated only by the kernel. */
typedef uint64_t gn_conn_id_t;

/** Opaque per-handler-registration handle. Returned by register_handler. */
typedef uint64_t gn_handler_id_t;

/** Opaque per-link-registration handle. Returned by register_link. */
typedef uint64_t gn_link_id_t;

/** Opaque service-executor timer handle. Returned by set_timer. */
typedef uint64_t gn_timer_id_t;

/** Sentinel value indicating an unset / invalid id. */
#define GN_INVALID_ID ((uint64_t)0)

/** Sentinels indicating an unset / invalid id. All four alias
 *  `GN_INVALID_ID` and exist purely for source-level type-tagged
 *  convenience — call sites read `auto t = GN_INVALID_TIMER_ID;`
 *  rather than `auto t = (gn_timer_id_t)GN_INVALID_ID;`.
 */
#define GN_INVALID_HANDLER_ID ((gn_handler_id_t)0)
#define GN_INVALID_LINK_ID    ((gn_link_id_t)0)
#define GN_INVALID_TIMER_ID   ((gn_timer_id_t)0)

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

    GN_DROP_FRAME_TOO_LARGE                 = 1,  /**< exceeds max_frame_bytes */
    GN_DROP_PAYLOAD_TOO_LARGE               = 2,  /**< exceeds max_payload_bytes */
    GN_DROP_QUEUE_HARD_CAP                  = 3,  /**< per-conn pending queue full */
    GN_DROP_RESERVED_BIT_SET                = 4,  /**< unknown reserved flag in frame */
    GN_DROP_DEFRAME_CORRUPT                 = 5,  /**< plugin signalled corruption */
    GN_DROP_ZERO_SENDER                     = 6,  /**< envelope sender_pk all zero */
    GN_DROP_UNKNOWN_RECEIVER                = 7,  /**< no local identity matches receiver_pk */
    GN_DROP_RELAY_TTL_EXCEEDED              = 8,
    GN_DROP_RELAY_LOOP_DEDUP                = 9,
    GN_DROP_RATE_LIMITED                    = 10,
    GN_DROP_TRUST_CLASS_MISMATCH            = 11,

    /**
     * @name Attestation dispatcher (`attestation.md` §5)
     * Per-step rejection reasons emitted by the kernel-internal
     * attestation flow. The connection is closed on each.
     * @{
     */
    GN_DROP_ATTESTATION_BAD_SIZE            = 12, /**< payload size != 232 (§5 step 1) */
    GN_DROP_ATTESTATION_REPLAY              = 13, /**< binding != session handshake_hash (§5 step 3) */
    GN_DROP_ATTESTATION_PARSE_FAILED        = 14, /**< 136-byte cert did not parse (§5 step 4) */
    GN_DROP_ATTESTATION_BAD_SIGNATURE       = 15, /**< Ed25519 over `cert||binding` rejected (§5 step 5) */
    GN_DROP_ATTESTATION_EXPIRED_OR_INVALID  = 16, /**< cert verify failed (§5 step 6) */
    GN_DROP_ATTESTATION_IDENTITY_CHANGE     = 17  /**< device_pk differs from pinned (§5 step 7) */
    /** @} */
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
    GN_ON_RESULT_CONTINUE_CHAIN = 0, /**< default: dispatch continues per `Propagation` */
    GN_ON_RESULT_STOP_CHAIN     = 1  /**< stop the chain regardless of `Propagation` */
} gn_on_result_policy_t;

/**
 * @brief Layer selector for `host_api->inject`.
 *
 * @ref GN_INJECT_LAYER_MESSAGE accepts an envelope payload; the kernel
 * builds the envelope around it under the source connection's
 * `remote_pk` as sender. `msg_id` is the routing key.
 *
 * @ref GN_INJECT_LAYER_FRAME accepts a fully framed wire-side buffer;
 * the kernel runs the active protocol layer's deframer over it and
 * routes the resulting envelopes. `msg_id` is ignored.
 *
 * Per `host-api.md` §8.
 */
typedef enum gn_inject_layer_e {
    GN_INJECT_LAYER_MESSAGE = 0,
    GN_INJECT_LAYER_FRAME   = 1
} gn_inject_layer_t;

/**
 * @brief Kind selector for `host_api->register` / `unregister`.
 *
 * The plugin declares which family of vtable it is wiring; the
 * kernel routes the call into the matching kernel registry
 * (`HandlerRegistry`, `LinkRegistry`). The returned id carries
 * the kind tag in its top bits so a later `unregister(id)` reaches
 * the right registry without naming the kind a second time.
 *
 * Per-kind expectations on `gn_register_meta_t`:
 *
 * | Kind                     | `name`                    | `msg_id` / `priority`                  | `vtable`                       | `self`                  |
 * |--------------------------|---------------------------|----------------------------------------|--------------------------------|-------------------------|
 * | `GN_REGISTER_HANDLER`    | protocol id               | meaningful (per `host-api.md` §6)      | `gn_handler_vtable_t*`         | per-handler instance    |
 * | `GN_REGISTER_LINK`       | URI scheme                | ignored (zero them)                    | `gn_link_vtable_t*`            | per-link instance       |
 */
typedef enum gn_register_kind_e {
    GN_REGISTER_HANDLER = 0,
    GN_REGISTER_LINK    = 1
} gn_register_kind_t;

/**
 * @brief Metadata for `host_api->register`.
 *
 * Begins with `api_size` for size-prefix evolution per
 * `abi-evolution.md` §3. New fields land before `_reserved`.
 *
 * **Zero-initialisation contract** (`abi-evolution.md` §4): the
 * caller MUST zero `_pad` and `_reserved` before populating named
 * fields. C++ code achieves this with `gn_register_meta_t mt{};`
 * (value-init); C code uses `memset(&mt, 0, sizeof(mt))` or per-field
 * assignment that hits every byte. The kernel may read these bytes as
 * a contiguous range for ABI evolution / hashing / equality checks; a
 * non-zero `_pad` byte from a partially-initialised struct will
 * silently break those reads. Per-field assignment without an explicit
 * zero pass leaks stack garbage and is forbidden.
 */
typedef struct gn_register_meta_s {
    uint32_t      api_size;        /**< sizeof(gn_register_meta_t) */
    const char*   name;            /**< @borrowed for the call */
    uint32_t      msg_id;          /**< HANDLER only; zero otherwise */
    uint8_t       priority;        /**< HANDLER only; zero otherwise */
    uint8_t       _pad[3];         /**< MUST be zero; see contract above */
    void*         _reserved[4];    /**< MUST be zero; see contract above */
} gn_register_meta_t;

/**
 * @brief Type tag for `host_api->config_get`.
 *
 * The config tree carries values typed at parse time. The plugin
 * declares the type it expects on every read; the kernel rejects
 * a mismatch with `GN_ERR_INVALID_ENVELOPE` so a config drift
 * (operator wrote a string where the plugin wanted an integer)
 * surfaces at the call site instead of producing silent zero
 * defaults further downstream.
 *
 * `out_value` shape per type:
 *
 * | Type            | Plugin passes                                        | Kernel writes              |
 * |-----------------|------------------------------------------------------|----------------------------|
 * | `INT64`         | `int64_t*`                                           | the parsed integer         |
 * | `BOOL`          | `int32_t*`                                           | 0 or 1                     |
 * | `DOUBLE`        | `double*`                                            | the parsed float           |
 * | `STRING`        | `char**` + `void(**)(void*)` `out_free`              | malloc'd NUL-terminated; plugin frees through *out_free |
 * | `ARRAY_SIZE`    | `size_t*`                                            | element count              |
 *
 * `index` carries the array-element ordinal for `INT64` / `STRING`
 * reads inside an array; pass @ref GN_CONFIG_NO_INDEX for scalar
 * lookups and for the `ARRAY_SIZE` query.
 *
 * Per `host-api.md` §2 and `config.md` §3.
 */
typedef enum gn_config_value_type_e {
    GN_CONFIG_VALUE_INT64      = 0,
    GN_CONFIG_VALUE_BOOL       = 1,
    GN_CONFIG_VALUE_DOUBLE     = 2,
    GN_CONFIG_VALUE_STRING     = 3,
    GN_CONFIG_VALUE_ARRAY_SIZE = 4
} gn_config_value_type_t;

/** Sentinel `index` for scalar `config_get` calls. */
#define GN_CONFIG_NO_INDEX ((size_t)-1)

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
    GN_ERR_UNKNOWN_RECEIVER   = -4,  /**< receiver_pk not in local_identities,
                                       *   no relay loaded. Reserved for the
                                       *   message-routing path. The router
                                       *   surfaces this case through the
                                       *   `RouteOutcome::DroppedUnknownReceiver`
                                       *   internal enum and the
                                       *   `route.outcome.dropped_unknown_receiver`
                                       *   counter, not as a return from any
                                       *   C ABI thunk. Lookup misses elsewhere
                                       *   (registry id miss, config key
                                       *   absent, link session miss)
                                       *   return `GN_ERR_NOT_FOUND` (-14).
                                       *   Out-of-bounds array indices
                                       *   return `GN_ERR_OUT_OF_RANGE` (-15). */
    GN_ERR_PAYLOAD_TOO_LARGE  = -5,  /**< payload_size > plugin.max_payload_size() */
    GN_ERR_DEFRAME_INCOMPLETE = -6,  /**< partial frame — kernel buffers and retries */
    GN_ERR_DEFRAME_CORRUPT    = -7,  /**< magic mismatch / bad version / overflow */
    GN_ERR_NOT_IMPLEMENTED    = -8,
    GN_ERR_VERSION_MISMATCH   = -9,  /**< plugin SDK major != kernel SDK major */
    GN_ERR_LIMIT_REACHED      = -10,
    GN_ERR_INVALID_STATE      = -11, /**< callee in wrong phase for the requested op
                                       *   (Noise handshake on a transport-phase session,
                                       *   set_timer after shutdown, etc.) */
    GN_ERR_INTEGRITY_FAILED   = -12, /**< integrity / authenticity check failed
                                       *   (plugin SHA-256 manifest mismatch,
                                       *   tampered binary, manifest absent in
                                       *   strict mode) */
    GN_ERR_INTERNAL           = -13, /**< kernel caught an exception that
                                       *   crossed a plugin C ABI boundary;
                                       *   the call was aborted before any
                                       *   side effect reached the kernel.
                                       *   Plugin authors must not throw
                                       *   across `extern "C"`. */
    GN_ERR_NOT_FOUND          = -14, /**< lookup miss — config key absent,
                                       *   handler/link id unknown,
                                       *   inject-target id absent. Distinct
                                       *   from `GN_ERR_UNKNOWN_RECEIVER`
                                       *   which is reserved for the
                                       *   message-routing receiver_pk path
                                       *   (no local identity matches /
                                       *   no relay loaded). */
    GN_ERR_OUT_OF_RANGE       = -15, /**< value outside the contract's
                                       *   permitted range — config integer
                                       *   above the cap declared in
                                       *   `limits.md`, array index past
                                       *   end, etc. */
    GN_ERR_FRAME_TOO_LARGE    = -16  /**< wire frame length exceeds the
                                       *   contract's per-frame ceiling
                                       *   (`plugins/protocols/gnet/docs/wire-format.md` §2.4
                                       *   `kMaxFrameBytes`). Distinct from
                                       *   `GN_ERR_DEFRAME_CORRUPT` so the
                                       *   operator metric distinguishes a
                                       *   hostile peer (frame_too_large)
                                       *   from a random corruption
                                       *   (deframe_corrupt). The kernel
                                       *   maps this code to the
                                       *   `drop.frame_too_large` counter
                                       *   per `metrics.md` §3. */
} gn_result_t;

/**
 * @brief Translate a `gn_result_t` value into a stable human-readable
 *        string suitable for log lines and error reporting.
 *
 * The returned pointer references a string literal owned by the SDK
 * binary; callers MUST NOT free it. The mapping is one-to-one with
 * the enumerators above; unknown values (`r` outside the enum) return
 * `"unknown gn_result_t"` rather than NULL so log call sites need no
 * NULL-guard.
 *
 * The function is `static inline` so a plugin built only against the
 * SDK headers gets the table without linking against `goodnet_kernel`.
 */
static inline const char* gn_strerror(gn_result_t r) {
    switch (r) {
        case GN_OK:                       return "ok";
        case GN_ERR_NULL_ARG:              return "null argument where required";
        case GN_ERR_OUT_OF_MEMORY:         return "out of memory";
        case GN_ERR_INVALID_ENVELOPE:      return "invalid envelope (zero sender_pk, zero msg_id, or non-zero _reserved)";
        case GN_ERR_UNKNOWN_RECEIVER:      return "unknown receiver public key (no local identity, no relay)";
        case GN_ERR_PAYLOAD_TOO_LARGE:     return "payload exceeds the configured max_payload_size";
        case GN_ERR_DEFRAME_INCOMPLETE:    return "partial frame buffered for retry";
        case GN_ERR_DEFRAME_CORRUPT:       return "frame deframe failed (magic mismatch, bad version, or length overflow)";
        case GN_ERR_NOT_IMPLEMENTED:       return "not implemented";
        case GN_ERR_VERSION_MISMATCH:      return "version mismatch (plugin SDK major != kernel SDK major)";
        case GN_ERR_LIMIT_REACHED:         return "limit reached";
        case GN_ERR_INVALID_STATE:         return "invalid state (operation illegal in current phase)";
        case GN_ERR_INTEGRITY_FAILED:      return "integrity check failed (manifest mismatch, tampered binary, or strict-mode manifest absent)";
        case GN_ERR_INTERNAL:              return "internal kernel error (exception crossed a C ABI boundary)";
        case GN_ERR_NOT_FOUND:             return "not found";
        case GN_ERR_OUT_OF_RANGE:          return "value outside the contract's permitted range";
        case GN_ERR_FRAME_TOO_LARGE:       return "wire frame exceeds kMaxFrameBytes ceiling";
    }
    return "unknown gn_result_t";
}

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
    /**
     * sizeof(gn_message_t) at the producer's build time. Caller-
     * allocated structs carry the size prefix so the consumer
     * (kernel thunk, handler) can refuse to read fields the caller's
     * SDK did not allocate. Per `abi-evolution.md` §3 the size lives
     * at offset zero; the static_assert below pins that.
     *
     * Zero is permitted in v1.0 — pre-3.1 callsites that have not
     * been migrated to set the field still produce a usable
     * envelope under the v1.0 layout. v1.x consumers that read
     * fields added after `_reserved` MUST gate the read on
     * `api_size >= offsetof(gn_message_t, <field>) + sizeof(<field>)`.
     */
    uint32_t       api_size;
    uint8_t        sender_pk[GN_PUBLIC_KEY_BYTES];   /**< Ed25519, end-to-end identity */
    uint8_t        receiver_pk[GN_PUBLIC_KEY_BYTES]; /**< ZERO bytes ⇒ broadcast */
    uint32_t       msg_id;                           /**< per-protocol routing key */
    const uint8_t* payload;                          /**< borrowed; opaque application bytes */
    size_t         payload_size;
    /**
     * Inbound-edge connection that produced this envelope.
     *
     * - For envelopes from `notify_inbound_bytes`: the connection on
     *   which the bytes arrived (stamped by the kernel thunk before
     *   dispatch).
     * - For envelopes from `inject`: the bridge `source` connection
     *   passed to the thunk (the bridge handler's IPC/foreign edge);
     *   stamped at both `LAYER_MESSAGE` and `LAYER_FRAME` so handlers
     *   reading `env.conn_id` get the bridge edge rather than zero.
     *
     * Handlers consult this field instead of resolving `sender_pk`
     * through `find_conn_by_pk` — the latter is wrong on relay paths
     * where `sender_pk` is the originating peer (set via
     * `EXPLICIT_SENDER`) but the receiving connection belongs to the
     * relay. Per `host-api.md` §8 (inject) and §7 (notify_inbound).
     *
     * Producers built before this field existed leave
     * `api_size < offsetof(conn_id) + sizeof(conn_id)` — handlers that
     * read the field MUST gate on the size check per the contract
     * above. A `GN_INVALID_ID` value MUST be tolerated as an unknown
     * edge: handlers degrade gracefully (return `CONTINUE`) rather
     * than rejecting the envelope, per `handler-registration.md` §3a.
     */
    gn_conn_id_t   conn_id;
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
_Static_assert(offsetof(gn_message_t, api_size) == 0,
               "gn_message_t must begin with `uint32_t api_size` per "
               "abi-evolution.md §3");
#endif

#ifdef __cplusplus
static_assert(offsetof(gn_message_t, api_size) == 0,
              "gn_message_t must begin with `uint32_t api_size` per "
              "abi-evolution.md §3");
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_TYPES_H */
