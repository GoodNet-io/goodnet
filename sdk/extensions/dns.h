/**
 * @file   sdk/extensions/dns.h
 * @brief  Extension vtable: `gn.dns` — distributed key-value
 *         database surfaced as a system handler. Brings the legacy
 *         `goodnetd-dns` surface forward as a v1 handler plugin.
 *
 * The legacy `apps/store` layer was a routing layer that doubled
 * as a full key-value DB: TTL'd records, prefix queries, subscribe-
 * and-notify on write, and bulk sync across nodes by
 * `since_timestamp` watermark. This extension exposes that surface
 * as the `gn.dns` handler plugin.
 *
 * The plugin owns a pluggable `IDnsBackend` (memory for the
 * reference; sqlite + DHT + Redis planned) and a wire dispatcher
 * that maps the seven `DNS_*` envelope types onto the backend.
 * Local callers reach the same surface through the in-process
 * extension vtable below — no wire framing, no conn-id needed.
 *
 * @par Not the SDK hostname resolver
 * `sdk/cpp/dns.hpp` is an unrelated header — that one rewrites
 * `tcp://example.com:443` URIs into IP literals at connect time
 * (see `docs/contracts/hostname-resolver.md`). Same word, different
 * concept: this header is the networked KV DB surface; that one
 * is a pure-function URI rewrite. Both keep the name because the
 * legacy `goodnetd-dns` binary covered the same conceptual
 * territory either way.
 *
 * @par msg_id allocation
 * The handler subscribes to `0x0600..0x0606` under `protocol_id`
 * `"gnet-v1"`. These ids are outside the kernel-reserved
 * `0x10..0x1F` range (see `system-handlers.md` §2); plugin
 * registration is unrestricted.
 */
#ifndef GOODNET_SDK_EXTENSIONS_DNS_H
#define GOODNET_SDK_EXTENSIONS_DNS_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Stable extension identifier. Unchanged across minor releases. */
#define GN_EXT_DNS          "gn.dns"

/** v1.0.0 — initial release. */
#define GN_EXT_DNS_VERSION  0x00010000u

/** Hard cap on key length. Backends MAY enforce a smaller cap. */
#define GN_DNS_KEY_MAX_LEN     256u

/** Hard cap on value length (64 KiB). Widened to size_t so a
 *  `size() > GN_DNS_VALUE_MAX_LEN` check stays within the same
 *  promoted type clang-tidy's `bugprone-implicit-widening-of-
 *  multiplication-result` accepts. */
#define GN_DNS_VALUE_MAX_LEN  ((size_t)(64u * 1024u))

/** Maximum records returned from a single prefix / since query. */
#define GN_DNS_QUERY_MAX_RESULTS  256u

/**
 * @brief Query mode for `get` / `subscribe` calls.
 */
typedef enum gn_dns_query_e {
    GN_DNS_QUERY_EXACT  = 0,  /**< key matches verbatim */
    GN_DNS_QUERY_PREFIX = 1,  /**< key prefix sweep, up to `max_results` */
    GN_DNS_QUERY_SINCE  = 2   /**< all records newer than `since_us` (sync) */
} gn_dns_query_t;

/**
 * @brief Event kind delivered to `subscribe` callbacks.
 */
typedef enum gn_dns_event_e {
    GN_DNS_EVENT_PUT    = 0,  /**< new or overwritten record */
    GN_DNS_EVENT_DELETE = 1   /**< record removed */
} gn_dns_event_t;

/**
 * @brief One record stored under a key.
 *
 * All bytes are owned by the backend during the callback; consumers
 * that need to retain `key` / `value` past the call must copy.
 */
typedef struct gn_dns_record_s {
    const char*    key;            /**< NUL-terminated UTF-8 key */
    size_t         key_len;        /**< key length excluding NUL */
    const uint8_t* value;          /**< value bytes */
    size_t         value_len;      /**< value length */
    uint64_t       timestamp_us;   /**< unix microseconds of last write */
    uint64_t       ttl_s;          /**< 0 = permanent; else expiry seconds */
    uint8_t        flags;          /**< user-defined; opaque to the backend */
} gn_dns_record_t;

/**
 * @brief Subscriber callback. Borrowed `record` valid for the call.
 */
typedef void (*gn_dns_event_cb_t)(void* user_data,
                                  gn_dns_event_t event,
                                  const gn_dns_record_t* record);

/**
 * @brief Vtable surfaced as the `gn.dns` extension.
 *
 * Versioned with @ref GN_EXT_DNS_VERSION. Begins with `api_size`
 * for size-prefix evolution per `abi-evolution.md` §3.
 *
 * The `ctx` field carries the handler's `self` pointer; every entry
 * receives it as its first argument.
 */
typedef struct gn_dns_api_s {
    uint32_t api_size;          /**< sizeof(gn_dns_api_t) at producer build time */

    /**
     * @brief Insert or overwrite `(key, value)`.
     *
     * @return 0 on success, -1 on invalid arg / size cap, -2 on backend error.
     */
    int (*put)(void* ctx,
               const char* key, size_t key_len,
               const uint8_t* value, size_t value_len,
               uint64_t ttl_s, uint8_t flags);

    /**
     * @brief Look up the record with exact key match.
     *
     * @param out_record @borrowed during the call. NULL when not found.
     * @return 0 on hit, -1 on miss, -2 on invalid arg.
     */
    int (*get)(void* ctx,
               const char* key, size_t key_len,
               gn_dns_record_t* out_record);

    /**
     * @brief Sweep records by prefix / since-timestamp.
     *
     * Calls @p cb once per match, in undefined order. Returns the
     * number of records delivered (clamped to @p max_results, which
     * itself is capped at `GN_DNS_QUERY_MAX_RESULTS`).
     */
    int (*query)(void* ctx,
                 gn_dns_query_t mode,
                 const char* key, size_t key_len,
                 uint64_t since_us,
                 uint32_t max_results,
                 void (*emit)(void* user, const gn_dns_record_t*),
                 void* emit_user);

    /**
     * @brief Remove the record with exact key match.
     *
     * @return 0 on deletion, -1 if absent, -2 on invalid arg.
     */
    int (*del)(void* ctx, const char* key, size_t key_len);

    /**
     * @brief Subscribe to PUT / DELETE on a key (exact or prefix).
     *
     * Returned token must be passed to `unsubscribe`; tokens are
     * never reused after release. Returns 0 on a NULL out token.
     */
    uint64_t (*subscribe)(void* ctx,
                          gn_dns_query_t mode,
                          const char* key, size_t key_len,
                          gn_dns_event_cb_t cb,
                          void* user_data);

    /** Release a subscription token. No-op for unknown tokens. */
    void (*unsubscribe)(void* ctx, uint64_t token);

    /**
     * @brief Purge expired records.
     *
     * @return number of records removed.
     */
    uint64_t (*cleanup_expired)(void* ctx);

    void* ctx;
    void* _reserved[4];
} gn_dns_api_t;

GN_VTABLE_API_SIZE_FIRST(gn_dns_api_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_DNS_H */
