/**
 * @file   sdk/extensions/dns.h
 * @brief  Extension vtable: `gn.dns` — typed DNS service backed by
 *         the `gn.handler.store` plugin's KV primitive.
 *
 * The handler exposes typed resource-record operations (A / AAAA /
 * SRV / TXT / PTR / CNAME / NS / MX) over a three-tier resolver
 * cascade: local store → cached upstream → c-ares upstream. Other
 * plugins reach the surface through this extension; `link-ice`
 * uses it to expand `stun:<hostname>` configs via SRV lookups.
 *
 * Storage is delegated — this extension never carries `put` / `get`
 * slots for raw bytes. Those live on `gn.store` if a caller needs
 * untyped KV access. See `docs/contracts/dns.md` for the wire
 * surface, `docs/contracts/store.md` for the storage primitive.
 *
 * @par Not the SDK hostname resolver
 * `sdk/cpp/dns.hpp` is an unrelated header — that one rewrites
 * `tcp://example.com:443` URIs into IP literals at connect time
 * (see `docs/contracts/hostname-resolver.md`). Same word, different
 * concept: this header is the networked record-DB surface; that
 * one is a pure-function URI rewrite. Both keep the name because
 * the legacy `goodnetd-dns` binary covered the same conceptual
 * territory either way.
 *
 * @par msg_id allocation
 * The handler subscribes to `0x0610..0x0616` under `protocol_id`
 * `"gnet-v1"` (see plugin-side `dns.hpp::kMsg*` constants). The
 * block sits next to the legacy `0x0600..0x0606` range that
 * `gn.handler.store` keeps so a node hosting both plugins routes
 * unambiguously by `msg_id`. These ids are outside the kernel-
 * reserved `0x10..0x1F` range (see `system-handlers.md` §2).
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

/** v1.0.0 — initial typed-API release. The earlier KV-style shape
 *  shipped as 0x00010000 in handler-dns 1.0.0-rc0 (`015c287`) was
 *  never published because the throwaway plugin checkpoint did not
 *  register an extension. This release reuses the version number;
 *  consumers can assume the typed shape below as the v1 contract.
 */
#define GN_EXT_DNS_VERSION  0x00010000u

/** Hard cap on a single DNS name (one label-sequence on the wire).
 *  RFC 1035 §2.3.4. */
#define GN_DNS_NAME_MAX_LEN    255u

/** Hard cap on a record's wire-encoded rdata. 64 KiB matches the
 *  upper bound for any RR type defined in RFC 1035 / RFC 3596. */
#define GN_DNS_RDATA_MAX_LEN   ((size_t)(64u * 1024u))

/** Maximum records returned from a single `resolve` call. */
#define GN_DNS_QUERY_MAX_RESULTS  256u

/**
 * @brief Numeric resource-record type identifiers matching the
 *        IANA DNS-parameters registry. Names line up with the
 *        plugin-side `gn::handler::dns::RrType` enum.
 */
typedef enum gn_dns_rrtype_e {
    GN_DNS_RR_A     = 1,
    GN_DNS_RR_NS    = 2,
    GN_DNS_RR_CNAME = 5,
    GN_DNS_RR_PTR   = 12,
    GN_DNS_RR_MX    = 15,
    GN_DNS_RR_TXT   = 16,
    GN_DNS_RR_AAAA  = 28,
    GN_DNS_RR_SRV   = 33
} gn_dns_rrtype_t;

/**
 * @brief One typed DNS record emitted by `resolve` or installed
 *        through `put_record`. The `rdata` buffer carries the
 *        per-type wire body (4 bytes for A, 16 for AAAA, an
 *        RFC 2782 SRV body for SRV, etc.); consumers parse it
 *        with the matching codec in the plugin tree's
 *        `dns_records.{hpp,cpp}`.
 *
 * All pointer fields are `@borrowed` for the duration of the call
 * that delivered them. Consumers that need to retain the data
 * past the call must copy.
 */
typedef struct gn_dns_record_s {
    uint16_t       type;          /**< gn_dns_rrtype_t value */
    uint16_t       _pad;          /**< zero; reserved */
    const char*    name;          /**< borrowed; not necessarily NUL-terminated */
    size_t         name_len;
    const uint8_t* rdata;         /**< borrowed; per-type wire body */
    size_t         rdata_len;
    uint32_t       ttl_s;         /**< 0 = permanent (operator-curated) */
    uint64_t       timestamp_us;  /**< wall-clock of last refresh */
    uint8_t        flags;         /**< user-defined; opaque to the resolver */
    uint8_t        _pad2[7];
} gn_dns_record_t;

/**
 * @brief Emit-callback shape used by `resolve`. The resolver
 *        invokes the callback once per record produced by the
 *        cascade.
 */
typedef void (*gn_dns_emit_cb_t)(void* user, const gn_dns_record_t* record);

/**
 * @brief Vtable surfaced as the `gn.dns` extension.
 *
 * Versioned with @ref GN_EXT_DNS_VERSION. Begins with `api_size`
 * for size-prefix evolution per `abi-evolution.md` §3.
 *
 * The `ctx` field carries the handler's `self` pointer; every
 * entry receives it as its first argument.
 */
typedef struct gn_dns_api_s {
    uint32_t api_size;          /**< sizeof(gn_dns_api_t) at producer build time */

    /**
     * @brief Resolve (name, type) through the cascade. The emit
     *        callback fires once per record; the resolver
     *        guarantees the records share the `(name, type)` of
     *        the query. Returns the number of records delivered,
     *        clamped at `min(max_results, GN_DNS_QUERY_MAX_RESULTS)`.
     *
     * @param ctx         the handler's self pointer from `ctx`.
     * @param name        @borrowed during the call.
     * @param type        one of @ref gn_dns_rrtype_t.
     * @param max_results 0 means "no caller cap" — the resolver
     *                    still bounds the result at `GN_DNS_QUERY_MAX_RESULTS`.
     */
    int (*resolve)(void* ctx,
                   const char* name, size_t name_len,
                   uint16_t type,
                   uint32_t max_results,
                   gn_dns_emit_cb_t emit, void* emit_user);

    /**
     * @brief Install a typed record. The plugin writes it into the
     *        `gn.handler.store` backing under the `<type>/<name>`
     *        store-key shape. Returns 0 on success, -1 on bad
     *        args, -2 on backend error.
     *
     * @param ttl_s 0 marks the record permanent (no auto-eviction).
     * @param flags caller-defined; opaque to the resolver.
     */
    int (*put_record)(void* ctx,
                      const char* name, size_t name_len,
                      uint16_t type,
                      const uint8_t* rdata, size_t rdata_len,
                      uint32_t ttl_s, uint8_t flags);

    /**
     * @brief Drop a typed record. Returns 0 on success (record
     *        existed), -1 on miss, -2 on bad args / no backend.
     */
    int (*delete_record)(void* ctx,
                         const char* name, size_t name_len,
                         uint16_t type);

    void* ctx;
    void* _reserved[4];
} gn_dns_api_t;

GN_VTABLE_API_SIZE_FIRST(gn_dns_api_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_DNS_H */
