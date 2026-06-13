/**
 * @file   sdk/extensions/mdns.h
 * @brief  Extension vtable: `gn.discovery.mdns` — multicast DNS responder
 *         and resolver for ICE host-candidate obfuscation per
 *         draft-ietf-mmusic-mdns-ice-candidates and RFC 6762.
 *
 * The plugin is optional. Consumers handle a missing extension
 * (`query_extension_checked` returning `GN_ERR_NOT_FOUND`) by degrading
 * gracefully: ICE emits raw host candidates instead of `<uuid>.local`
 * ones, and incoming `HostMdns` remote candidates are skipped.
 */
#ifndef GOODNET_SDK_EXTENSIONS_MDNS_H
#define GOODNET_SDK_EXTENSIONS_MDNS_H

#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Stable extension identifier. */
#define GN_EXT_MDNS         "gn.discovery.mdns"

/** v1.0.0 — initial release. */
#define GN_EXT_MDNS_VERSION  0x00010000u

/** Maximum number of addresses returned per family in a resolve result. */
#define GN_MDNS_MAX_ADDRS  16

/** Maximum string length of a single IP address (INET6_ADDRSTRLEN). */
#define GN_MDNS_ADDR_LEN   46

/**
 * @brief Result passed to @ref gn_mdns_resolve_cb_t. All string storage
 *        is owned by the struct; the callback must copy any data it
 *        needs before returning.
 */
typedef struct gn_mdns_resolve_result_s {
    uint32_t api_size;
    uint8_t  ipv4_count;
    uint8_t  ipv6_count;
    /** 1 = at least one answer arrived before timeout; 0 = timeout. */
    int      resolved;
    char     ipv4[GN_MDNS_MAX_ADDRS][GN_MDNS_ADDR_LEN];
    char     ipv6[GN_MDNS_MAX_ADDRS][GN_MDNS_ADDR_LEN];
} gn_mdns_resolve_result_t;

GN_VTABLE_API_SIZE_FIRST(gn_mdns_resolve_result_t);

/**
 * @brief Callback invoked when an async resolve completes (either with
 *        answers or on timeout). Called from the mDNS plugin's strand;
 *        post back to your own strand before touching shared state.
 */
typedef void (*gn_mdns_resolve_cb_t)(const gn_mdns_resolve_result_t* result,
                                      void* user_data);

/**
 * @brief Vtable surfaced as the `gn.discovery.mdns` extension.
 */
typedef struct gn_mdns_api_s {
    uint32_t api_size;

    /**
     * Register `hostname` (must end in `.local`) so the responder
     * answers A/AAAA queries with the host's interface addresses.
     * Idempotent; safe to call before the socket is bound.
     */
    void (*register_name)(void* ctx, const char* hostname);

    /** Stop answering queries for `hostname`. */
    void (*unregister_name)(void* ctx, const char* hostname);

    /**
     * Issue a one-shot multicast query for `hostname`. The callback
     * fires exactly once — either with collected answers when
     * `timeout_ms` expires, or earlier on first answer. Thread-safe;
     * the callback runs on the mDNS plugin's internal strand.
     */
    void (*resolve)(void* ctx, const char* hostname, uint32_t timeout_ms,
                    gn_mdns_resolve_cb_t cb, void* user_data);

    void* ctx;
    void* _reserved[4];
} gn_mdns_api_t;

GN_VTABLE_API_SIZE_FIRST(gn_mdns_api_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_MDNS_H */
