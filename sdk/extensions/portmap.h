/**
 * @file   sdk/extensions/portmap.h
 * @brief  Extension vtable: `gn.link.portmap` — explicit NAT port
 *         mapping (UPnP IGD / PCP / NAT-PMP).
 *
 * Carrier links (ICE in particular) query this extension before
 * gathering host candidates. When the local router supports any of
 * the three protocols the plugin returns a known-good `(ext_ip,
 * ext_port)` mapping the peer can reach directly, which works for
 * symmetric NATs that STUN cannot punch.
 *
 * The plugin is optional. Consumers handle a missing extension
 * (`query_extension_checked` returning `GN_ERR_NOT_FOUND`) and a
 * zero `supported_protocols` mask the same way: skip the mapping
 * step, fall back to STUN srflx or TURN.
 *
 * See `plugins/links/portmap/README.md` for the protocol matrix and
 * RFC references (NAT-PMP RFC 6886, PCP RFC 6887, UPnP IGD-D 1.0/2.0).
 */
#ifndef GOODNET_SDK_EXTENSIONS_PORTMAP_H
#define GOODNET_SDK_EXTENSIONS_PORTMAP_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Stable extension identifier. Unchanged across minor releases. */
#define GN_EXT_PORTMAP          "gn.link.portmap"

/** v1.0.0 — initial release. */
#define GN_EXT_PORTMAP_VERSION  0x00010000u

/**
 * @brief Transport protocol for a mapping. The router programs its
 *        NAPT table per (protocol, internal_port) tuple.
 */
typedef enum gn_portmap_protocol_e {
    GN_PORTMAP_TCP = 1,
    GN_PORTMAP_UDP = 2
} gn_portmap_protocol_t;

/**
 * @brief Bitmask returned by @ref gn_portmap_api_t::supported_protocols.
 *
 * Multiple bits MAY be set when the router answers more than one
 * discovery probe (a dual-stack PCP/NAT-PMP host is the common case).
 * Consumers normally try the bits in the order `PCP > NAT-PMP > UPnP`
 * because PCP carries the richest error reporting.
 */
#define GN_PORTMAP_PROTO_UPNP   0x1u  /**< UPnP IGD (SSDP + SOAP) */
#define GN_PORTMAP_PROTO_PCP    0x2u  /**< PCP RFC 6887 */
#define GN_PORTMAP_PROTO_NATPMP 0x4u  /**< NAT-PMP RFC 6886 */

/**
 * @brief A mapping returned by the router. Stable for `lifetime_s`
 *        seconds; the plugin renews it at `lifetime_s / 2` cadence
 *        per RFC 6886 §3.3.
 */
typedef struct gn_portmap_mapping_s {
    /** sizeof(gn_portmap_mapping_t) at producer build time. */
    uint32_t              api_size;

    /** External address the router assigned (NUL-terminated dotted
     *  decimal for IPv4 or RFC 5952 textual for IPv6). */
    char                  ext_ip[64];

    /** External port the router opened. May differ from the hint. */
    uint16_t              ext_port;

    /** Internal port the mapping forwards to. Equals the requested
     *  `int_port`; included so the caller can correlate when several
     *  mappings live concurrently. */
    uint16_t              int_port;

    /** Remaining lifetime in seconds. `0` means the mapping expired
     *  or never existed (e.g., release acknowledgement). */
    uint32_t              lifetime_s;

    /** Transport protocol of the mapping. */
    gn_portmap_protocol_t protocol;
} gn_portmap_mapping_t;

GN_VTABLE_API_SIZE_FIRST(gn_portmap_mapping_t);

/**
 * @brief Vtable surfaced as the `gn.link.portmap` extension.
 *
 * The `ctx` field is the plugin's `self` pointer; every entry takes
 * it as its first argument. Versioned with @ref GN_EXT_PORTMAP_VERSION.
 */
typedef struct gn_portmap_api_s {
    /** sizeof(gn_portmap_api_t) at producer build time. */
    uint32_t api_size;

    /**
     * @brief Ask the router for a new mapping.
     *
     * On success the plugin starts the renewal cadence internally
     * and `out_mapping->lifetime_s` reports the router-granted
     * lifetime so the caller knows when the mapping turns stale even
     * if renewals stop succeeding (router reboot, link change).
     *
     * @param ctx                  the `ctx` field of this vtable.
     * @param protocol             TCP or UDP.
     * @param int_port             local listening port to forward to.
     * @param external_port_hint   preferred external port; pass `0`
     *                             to let the router pick.
     * @param lifetime_s_hint      preferred lifetime in seconds; pass
     *                             `0` to accept the router default
     *                             (NAT-PMP traditionally 7200s).
     * @param out_mapping          @borrowed caller-allocated; written
     *                             on success.
     *
     * @return `0` on success, `-1` on failure (no router, protocol
     *         not supported, router refused).
     */
    int (*request)(void* ctx,
                   gn_portmap_protocol_t protocol,
                   uint16_t int_port,
                   uint16_t external_port_hint,
                   uint32_t lifetime_s_hint,
                   gn_portmap_mapping_t* out_mapping);

    /**
     * @brief Release a previously-requested mapping. Best effort:
     *        the plugin sends the protocol's "delete" request and
     *        drops the mapping from its renewal table regardless of
     *        the router's reply.
     */
    int (*release)(void* ctx,
                   gn_portmap_protocol_t protocol,
                   uint16_t int_port);

    /**
     * @brief Bitmask of `GN_PORTMAP_PROTO_*` bits. `0` means no
     *        portmap protocol is reachable (no default gateway, the
     *        gateway is silent, or it actively rejects every probe).
     *        The result is cached after first call; a `request()`
     *        failure invalidates the cache so the next call re-probes.
     */
    uint32_t (*supported_protocols)(void* ctx);

    void* ctx;
    void* _reserved[4];
} gn_portmap_api_t;

GN_VTABLE_API_SIZE_FIRST(gn_portmap_api_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_PORTMAP_H */
