/**
 * @file   sdk/extensions/link_capability.h
 * @brief  Extension vtable: `gn.link.capability` — host-side bind
 *         probe result for UDP / TCP on IPv4 and IPv6.
 *
 * Link plugins (UDP, DTLS, QUIC, ICE) and strategy plugins consult
 * the cached capability before emitting candidates or attempting
 * binds that would fail anyway on the current network environment.
 * The kernel probes once at startup and re-probes on netlink
 * interface-change events; consumers receive an immutable snapshot
 * copy through @ref gn_link_capability_api_t::get.
 */
#ifndef GOODNET_SDK_EXTENSIONS_LINK_CAPABILITY_H
#define GOODNET_SDK_EXTENSIONS_LINK_CAPABILITY_H

#include <stdbool.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Stable extension identifier. */
#define GN_EXT_LINK_CAPABILITY          "gn.link.capability"

/** v1.0.0 — initial release. */
#define GN_EXT_LINK_CAPABILITY_VERSION  0x00010000u

/**
 * @brief POD describing what kinds of sockets the host can bind to
 *        wildcard:0 right now. Mirrors `gn::LinkCapability` in
 *        `core/kernel/link_capability.hpp`.
 */
typedef struct gn_link_capability_s {
    bool can_bind_udp_v4;
    bool can_bind_udp_v6;
    bool can_bind_tcp_v4;
    bool can_bind_tcp_v6;
} gn_link_capability_t;

/**
 * @brief Vtable surfaced as the `gn.link.capability` extension.
 *
 * The `ctx` field is unused by the producer (the kernel keeps the
 * snapshot in process-static state); plugins still pass it through
 * to the `get` slot for ABI uniformity with other extensions.
 */
typedef struct gn_link_capability_api_s {
    uint32_t api_size;  /**< sizeof(gn_link_capability_api_t) at producer build time */

    /**
     * @brief Copy the current capability snapshot into @p out.
     *
     * @param out @borrowed caller-allocated; the kernel writes the
     *            four-bool snapshot into the struct. Returns 0 on
     *            success, -1 when @p out is NULL.
     */
    int (*get)(void* ctx, gn_link_capability_t* out);

    void* ctx;
    void* _reserved[4];
} gn_link_capability_api_t;

GN_VTABLE_API_SIZE_FIRST(gn_link_capability_api_t);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  /* GOODNET_SDK_EXTENSIONS_LINK_CAPABILITY_H */
