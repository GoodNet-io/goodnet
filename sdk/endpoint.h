/**
 * @file   sdk/endpoint.h
 * @brief  Read-only snapshot of a connection state for plugins.
 *
 * Plugins access live registry data through `host_api->get_endpoint`. The
 * returned snapshot is a copy of the small fields; pointers into the
 * registry are intentionally not exposed. See `docs/contracts/registry.md`.
 */
#ifndef GOODNET_SDK_ENDPOINT_H
#define GOODNET_SDK_ENDPOINT_H

#include <stdint.h>
#include <stddef.h>

#include <sdk/abi.h>
#include <sdk/types.h>
#include <sdk/trust.h>

#ifdef __cplusplus
extern "C" {
#endif

/* URI buffer ceiling — long enough for IPv6+port plus a scheme. */
#define GN_ENDPOINT_URI_MAX 256

/**
 * @brief Snapshot of a connection record.
 *
 * Owned by the caller of `host_api->get_endpoint`. The kernel fills the
 * struct in place; pointers inside are valid until the caller's stack frame
 * unwinds (URI is held inline in `uri[]`).
 */
typedef struct gn_endpoint_s {
    /** sizeof(gn_endpoint_t) at the producer's build time; see
     *  `abi-evolution.md` §3. Zero is permitted in v1.0 — pre-3.1
     *  callsites that have not been migrated to set the field still
     *  produce a usable snapshot under the v1.0 layout. */
    uint32_t          api_size;
    gn_conn_id_t      conn_id;
    uint8_t           remote_pk[GN_PUBLIC_KEY_BYTES];
    gn_trust_class_t  trust;
    char              uri[GN_ENDPOINT_URI_MAX];
    char              scheme[16];          /**< "tcp", "udp", "ws", "ipc", … */

    /* Counters (atomic snapshots). */
    uint64_t          bytes_in;
    uint64_t          bytes_out;
    uint64_t          frames_in;
    uint64_t          frames_out;
    uint64_t          pending_queue_bytes;
    uint64_t          last_rtt_us;

    /* ABI evolution. */
    void*             _reserved[4];
} gn_endpoint_t;

GN_VTABLE_API_SIZE_FIRST(gn_endpoint_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_ENDPOINT_H */
