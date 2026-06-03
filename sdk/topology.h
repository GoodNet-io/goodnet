/**
 * @file   sdk/topology.h
 * @brief  Kernel topology snapshot — registered plugins + capability declarations.
 *
 * Built once at `gn_core_start()` when the kernel transitions to Phase::Running.
 * Immutable thereafter unless `gn_core_reload_topology()` is called explicitly.
 * All pointer fields are @borrowed from kernel-owned storage.
 *
 * Consumers read the topology through `gn_core_get_topology()` (C ABI) or the
 * `gn.topology` named extension. Link plugins receive a pointer via the
 * `on_topology_sealed` vtable slot (`sdk/link.h`) so they can self-configure
 * before the first connection is accepted.
 *
 * See `docs/contracts/layer-capability.en.md`.
 */
#ifndef GOODNET_SDK_TOPOLOGY_H
#define GOODNET_SDK_TOPOLOGY_H

#include <stdint.h>
#include <stddef.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Stable extension name under which the kernel registers the topology vtable. */
#define GN_EXT_TOPOLOGY         "gn.topology"
/** v1.0.0 — initial release. */
#define GN_EXT_TOPOLOGY_VERSION  0x00010000u

/**
 * @brief One registered link transport in the topology snapshot.
 *
 * `scheme` is @borrowed; valid for the kernel's lifetime.
 * `caps_flags` holds the GN_LINK_CAP_* bitmask from the link's
 * `get_capabilities` extension slot; 0 when the link exposes no extension.
 */
typedef struct gn_topo_link_entry_s {
    const char* scheme;       /**< @borrowed; stable for kernel lifetime. */
    uint32_t    caps_flags;   /**< OR of GN_LINK_CAP_*; 0 if not queryable. */
    uint32_t    max_payload;  /**< Soft MTU in bytes; 0 = unlimited. */
} gn_topo_link_entry_t;

/**
 * @brief One registered security provider in the topology snapshot.
 *
 * `provides_flags` is populated from the provider's `provides_flags()` vtable
 * slot (GN_SEC_PROVIDES_* bitmask from `sdk/security.h`). Zero means the
 * provider declares no session-layer cryptographic guarantees.
 */
typedef struct gn_topo_security_entry_s {
    const char* provider_id;         /**< @borrowed; stable for kernel lifetime. */
    uint32_t    allowed_trust_mask;  /**< Bit N set = admits GN_TRUST_<N>. */
    uint32_t    provides_flags;      /**< OR of GN_SEC_PROVIDES_*. */
} gn_topo_security_entry_t;

/**
 * @brief One registered protocol layer in the topology snapshot.
 */
typedef struct gn_topo_protocol_entry_s {
    const char* protocol_id;  /**< @borrowed; stable for kernel lifetime. */
} gn_topo_protocol_entry_t;

/**
 * @brief One (protocol_id, msg_id) handler registration in the topology snapshot.
 *
 * `chain_length` is the total number of handlers across all namespaces for
 * this (protocol_id, msg_id) pair.
 */
typedef struct gn_topo_handler_entry_s {
    const char* protocol_id;  /**< @borrowed; stable for kernel lifetime. */
    uint32_t    msg_id;
    uint32_t    chain_length;
} gn_topo_handler_entry_t;

/**
 * @brief Immutable kernel topology snapshot.
 *
 * All pointer fields are @borrowed from kernel-owned storage and are valid
 * until `gn_core_destroy()` or an explicit `gn_core_reload_topology()` call.
 *
 * `fingerprint` is SHA-256 over the sorted structural layers
 * (link + security + protocol + handler entries). The sort key for each
 * section is the identifying string (scheme, provider_id, protocol_id,
 * protocol_id+msg_id). Deterministic regardless of plugin registration order.
 * Use for peer capability exchange (Slice 4).
 *
 * `contour_gaps` has bit N set when no registered security provider covers
 * trust class N with `GN_SEC_PROVIDES_E2E_ENCRYPTION`. A value of 0 means
 * the security contour is closed across all trust classes. Bits for
 * GN_TRUST_LOOPBACK and GN_TRUST_INTRA_NODE are expected to be set when only
 * a null provider covers those classes — this is correct behaviour, not a gap.
 * The external classes (GN_TRUST_UNTRUSTED=0, GN_TRUST_PEER=1) must not be set
 * for a closed contour.
 */
typedef struct gn_topology_s {
    uint8_t  fingerprint[32];  /**< SHA-256 over sorted structural layers. */
    uint32_t link_count;
    uint32_t security_count;
    uint32_t protocol_count;
    uint32_t handler_count;
    const gn_topo_link_entry_t*     links;
    const gn_topo_security_entry_t* security;
    const gn_topo_protocol_entry_t* protocols;
    const gn_topo_handler_entry_t*  handlers;
    uint32_t contour_gaps;    /**< Bitmask: bit N = trust class N lacks E2E coverage. */
    void*    _reserved[4];    /**< MUST be zero; see abi-evolution.en.md §4. */
} gn_topology_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_TOPOLOGY_H */
