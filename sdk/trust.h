/**
 * @file   sdk/trust.h
 * @brief  Trust class declaration for connections.
 *
 * Every connection has a trust level. Every security stack has a permitted
 * set of trust levels. The kernel rejects mismatches at construction time.
 * See `docs/contracts/security-trust.en.md`.
 */
#ifndef GOODNET_SDK_TRUST_H
#define GOODNET_SDK_TRUST_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Trust level associated with a connection.
 *
 * Values are ordered by increasing trust. The kernel never decreases a
 * connection's trust over its lifetime; only the upgrade
 * `Untrusted → Peer` after a security handshake is permitted.
 */
typedef enum gn_trust_class_e {
    /** Inbound connection from an untrusted address; default. */
    GN_TRUST_UNTRUSTED  = 0,

    /** Public key known and verified through a security handshake. */
    GN_TRUST_PEER       = 1,

    /** Local IPC or 127.0.0.1/::1 — no encryption needed. */
    GN_TRUST_LOOPBACK   = 2,

    /** Between plugins of the same kernel; in-process. */
    GN_TRUST_INTRA_NODE = 3
} gn_trust_class_t;

/**
 * @brief Returns nonzero if a transition from @p from to @p to is permitted.
 *
 * Only `Untrusted → Peer` is allowed as an upgrade; identity transitions
 * are no-ops; any other combination is rejected.
 */
static inline int gn_trust_can_upgrade(gn_trust_class_t from, gn_trust_class_t to) {
    if (from == GN_TRUST_UNTRUSTED && to == GN_TRUST_PEER) return 1;
    return from == to;
}

/**
 * @brief Handshake role at the transport ↔ security boundary.
 *
 * The transport plugin sets the role on `host_api->notify_connect` based on
 * who initiated the connection: the side that called `connect(uri)` is the
 * initiator; the side that accepted an inbound socket is the responder.
 * The kernel propagates the value to `security_provider->handshake_open`
 * so the provider can drive the asymmetric pattern progression.
 */
typedef enum gn_handshake_role_e {
    GN_ROLE_INITIATOR = 0,
    GN_ROLE_RESPONDER = 1
} gn_handshake_role_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_TRUST_H */
