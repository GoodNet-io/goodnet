/**
 * @file   sdk/connection.h
 * @brief  Per-connection context accessors used by the protocol layer.
 *
 * The `gn_connection_context_t` type is opaque to plugins; the kernel hands
 * a pointer to it on every `IProtocolLayer::deframe` and `frame` call. The
 * accessors below are how plugins read connection state.
 *
 * See `docs/contracts/link.md` §7 and
 * `docs/contracts/protocol-layer.md` §3.
 */
#ifndef GOODNET_SDK_CONNECTION_H
#define GOODNET_SDK_CONNECTION_H

#include <stdint.h>

#include <sdk/types.h>
#include <sdk/trust.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque per-connection state.
 *
 * Defined in the kernel. Plugins receive a pointer and pass it to the
 * accessors below; the layout is not exposed.
 */
typedef struct gn_connection_context_s gn_connection_context_t;

/**
 * @brief Local node public key for this connection (32 bytes).
 *
 * @return @borrowed pointer to the local node's Ed25519 public key. The
 *         pointer is valid for the lifetime of the connection context.
 */
const uint8_t* gn_ctx_local_pk(const gn_connection_context_t* ctx);

/**
 * @brief Remote peer public key (32 bytes).
 *
 * Populated after the security handshake completes. Before that, the
 * pointer addresses an all-zero buffer.
 *
 * @return @borrowed pointer; valid for the lifetime of the connection.
 */
const uint8_t* gn_ctx_remote_pk(const gn_connection_context_t* ctx);

/** Stable kernel-allocated id for this connection. */
gn_conn_id_t gn_ctx_conn_id(const gn_connection_context_t* ctx);

/** Trust class of the connection. Read-only at the plugin layer. */
gn_trust_class_t gn_ctx_trust(const gn_connection_context_t* ctx);

/**
 * @brief Whether the protocol layer may honour `EXPLICIT_SENDER` /
 *        `EXPLICIT_RECEIVER` flags on inbound frames.
 *
 * Default `false`. The deframer reads this flag to gate against
 * sender_pk spoofing: a regular peer that has not been granted relay
 * capability cannot claim a sender_pk other than the connection's
 * authenticated remote pk. Operators / a future relay handler set the
 * flag on connections that legitimately carry forwarded traffic.
 *
 * Returns 1 when relay is allowed, 0 otherwise.
 */
int gn_ctx_allows_relay(const gn_connection_context_t* ctx);

/**
 * @brief Plugin-private scratch slot.
 *
 * The kernel never inspects the value. Transports use this to attach a
 * per-connection state object that protocol-layer or security-layer
 * partners can pick up by calling the accessor with the same context.
 */
void* gn_ctx_plugin_state(const gn_connection_context_t* ctx);

/** Set the plugin-private scratch slot. */
void gn_ctx_set_plugin_state(gn_connection_context_t* ctx, void* state);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_CONNECTION_H */
