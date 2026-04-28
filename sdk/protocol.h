/**
 * @file   sdk/protocol.h
 * @brief  C ABI for the mesh-framing protocol layer.
 *
 * The protocol layer is the single mandatory plugin slot. The kernel binary
 * statically links exactly one implementation of @ref gn_protocol_layer_vtable_t.
 * See `docs/contracts/protocol-layer.md`.
 */
#ifndef GOODNET_SDK_PROTOCOL_H
#define GOODNET_SDK_PROTOCOL_H

#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Per-connection state passed to @ref gn_protocol_layer_vtable_t.deframe
 *        and `.frame`.
 *
 * The struct is opaque to the plugin; accessor functions (TBD in
 * `sdk/connection.h` once the transport contract lands) provide read access
 * to local identity, remote identity, connection id, and a plugin-private
 * scratch slot.
 */
typedef struct gn_connection_context_s gn_connection_context_t;

/**
 * @brief Result of a single deframe call.
 *
 * The plugin owns @ref messages storage; envelope payload pointers are
 * borrowed from the input byte buffer. Both remain valid for the duration
 * of one dispatch cycle.
 */
typedef struct gn_deframe_result_s {
    const gn_message_t* messages;        /**< zero or more envelopes */
    size_t              count;
    size_t              bytes_consumed;  /**< wire bytes the kernel may discard */
    void*               _reserved[4];
} gn_deframe_result_t;

/**
 * @brief Vtable for an `IProtocolLayer` implementation in C.
 *
 * The kernel calls every function with a plugin-supplied `self` pointer
 * obtained at plugin init.
 */
typedef struct gn_protocol_layer_vtable_s {
    /**
     * @brief Stable identifier; lowercase hyphenated. Example: "gnet-v1".
     *
     * The returned pointer must remain valid for the lifetime of the plugin.
     */
    const char* (*protocol_id)(void* self);

    /**
     * @brief Parse one or more envelopes from a decrypted byte stream.
     *
     * @param self       plugin instance
     * @param ctx        per-connection context
     * @param bytes      input buffer (may contain partial trailing frame)
     * @param bytes_size length of @p bytes
     * @param out        populated on @ref GN_OK; messages borrow from `bytes`
     *
     * @return @ref GN_OK and a populated @p out; @ref GN_ERR_DEFRAME_INCOMPLETE
     *         when no full frame is available (kernel will retry); other
     *         negative codes on permanent error (kernel closes the connection).
     */
    gn_result_t (*deframe)(void* self,
                           gn_connection_context_t* ctx,
                           const uint8_t* bytes, size_t bytes_size,
                           gn_deframe_result_t* out);

    /**
     * @brief Serialise an envelope into wire bytes.
     *
     * The plugin allocates the output buffer and sets `*out_free` to a
     * destructor that the kernel calls once the bytes are committed to the
     * security layer.
     */
    gn_result_t (*frame)(void* self,
                         gn_connection_context_t* ctx,
                         const gn_message_t* msg,
                         uint8_t** out_bytes, size_t* out_size,
                         void (**out_free)(uint8_t*));

    /**
     * @brief Maximum payload that this protocol can frame in one message.
     *
     * Used by the kernel for fragmentation decisions. Must be a constant
     * over the plugin's lifetime.
     */
    size_t (*max_payload_size)(void* self);

    /**
     * @brief Optional teardown. Called once after all in-flight dispatches
     *        complete. Plugin frees its `self`-owned resources here.
     */
    void (*destroy)(void* self);

    /**
     * @brief Bitmask of `gn_trust_class_t` values this protocol may
     *        serve.
     *
     * Bit `1u << GN_TRUST_<X>` set means this protocol may deframe a
     * connection at class `<X>`. The kernel reads the mask at
     * registration; per `security-trust.md` §4 the cartesian product
     * across {transport-trust, security mask, protocol mask} is
     * validated on Wire phase before any envelope rides.
     *
     * Examples:
     *   - gnet-v1: `1u<<UNTRUSTED | 1u<<PEER | 1u<<LOOPBACK | 1u<<INTRA_NODE`
     *   - raw-v1:  `1u<<LOOPBACK | 1u<<INTRA_NODE`
     */
    uint32_t (*allowed_trust_mask)(void* self);

    void* _reserved[3];
} gn_protocol_layer_vtable_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_PROTOCOL_H */
