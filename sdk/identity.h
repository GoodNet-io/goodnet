/**
 * @file   sdk/identity.h
 * @brief  Identity primitives surface (kernel-held key registry,
 *         purpose enum, capability blob callback).
 *
 * Exposes the kernel's NodeIdentity v2 sub-key registry to plugins
 * through six host_api slots (`register_local_key`,
 * `delete_local_key`, `list_local_keys`, `sign_local`,
 * `sign_local_by_id`, plus `present_capability_blob` /
 * `subscribe_capability_blob` for the wire blob channel). Plugin
 * authors compose multi-factor authentication, verifiable
 * credentials, and similar identity-bearing layers on these
 * primitives — the kernel never lets a plugin see a private-key
 * byte. See `docs/contracts/identity.en.md` §4-§6 for the
 * authoritative semantics.
 */
#ifndef GOODNET_SDK_IDENTITY_H
#define GOODNET_SDK_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Purpose of a key registered in the kernel's sub-key
 *        registry.
 *
 * Mirrors the W3C DID `verificationMethod.purpose` model and the
 * FIDO key-purpose taxonomy. Each registered sub-key carries
 * exactly one purpose; a plugin asking the kernel to sign with
 * `GN_KEY_PURPOSE_X` selects the first sub-key registered with
 * that purpose. Built-in keys carry implicit purposes:
 *
 * - `user_pk` (the long-lived portable identity) signs with
 *   `ASSERT` and `ROTATION_SIGN`.
 * - `device_pk` (per-machine handshake key) signs with `AUTH`
 *   and `KEY_AGREEMENT`.
 *
 * Plugin-registered sub-keys may take any purpose; multiple
 * sub-keys per purpose are allowed (e.g. a user with two
 * yubikeys both registered as `SECOND_FACTOR`). Kernel chooses
 * via `sign_local` first-found heuristic; explicit selection is
 * available through `sign_local_by_id`.
 */
typedef enum gn_key_purpose_e {
    GN_KEY_PURPOSE_AUTH              = 1, /**< device handshake auth */
    GN_KEY_PURPOSE_ASSERT            = 2, /**< sign claims about self */
    GN_KEY_PURPOSE_KEY_AGREEMENT     = 3, /**< X25519 ECDH (device) */
    GN_KEY_PURPOSE_CAPABILITY_INVOKE = 4, /**< sign RPC invocations */
    GN_KEY_PURPOSE_ROTATION_SIGN     = 5, /**< sign next-pk in rotation chain */
    GN_KEY_PURPOSE_SECOND_FACTOR     = 6, /**< user-level 2FA challenge response */
    GN_KEY_PURPOSE_RECOVERY          = 7  /**< offline backup, signs rotation when primary lost */
} gn_key_purpose_t;

/**
 * @brief Opaque identifier for a registered sub-key.
 *
 * Allocated by the kernel on `register_local_key` success.
 * Values are monotonically increasing starting at 1; 0 is the
 * `GN_INVALID_KEY_ID` sentinel. The id encodes the purpose in
 * its top 4 bits so iteration callers can filter without a
 * round-trip through `list_local_keys`.
 */
typedef uint64_t gn_key_id_t;

/** Sentinel value indicating an unset / invalid key id. */
#define GN_INVALID_KEY_ID ((gn_key_id_t)0)

/**
 * @brief Read-only descriptor of a registered sub-key.
 *
 * Returned by `list_local_keys`. The descriptor never carries
 * private bytes — only the purpose, public-key copy, free-text
 * label, creation timestamp, and the kernel-allocated id. Callers
 * use the id with `sign_local_by_id` for explicit key selection.
 *
 * Field order is tuned against `clang-tidy`'s padding analysis:
 * 64-bit fields up front, then the 32-byte public-key block,
 * then the 64-byte label, then the 4-pointer reserved tail, then
 * the small scalars. Adding fields lands before `_reserved` per
 * `abi-evolution.md` §3.
 */
typedef struct gn_key_descriptor_s {
    gn_key_id_t         id;
    int64_t             created_unix_ts;
    uint8_t             public_key[GN_PUBLIC_KEY_BYTES];
    /** NUL-terminated UTF-8; up to 64 bytes including the NUL. */
    char                label[64];
    void*               _reserved[4];
    uint32_t            api_size;        /**< sizeof(gn_key_descriptor_t) */
    gn_key_purpose_t    purpose;
} gn_key_descriptor_t;

/**
 * @brief Capability-blob inbound callback.
 *
 * Fired on the publishing thread when a peer's
 * `present_capability_blob` arrives over the wire (msg id
 * `0x13`). `blob` borrows for the call duration; subscribers
 * must not retain the pointer past the callback return. The
 * `expires_unix_ts` field carries the sender's stated
 * expiration; the kernel does not parse the blob payload.
 *
 * Subscribers running long work post back through
 * `host_api->set_timer(0, …)` per `timer.md` §2.
 */
typedef void (*gn_capability_blob_cb_t)(
    void*               user_data,
    gn_conn_id_t        from_conn,
    const uint8_t*      blob,
    size_t              size,
    int64_t             expires_unix_ts);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_IDENTITY_H */
