/**
 * @file   sdk/security.h
 * @brief  C ABI for security-provider plugins.
 *
 * Security providers terminate the handshake, derive transport keys,
 * and perform per-message encryption/decryption. The canonical
 * implementation is the Noise provider (`plugins/security/noise/docs/handshake.md`).
 *
 * See `docs/contracts/security-trust.en.md` for trust-class policy.
 */
#ifndef GOODNET_SDK_SECURITY_H
#define GOODNET_SDK_SECURITY_H

#include <stdint.h>
#include <stddef.h>

#include <sdk/abi.h>
#include <sdk/types.h>
#include <sdk/trust.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sizes of cryptographic material for the canonical suite. */
#define GN_CIPHER_KEY_BYTES     32   /**< ChaCha20 key */
#define GN_CIPHER_NONCE_BYTES   12   /**< AEAD nonce */
#define GN_AEAD_TAG_BYTES       16   /**< Poly1305 tag */
#define GN_HASH_BYTES           32   /**< channel-binding hash exposed via gn_handshake_keys_t */

/* `gn_handshake_role_t` lives in `sdk/trust.h` so that both `host_api.h`
 * and `security.h` see the type without circular includes. */

/**
 * @brief Transport-phase symmetric keys produced by a successful handshake.
 *
 * The provider exports these once. After export the source session
 * zeroises its own copies and refuses further encrypt/decrypt calls.
 */
typedef struct gn_handshake_keys_s {
    /** sizeof(gn_handshake_keys_t) at producer build time per
     *  `abi-evolution.md` §3. */
    uint32_t api_size;
    uint8_t  send_cipher_key[GN_CIPHER_KEY_BYTES];
    uint8_t  recv_cipher_key[GN_CIPHER_KEY_BYTES];
    uint64_t initial_send_nonce;
    uint64_t initial_recv_nonce;
    uint8_t  handshake_hash[GN_HASH_BYTES];   /**< channel binding */
    uint8_t  peer_static_pk[GN_PUBLIC_KEY_BYTES];

    void*    _reserved[4];
} gn_handshake_keys_t;

GN_VTABLE_API_SIZE_FIRST(gn_handshake_keys_t);

/**
 * @brief Output buffer for variable-length security messages.
 *
 * The plugin allocates `bytes` and pairs it with `free_fn` so the
 * kernel can release it once the bytes have been handed to the
 * transport. The struct is per-call output — both sides build it
 * fresh on every API entry — so the size-prefix evolution pattern
 * (`api_size` first) does not apply; growing the struct requires
 * a major ABI bump, not a runtime size check.
 */
typedef struct gn_secure_buffer_s {
    uint8_t* bytes;
    size_t   size;
    /**
     * Producer-supplied opaque pointer passed back through
     * `free_fn`. Captures whatever destruction state the
     * producer needs — a Rust `Box::into_raw` handle, a Python
     * `Py_INCREF`'d object, an arena id. May be NULL when the
     * producer's free_fn is stateless (`std::free`, etc.).
     */
    void*    free_user_data;
    /**
     * Free the buffer. The first argument is the producer-supplied
     * @ref free_user_data so non-C language bindings can recover
     * captured destruction state without the C-level
     * `void(*)(uint8_t*)` form leaking. The second argument is
     * @ref bytes verbatim. NULL when the buffer needs no
     * destruction (e.g. zero-length).
     */
    void  (*free_fn)(void* user_data, uint8_t* bytes);
} gn_secure_buffer_t;

/**
 * @brief Vtable for an `ISecurityProvider` implementation.
 *
 * Per `security-trust.md`, every entry that creates or routes a
 * connection takes @ref gn_trust_class_t explicitly.
 */
typedef struct gn_security_provider_vtable_s {
    uint32_t api_size;

    /**
     * @brief Stable identifier. Examples: `"noise-xx"`, `"noise-ik"`,
     *        `"null"`.
     *
     * @return @borrowed pointer; valid for the lifetime of the plugin.
     */
    const char* (*provider_id)(void* self);

    /**
     * @brief Open a new handshake state for a connection.
     *
     * @param trust            declared trust class of the connection
     * @param role             initiator or responder per `notify_connect`
     * @param local_static_sk  @borrowed local Ed25519 secret key
     *                         (libsodium layout, 64 bytes). The plugin
     *                         derives X25519 / sign material as needed.
     * @param local_static_pk  @borrowed matching Ed25519 public key
     *                         (32 bytes).
     * @param remote_static_pk @borrowed peer Ed25519 public key when
     *                         the pattern knows it up-front (IK
     *                         initiator side); NULL when the pattern
     *                         learns it during the handshake (XX, NK).
     * @param out_state        @owned handshake-state handle; the kernel
     *                         pairs it with `handshake_close` for
     *                         disposal.
     */
    gn_result_t (*handshake_open)(void* self,
                                  gn_conn_id_t conn,
                                  gn_trust_class_t trust,
                                  gn_handshake_role_t role,
                                  const uint8_t local_static_sk[GN_PRIVATE_KEY_BYTES],
                                  const uint8_t local_static_pk[GN_PUBLIC_KEY_BYTES],
                                  const uint8_t* remote_static_pk,
                                  void** out_state);

    /**
     * @brief Drive one step of the handshake.
     *
     * @param incoming      @borrowed bytes received from peer.
     * @param incoming_size length of @p incoming; may be 0 on the
     *                      initial step.
     * @param out_message   caller-allocated; on return the plugin
     *                      fills `bytes` with `@owned` outgoing
     *                      handshake bytes paired with `free_fn`.
     *                      `bytes == NULL` when no output is produced
     *                      this step.
     */
    gn_result_t (*handshake_step)(void* self,
                                  void* state,
                                  const uint8_t* incoming, size_t incoming_size,
                                  gn_secure_buffer_t* out_message);

    /**
     * @brief Test whether the handshake has reached the transport phase.
     */
    int (*handshake_complete)(void* self, void* state);

    /**
     * @brief Export transport keys after `handshake_complete` returns true.
     *
     * The plugin zeroises its own copy of the keys after this call. Any
     * subsequent encrypt/decrypt on @p state returns
     * @ref GN_ERR_INVALID_STATE.
     *
     * @param out_keys @borrowed caller-allocated; the plugin writes
     *                 the symmetric keys + channel-binding hash into
     *                 the struct. The caller copies the bytes it
     *                 needs and zeroises the struct after use.
     */
    gn_result_t (*export_transport_keys)(void* self,
                                         void* state,
                                         gn_handshake_keys_t* out_keys);

    /**
     * @brief Encrypt a plaintext payload.
     *
     * @param plaintext @borrowed; copied internally if needed.
     * @param out       caller-allocated; on return the plugin fills
     *                  `bytes` with `@owned` ciphertext paired with
     *                  `free_fn`.
     */
    gn_result_t (*encrypt)(void* self,
                           void* state,
                           const uint8_t* plaintext, size_t plaintext_size,
                           gn_secure_buffer_t* out);

    /**
     * @brief Decrypt a ciphertext payload.
     *
     * @param ciphertext @borrowed; copied internally if needed.
     * @param out        caller-allocated; on return the plugin fills
     *                   `bytes` with `@owned` plaintext paired with
     *                   `free_fn`.
     */
    gn_result_t (*decrypt)(void* self,
                           void* state,
                           const uint8_t* ciphertext, size_t ciphertext_size,
                           gn_secure_buffer_t* out);

    /**
     * @brief Rekey both ciphers atomically.
     *
     * Resets the nonce on both send and receive cipher state.
     */
    gn_result_t (*rekey)(void* self, void* state);

    /**
     * @brief Tear down a handshake state. Zeroises remaining key material.
     */
    void (*handshake_close)(void* self, void* state);

    /** Plugin destruction. */
    void (*destroy)(void* self);

    /**
     * @brief Bitmask of `gn_trust_class_t` values this provider may serve.
     *
     * Bit `1u << GN_TRUST_<X>` set means the provider permits its own
     * involvement on a connection of class `<X>`. The kernel reads
     * this once at `register_security` time and enforces the gate on
     * every `SessionRegistry::create`; a connection whose trust class is not
     * in the mask is rejected before any handshake byte rides — per
     * `security-trust.md` §4.
     *
     * Examples:
     *   - NoiseProvider: `1u<<UNTRUSTED | 1u<<PEER | 1u<<LOOPBACK | 1u<<INTRA_NODE`
     *   - NullProvider:  `1u<<LOOPBACK | 1u<<INTRA_NODE`
     */
    uint32_t (*allowed_trust_mask)(void* self);

    void* _reserved[4];
} gn_security_provider_vtable_t;

GN_VTABLE_API_SIZE_FIRST(gn_security_provider_vtable_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_SECURITY_H */
