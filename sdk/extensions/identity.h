/**
 * @file   sdk/extensions/identity.h
 * @brief  Extension contract for identity signers — HSM, PKCS#11,
 *         TPM, Keychain, WebAuthn, ... all conform to this vtable.
 *
 * A plugin that wants to back the kernel identity registers an
 * extension whose vtable is `gn_identity_signer_vtable_t`. The
 * kernel pulls signer thunks through the standard extension query;
 * when `gn_core_install_identity_from_provider(core, ext_id, key_label)`
 * is called, the kernel wraps the queried vtable in an internal
 * `IdentityPluginSigner` adapter and installs it on NodeIdentity.
 *
 * Pinned by `api_size` — older plugins pass a smaller value and the
 * kernel skips trailing thunks. Plugins MAY register under the
 * generic `GN_IDENTITY_EXTENSION_ID` name but the recommended
 * convention is a more specific dotted identifier within the
 * `gn.identity.*` family (e.g. `"gn.identity.pkcs11"`,
 * `"gn.identity.tpm"`, `"gn.identity.keychain"`) so multiple HSM
 * back-ends can coexist on the same kernel.
 *
 * Version pinning follows `abi-evolution.en.md` §2: query
 * `gn_core_query_extension_checked(name, GN_EXT_IDENTITY_SIGNER_VERSION)`
 * rejects with `GN_ERR_VERSION_MISMATCH` if the producer's major
 * differs or its minor is older than the consumer's compile-time pin.
 */
#ifndef GOODNET_SDK_EXTENSIONS_IDENTITY_H
#define GOODNET_SDK_EXTENSIONS_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Extension id under which identity providers register.
 *
 * Generic family root. Concrete HSM back-ends publish a more
 * specific dotted name (`gn.identity.pkcs11`, `gn.identity.tpm`,
 * `gn.identity.keychain`, `gn.identity.webauthn`) so a single
 * host can carry several identity providers and pick between
 * them by extension id at install time.
 */
#define GN_IDENTITY_EXTENSION_ID "gn.identity"

/** v1.0.0 — initial release. */
#define GN_EXT_IDENTITY_SIGNER_VERSION 0x00010000u

/**
 * @brief Thunk vtable — every identity provider plugin exposes one
 *        of these via `register_extension`.
 *
 * The provider chooses which key to use based on the @p key_label
 * parameter (opaque to the kernel; PKCS#11 plugins use CKA_LABEL,
 * TPM plugins use a persistent-handle string, Keychain plugins
 * use the keychain item name, etc.). The kernel does not parse
 * the label.
 *
 * `api_size` is the producer-side `sizeof(gn_identity_signer_vtable_t)`
 * at build time. The kernel uses it to gate which slots it may
 * dereference — an older plugin built against a smaller struct
 * passes a smaller `api_size`, the kernel skips trailing thunks,
 * and slots beyond the producer's `api_size` surface as
 * `GN_ERR_NOT_IMPLEMENTED` at install / sign time.
 */
typedef struct gn_identity_signer_vtable_s {
    /** sizeof(gn_identity_signer_vtable_t) at producer build time */
    size_t api_size;

    /**
     * @brief Copy the Ed25519 public key for @p key_label into the
     *        32-byte @p out buffer.
     *
     * @param ctx       Plugin self pointer (`gn_identity_signer_vtable_t::ctx`
     *                  if the plugin chose to carry one there, otherwise the
     *                  pointer it passed alongside the registration).
     * @param key_label @borrowed plugin-opaque key identifier.
     *                  NUL-terminated.
     * @param out       @borrowed caller-allocated 32-byte buffer.
     *
     * @return `GN_OK` on success; `GN_ERR_NOT_FOUND` if the label
     *         doesn't resolve to a known key; `GN_ERR_INVALID_STATE`
     *         if the token / device isn't ready; `GN_ERR_NULL_ARG`
     *         on NULL inputs.
     */
    gn_result_t (*get_pubkey)(
        void*               ctx,
        const char*         key_label,
        uint8_t*            out);  /* 32 bytes */

    /**
     * @brief Sign @p message_len bytes at @p message with the key
     *        identified by @p key_label. Output: 64-byte Ed25519
     *        detached signature at @p out_sig.
     *
     * Thread-safe — multiple sign calls may overlap. The plugin owns
     * any per-token serialisation it needs (PKCS#11 session locking,
     * TPM tab management, etc.); the kernel does not coordinate.
     *
     * @param ctx          Plugin self pointer; same as in get_pubkey.
     * @param key_label    @borrowed plugin-opaque key identifier.
     * @param message      @borrowed bytes to sign for the duration
     *                     of the call.
     * @param message_len  Length of @p message in bytes.
     * @param out_sig      @borrowed caller-allocated 64-byte buffer.
     *
     * @return `GN_OK` on success; `GN_ERR_NOT_FOUND` if the label
     *         doesn't resolve to a known key; `GN_ERR_INVALID_STATE`
     *         on token / device error; `GN_ERR_NULL_ARG` on NULL
     *         inputs.
     */
    gn_result_t (*sign)(
        void*               ctx,
        const char*         key_label,
        const uint8_t*      message,
        size_t              message_len,
        uint8_t*            out_sig);  /* 64 bytes */
} gn_identity_signer_vtable_t;

GN_VTABLE_API_SIZE_FIRST(gn_identity_signer_vtable_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_IDENTITY_H */
