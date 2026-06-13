/// @file   core/identity/identity_plugin_signer.hpp
/// @brief  `IdentitySigner` adapter that routes through a plugin
///         vtable conforming to `sdk/extensions/identity.h`.
///
/// Phase 2 of the HSM-friendly identity refactor: hosts call
/// `gn_core_install_identity_from_provider(core, ext_id, key_label)`,
/// the kernel resolves the extension by name, pulls the
/// `gn_identity_signer_vtable_t`, and wraps it in this adapter so
/// every kernel call site that already migrated to
/// `signer()->sign(...)` in Phase 1 stays untouched while the actual
/// private bytes live in a PKCS#11 token, TPM, OS keychain, or
/// WebAuthn authenticator.
///
/// The wrapped vtable + opaque `ctx` pointer + opaque `key_label`
/// are all plugin-supplied; the kernel hands them back unchanged on
/// every thunk invocation. The plugin keeps its lifetime anchor alive
/// for the duration of the kernel session (registered alongside the
/// extension entry per `core/registry/extension.hpp`); on kernel
/// shutdown the unique_ptr<IdentitySigner> embedded in NodeIdentity
/// is destroyed before the plugin manager drops the anchor.

#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>

#include <sdk/extensions/identity.h>

#include "signer.hpp"

namespace gn::core::identity {

/// Forwards every `IdentitySigner` method through the plugin-supplied
/// `gn_identity_signer_vtable_t`. Thread-safe — `sign()` is documented
/// as concurrency-safe at the SDK level (`sdk/extensions/identity.h`
/// §sign thunk) and the cached pubkey uses double-checked locking so
/// the first read populates the slot without serialising subsequent
/// hot-path callers.
class IdentityPluginSigner final : public IdentitySigner {
public:
    /// @param vtable    Plugin-owned vtable; the kernel keeps the
    ///                  pointer for the signer's lifetime. The plugin
    ///                  guarantees vtable-pointer stability via its
    ///                  lifetime anchor (extension registration).
    /// @param ctx       Plugin-opaque self pointer; kernel never
    ///                  dereferences, passes through to every thunk.
    /// @param key_label Plugin-opaque key identifier (PKCS#11
    ///                  CKA_LABEL, TPM handle string, Keychain item
    ///                  name, ...). The signer keeps a private copy.
    IdentityPluginSigner(const gn_identity_signer_vtable_t* vtable,
                         void*                              ctx,
                         std::string                        key_label) noexcept;

    IdentityPluginSigner(const IdentityPluginSigner&)            = delete;
    IdentityPluginSigner& operator=(const IdentityPluginSigner&) = delete;
    IdentityPluginSigner(IdentityPluginSigner&&)                 = delete;
    IdentityPluginSigner& operator=(IdentityPluginSigner&&)      = delete;

    gn_result_t pubkey(std::span<std::uint8_t, 32> out) const override;
    gn_result_t sign(std::span<const std::uint8_t> message,
                     std::span<std::uint8_t, 64>   out_signature) override;

private:
    const gn_identity_signer_vtable_t*   vtable_;
    void*                                ctx_;
    std::string                          key_label_;
    mutable std::array<std::uint8_t, 32> pubkey_cache_{};
    mutable std::atomic<bool>            pubkey_cached_{false};
    mutable std::mutex                   pubkey_mu_;
};

}  // namespace gn::core::identity
