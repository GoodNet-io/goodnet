/// @file   core/identity/identity_plugin_signer.cpp

#include "identity_plugin_signer.hpp"

#include <cstring>

namespace gn::core::identity {

IdentityPluginSigner::IdentityPluginSigner(
    const gn_identity_signer_vtable_t* vtable,
    void*                              ctx,
    std::string                        key_label) noexcept
    : vtable_(vtable),
      ctx_(ctx),
      key_label_(std::move(key_label)) {
}

gn_result_t IdentityPluginSigner::pubkey(
    std::span<std::uint8_t, 32> out) const {
    if (vtable_ == nullptr || vtable_->get_pubkey == nullptr) {
        return GN_ERR_NOT_IMPLEMENTED;
    }

    /// Hot-path fast read — once a successful pubkey lookup populated
    /// the cache, subsequent callers skip the plugin thunk entirely.
    /// Identity pubkey is a stable per-key constant; rotating keys
    /// goes through a fresh `gn_core_install_identity_from_provider`
    /// install + kernel reload, not in-place mutation of this signer.
    if (pubkey_cached_.load(std::memory_order_acquire)) {
        std::memcpy(out.data(), pubkey_cache_.data(), 32);
        return GN_OK;
    }

    /// Slow path — double-checked under the mutex so concurrent first
    /// callers don't race two plugin queries against the same key.
    std::lock_guard<std::mutex> lk(pubkey_mu_);
    if (pubkey_cached_.load(std::memory_order_relaxed)) {
        std::memcpy(out.data(), pubkey_cache_.data(), 32);
        return GN_OK;
    }

    std::array<std::uint8_t, 32> tmp{};
    const auto rc = vtable_->get_pubkey(ctx_,
                                         key_label_.c_str(),
                                         tmp.data());
    if (rc != GN_OK) return rc;

    pubkey_cache_ = tmp;
    pubkey_cached_.store(true, std::memory_order_release);
    std::memcpy(out.data(), tmp.data(), 32);
    return GN_OK;
}

gn_result_t IdentityPluginSigner::sign(
    std::span<const std::uint8_t> message,
    std::span<std::uint8_t, 64>   out_signature) {
    if (vtable_ == nullptr || vtable_->sign == nullptr) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    return vtable_->sign(ctx_,
                          key_label_.c_str(),
                          message.data(),
                          message.size(),
                          out_signature.data());
}

}  // namespace gn::core::identity
