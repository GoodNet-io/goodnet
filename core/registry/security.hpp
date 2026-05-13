/// @file   core/registry/security.hpp
/// @brief  Security-provider registry (StackRegistry v1.x preview).
///
/// Holds N security providers concurrently, each declaring which
/// `gn_trust_class_t` values it admits via its
/// `allowed_trust_mask` slot. `find_for_trust(trust)` picks the
/// first registered provider whose mask admits the queried class
/// — that is how the kernel runs `null` on `Loopback` /
/// `IntraNode` and `noise` on `Untrusted` / `Peer` in the same
/// process without an operator config switch.
///
/// Per `docs/contracts/security-trust.en.md` §5 this is the
/// "StackRegistry v1.x" the v1.0-rc series promised. The
/// `register_provider` contract now allows multiple distinct
/// `provider_id`s; only duplicate ids still return
/// `GN_ERR_LIMIT_REACHED`. `current()` stays for backwards-compat
/// — returns the first registered provider, which is what
/// callers that don't carry a trust class observe.

#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <sdk/security.h>
#include <sdk/types.h>

namespace gn::core {

struct SecurityEntry {
    std::string                          provider_id;
    const gn_security_provider_vtable_t* vtable = nullptr;
    void*                                self   = nullptr;

    /// Same shape as `HandlerEntry::lifetime_anchor`. The kernel
    /// snapshots a `SecurityEntry` value-style; the returned
    /// anchor lives for the duration of the snapshot.
    std::shared_ptr<void>                lifetime_anchor;
};

class SecurityRegistry {
public:
    SecurityRegistry()                                    = default;
    SecurityRegistry(const SecurityRegistry&)             = delete;
    SecurityRegistry& operator=(const SecurityRegistry&)  = delete;

    /// Install @p vtable as a registered security provider.
    /// Returns `GN_ERR_LIMIT_REACHED` only when @p provider_id is
    /// already present (post-StackRegistry contract). Adding a
    /// second provider with a distinct id (e.g. `gn.security.noise`
    /// + `gn.security.null`) is the canonical path for
    /// per-trust-class selection.
    [[nodiscard]] gn_result_t register_provider(std::string_view provider_id,
                                                const gn_security_provider_vtable_t* vtable,
                                                void* self,
                                                std::shared_ptr<void> lifetime_anchor = {}) noexcept;

    /// Remove the provider matching @p provider_id. Other
    /// providers stay registered.
    [[nodiscard]] gn_result_t unregister_provider(std::string_view provider_id) noexcept;

    /// Pick a provider whose `allowed_trust_mask` admits @p trust.
    /// Returns the first matching entry in registration order, or
    /// a default-constructed entry when no registered provider
    /// admits the class.
    [[nodiscard]] SecurityEntry find_for_trust(gn_trust_class_t trust) const;

    /// Snapshot of the first registered provider (or empty when
    /// none). Backwards-compat for callers that pre-dated the
    /// StackRegistry split; new call sites should use
    /// `find_for_trust(trust)`.
    [[nodiscard]] SecurityEntry current() const;

    /// True when at least one provider is registered.
    [[nodiscard]] bool is_active() const noexcept;

private:
    using EntryVec = std::vector<SecurityEntry>;
    std::atomic<std::shared_ptr<const EntryVec>> entries_{nullptr};
};

} // namespace gn::core
