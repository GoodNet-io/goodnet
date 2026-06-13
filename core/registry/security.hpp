/// @file   core/registry/security.hpp
/// @brief  Security-provider registry (multi-provider StackRegistry).
///
/// Holds N security providers concurrently, each declaring which
/// `gn_trust_class_t` values it admits via its
/// `allowed_trust_mask` slot. `find_for_trust(trust)` picks the
/// first registered provider whose mask admits the queried class
/// — that is how the kernel runs `null` on `Loopback` /
/// `IntraNode` and `noise` on `Untrusted` / `Peer` in the same
/// process without an operator config switch.
///
/// `register_provider` admits multiple distinct `provider_id`s;
/// only duplicate ids return `GN_ERR_LIMIT_REACHED`. `current()`
/// is kept for callers that do not carry a trust class — it
/// returns the first registered provider. See
/// `docs/contracts/security-trust.en.md` §4 for the per-component
/// mask gate this registry feeds.

#pragma once

#include <memory>
#include <atomic>
#include <string>
#include <string_view>
#include <vector>

#include <sdk/security.h>
#include <sdk/types.h>
#include <core/util/atomic_shared_ptr.hpp>

namespace gn::core {

struct SecurityEntry {
    std::string                          provider_id;
    const gn_security_provider_vtable_t* vtable = nullptr;
    void*                                self   = nullptr;

    /// Same shape as `HandlerEntry::lifetime_anchor`. The kernel
    /// snapshots a `SecurityEntry` value-style; the returned
    /// anchor lives for the duration of the snapshot.
    std::shared_ptr<void>                lifetime_anchor;

    /// Read the provider's `allowed_trust_mask` through the
    /// `safe_invoke` wrapper. A throwing slot or a missing entry
    /// collapses to 0 (deny) per `security-trust.en.md` §4 — the
    /// gate cannot trust a provider that cannot enumerate its
    /// admitted classes. Single source of truth so `find_for_trust`
    /// and `SessionRegistry::create` cannot drift apart on the
    /// gate's interpretation.
    [[nodiscard]] std::uint32_t trust_mask() const noexcept;

    /// Read the provider's `provides_flags` bitmask (GN_SEC_PROVIDES_*).
    /// Guards with GN_API_HAS for vtables built before this slot existed.
    /// Returns 0 on NULL vtable, missing slot, or throwing slot.
    [[nodiscard]] std::uint32_t provides_flags() const noexcept;
};

class SecurityRegistry {
public:
    SecurityRegistry()                                    = default;
    SecurityRegistry(const SecurityRegistry&)             = delete;
    SecurityRegistry& operator=(const SecurityRegistry&)  = delete;

    /// Install @p vtable as a registered security provider.
    /// Returns `GN_ERR_LIMIT_REACHED` only when @p provider_id is
    /// already present. Adding a second provider with a distinct
    /// id (e.g. `gn.security.noise` + `gn.security.null`) is the
    /// canonical path for per-trust-class selection.
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

    /// Atomic snapshot of all registered providers in registration order.
    /// Used by the topology builder. Returns an empty vector when none are
    /// registered.
    [[nodiscard]] std::vector<SecurityEntry> snapshot() const;

private:
    using EntryVec = std::vector<SecurityEntry>;
    util::AtomicSharedPtr<const EntryVec> entries_;
};

} // namespace gn::core
