/// @file   core/registry/security.cpp

#include "security.hpp"

#include <core/kernel/safe_invoke.hpp>

namespace gn::core {

std::uint32_t SecurityEntry::trust_mask() const noexcept {
    if (vtable == nullptr || vtable->allowed_trust_mask == nullptr) {
        return 0u;
    }
    const auto v = ::gn::core::safe_call_value<std::uint32_t>(
        "security.allowed_trust_mask",
        vtable->allowed_trust_mask, self);
    return v.value_or(0u);
}

gn_result_t SecurityRegistry::register_provider(
    std::string_view provider_id,
    const gn_security_provider_vtable_t* vtable,
    void* self,
    std::shared_ptr<void> lifetime_anchor_in) noexcept {
    /// Local copy — the lambda below stores the anchor by value
    /// into the fresh `SecurityEntry`. Renamed from the header's
    /// `lifetime_anchor` to dodge clang-tidy's pass-by-value
    /// warning while still matching the parameter name in the
    /// public declaration.
    auto lifetime_anchor = std::move(lifetime_anchor_in);

    if (provider_id.empty() || vtable == nullptr) return GN_ERR_NULL_ARG;

    /// `abi-evolution.md` §3a: defensive size-prefix check.
    if (vtable->api_size < sizeof(gn_security_provider_vtable_t)) {
        return GN_ERR_VERSION_MISMATCH;
    }

    /// CAS-driven append. Read the current vec, copy + append,
    /// CAS-swap; retry on contention. Duplicate provider_id is
    /// rejected — the kernel admits one entry per provider name.
    for (;;) {
        auto cur = entries_.load(std::memory_order_acquire);
        if (cur != nullptr) {
            for (const auto& e : *cur) {
                if (e.provider_id == provider_id) {
                    return GN_ERR_LIMIT_REACHED;
                }
            }
        }
        auto fresh = std::make_shared<EntryVec>(cur ? *cur : EntryVec{});
        fresh->push_back(SecurityEntry{
            .provider_id     = std::string{provider_id},
            .vtable          = vtable,
            .self            = self,
            .lifetime_anchor = lifetime_anchor,
        });
        std::shared_ptr<const EntryVec> publish = std::move(fresh);
        if (entries_.compare_exchange_weak(cur, publish,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            return GN_OK;
        }
    }
}

gn_result_t SecurityRegistry::unregister_provider(
    std::string_view provider_id) noexcept {

    for (;;) {
        auto cur = entries_.load(std::memory_order_acquire);
        if (!cur || cur->empty()) return GN_ERR_NOT_FOUND;
        std::size_t hit = cur->size();
        for (std::size_t i = 0; i < cur->size(); ++i) {
            if ((*cur)[i].provider_id == provider_id) {
                hit = i;
                break;
            }
        }
        if (hit == cur->size()) return GN_ERR_NOT_FOUND;

        auto fresh = std::make_shared<EntryVec>();
        fresh->reserve(cur->size() - 1);
        for (std::size_t i = 0; i < cur->size(); ++i) {
            if (i == hit) continue;
            fresh->push_back((*cur)[i]);
        }
        std::shared_ptr<const EntryVec> publish =
            fresh->empty() ? nullptr
                            : std::shared_ptr<const EntryVec>(std::move(fresh));
        if (entries_.compare_exchange_weak(cur, publish,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            return GN_OK;
        }
    }
}

SecurityEntry SecurityRegistry::find_for_trust(gn_trust_class_t trust) const {
    auto cur = entries_.load(std::memory_order_acquire);
    if (!cur || cur->empty()) return SecurityEntry{};
    const std::uint32_t bit = 1u << static_cast<unsigned>(trust);
    for (const auto& e : *cur) {
        if ((e.trust_mask() & bit) != 0u) return e;
    }
    return SecurityEntry{};
}

SecurityEntry SecurityRegistry::current() const {
    auto cur = entries_.load(std::memory_order_acquire);
    if (!cur || cur->empty()) return SecurityEntry{};
    return cur->front();
}

bool SecurityRegistry::is_active() const noexcept {
    auto cur = entries_.load(std::memory_order_acquire);
    return cur != nullptr && !cur->empty();
}

} // namespace gn::core
