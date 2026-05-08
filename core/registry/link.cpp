/// @file   core/registry/link.cpp
/// @brief  Implementation of the link registry.

#include "link.hpp"

#include <mutex>

namespace gn::core {

gn_result_t LinkRegistry::register_link(
    std::string_view scheme,
    std::string_view protocol_id,
    const gn_link_vtable_t* vtable,
    void* self,
    gn_link_id_t* out_id,
    std::shared_ptr<void> lifetime_anchor) noexcept {

    if (vtable == nullptr || out_id == nullptr || scheme.empty()) {
        return GN_ERR_NULL_ARG;
    }

    /// `abi-evolution.md` §3a: defensive size-prefix check on the
    /// plugin-provided vtable. A vtable that declares a smaller
    /// size than the kernel's known minimum is from an SDK older
    /// than the slots the kernel intends to call — reject before
    /// any slot lookup.
    if (vtable->api_size < sizeof(gn_link_vtable_t)) {
        return GN_ERR_VERSION_MISMATCH;
    }

    std::unique_lock lock(mu_);
    std::string scheme_str{scheme};

    if (by_scheme_.contains(scheme_str)) {
        return GN_ERR_LIMIT_REACHED;
    }

    /// Empty or unset protocol_id selects the kernel default
    /// (`gnet-v1`). Resolution against ProtocolLayerRegistry
    /// happens at first `notify_connect` so an unregistered id
    /// surfaces close to the operator-controlled site.
    std::string protocol_id_str = protocol_id.empty()
        ? std::string{kDefaultProtocolId}
        : std::string{protocol_id};

    LinkEntry entry;
    entry.id              = next_id_.fetch_add(1, std::memory_order_relaxed);
    entry.scheme          = scheme_str;
    entry.protocol_id     = std::move(protocol_id_str);
    entry.vtable          = vtable;
    entry.self            = self;
    entry.lifetime_anchor = std::move(lifetime_anchor);

    const auto assigned_id = entry.id;
    by_id_[assigned_id] = scheme_str;
    by_scheme_.emplace(std::move(scheme_str), std::move(entry));
    *out_id = assigned_id;
    return GN_OK;
}

gn_result_t LinkRegistry::unregister_link(gn_link_id_t id) noexcept {
    if (id == GN_INVALID_ID) return GN_ERR_INVALID_ENVELOPE;

    std::unique_lock lock(mu_);

    auto it = by_id_.find(id);
    if (it == by_id_.end()) return GN_ERR_NOT_FOUND;

    const std::string scheme = it->second;
    by_id_.erase(it);
    by_scheme_.erase(scheme);
    return GN_OK;
}

std::optional<LinkEntry> LinkRegistry::find_by_scheme(
    std::string_view scheme) const {
    std::shared_lock lock(mu_);
    auto it = by_scheme_.find(std::string{scheme});
    if (it == by_scheme_.end()) return std::nullopt;
    return it->second;
}

std::optional<LinkEntry> LinkRegistry::find_by_id(gn_link_id_t id) const {
    std::shared_lock lock(mu_);
    auto by_id_it = by_id_.find(id);
    if (by_id_it == by_id_.end()) return std::nullopt;
    auto by_scheme_it = by_scheme_.find(by_id_it->second);
    if (by_scheme_it == by_scheme_.end()) return std::nullopt;
    return by_scheme_it->second;
}

std::size_t LinkRegistry::size() const noexcept {
    std::shared_lock lock(mu_);
    return by_id_.size();
}

} // namespace gn::core
