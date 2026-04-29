/// @file   core/registry/extension.cpp
/// @brief  Implementation of the extension registry.

#include "extension.hpp"

#include <mutex>

namespace gn::core {

namespace {

/// Compatibility rule from abi-evolution.md §2: major must match,
/// registered minor must be at least the requested minor. The
/// version word packs (major:8 minor:8 patch:16) per `gn_version_pack`.
[[nodiscard]] bool versions_compatible(std::uint32_t registered,
                                       std::uint32_t requested) noexcept {
    const std::uint32_t reg_major = (registered >> 24) & 0xff;
    const std::uint32_t req_major = (requested  >> 24) & 0xff;
    if (reg_major != req_major) return false;

    const std::uint32_t reg_minor = (registered >> 16) & 0xff;
    const std::uint32_t req_minor = (requested  >> 16) & 0xff;
    return reg_minor >= req_minor;
}

} // namespace

gn_result_t ExtensionRegistry::register_extension(
    std::string_view name,
    std::uint32_t version,
    const void* vtable,
    std::shared_ptr<void> lifetime_anchor) noexcept {

    if (name.empty() || vtable == nullptr) return GN_ERR_NULL_ARG;

    std::unique_lock lock(mu_);
    std::string key{name};
    if (entries_.contains(key)) return GN_ERR_LIMIT_REACHED;
    if (max_entries_ != 0 && entries_.size() >= max_entries_) {
        return GN_ERR_LIMIT_REACHED;
    }

    ExtensionEntry entry;
    entry.name            = std::string{name};
    entry.version         = version;
    entry.vtable          = vtable;
    entry.lifetime_anchor = std::move(lifetime_anchor);

    entries_.emplace(std::move(key), std::move(entry));
    return GN_OK;
}

void ExtensionRegistry::set_max_extensions(std::uint32_t cap) noexcept {
    std::unique_lock lock(mu_);
    max_entries_ = cap;
}

gn_result_t ExtensionRegistry::unregister_extension(std::string_view name) noexcept {
    if (name.empty()) return GN_ERR_NULL_ARG;
    std::unique_lock lock(mu_);
    auto it = entries_.find(std::string{name});
    if (it == entries_.end()) return GN_ERR_UNKNOWN_RECEIVER;
    entries_.erase(it);
    return GN_OK;
}

gn_result_t ExtensionRegistry::query_extension_checked(
    std::string_view name,
    std::uint32_t requested_version,
    const void** out_vtable) const noexcept {

    if (out_vtable == nullptr) return GN_ERR_NULL_ARG;
    *out_vtable = nullptr;

    std::shared_lock lock(mu_);
    auto it = entries_.find(std::string{name});
    if (it == entries_.end()) return GN_ERR_UNKNOWN_RECEIVER;

    if (!versions_compatible(it->second.version, requested_version)) {
        return GN_ERR_VERSION_MISMATCH;
    }
    *out_vtable = it->second.vtable;
    return GN_OK;
}

std::vector<ExtensionEntry> ExtensionRegistry::query_prefix(
    std::string_view prefix) const {
    std::vector<ExtensionEntry> matches;
    std::shared_lock lock(mu_);
    matches.reserve(entries_.size());
    for (const auto& [name, entry] : entries_) {
        if (name.starts_with(prefix)) matches.push_back(entry);
    }
    return matches;
}

std::size_t ExtensionRegistry::size() const noexcept {
    std::shared_lock lock(mu_);
    return entries_.size();
}

} // namespace gn::core
