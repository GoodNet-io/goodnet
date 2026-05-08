/// @file   core/registry/protocol_layer.cpp
/// @brief  Implementation of the protocol-layer registry.

#include "protocol_layer.hpp"

#include <mutex>
#include <utility>

namespace gn::core {

gn_result_t ProtocolLayerRegistry::register_layer(
    std::shared_ptr<::gn::IProtocolLayer> layer,
    protocol_layer_id_t* out_id,
    std::shared_ptr<void> lifetime_anchor) noexcept {

    if (layer == nullptr || out_id == nullptr) {
        return GN_ERR_NULL_ARG;
    }

    std::string protocol_id_str{layer->protocol_id()};
    if (protocol_id_str.empty()) {
        return GN_ERR_NULL_ARG;
    }

    std::unique_lock lock(mu_);

    if (by_protocol_id_.contains(protocol_id_str)) {
        return GN_ERR_LIMIT_REACHED;
    }

    ProtocolLayerEntry entry;
    entry.id              = next_id_.fetch_add(1, std::memory_order_relaxed);
    entry.protocol_id     = protocol_id_str;
    entry.layer           = std::move(layer);
    entry.lifetime_anchor = std::move(lifetime_anchor);

    const auto assigned_id = entry.id;
    by_id_[assigned_id]    = protocol_id_str;
    by_protocol_id_.emplace(std::move(protocol_id_str), std::move(entry));
    *out_id = assigned_id;
    return GN_OK;
}

gn_result_t ProtocolLayerRegistry::unregister_layer(
    protocol_layer_id_t id) noexcept {
    if (id == kInvalidProtocolLayerId) return GN_ERR_INVALID_ENVELOPE;

    std::unique_lock lock(mu_);

    auto it = by_id_.find(id);
    if (it == by_id_.end()) return GN_ERR_NOT_FOUND;

    const std::string protocol_id = it->second;
    by_id_.erase(it);
    by_protocol_id_.erase(protocol_id);
    return GN_OK;
}

std::shared_ptr<::gn::IProtocolLayer>
ProtocolLayerRegistry::find_by_protocol_id(
    std::string_view protocol_id) const {
    std::shared_lock lock(mu_);
    auto it = by_protocol_id_.find(std::string{protocol_id});
    if (it == by_protocol_id_.end()) return nullptr;
    return it->second.layer;
}

std::optional<ProtocolLayerEntry>
ProtocolLayerRegistry::find_entry_by_protocol_id(
    std::string_view protocol_id) const {
    std::shared_lock lock(mu_);
    auto it = by_protocol_id_.find(std::string{protocol_id});
    if (it == by_protocol_id_.end()) return std::nullopt;
    return it->second;
}

std::size_t ProtocolLayerRegistry::size() const noexcept {
    std::shared_lock lock(mu_);
    return by_id_.size();
}

} // namespace gn::core
