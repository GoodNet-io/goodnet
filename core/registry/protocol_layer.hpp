/// @file   core/registry/protocol_layer.hpp
/// @brief  Named registry of mesh-framing protocol layers.
///
/// Per `protocol-layer.md` §4 the kernel maintains a registry of one
/// or more `IProtocolLayer` implementations identified by their
/// `protocol_id` ("gnet-v1", "raw-v1", "ssh-v1" once the SSH plugin
/// lands). Each connection records which `protocol_id` drives it at
/// `notify_connect`; the dispatch sites look up the matching layer
/// here. Cross-protocol envelope isolation is the registry's
/// invariant: a handler scoped to one `protocol_id` never sees
/// envelopes that arrived through a different protocol.
///
/// Shape mirrors `LinkRegistry`: shared_mutex over a by-name map with
/// a parallel by-id map. Lookups return `shared_ptr<IProtocolLayer>`
/// that extends the layer's lifetime past concurrent `unregister_layer`
/// — caller dereferences without lock.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include <sdk/cpp/protocol_layer.hpp>
#include <sdk/types.h>

namespace gn::core {

/// Default protocol_id used when a link plugin registers without
/// declaring one. Equals the kernel's canonical mesh-framing layer.
inline constexpr std::string_view kDefaultProtocolId = "gnet-v1";

/// Internal handle for unregister. Not exposed across the C ABI —
/// plugin-side registration goes through `gn_core_register_protocol`
/// which mints its own `gn_protocol_layer_id_t` (sdk/types.h).
using protocol_layer_id_t = std::uint64_t;
inline constexpr protocol_layer_id_t kInvalidProtocolLayerId = 0;

/// One row in the protocol-layer registry. Holds the C++-wrapped
/// protocol implementation plus the lifetime anchor of the entity
/// that registered it (kernel-static for `gnet-v1` / `raw-v1`,
/// `PluginInstance` for plugin-side protocols once the C ABI path
/// lands).
struct ProtocolLayerEntry {
    protocol_layer_id_t                   id = kInvalidProtocolLayerId;
    std::string                           protocol_id;
    std::shared_ptr<::gn::IProtocolLayer> layer;

    /// Same shape as `LinkEntry::lifetime_anchor`. `find_by_*` value-
    /// snapshots the entry; `layer` is a `shared_ptr` so the caller's
    /// copy keeps the implementation alive past concurrent
    /// `unregister_layer`.
    std::shared_ptr<void>                 lifetime_anchor;
};

class ProtocolLayerRegistry {
public:
    ProtocolLayerRegistry()                                       = default;
    ProtocolLayerRegistry(const ProtocolLayerRegistry&)            = delete;
    ProtocolLayerRegistry& operator=(const ProtocolLayerRegistry&) = delete;

    /// Register @p layer under its `protocol_id()`. Fails with
    /// `GN_ERR_LIMIT_REACHED` when a layer with the same
    /// `protocol_id` is already registered.
    [[nodiscard]] gn_result_t register_layer(
        std::shared_ptr<::gn::IProtocolLayer> layer,
        protocol_layer_id_t* out_id,
        std::shared_ptr<void> lifetime_anchor = {}) noexcept;

    [[nodiscard]] gn_result_t unregister_layer(protocol_layer_id_t id) noexcept;

    /// Lookup by `protocol_id` string. Returns `nullptr` when no
    /// matching layer is registered. The returned `shared_ptr`
    /// extends the layer's lifetime past concurrent unregister so
    /// the caller may dereference outside the registry lock.
    [[nodiscard]] std::shared_ptr<::gn::IProtocolLayer>
        find_by_protocol_id(std::string_view protocol_id) const;

    /// Snapshot of the full entry — used by the `notify_connect`
    /// trust-mask gate which needs `allowed_trust_mask()` plus the
    /// `protocol_id` round-trip in one read.
    [[nodiscard]] std::optional<ProtocolLayerEntry>
        find_entry_by_protocol_id(std::string_view protocol_id) const;

    [[nodiscard]] std::size_t size() const noexcept;

private:
    mutable std::shared_mutex                                  mu_;
    std::unordered_map<std::string, ProtocolLayerEntry>        by_protocol_id_;
    std::unordered_map<protocol_layer_id_t, std::string>       by_id_;
    std::atomic<protocol_layer_id_t>                           next_id_{1};
};

} // namespace gn::core
