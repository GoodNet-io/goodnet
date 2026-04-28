/// @file   core/registry/handler.hpp
/// @brief  Handler registry — `(protocol_id, msg_id)` → priority chain.
///
/// Implements `docs/contracts/handler-registration.md`. Handlers
/// register against a `(protocol_id, msg_id)` pair; lookup returns a
/// snapshot of the priority-ordered chain so dispatchers do not race
/// with concurrent (un)registration.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sdk/handler.h>
#include <sdk/types.h>

namespace gn::core {

/// One entry in a dispatch chain. Holds the handler's vtable pointer,
/// opaque self pointer, registration metadata, and the priority used
/// for chain ordering.
struct HandlerEntry {
    gn_handler_id_t            id           = GN_INVALID_ID;
    std::string                protocol_id;
    std::uint32_t              msg_id       = 0;
    std::uint8_t               priority     = 128;

    /// Plugin-supplied vtable. `@borrowed` per `host-api.md` until
    /// the matching unregister call returns.
    const gn_handler_vtable_t* vtable       = nullptr;

    /// Plugin-private state pointer; passed back to every vtable call.
    void*                      self         = nullptr;

    /// Monotonic insertion sequence used to break ties between
    /// handlers that share a priority.
    std::uint64_t              insertion_seq = 0;

    /// Reference-counted plugin liveness anchor. Copied by value into
    /// every dispatch snapshot; PluginManager observes the underlying
    /// control block through `weak_ptr` during unload to drive the
    /// quiescence wait before `dlclose` (see `plugin-lifetime.md` §4).
    std::shared_ptr<void>      lifetime_anchor;
};

class HandlerRegistry {
public:
    HandlerRegistry()                                  = default;
    HandlerRegistry(const HandlerRegistry&)            = delete;
    HandlerRegistry& operator=(const HandlerRegistry&) = delete;

    /// Register a handler against `(protocol_id, msg_id)`.
    ///
    /// Fails with `GN_ERR_LIMIT_REACHED` when the chain is already at
    /// `max_chain_length`. `out_id` receives a fresh handler id that
    /// the caller hands back on `unregister_handler`.
    ///
    /// @p lifetime_anchor is a strong reference to the registering
    /// plugin's quiescence sentinel. The registry stores it on the
    /// entry so dispatch-time snapshots automatically extend the
    /// plugin's lifetime; PluginManager drains the corresponding
    /// `weak_ptr` between unregister and `dlclose`. Callers that do
    /// not load through PluginManager (in-tree tests, kernel-built
    /// fixtures) pass an empty anchor.
    [[nodiscard]] gn_result_t register_handler(std::string_view           protocol_id,
                                               std::uint32_t              msg_id,
                                               std::uint8_t               priority,
                                               const gn_handler_vtable_t* vtable,
                                               void*                      self,
                                               gn_handler_id_t*           out_id,
                                               std::shared_ptr<void>      lifetime_anchor = {}) noexcept;

    /// Remove the handler with id @p id from whichever chain holds it.
    [[nodiscard]] gn_result_t unregister_handler(gn_handler_id_t id) noexcept;

    /// Return the dispatch chain for `(protocol_id, msg_id)` ordered
    /// from highest priority to lowest. Empty vector if no handlers
    /// are registered for the pair.
    ///
    /// The result is a value-type snapshot; vtable pointers inside
    /// remain owned by the registering plugin and are valid until that
    /// plugin's `unregister` returns.
    [[nodiscard]] std::vector<HandlerEntry> lookup(std::string_view protocol_id,
                                                   std::uint32_t    msg_id) const;

    /// Per-pair chain length cap. Mirrors `gn_limits_t::max_handlers_per_msg_id`.
    void set_max_chain_length(std::size_t cap) noexcept;
    [[nodiscard]] std::size_t max_chain_length() const noexcept;

    /// Generation counter; bumps on every register/unregister so that
    /// dispatchers can validate cached chain snapshots per
    /// `docs/contracts/fsm-events.md` §6.
    [[nodiscard]] std::uint64_t generation() const noexcept;

    /// Total registered handler count.
    [[nodiscard]] std::size_t size() const noexcept;

private:
    using Key   = std::pair<std::string, std::uint32_t>;
    struct KeyHash {
        [[nodiscard]] std::size_t operator()(const Key& k) const noexcept {
            return std::hash<std::string>{}(k.first) ^
                   (std::hash<std::uint32_t>{}(k.second) << 1);
        }
    };
    using Chain = std::vector<HandlerEntry>;

    mutable std::shared_mutex                    mu_;
    std::unordered_map<Key, Chain, KeyHash>      chains_;
    std::unordered_map<gn_handler_id_t, Key>     by_id_;

    std::atomic<gn_handler_id_t> next_id_{1};
    std::atomic<std::uint64_t>   generation_{0};
    std::atomic<std::uint64_t>   insertion_seq_{0};
    std::atomic<std::size_t>     max_chain_length_{8};
};

} // namespace gn::core
