/// @file   core/registry/handler.hpp
/// @brief  Handler registry — `(protocol_id, msg_id)` → priority chain.
///
/// Implements `docs/contracts/handler-registration.en.md`. Handlers
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

/// Default tenant namespace used when a handler registration omits
/// `meta->namespace_id` (NULL or empty). All handlers from the
/// pre-namespace world land here so the dispatch fan-out is
/// unchanged for plugins that pre-date the slot.
inline constexpr std::string_view kDefaultHandlerNamespace = "default";

/// One entry in a dispatch chain. Holds the handler's vtable pointer,
/// opaque self pointer, registration metadata, and the priority used
/// for chain ordering.
struct HandlerEntry {
    gn_handler_id_t            id           = GN_INVALID_ID;
    /// Tenant namespace per `handler-registration.md`. Two handlers
    /// on the same `(protocol_id, msg_id)` under different namespaces
    /// coexist; dispatch fans out across every namespace's chain for
    /// the matching pair.
    std::string                namespace_id = std::string{kDefaultHandlerNamespace};
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

    /// Plugin display name from `PluginContext::plugin_name`. Carried
    /// onto the entry at register time so `safe_call_*` log lines
    /// from dispatch (`router.cpp::dispatch_chain`) name the
    /// misbehaving plugin without grepping symbol tables. Empty for
    /// in-tree fixtures that register without a PluginManager.
    std::string                plugin_name;
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
    /// plugin's lifetime anchor. The registry stores it on the
    /// entry so dispatch-time snapshots automatically extend the
    /// plugin's lifetime; PluginManager drains the corresponding
    /// `weak_ptr` between unregister and `dlclose`. Callers that do
    /// not load through PluginManager (in-tree tests, kernel-built
    /// fixtures) pass an empty anchor.
    [[nodiscard]] gn_result_t register_handler(std::string_view           namespace_id,
                                               std::string_view           protocol_id,
                                               std::uint32_t              msg_id,
                                               std::uint8_t               priority,
                                               const gn_handler_vtable_t* vtable,
                                               void*                      self,
                                               gn_handler_id_t*           out_id,
                                               std::shared_ptr<void>      lifetime_anchor = {},
                                               std::string_view           plugin_name = {}) noexcept;

    /// Backward-compat overload — registers in the default namespace.
    /// Pre-namespace call sites continue to compile unchanged; the
    /// default-namespace lookup contract is identical to the
    /// pre-relax single-namespace world.
    [[nodiscard]] gn_result_t register_handler(std::string_view           protocol_id,
                                               std::uint32_t              msg_id,
                                               std::uint8_t               priority,
                                               const gn_handler_vtable_t* vtable,
                                               void*                      self,
                                               gn_handler_id_t*           out_id,
                                               std::shared_ptr<void>      lifetime_anchor = {},
                                               std::string_view           plugin_name = {}) noexcept {
        return register_handler(kDefaultHandlerNamespace,
                                protocol_id, msg_id, priority,
                                vtable, self, out_id,
                                std::move(lifetime_anchor),
                                plugin_name);
    }

    /// Remove the handler with id @p id from whichever chain holds it.
    [[nodiscard]] gn_result_t unregister_handler(gn_handler_id_t id) noexcept;

    /// Unregister every handler whose `namespace_id` matches @p ns.
    /// Each removal bumps the generation counter so cached snapshots
    /// invalidate. Returns the number of entries removed.
    ///
    /// Drain semantics — the kernel's
    /// `Kernel::drain_namespace(ns_id, deadline)` walks this method
    /// then spin-waits on the lifetime anchors collected from the
    /// removed entries before returning to the caller (the same
    /// quiescence pattern PluginManager uses across `dlclose`).
    std::size_t drain_by_namespace(std::string_view ns) noexcept;

    /// Snapshot every registered entry's lifetime anchor under the
    /// given namespace. Used by `Kernel::drain_namespace` together
    /// with `drain_by_namespace` to capture the in-flight refs
    /// before unregistering, so the spin-wait waits on the correct
    /// set even if a handler is unregistered between collection and
    /// the wait loop.
    [[nodiscard]] std::vector<std::weak_ptr<void>>
    collect_anchors_by_namespace(std::string_view ns) const;

    /// Atomic snapshot of one dispatch chain plus the registry-wide
    /// generation counter at the moment the lookup ran. Returned by
    /// `lookup_with_generation` so a dispatcher that wants to detect
    /// mid-walk registry mutations (registrations or unregistrations
    /// landing concurrently) can compare `generation` against the
    /// live counter without a second lookup.
    struct LookupResult {
        std::vector<HandlerEntry> chain;
        std::uint64_t             generation = 0;
    };

    /// Return the dispatch chain for `(protocol_id, msg_id)` ordered
    /// from highest priority to lowest, fanning out across every
    /// namespace registered against the pair. Empty vector if no
    /// handlers are registered. Handler-side namespace isolation:
    /// registry returns one merged priority-sorted chain so the
    /// router does not need to learn about namespaces.
    ///
    /// The result is a value-type snapshot; vtable pointers inside
    /// remain owned by the registering plugin and are valid until that
    /// plugin's `unregister` returns.
    [[nodiscard]] std::vector<HandlerEntry> lookup(std::string_view protocol_id,
                                                   std::uint32_t    msg_id) const;

    /// Same shape as `lookup`, but returns the chain together with
    /// the generation counter the registry recorded inside the same
    /// shared-lock window. Per `handler-registration.md` §6 the
    /// generation increments on every successful register and
    /// unregister; a dispatcher that wants to short-circuit on a
    /// stale chain compares `LookupResult::generation` against
    /// `HandlerRegistry::generation()` post-invoke. Returning the
    /// pair atomically avoids a TOCTOU between the lookup and a
    /// separate `generation()` call where a concurrent registration
    /// could land.
    [[nodiscard]] LookupResult lookup_with_generation(
        std::string_view protocol_id,
        std::uint32_t    msg_id) const;

    /// Per-pair chain length cap. Mirrors `gn_limits_t::max_handlers_per_msg_id`.
    void set_max_chain_length(std::size_t cap) noexcept;
    [[nodiscard]] std::size_t max_chain_length() const noexcept;

    /// Generation counter; bumps on every register/unregister so that
    /// dispatchers can validate cached chain snapshots per
    /// `docs/contracts/fsm-events.en.md` §6.
    [[nodiscard]] std::uint64_t generation() const noexcept;

    /// Total registered handler count.
    [[nodiscard]] std::size_t size() const noexcept;

private:
    /// Triple key: (namespace_id, protocol_id, msg_id). Namespace as
    /// the leading dimension keeps `drain_by_namespace` cheap (one
    /// erase pass over chains whose key starts with `ns`); the
    /// alternative ordering forces a per-key string compare on every
    /// erase iteration.
    struct Key {
        std::string   namespace_id;
        std::string   protocol_id;
        std::uint32_t msg_id = 0;

        bool operator==(const Key& o) const noexcept {
            return namespace_id == o.namespace_id
                && protocol_id  == o.protocol_id
                && msg_id       == o.msg_id;
        }
    };
    struct KeyHash {
        [[nodiscard]] std::size_t operator()(const Key& k) const noexcept {
            const std::size_t h_ns    = std::hash<std::string>{}(k.namespace_id);
            const std::size_t h_proto = std::hash<std::string>{}(k.protocol_id);
            const std::size_t h_msg   = std::hash<std::uint32_t>{}(k.msg_id);
            return h_ns ^ (h_proto << 1) ^ (h_msg << 2);
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
