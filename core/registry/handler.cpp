/// @file   core/registry/handler.cpp
/// @brief  Implementation of the handler registry.

#include "handler.hpp"

#include <algorithm>
#include <mutex>

#include <core/kernel/system_handler_ids.hpp>

namespace gn::core {

gn_result_t HandlerRegistry::register_handler(std::string_view           namespace_id,
                                              std::string_view           protocol_id,
                                              std::uint32_t              msg_id,
                                              std::uint8_t               priority,
                                              const gn_handler_vtable_t* vtable,
                                              void*                      self,
                                              gn_handler_id_t*           out_id,
                                              std::shared_ptr<void>      lifetime_anchor,
                                              std::string_view           plugin_name) noexcept {
    if (vtable == nullptr || out_id == nullptr || protocol_id.empty()) {
        return GN_ERR_NULL_ARG;
    }
    /// `abi-evolution.md` §3a: defensive size-prefix check on the
    /// plugin-provided vtable. A vtable that declares a smaller
    /// size than the kernel's known minimum is from an SDK older
    /// than the slots the kernel intends to call — reject before
    /// any slot lookup.
    if (vtable->api_size < sizeof(gn_handler_vtable_t)) {
        return GN_ERR_VERSION_MISMATCH;
    }
    if (msg_id == 0) {
        /// `0` is reserved as the unset sentinel — registrations against
        /// it would shadow legitimate dispatches.
        return GN_ERR_INVALID_ENVELOPE;
    }
    if (is_reserved_system_msg_id(msg_id)) {
        /// Per `handler-registration.md` §2a — kernel-internal
        /// dispatch ids are not exposed to plugin registrations.
        return GN_ERR_INVALID_ENVELOPE;
    }

    /// Empty / NULL namespace_id resolves to the kernel default.
    /// Pre-namespace plugins zero-init `gn_register_meta_t` so
    /// `meta->namespace_id == NULL` lands here as `"default"`.
    std::string namespace_str = namespace_id.empty()
        ? std::string{kDefaultHandlerNamespace}
        : std::string{namespace_id};

    const std::size_t cap = max_chain_length_.load(std::memory_order_relaxed);

    HandlerEntry entry;
    entry.id              = next_id_.fetch_add(1, std::memory_order_relaxed);
    entry.namespace_id    = namespace_str;
    entry.protocol_id     = std::string{protocol_id};
    entry.msg_id          = msg_id;
    entry.priority        = priority;
    entry.vtable          = vtable;
    entry.self            = self;
    entry.insertion_seq   = insertion_seq_.fetch_add(1, std::memory_order_relaxed);
    entry.lifetime_anchor = std::move(lifetime_anchor);
    entry.plugin_name     = std::string{plugin_name};

    Key key{namespace_str, entry.protocol_id, msg_id};

    std::unique_lock lock(mu_);

    /// `chains_[key]` default-creates an empty chain on miss;
    /// the find lookup keeps a rejected registration from
    /// leaving an orphan entry behind. A cap of zero disables
    /// enforcement per `limits.md §4a`.
    if (cap != 0) {
        if (auto it = chains_.find(key); it != chains_.end() &&
                                         it->second.size() >= cap) {
            return GN_ERR_LIMIT_REACHED;
        }
    }

    auto& chain = chains_[key];
    /// Insert sorted by (priority desc, insertion_seq asc).
    auto pos = std::lower_bound(
        chain.begin(), chain.end(), entry,
        [](const HandlerEntry& a, const HandlerEntry& b) {
            if (a.priority != b.priority) return a.priority > b.priority;
            return a.insertion_seq < b.insertion_seq;
        });
    chain.insert(pos, entry);

    by_id_.emplace(entry.id, key);
    *out_id = entry.id;
    generation_.fetch_add(1, std::memory_order_acq_rel);
    return GN_OK;
}

gn_result_t HandlerRegistry::unregister_handler(gn_handler_id_t id) noexcept {
    if (id == GN_INVALID_ID) return GN_ERR_INVALID_ENVELOPE;

    std::unique_lock lock(mu_);

    auto by_id_it = by_id_.find(id);
    if (by_id_it == by_id_.end()) {
        return GN_ERR_NOT_FOUND;
    }

    const Key key = by_id_it->second;
    by_id_.erase(by_id_it);

    auto chain_it = chains_.find(key);
    if (chain_it != chains_.end()) {
        auto& chain = chain_it->second;
        std::erase_if(chain, [id](const HandlerEntry& e) { return e.id == id; });
        if (chain.empty()) {
            chains_.erase(chain_it);
        }
    }

    generation_.fetch_add(1, std::memory_order_acq_rel);
    return GN_OK;
}

std::vector<HandlerEntry> HandlerRegistry::lookup(std::string_view protocol_id,
                                                  std::uint32_t    msg_id) const {
    /// Fan out across every namespace registered for the
    /// (protocol_id, msg_id) pair. Per `handler-registration.md`
    /// the merged chain is sorted by (priority desc, insertion_seq
    /// asc) so a router treats the result identically to the
    /// pre-namespace single-chain world.
    std::shared_lock lock(mu_);
    std::vector<HandlerEntry> merged;
    for (const auto& [k, chain] : chains_) {
        if (k.protocol_id == protocol_id && k.msg_id == msg_id) {
            merged.insert(merged.end(), chain.begin(), chain.end());
        }
    }
    if (merged.size() > 1) {
        std::sort(merged.begin(), merged.end(),
            [](const HandlerEntry& a, const HandlerEntry& b) {
                if (a.priority != b.priority) return a.priority > b.priority;
                return a.insertion_seq < b.insertion_seq;
            });
    }
    return merged;
}

HandlerRegistry::LookupResult HandlerRegistry::lookup_with_generation(
    std::string_view protocol_id,
    std::uint32_t    msg_id) const {
    /// Capture the generation counter under the same shared lock as
    /// the chain copy. Without that pairing, a writer landing
    /// between the lookup-side `find` and a follow-up
    /// `generation()` read would slip an in-between bump past the
    /// caller — making the returned counter unreliable for mid-walk
    /// stale-detection.
    std::shared_lock lock(mu_);
    LookupResult out;
    out.generation = generation_.load(std::memory_order_acquire);
    for (const auto& [k, chain] : chains_) {
        if (k.protocol_id == protocol_id && k.msg_id == msg_id) {
            out.chain.insert(out.chain.end(), chain.begin(), chain.end());
        }
    }
    if (out.chain.size() > 1) {
        std::sort(out.chain.begin(), out.chain.end(),
            [](const HandlerEntry& a, const HandlerEntry& b) {
                if (a.priority != b.priority) return a.priority > b.priority;
                return a.insertion_seq < b.insertion_seq;
            });
    }
    return out;
}

std::size_t HandlerRegistry::drain_by_namespace(std::string_view ns) noexcept {
    std::unique_lock lock(mu_);
    std::size_t removed = 0;

    /// Two-pass: collect the keys whose namespace matches, then
    /// erase. erase_if on the map mid-iteration is fine but the
    /// by_id_ map needs the same per-entry erasures, so doing the
    /// match in one pass keeps the by_id_ updates aligned.
    std::vector<gn_handler_id_t> ids_to_drop;
    for (auto chain_it = chains_.begin(); chain_it != chains_.end();) {
        if (chain_it->first.namespace_id == ns) {
            for (const auto& entry : chain_it->second) {
                ids_to_drop.push_back(entry.id);
            }
            chain_it = chains_.erase(chain_it);
        } else {
            ++chain_it;
        }
    }

    for (auto id : ids_to_drop) {
        if (by_id_.erase(id) == 1) {
            ++removed;
            generation_.fetch_add(1, std::memory_order_acq_rel);
        }
    }
    return removed;
}

std::vector<std::weak_ptr<void>>
HandlerRegistry::collect_anchors_by_namespace(std::string_view ns) const {
    std::shared_lock lock(mu_);
    std::vector<std::weak_ptr<void>> anchors;
    for (const auto& [key, chain] : chains_) {
        if (key.namespace_id != ns) continue;
        for (const auto& entry : chain) {
            if (entry.lifetime_anchor) {
                anchors.emplace_back(entry.lifetime_anchor);
            }
        }
    }
    return anchors;
}

void HandlerRegistry::set_max_chain_length(std::size_t cap) noexcept {
    max_chain_length_.store(cap, std::memory_order_relaxed);
}

std::size_t HandlerRegistry::max_chain_length() const noexcept {
    return max_chain_length_.load(std::memory_order_relaxed);
}

std::uint64_t HandlerRegistry::generation() const noexcept {
    return generation_.load(std::memory_order_acquire);
}

std::size_t HandlerRegistry::size() const noexcept {
    return by_id_.size();
}

} // namespace gn::core
