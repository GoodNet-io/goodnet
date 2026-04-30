/// @file   core/registry/handler.cpp
/// @brief  Implementation of the handler registry.

#include "handler.hpp"

#include <algorithm>
#include <mutex>

#include <core/kernel/system_handler_ids.hpp>

namespace gn::core {

gn_result_t HandlerRegistry::register_handler(std::string_view           protocol_id,
                                              std::uint32_t              msg_id,
                                              std::uint8_t               priority,
                                              const gn_handler_vtable_t* vtable,
                                              void*                      self,
                                              gn_handler_id_t*           out_id,
                                              std::shared_ptr<void>      lifetime_anchor) noexcept {
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

    const std::size_t cap = max_chain_length_.load(std::memory_order_relaxed);

    HandlerEntry entry;
    entry.id              = next_id_.fetch_add(1, std::memory_order_relaxed);
    entry.protocol_id     = std::string{protocol_id};
    entry.msg_id          = msg_id;
    entry.priority        = priority;
    entry.vtable          = vtable;
    entry.self            = self;
    entry.insertion_seq   = insertion_seq_.fetch_add(1, std::memory_order_relaxed);
    entry.lifetime_anchor = std::move(lifetime_anchor);

    Key key{entry.protocol_id, msg_id};

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
        return GN_ERR_UNKNOWN_RECEIVER;
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
    Key key{std::string{protocol_id}, msg_id};
    std::shared_lock lock(mu_);
    auto it = chains_.find(key);
    if (it == chains_.end()) return {};
    return it->second;  // value-type copy is the snapshot
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
    Key key{std::string{protocol_id}, msg_id};
    std::shared_lock lock(mu_);
    LookupResult out;
    out.generation = generation_.load(std::memory_order_acquire);
    if (auto it = chains_.find(key); it != chains_.end()) {
        out.chain = it->second;
    }
    return out;
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
