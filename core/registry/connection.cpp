/// @file   core/registry/connection.cpp
/// @brief  Implementation of the sharded connection registry.

#include "connection.hpp"

#include <mutex>

namespace gn::core {

gn_conn_id_t ConnectionRegistry::alloc_id() noexcept {
    return next_id_.fetch_add(1, std::memory_order_relaxed);
}

ConnectionRegistry::Shard& ConnectionRegistry::shard_for(gn_conn_id_t id) noexcept {
    return shards_[id % kShardCount];
}

const ConnectionRegistry::Shard& ConnectionRegistry::shard_for(gn_conn_id_t id) const noexcept {
    return shards_[id % kShardCount];
}

gn_result_t ConnectionRegistry::insert_with_index(ConnectionRecord rec) noexcept {
    if (rec.id == GN_INVALID_ID) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    Shard& s = shard_for(rec.id);

    /// Lock all three mutexes in a fixed total order. `scoped_lock`
    /// picks an order that avoids deadlocks across concurrent
    /// inserters that share any subset of the locks.
    std::scoped_lock lock(s.mu, uri_mu_, pk_mu_);

    if (s.records.contains(rec.id))             return GN_ERR_LIMIT_REACHED;
    if (uri_index_.contains(rec.uri))           return GN_ERR_LIMIT_REACHED;
    if (pk_index_.contains(rec.remote_pk))      return GN_ERR_LIMIT_REACHED;

    const gn_conn_id_t id    = rec.id;
    const std::string  uri   = rec.uri;
    const PublicKey    pk    = rec.remote_pk;

    s.records.emplace(id, std::move(rec));
    uri_index_.emplace(uri, id);
    pk_index_.emplace(pk, id);

    return GN_OK;
}

gn_result_t ConnectionRegistry::erase_with_index(gn_conn_id_t id) noexcept {
    if (id == GN_INVALID_ID) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    Shard& s = shard_for(id);

    std::scoped_lock lock(s.mu, uri_mu_, pk_mu_);

    auto it = s.records.find(id);
    if (it == s.records.end()) {
        return GN_ERR_UNKNOWN_RECEIVER;
    }

    /// Copy index keys before erasing the record itself; after the
    /// shard erase the references would dangle.
    const std::string uri = it->second.uri;
    const PublicKey   pk  = it->second.remote_pk;

    uri_index_.erase(uri);
    pk_index_.erase(pk);
    s.records.erase(it);
    return GN_OK;
}

std::optional<ConnectionRecord> ConnectionRegistry::find_by_id(gn_conn_id_t id) const {
    if (id == GN_INVALID_ID) return std::nullopt;
    const Shard& s = shard_for(id);
    std::shared_lock lock(s.mu);
    auto it = s.records.find(id);
    if (it == s.records.end()) return std::nullopt;
    return it->second;
}

std::optional<ConnectionRecord> ConnectionRegistry::find_by_uri(std::string_view uri) const {
    gn_conn_id_t id = GN_INVALID_ID;
    {
        std::shared_lock lock(uri_mu_);
        auto it = uri_index_.find(std::string{uri});
        if (it == uri_index_.end()) return std::nullopt;
        id = it->second;
    }
    return find_by_id(id);
}

std::optional<ConnectionRecord> ConnectionRegistry::find_by_pk(const PublicKey& pk) const {
    gn_conn_id_t id = GN_INVALID_ID;
    {
        std::shared_lock lock(pk_mu_);
        auto it = pk_index_.find(pk);
        if (it == pk_index_.end()) return std::nullopt;
        id = it->second;
    }
    return find_by_id(id);
}

std::size_t ConnectionRegistry::size() const noexcept {
    std::size_t n = 0;
    for (const auto& s : shards_) {
        std::shared_lock lock(s.mu);
        n += s.records.size();
    }
    return n;
}

} // namespace gn::core
