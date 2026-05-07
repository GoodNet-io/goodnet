/// @file   core/registry/send_queue.cpp

#include "send_queue.hpp"

#include <utility>

namespace gn::core {

bool PerConnQueue::try_push(std::vector<std::uint8_t> frame,
                            SendPriority              priority) {
    if (closing.load(std::memory_order_acquire)) return false;

    const std::size_t sz = frame.size();
    /// Reserve bytes first so `pending_bytes >= live ring content`
    /// always holds — prevents underflow when a drainer dequeues
    /// before this thread finishes the push.
    const std::size_t prev = pending_bytes.fetch_add(sz, std::memory_order_acq_rel);
    if (prev + sz > max_bytes.load(std::memory_order_relaxed)) {
        pending_bytes.fetch_sub(sz, std::memory_order_acq_rel);
        return false;
    }
    auto& ring = (priority == SendPriority::High) ? frames_high : frames_low;
    if (!ring.try_push(std::move(frame))) {
        pending_bytes.fetch_sub(sz, std::memory_order_acq_rel);
        return false;
    }
    return true;
}

std::vector<std::vector<std::uint8_t>>
PerConnQueue::drain_batch(std::size_t max_frames) {
    if (max_frames == 0)
        max_frames = drain_batch_size.load(std::memory_order_relaxed);

    while (drain_lock_.test_and_set(std::memory_order_acquire))
        drain_lock_.wait(true, std::memory_order_relaxed);

    std::vector<std::vector<std::uint8_t>> batch;
    batch.reserve(max_frames);

    std::size_t budget = max_frames;
    const std::size_t high_drained = frames_high.drain(batch, budget);
    budget -= high_drained;
    if (budget > 0) frames_low.drain(batch, budget);

    drain_lock_.clear(std::memory_order_release);
    drain_lock_.notify_one();

    std::size_t bytes = 0;
    for (const auto& f : batch) bytes += f.size();
    pending_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
    return batch;
}

std::shared_ptr<PerConnQueue> SendQueueManager::get_or_create(gn_conn_id_t id) {
    {
        std::shared_lock lk(mu_);
        if (auto it = queues_.find(id); it != queues_.end()) return it->second;
    }
    std::unique_lock lk(mu_);
    auto& slot = queues_[id];
    if (!slot)
        slot = std::make_shared<PerConnQueue>(per_conn_limit_, drain_batch_size_);
    return slot;
}

void SendQueueManager::create(gn_conn_id_t id) {
    std::unique_lock lk(mu_);
    auto& slot = queues_[id];
    if (!slot)
        slot = std::make_shared<PerConnQueue>(per_conn_limit_, drain_batch_size_);
}

void SendQueueManager::erase(gn_conn_id_t id) {
    std::shared_ptr<PerConnQueue> released;
    {
        std::unique_lock lk(mu_);
        auto it = queues_.find(id);
        if (it == queues_.end()) return;
        released = std::move(it->second);
        queues_.erase(it);
    }
    if (released)
        released->closing.store(true, std::memory_order_release);
}

std::shared_ptr<PerConnQueue> SendQueueManager::find(gn_conn_id_t id) const {
    std::shared_lock lk(mu_);
    if (auto it = queues_.find(id); it != queues_.end()) return it->second;
    return nullptr;
}

std::size_t SendQueueManager::pending_bytes(gn_conn_id_t id) const noexcept {
    std::shared_lock lk(mu_);
    if (id != GN_INVALID_ID) {
        if (auto it = queues_.find(id); it != queues_.end())
            return it->second->pending_bytes.load(std::memory_order_relaxed);
        return 0;
    }
    std::size_t total = 0;
    for (const auto& [_, q] : queues_)
        total += q->pending_bytes.load(std::memory_order_relaxed);
    return total;
}

void SendQueueManager::update_limits(std::size_t per_conn_limit, std::size_t batch) {
    std::shared_lock lk(mu_);
    per_conn_limit_   = per_conn_limit;
    drain_batch_size_ = batch;
    for (const auto& [_, q] : queues_) {
        q->max_bytes.store(per_conn_limit, std::memory_order_relaxed);
        q->drain_batch_size.store(batch, std::memory_order_relaxed);
    }
}

} // namespace gn::core
