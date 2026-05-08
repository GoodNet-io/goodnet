/// @file   core/registry/send_queue.cpp

#include "send_queue.hpp"

#include <utility>

namespace gn::core {

namespace {

/// Push helper shared by both `try_push` and `try_push_plain`. The
/// only difference between the two is which priority pair the
/// frame goes onto; everything else (cap reservation, overflow
/// rollback) is identical.
[[nodiscard]] bool push_into(
    std::atomic<std::size_t>&             pending_bytes,
    std::atomic<std::size_t>&             max_bytes,
    std::atomic<bool>&                    closing,
    MpscRing<std::vector<std::uint8_t>>&  ring_high,
    MpscRing<std::vector<std::uint8_t>>&  ring_low,
    SendPriority                          priority,
    std::vector<std::uint8_t>             frame) {
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
    auto& ring = (priority == SendPriority::High) ? ring_high : ring_low;
    if (!ring.try_push(std::move(frame))) {
        pending_bytes.fetch_sub(sz, std::memory_order_acq_rel);
        return false;
    }
    return true;
}

[[nodiscard]] std::vector<std::vector<std::uint8_t>>
drain_pair(std::atomic<std::size_t>&             pending_bytes,
           std::atomic<std::size_t>&             drain_batch_size,
           std::atomic_flag&                     drain_lock,
           MpscRing<std::vector<std::uint8_t>>&  ring_high,
           MpscRing<std::vector<std::uint8_t>>&  ring_low,
           std::size_t                           max_frames) {
    if (max_frames == 0)
        max_frames = drain_batch_size.load(std::memory_order_relaxed);

    while (drain_lock.test_and_set(std::memory_order_acquire))
        drain_lock.wait(true, std::memory_order_relaxed);

    std::vector<std::vector<std::uint8_t>> batch;
    batch.reserve(max_frames);

    std::size_t budget = max_frames;
    const std::size_t high_drained = ring_high.drain(batch, budget);
    budget -= high_drained;
    if (budget > 0) ring_low.drain(batch, budget);

    drain_lock.clear(std::memory_order_release);
    drain_lock.notify_one();

    std::size_t bytes = 0;
    for (const auto& f : batch) bytes += f.size();
    pending_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
    return batch;
}

} // namespace

bool PerConnQueue::try_push(std::vector<std::uint8_t> frame,
                            SendPriority              priority) {
    return push_into(pending_bytes, max_bytes, closing,
                     frames_high, frames_low, priority, std::move(frame));
}

bool PerConnQueue::try_push_plain(std::vector<std::uint8_t> frame,
                                  SendPriority              priority) {
    return push_into(pending_bytes, max_bytes, closing,
                     frames_plain_high, frames_plain_low,
                     priority, std::move(frame));
}

std::vector<std::vector<std::uint8_t>>
PerConnQueue::drain_batch(std::size_t max_frames) {
    return drain_pair(pending_bytes, drain_batch_size, drain_lock_,
                      frames_high, frames_low, max_frames);
}

std::vector<std::vector<std::uint8_t>>
PerConnQueue::drain_plain_batch(std::size_t max_frames) {
    return drain_pair(pending_bytes, drain_batch_size, drain_lock_,
                      frames_plain_high, frames_plain_low, max_frames);
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
