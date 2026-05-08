/// @file   core/registry/send_queue.hpp
/// @brief  Per-connection backpressure queue with two-level priority
///         and an MPSC ring on the hot path.
///
/// Per `docs/contracts/backpressure.en.md` the kernel maintains a
/// per-connection send queue so concurrent producers (`host_api->send`
/// callers across plugin threads) never serialise behind one another
/// at the link's writev. Drain runs on the link plugin's executor
/// through `gn_link_vtable_t::send_batch`; the `drain_scheduled` CAS
/// flag guarantees at most one drain in flight per connection without
/// blocking pushers.

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

#include "spsc_ring.hpp"

#include <sdk/types.h>

namespace gn::core {

/// Two-level priority — system frames (handshake, heartbeat) bypass
/// user data so a saturated send queue cannot starve the control
/// plane. Per `docs/contracts/backpressure.en.md` §4.
enum class SendPriority : std::uint8_t {
    High = 0,
    Low  = 1,
};

/// @brief Per-connection MPSC ring pair plus byte-level backpressure.
///
/// Two priority rings (`frames_high`, `frames_low`); the drain pops
/// `high` first to its budget, then fills the rest from `low`.
/// `pending_bytes` tracks live bytes in the rings — producers reserve
/// against `max_bytes` before pushing so a concurrent overflow drops
/// rather than corrupts.
struct PerConnQueue {
    static constexpr std::size_t kDefaultQueueLimit = std::size_t{8} * 1024 * 1024;
    static constexpr std::size_t kDefaultDrainBatch = 64;

    /// Field order optimised against `clang-tidy` padding analysis —
    /// large alignment members (`MpscRing` is 64-byte cache-aligned)
    /// up front, small atomics packed after, the heap-managed
    /// `stalled_wire_batch` vector before the byte-sized atomic
    /// flags. Reordering the declarations changes neither runtime
    /// semantics nor the public surface; documentation comments stay
    /// next to each field.

    /// Encrypted-frame rings — used when the session has no
    /// fast-crypto path (loopback, null security) or when the
    /// security provider is not `InlineCrypto`-shaped. The kernel
    /// pushes wire bytes, the drainer hands them straight to the
    /// link's `send_batch`.
    MpscRing<std::vector<std::uint8_t>> frames_high;
    MpscRing<std::vector<std::uint8_t>> frames_low;

    /// Plaintext-frame rings — used when the session has
    /// `InlineCrypto` seeded. The kernel pushes framed plaintext
    /// here; the drainer reserves K send nonces, runs K parallel
    /// `chacha20poly1305_encrypt_job`s through `CryptoWorkerPool`,
    /// coalesces the ciphertexts into the link's `send_batch`.
    /// Single-writer per-conn invariant
    /// (`drain_scheduled` CAS) keeps the nonce reservation
    /// race-free across drainers.
    MpscRing<std::vector<std::uint8_t>> frames_plain_high;
    MpscRing<std::vector<std::uint8_t>> frames_plain_low;

    /// Live-tunable so `host_api->config_get` reload can retighten or
    /// relax existing connections, not only newly created ones. Reads
    /// on the producer hot path are relaxed because the values are
    /// advisory bounds — a stale read defers the limit by a few frames.
    std::atomic<std::size_t> max_bytes;
    std::atomic<std::size_t> drain_batch_size;

    std::atomic<std::size_t> pending_bytes{0};

    /// Wire frames that the link plugin's `send_batch` rejected on
    /// the previous drain attempt — typically `GN_ERR_LIMIT_REACHED`
    /// from a TCP plugin whose per-session write buffer is full
    /// (`tcp.cpp:611-625`). The drainer that retries these on the
    /// next claim sends the **same wire bytes** that were already
    /// AEAD-encrypted with their reserved nonces, so the receiver's
    /// nonce sequence stays gap-free. Until the stalled batch
    /// drains successfully, the drainer halts new pulls — kernel
    /// queue fills, producers see `GN_ERR_LIMIT_REACHED` per
    /// `backpressure.md` §1, back-off naturally re-triggers drain
    /// through subsequent push CAS attempts.
    ///
    /// Protected by `drain_lock_` (the same flag that gates ring
    /// drains). Only the drainer (single-writer per conn via
    /// `drain_scheduled` CAS) touches this — no readers, no
    /// concurrent producers.
    std::vector<std::vector<std::uint8_t>> stalled_wire_batch;

    /// Set during graceful close to block new pushes / drains.
    std::atomic<bool> closing{false};

    /// Drain serializer — at most one drain in flight per connection.
    /// CAS-only, never blocks pushers.
    std::atomic<bool> drain_scheduled{false};

    /// Consumer spinlock — protects against concurrent direct calls
    /// to `drain_batch`. In normal flow `drain_scheduled` already
    /// gates concurrency; this is belt-and-braces for tests that
    /// drive drain from multiple threads.
    std::atomic_flag drain_lock_ = ATOMIC_FLAG_INIT;

    explicit PerConnQueue(std::size_t limit = kDefaultQueueLimit,
                          std::size_t batch = kDefaultDrainBatch)
        : max_bytes(limit), drain_batch_size(batch) {}

    /// Reserve bytes against `max_bytes`, push the frame onto the
    /// matching priority ring. Returns false on overflow or ring-full;
    /// the caller surfaces `GN_ERR_LIMIT_REACHED` to the host_api
    /// caller.
    [[nodiscard]] bool try_push(std::vector<std::uint8_t> frame,
                                SendPriority              priority = SendPriority::Low);

    /// Same shape as `try_push` but routes onto the plaintext ring
    /// pair. Caller pushes here when the session has fast-crypto
    /// seeded — encryption deferred to drain time.
    [[nodiscard]] bool try_push_plain(std::vector<std::uint8_t> frame,
                                      SendPriority              priority = SendPriority::Low);

    /// Pop up to `max_frames` frames in priority order. Defaults to
    /// the live `drain_batch_size` value.
    [[nodiscard]] std::vector<std::vector<std::uint8_t>>
    drain_batch(std::size_t max_frames = 0);

    /// Pop up to `max_frames` plaintext frames in priority order.
    /// Defaults to the live `drain_batch_size` value.
    [[nodiscard]] std::vector<std::vector<std::uint8_t>>
    drain_plain_batch(std::size_t max_frames = 0);

    [[nodiscard]] bool has_frames() const {
        return !frames_high.empty() || !frames_low.empty();
    }

    [[nodiscard]] bool has_plain() const {
        return !frames_plain_high.empty() || !frames_plain_low.empty();
    }
};

/// @brief Per-connection send-queue table.
///
/// `create(id)` is invoked from `ConnectionRegistry::insert_with_index`
/// success paths so the queue exists by the time the first
/// `host_api->send` arrives. `erase(id)` is invoked from
/// `snapshot_and_erase` so the queue's storage is released alongside
/// the connection record (`docs/contracts/registry.en.md` §4a).
class SendQueueManager {
public:
    explicit SendQueueManager(std::size_t per_conn_limit = PerConnQueue::kDefaultQueueLimit,
                              std::size_t batch          = PerConnQueue::kDefaultDrainBatch)
        : per_conn_limit_(per_conn_limit), drain_batch_size_(batch) {}

    SendQueueManager(const SendQueueManager&)            = delete;
    SendQueueManager& operator=(const SendQueueManager&) = delete;

    /// Returns the queue for `id`, creating one if absent. The
    /// host_api hot path uses this so a `send` arriving before
    /// `notify_connect` (test scaffolding) does not hit a null slot.
    std::shared_ptr<PerConnQueue> get_or_create(gn_conn_id_t id);

    /// Pre-create a queue at `notify_connect` time so the first
    /// `host_api->send` is hash-table-hit, not insert.
    void create(gn_conn_id_t id);

    void erase(gn_conn_id_t id);

    [[nodiscard]] std::shared_ptr<PerConnQueue> find(gn_conn_id_t id) const;

    /// Total bytes pending across every queue, or for one connection
    /// when `id` is non-`GN_INVALID_ID`.
    [[nodiscard]] std::size_t pending_bytes(gn_conn_id_t id = GN_INVALID_ID) const noexcept;

    /// Live-tune limits across every existing queue.
    void update_limits(std::size_t per_conn_limit, std::size_t batch);

private:
    std::size_t per_conn_limit_;
    std::size_t drain_batch_size_;

    mutable std::shared_mutex mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<PerConnQueue>> queues_;
};

} // namespace gn::core
