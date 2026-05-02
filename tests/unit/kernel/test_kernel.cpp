/// @file   tests/unit/kernel/test_kernel.cpp
/// @brief  Tests for `gn::core::Kernel` FSM.
///
/// Pins the contract from `docs/contracts/fsm-events.md`:
///   §3 commit-then-notify on every transition,
///   §5 compare-and-exchange on idempotent `stop()`,
///   §7 weak-observer subscription with auto-prune at fire time.
///
/// Plus concurrent set/load on the kernel's atomic-shared fields
/// (`protocol_layer_` and `node_identity_`) to verify the
/// `std::atomic<std::shared_ptr<>>` plumbing closes the TSan-visible
/// race the previous raw-shared_ptr fields exposed.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <core/kernel/kernel.hpp>
#include <core/kernel/phase.hpp>

#include <sdk/cpp/protocol_layer.hpp>
#include <sdk/cpp/types.hpp>
#include <sdk/types.h>

namespace gn::core {
namespace {

/// Minimal recording observer. Captures every `(prev, next)` pair and
/// also the kernel's *visible* phase at fire time — used to assert the
/// commit-then-notify ordering.
struct RecordingObserver final : public IPhaseObserver {
    struct Event { Phase prev; Phase next; Phase observed_now; };

    /// Optional kernel pointer — when set, the observer records
    /// `kernel->current_phase()` as it fires, validating commit-before-
    /// notify (the visible phase must already equal `next`).
    Kernel* kernel = nullptr;

    std::mutex          mu;
    std::vector<Event>  events;
    std::atomic<int>    fire_count{0};

    void on_phase_change(Phase prev, Phase next) noexcept override {
        const Phase observed_now =
            (kernel != nullptr) ? kernel->current_phase() : next;
        {
            std::lock_guard lock{mu};
            events.push_back({prev, next, observed_now});
        }
        fire_count.fetch_add(1, std::memory_order_relaxed);
    }
};

// ── Initial state ────────────────────────────────────────────────────────

TEST(Kernel_Init, StartsInLoad) {
    Kernel k;
    EXPECT_EQ(k.current_phase(), Phase::Load);
    EXPECT_EQ(k.observer_count(), 0u);
}

// ── Forward transitions ──────────────────────────────────────────────────

TEST(Kernel_Advance, ForwardSucceedsAndFiresObserver) {
    Kernel k;
    auto obs = std::make_shared<RecordingObserver>();
    obs->kernel = &k;
    k.subscribe(obs);

    EXPECT_TRUE(k.advance_to(Phase::Wire));
    EXPECT_EQ(k.current_phase(), Phase::Wire);
    EXPECT_EQ(obs->fire_count.load(), 1);

    std::lock_guard lock{obs->mu};
    ASSERT_EQ(obs->events.size(), 1u);
    EXPECT_EQ(obs->events[0].prev, Phase::Load);
    EXPECT_EQ(obs->events[0].next, Phase::Wire);
    /// Commit-before-notify: visible phase at fire time equals `next`.
    EXPECT_EQ(obs->events[0].observed_now, Phase::Wire);
}

TEST(Kernel_Advance, IdempotentSamePhaseDoesNotFire) {
    Kernel k;
    auto obs = std::make_shared<RecordingObserver>();
    k.subscribe(obs);

    EXPECT_TRUE(k.advance_to(Phase::Load));
    EXPECT_EQ(k.current_phase(), Phase::Load);
    EXPECT_EQ(obs->fire_count.load(), 0)
        << "no notification on no-op same-phase advance";
}

TEST(Kernel_Advance, BackwardReturnsFalseAndIsNoOp) {
    Kernel k;
    auto obs = std::make_shared<RecordingObserver>();
    k.subscribe(obs);

    ASSERT_TRUE(k.advance_to(Phase::Wire));
    EXPECT_EQ(obs->fire_count.load(), 1);

    EXPECT_FALSE(k.advance_to(Phase::Load));
    EXPECT_EQ(k.current_phase(), Phase::Wire)
        << "rejected transition must not mutate state";
    EXPECT_EQ(obs->fire_count.load(), 1)
        << "rejected transition must not fire observers";
}

TEST(Kernel_Advance, SkippingReturnsFalseAndIsNoOp) {
    Kernel k;
    auto obs = std::make_shared<RecordingObserver>();
    k.subscribe(obs);

    EXPECT_FALSE(k.advance_to(Phase::Running));
    EXPECT_EQ(k.current_phase(), Phase::Load);
    EXPECT_EQ(obs->fire_count.load(), 0);
}

TEST(Kernel_Advance, FullForwardWalkFiresObserverPerStep) {
    Kernel k;
    auto obs = std::make_shared<RecordingObserver>();
    obs->kernel = &k;
    k.subscribe(obs);

    constexpr Phase kSeq[] = {
        Phase::Wire, Phase::Resolve, Phase::Ready, Phase::Running,
        Phase::PreShutdown, Phase::Shutdown, Phase::Unload,
    };
    for (Phase p : kSeq) {
        EXPECT_TRUE(k.advance_to(p));
        EXPECT_EQ(k.current_phase(), p);
    }

    EXPECT_EQ(obs->fire_count.load(), static_cast<int>(std::size(kSeq)));

    std::lock_guard lock{obs->mu};
    ASSERT_EQ(obs->events.size(), std::size(kSeq));
    Phase prev_expected = Phase::Load;
    for (std::size_t i = 0; i < std::size(kSeq); ++i) {
        EXPECT_EQ(obs->events[i].prev, prev_expected);
        EXPECT_EQ(obs->events[i].next, kSeq[i]);
        EXPECT_EQ(obs->events[i].observed_now, kSeq[i])
            << "commit-then-notify violated at step " << i;
        prev_expected = kSeq[i];
    }
}

// ── Subscribe / observers ────────────────────────────────────────────────

TEST(Kernel_Subscribe, MultipleObserversAllFire) {
    Kernel k;
    auto a = std::make_shared<RecordingObserver>();
    auto b = std::make_shared<RecordingObserver>();
    auto c = std::make_shared<RecordingObserver>();
    k.subscribe(a);
    k.subscribe(b);
    k.subscribe(c);
    EXPECT_EQ(k.observer_count(), 3u);

    EXPECT_TRUE(k.advance_to(Phase::Wire));
    EXPECT_EQ(a->fire_count.load(), 1);
    EXPECT_EQ(b->fire_count.load(), 1);
    EXPECT_EQ(c->fire_count.load(), 1);

    EXPECT_TRUE(k.advance_to(Phase::Resolve));
    EXPECT_EQ(a->fire_count.load(), 2);
    EXPECT_EQ(b->fire_count.load(), 2);
    EXPECT_EQ(c->fire_count.load(), 2);
}

TEST(Kernel_Subscribe, ExpiredWeakObserverIsPrunedAtFire) {
    Kernel k;
    auto live = std::make_shared<RecordingObserver>();
    k.subscribe(live);

    {
        /// Local scope — drops to expired before the next transition.
        auto temp = std::make_shared<RecordingObserver>();
        k.subscribe(temp);
        EXPECT_EQ(k.observer_count(), 2u);
    }
    /// Source dropped: weak ref still in vector, but `observer_count`
    /// reports the live count.
    EXPECT_EQ(k.observer_count(), 1u);

    /// First transition prunes the expired entry.
    EXPECT_TRUE(k.advance_to(Phase::Wire));
    EXPECT_EQ(live->fire_count.load(), 1);
    EXPECT_EQ(k.observer_count(), 1u);

    /// And the still-live observer keeps receiving events.
    EXPECT_TRUE(k.advance_to(Phase::Resolve));
    EXPECT_EQ(live->fire_count.load(), 2);
}

TEST(Kernel_Subscribe, AlreadyExpiredAtSubscribeIsRejected) {
    Kernel k;
    std::weak_ptr<IPhaseObserver> dead;
    {
        auto tmp = std::make_shared<RecordingObserver>();
        dead = tmp;
    }
    EXPECT_TRUE(dead.expired());
    k.subscribe(dead);
    EXPECT_EQ(k.observer_count(), 0u);
}

// ── stop() ───────────────────────────────────────────────────────────────

TEST(Kernel_Stop, WalksPreShutdownThenShutdown) {
    Kernel k;
    auto obs = std::make_shared<RecordingObserver>();
    obs->kernel = &k;
    k.subscribe(obs);

    /// Bring the kernel to Running before invoking stop.
    ASSERT_TRUE(k.advance_to(Phase::Wire));
    ASSERT_TRUE(k.advance_to(Phase::Resolve));
    ASSERT_TRUE(k.advance_to(Phase::Ready));
    ASSERT_TRUE(k.advance_to(Phase::Running));
    ASSERT_EQ(obs->fire_count.load(), 4);

    k.stop();
    EXPECT_EQ(k.current_phase(), Phase::Shutdown);

    /// Two fires from Running: Running→PreShutdown and PreShutdown→Shutdown.
    EXPECT_EQ(obs->fire_count.load(), 6);

    std::lock_guard lock{obs->mu};
    ASSERT_GE(obs->events.size(), 6u);
    EXPECT_EQ(obs->events[4].prev, Phase::Running);
    EXPECT_EQ(obs->events[4].next, Phase::PreShutdown);
    EXPECT_EQ(obs->events[5].prev, Phase::PreShutdown);
    EXPECT_EQ(obs->events[5].next, Phase::Shutdown);
}

TEST(Kernel_Stop, IdempotentSecondCallIsNoOp) {
    Kernel k;
    auto obs = std::make_shared<RecordingObserver>();
    k.subscribe(obs);
    ASSERT_TRUE(k.advance_to(Phase::Wire));
    ASSERT_TRUE(k.advance_to(Phase::Resolve));
    ASSERT_TRUE(k.advance_to(Phase::Ready));
    ASSERT_TRUE(k.advance_to(Phase::Running));
    const int before_stop = obs->fire_count.load();

    k.stop();
    const int after_first = obs->fire_count.load();
    EXPECT_EQ(after_first - before_stop, 2);
    EXPECT_EQ(k.current_phase(), Phase::Shutdown);

    /// Second stop must not fire anything — the CAS guard wins exactly
    /// once.
    k.stop();
    EXPECT_EQ(obs->fire_count.load(), after_first);
    EXPECT_EQ(k.current_phase(), Phase::Shutdown);
}

TEST(Kernel_Stop, ConcurrentStopFiresExactlyTwice) {
    Kernel k;
    auto obs = std::make_shared<RecordingObserver>();
    k.subscribe(obs);
    ASSERT_TRUE(k.advance_to(Phase::Wire));
    ASSERT_TRUE(k.advance_to(Phase::Resolve));
    ASSERT_TRUE(k.advance_to(Phase::Ready));
    ASSERT_TRUE(k.advance_to(Phase::Running));
    const int baseline = obs->fire_count.load();

    constexpr int kThreads = 4;
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    const auto start = std::chrono::steady_clock::now();
    for (int t = 0; t < kThreads; ++t) threads.emplace_back([&] { k.stop(); });
    for (auto& th : threads) th.join();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(elapsed, std::chrono::seconds(30))
        << "concurrent stop took unexpectedly long; possible deadlock";

    /// Exactly two phase fires regardless of how many threads tried.
    EXPECT_EQ(obs->fire_count.load() - baseline, 2);
    EXPECT_EQ(k.current_phase(), Phase::Shutdown);
}

// ── Concurrent atomic-shared field stress (HIGH-B + HIGH-C) ──────────────

/// Empty IProtocolLayer that satisfies the interface enough to be
/// stored in `protocol_layer_`. The body never runs in this test —
/// the point is to exercise the atomic store/load on a real shared
/// snapshot, not to dispatch through it.
class StubProtocolLayer final : public ::gn::IProtocolLayer {
public:
    [[nodiscard]] std::string_view protocol_id() const noexcept override {
        return "stub";
    }
    Result<DeframeResult> deframe(::gn::ConnectionContext&,
                                   std::span<const std::uint8_t>) override {
        return std::unexpected(::gn::Error{
            GN_ERR_NOT_IMPLEMENTED, "stub"});
    }
    Result<std::vector<std::uint8_t>> frame(::gn::ConnectionContext&,
                                             const gn_message_t&) override {
        return std::unexpected(::gn::Error{
            GN_ERR_NOT_IMPLEMENTED, "stub"});
    }
    [[nodiscard]] std::size_t max_payload_size() const noexcept override {
        return 0;
    }
};

TEST(Kernel_AtomicFields, ProtocolLayerConcurrentSetLoadHasNoRace) {
    Kernel k;
    auto a = std::make_shared<StubProtocolLayer>();
    auto b = std::make_shared<StubProtocolLayer>();

    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> reads{0};

    /// Reader thread: load and verify the snapshot is one of the
    /// two stub layers (or the initial null on the first iteration).
    /// `protocol_id()` is the stable observable per IProtocolLayer.
    std::thread reader([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            auto snap = k.protocol_layer();
            if (snap) {
                EXPECT_EQ(snap->protocol_id(), "stub");
            }
            reads.fetch_add(1, std::memory_order_relaxed);
        }
    });

    /// Writer thread: alternate between the two stubs in a tight
    /// loop. Each iteration is a release store; the reader's load
    /// pairs acquire-release with whichever store it observes.
    std::thread writer([&] {
        for (int i = 0; i < 100'000; ++i) {
            k.set_protocol_layer(i % 2 == 0 ? a : b);
        }
        stop.store(true, std::memory_order_relaxed);
    });

    writer.join();
    reader.join();

    EXPECT_GT(reads.load(), 0u)
        << "reader thread must have observed at least one snapshot";
}

TEST(Kernel_AtomicFields, ProtocolLayerSnapshotOutlivesReplacement) {
    Kernel k;
    auto first = std::make_shared<StubProtocolLayer>();
    k.set_protocol_layer(first);

    auto snapshot = k.protocol_layer();
    ASSERT_TRUE(snapshot);
    EXPECT_EQ(snapshot.get(), first.get());

    /// Replace the layer; a thunk holding `snapshot` must keep the
    /// old layer alive for the duration of its dispatch.
    auto second = std::make_shared<StubProtocolLayer>();
    k.set_protocol_layer(second);

    /// The kernel's current value is `second`, but `snapshot` still
    /// points at `first` because shared_ptr ref-count semantics keep
    /// the old object alive while any caller holds a snapshot.
    EXPECT_EQ(snapshot.get(), first.get())
        << "in-flight snapshot must not flip under a concurrent set";
    EXPECT_EQ(k.protocol_layer().get(), second.get());

    /// Drop our remaining strong references; the second-set object
    /// stays in the kernel until the kernel itself dies.
    snapshot.reset();
    first.reset();
    second.reset();
    EXPECT_TRUE(k.protocol_layer())
        << "kernel still holds the most-recent set, even after the "
           "external strong refs went away";
}

}  // namespace
}  // namespace gn::core
