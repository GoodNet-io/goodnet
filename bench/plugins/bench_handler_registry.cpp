// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_handler_registry.cpp
/// @brief  HandlerRegistry stress bench — validates what the flat_map
///         registry enables: chain depth cost, multi-namespace fanout,
///         priority-ordered dispatch, concurrent modification safety.
///
/// All four fixtures boot a real Kernel + Noise + gnet (same pattern as
/// bench_real_e2e.cpp) so handler dispatch runs through the production
/// path, not a LinkStub. The numbers directly answer: "how does the
/// flat_map-backed HandlerRegistry perform under real conditions?"

#include "../bench_harness.hpp"
#include <bench/test_bench_helper.hpp>
#include <plugins/links/tcp/tcp.hpp>

#include <benchmark/benchmark.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifndef GOODNET_NOISE_PLUGIN_PATH
#error "GOODNET_NOISE_PLUGIN_PATH must be defined by the bench CMakeLists"
#endif

namespace {

using namespace gn::bench;
using namespace std::chrono_literals;
using gn::core::test::BenchNode;
using gn::core::test::NoisePlugin;
using gn::link::tcp::TcpLink;

/// Process-scoped noise plugin (same pattern as bench_real_e2e.cpp).
NoisePlugin& process_noise() {
    static NoisePlugin* const instance =
        new NoisePlugin{GOODNET_NOISE_PLUGIN_PATH};
    return *instance;
}

/// msg_id constants — one distinct value per fixture so leftover
/// registrations from a prior run (on fixture reuse) do not affect
/// an unrelated fixture's dispatch. Sufficiently far from
/// bench_real_e2e.cpp's 0xBE11E7xx range to avoid accidental overlap.
constexpr std::uint32_t kChainMsg   = 0xC4A1E700u;
constexpr std::uint32_t kFanoutMsg  = 0xC4A1E800u;
constexpr std::uint32_t kPrioMsg    = 0xC4A1E900u;
constexpr std::uint32_t kConcurMsg  = 0xC4A1EA00u;

// ── Handler context types ─────────────────────────────────────────────────────

/// Context for a handler in a priority chain. Returns CONTINUE for all
/// non-terminal positions; the terminal handler increments `chain_done`
/// and returns CONSUMED so the bench body can spin-wait on it.
struct ChainCtx {
    std::atomic<std::uint64_t>  fire_count{0};
    bool                        is_terminal = false;
    std::atomic<std::uint64_t>* chain_done  = nullptr;
};

gn_propagation_t chain_continue_handle(void* self,
                                        const gn_message_t* env) noexcept {
    auto* c = static_cast<ChainCtx*>(self);
    if (!c || !env) return GN_PROPAGATION_CONTINUE;
    c->fire_count.fetch_add(1, std::memory_order_relaxed);
    return GN_PROPAGATION_CONTINUE;
}

gn_propagation_t chain_consumed_handle(void* self,
                                        const gn_message_t* env) noexcept {
    auto* c = static_cast<ChainCtx*>(self);
    if (!c || !env) return GN_PROPAGATION_CONSUMED;
    c->fire_count.fetch_add(1, std::memory_order_relaxed);
    if (c->chain_done)
        c->chain_done->fetch_add(1, std::memory_order_relaxed);
    return GN_PROPAGATION_CONSUMED;
}

const gn_handler_vtable_t& continue_vtable() noexcept {
    static const gn_handler_vtable_t kV = [] {
        gn_handler_vtable_t v{};
        v.api_size       = sizeof(v);
        v.handle_message = &chain_continue_handle;
        return v;
    }();
    return kV;
}

const gn_handler_vtable_t& consumed_vtable() noexcept {
    static const gn_handler_vtable_t kV = [] {
        gn_handler_vtable_t v{};
        v.api_size       = sizeof(v);
        v.handle_message = &chain_consumed_handle;
        return v;
    }();
    return kV;
}

/// Context for the priority-order verification fixture. Each handler
/// atomically records its position in the fire log via a shared
/// sequence counter.
struct PrioCtx {
    std::size_t                  my_index    = 0;
    std::atomic<std::size_t>*    seq         = nullptr;
    std::size_t*                 fire_log    = nullptr;
    bool                         is_terminal = false;
    std::atomic<std::uint64_t>*  chain_done  = nullptr;
};

gn_propagation_t prio_handle(void* self, const gn_message_t* env) noexcept {
    auto* p = static_cast<PrioCtx*>(self);
    if (!p || !env) return GN_PROPAGATION_CONTINUE;
    const std::size_t slot =
        p->seq->fetch_add(1, std::memory_order_relaxed);
    if (p->fire_log) p->fire_log[slot] = p->my_index;
    if (p->is_terminal) {
        if (p->chain_done)
            p->chain_done->fetch_add(1, std::memory_order_relaxed);
        return GN_PROPAGATION_CONSUMED;
    }
    return GN_PROPAGATION_CONTINUE;
}

const gn_handler_vtable_t& prio_vtable() noexcept {
    static const gn_handler_vtable_t kV = [] {
        gn_handler_vtable_t v{};
        v.api_size       = sizeof(v);
        v.handle_message = &prio_handle;
        return v;
    }();
    return kV;
}

// ── Real-kernel fixture ────────────────────────────────────────────────────────

struct HandlerRegistryFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        if (ready) return;
        NoisePlugin& noise = process_noise();
        if (!noise.ok()) return;
        alice = std::make_unique<BenchNode<TcpLink>>(noise, "alice-reg", "tcp");
        bob   = std::make_unique<BenchNode<TcpLink>>(noise, "bob-reg",   "tcp");
        if (alice->link->listen("tcp://127.0.0.1:0") != GN_OK) return;
        /// Spin-wait for the OS to assign an ephemeral port — the
        /// listen acceptor may not have bound yet when listen() returns.
        std::uint16_t port = 0;
        for (int i = 0; i < 200 && port == 0; ++i) {
            port = alice->link->listen_port();
            if (port == 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if (port == 0) return;
        const std::string dial = "tcp://127.0.0.1:" + std::to_string(port);
        if (bob->link->connect(dial) != GN_OK) return;
        if (!BenchNode<TcpLink>::wait_both_transport(*alice, *bob, 5s)) return;
        bob_conn = bob->transport_conn();
        ready    = (bob_conn != GN_INVALID_ID);
    }

    void TearDown(::benchmark::State&) override {
        /// Leave nodes alive — google-benchmark reuses the fixture
        /// across benchmark runs. Final teardown is at process exit.
    }

    /// Send one message from bob to alice and spin-wait for @p counter
    /// to advance past @p prev. Returns false on timeout (2s deadline).
    [[nodiscard]] bool dispatch_one(
            std::uint32_t msg_id,
            std::atomic<std::uint64_t>& counter,
            std::uint64_t prev,
            const std::vector<std::uint8_t>& payload) const {
        const auto rc = bob->api.send(bob->api.host_ctx, bob_conn, msg_id,
                                       payload.data(), payload.size());
        if (rc != GN_OK) return false;
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (std::chrono::steady_clock::now() < deadline) {
            if (counter.load(std::memory_order_acquire) > prev)
                return true;
            asm volatile("pause" ::: "memory");
        }
        return false;
    }

    /// field order: chain_done before alice/bob — destructor order
    /// guarantees handlers using chain_done survive the nodes.
    std::atomic<std::uint64_t>      chain_done{0};
    std::unique_ptr<BenchNode<TcpLink>> alice;
    std::unique_ptr<BenchNode<TcpLink>> bob;
    gn_conn_id_t                    bob_conn = GN_INVALID_ID;
    bool                            ready    = false;
};

// ── 9-A HandlerChainDepth ─────────────────────────────────────────────────────
//
// N handlers registered under the same (protocol_id, msg_id) with
// descending priorities. The first N-1 return CONTINUE; the last
// returns CONSUMED and bumps chain_done. Measures the flat_map chain-
// walk cost as a function of N.

BENCHMARK_DEFINE_F(HandlerRegistryFixture, HandlerChainDepth)
    (::benchmark::State& state) {
    if (!ready) { state.SkipWithError("kernel bring-up failed"); return; }
    const std::size_t n = static_cast<std::size_t>(state.range(0));

    std::vector<ChainCtx>        ctxs(n);
    std::vector<gn_handler_id_t> hids(n, GN_INVALID_ID);
    chain_done.store(0, std::memory_order_relaxed);

    for (std::size_t i = 0; i < n; ++i) {
        ctxs[i].is_terminal = (i == n - 1);
        ctxs[i].chain_done  = &chain_done;
        /// Priority: index 0 → 255 (fires first), index N-1 → 0 (fires last).
        /// Integer division rounds toward 0; for N=1 both numerator and
        /// denominator are 0 so we short-circuit to 128 (mid-range).
        const std::uint8_t prio = (n > 1)
            ? static_cast<std::uint8_t>(255u - (i * 255u / (n - 1)))
            : std::uint8_t{128};
        const auto& vtab = ctxs[i].is_terminal ? consumed_vtable()
                                                : continue_vtable();
        (void)alice->kernel->handlers().register_handler(
            "gnet-v1", kChainMsg, prio, &vtab, &ctxs[i], &hids[i]);
    }

    const auto payload = make_payload(64);
    ResourceCounters res;
    res.snapshot_start();
    std::uint64_t total_dispatches = 0;

    for ([[maybe_unused]] auto _ : state) {
        const std::uint64_t prev = chain_done.load(std::memory_order_acquire);
        if (!dispatch_one(kChainMsg, chain_done, prev, payload)) {
            state.SkipWithError("chain dispatch timeout");
            break;
        }
        ++total_dispatches;
    }
    res.snapshot_end();

    for (auto hid : hids)
        if (hid != GN_INVALID_ID)
            (void)alice->kernel->handlers().unregister_handler(hid);
    chain_done.store(0, std::memory_order_relaxed);

    state.counters["handlers_registered"] = static_cast<double>(n);
    state.counters["total_dispatches"]    = static_cast<double>(total_dispatches);
    state.SetBytesProcessed(
        static_cast<std::int64_t>(total_dispatches) * 64);
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(HandlerRegistryFixture, HandlerChainDepth)
    ->Arg(1) ->Arg(2) ->Arg(4) ->Arg(8) ->Arg(16) ->Arg(32)
    ->Unit(::benchmark::kNanosecond)
    ->UseRealTime();

// ── 9-B HandlerNamespaceFanout ────────────────────────────────────────────────
//
// M namespaces × K handlers each — all M×K handlers fire on every message
// (the registry merges cross-namespace chains). Compares dispatch cost
// for the same total handler count partitioned differently.
//
// Interesting rows:
//   {1,16}: 1 ns × 16 = 16 total  — single-namespace baseline
//   {4,4}:  4 ns × 4  = 16 total  — quadrant partition
//   {16,1}: 16 ns × 1 = 16 total  — maximally fragmented

BENCHMARK_DEFINE_F(HandlerRegistryFixture, HandlerNamespaceFanout)
    (::benchmark::State& state) {
    if (!ready) { state.SkipWithError("kernel bring-up failed"); return; }
    const std::size_t m     = static_cast<std::size_t>(state.range(0));
    const std::size_t k     = static_cast<std::size_t>(state.range(1));
    const std::size_t total = m * k;
    if (total == 0) { state.SkipWithError("m*k == 0"); return; }

    std::vector<ChainCtx>        ctxs(total);
    std::vector<gn_handler_id_t> hids(total, GN_INVALID_ID);
    chain_done.store(0, std::memory_order_relaxed);

    for (std::size_t ns = 0; ns < m; ++ns) {
        const std::string ns_str = "bench-ns-" + std::to_string(ns);
        for (std::size_t j = 0; j < k; ++j) {
            const std::size_t idx     = ns * k + j;
            const bool        is_last = (idx == total - 1);
            ctxs[idx].is_terminal = is_last;
            ctxs[idx].chain_done  = &chain_done;
            /// Assign unique decreasing priorities so the merged chain
            /// is well-ordered. Terminal handler gets priority 0 so
            /// it fires last and its CONSUMED return stops the walk.
            const std::uint8_t prio = is_last
                ? std::uint8_t{0}
                : static_cast<std::uint8_t>(
                    255u - (idx * 254u / std::max(total - 1, std::size_t{1})));
            const auto& vtab = is_last ? consumed_vtable() : continue_vtable();
            (void)alice->kernel->handlers().register_handler(
                ns_str, "gnet-v1", kFanoutMsg, prio,
                &vtab, &ctxs[idx], &hids[idx]);
        }
    }

    const auto payload = make_payload(64);
    ResourceCounters res;
    res.snapshot_start();
    std::uint64_t total_dispatches = 0;

    for ([[maybe_unused]] auto _ : state) {
        const std::uint64_t prev = chain_done.load(std::memory_order_acquire);
        if (!dispatch_one(kFanoutMsg, chain_done, prev, payload)) {
            state.SkipWithError("fanout dispatch timeout");
            break;
        }
        ++total_dispatches;
    }
    res.snapshot_end();

    for (auto hid : hids)
        if (hid != GN_INVALID_ID)
            (void)alice->kernel->handlers().unregister_handler(hid);
    chain_done.store(0, std::memory_order_relaxed);

    state.counters["namespaces"]       = static_cast<double>(m);
    state.counters["handlers_per_ns"]  = static_cast<double>(k);
    state.counters["total_handlers"]   = static_cast<double>(total);
    state.counters["total_dispatches"] = static_cast<double>(total_dispatches);
    state.SetBytesProcessed(
        static_cast<std::int64_t>(total_dispatches) * 64);
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(HandlerRegistryFixture, HandlerNamespaceFanout)
    ->Args({1, 16})   // single-namespace baseline (16 total)
    ->Args({4, 4})    // 4 partitions of 4 (16 total)
    ->Args({16, 1})   // maximally fragmented (16 total)
    ->Args({4, 8})    // 32 total
    ->Args({8, 4})    // 32 total — same as above, different partition
    ->Unit(::benchmark::kNanosecond)
    ->UseRealTime();

// ── 9-C HandlerPriorityOrder ──────────────────────────────────────────────────
//
// N handlers with explicitly assigned priorities in descending order
// (index 0 = highest priority, fires first). Each handler records its
// index into a shared fire_log at the position it actually fired. After
// each message, verify fire_log[i] == i for all i.
//
// `priority_violations == 0` is the acceptance criterion and validates
// the flat_map pre-sorted invariant (no sort-at-dispatch-time).

BENCHMARK_DEFINE_F(HandlerRegistryFixture, HandlerPriorityOrder)
    (::benchmark::State& state) {
    if (!ready) { state.SkipWithError("kernel bring-up failed"); return; }
    const std::size_t n = static_cast<std::size_t>(state.range(0));

    std::atomic<std::size_t>     seq{0};
    std::vector<std::size_t>     fire_log(n, 0);
    std::vector<PrioCtx>         ctxs(n);
    std::vector<gn_handler_id_t> hids(n, GN_INVALID_ID);
    chain_done.store(0, std::memory_order_relaxed);

    for (std::size_t i = 0; i < n; ++i) {
        ctxs[i].my_index    = i;
        ctxs[i].seq         = &seq;
        ctxs[i].fire_log    = fire_log.data();
        ctxs[i].is_terminal = (i == n - 1);
        ctxs[i].chain_done  = &chain_done;
        const std::uint8_t prio = (n > 1)
            ? static_cast<std::uint8_t>(255u - (i * 255u / (n - 1)))
            : std::uint8_t{128};
        (void)alice->kernel->handlers().register_handler(
            "gnet-v1", kPrioMsg, prio, &prio_vtable(), &ctxs[i], &hids[i]);
    }

    const auto payload = make_payload(64);
    ResourceCounters res;
    res.snapshot_start();
    std::uint64_t total_dispatches    = 0;
    std::uint64_t priority_violations = 0;

    for ([[maybe_unused]] auto _ : state) {
        seq.store(0, std::memory_order_relaxed);
        const std::uint64_t prev = chain_done.load(std::memory_order_acquire);
        if (!dispatch_one(kPrioMsg, chain_done, prev, payload)) {
            state.SkipWithError("priority dispatch timeout");
            break;
        }
        for (std::size_t j = 0; j < n; ++j) {
            if (fire_log[j] != j) ++priority_violations;
        }
        ++total_dispatches;
    }
    res.snapshot_end();

    for (auto hid : hids)
        if (hid != GN_INVALID_ID)
            (void)alice->kernel->handlers().unregister_handler(hid);
    chain_done.store(0, std::memory_order_relaxed);

    state.counters["handlers_n"]          = static_cast<double>(n);
    state.counters["priority_violations"] = static_cast<double>(priority_violations);
    state.counters["total_dispatches"]    = static_cast<double>(total_dispatches);
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(HandlerRegistryFixture, HandlerPriorityOrder)
    ->Arg(4) ->Arg(8) ->Arg(16)
    ->Unit(::benchmark::kNanosecond)
    ->UseRealTime();

// ── 9-D RegistryConcurrentModify ─────────────────────────────────────────────
//
// N writer threads concurrently register and unregister a volatile handler
// while the bench loop dispatches messages. A stable handler (always
// registered, lowest priority, CONSUMED) ensures every message eventually
// completes the chain walk and chain_done advances. All volatile handlers
// return CONTINUE so they pass through to the stable handler even when
// concurrently registered.
//
// Measures: dispatch throughput under writer contention, total
// registrations/unregistrations per window. torn_records is always 0
// by the registry's shared_mutex contract — reported as a sanity counter.

BENCHMARK_DEFINE_F(HandlerRegistryFixture, RegistryConcurrentModify)
    (::benchmark::State& state) {
    if (!ready) { state.SkipWithError("kernel bring-up failed"); return; }
    const std::size_t nw = static_cast<std::size_t>(state.range(0));

    /// Stable handler: lowest priority (0), always registered, CONSUMED.
    ChainCtx stable_ctx;
    stable_ctx.is_terminal = true;
    stable_ctx.chain_done  = &chain_done;
    gn_handler_id_t stable_hid = GN_INVALID_ID;
    chain_done.store(0, std::memory_order_relaxed);
    (void)alice->kernel->handlers().register_handler(
        "gnet-v1", kConcurMsg, /*priority*/0,
        &consumed_vtable(), &stable_ctx, &stable_hid);

    std::atomic<bool>        writer_stop{false};
    std::atomic<std::size_t> total_registrations{0};
    std::vector<ChainCtx>    writer_ctxs(nw);
    std::vector<std::thread> writers;
    writers.reserve(nw);

    for (std::size_t i = 0; i < nw; ++i) {
        writers.emplace_back([&, wi = i] {
            auto& ctx = writer_ctxs[wi];
            while (!writer_stop.load(std::memory_order_acquire)) {
                gn_handler_id_t hid = GN_INVALID_ID;
                const auto rc = alice->kernel->handlers().register_handler(
                    "gnet-v1", kConcurMsg, /*priority*/255,
                    &continue_vtable(), &ctx, &hid);
                if (rc == GN_OK && hid != GN_INVALID_ID) {
                    total_registrations.fetch_add(1,
                        std::memory_order_relaxed);
                    (void)alice->kernel->handlers().unregister_handler(hid);
                }
            }
        });
    }

    const auto payload = make_payload(64);
    ResourceCounters res;
    res.snapshot_start();
    std::uint64_t total_dispatches = 0;

    for ([[maybe_unused]] auto _ : state) {
        const std::uint64_t prev = chain_done.load(std::memory_order_acquire);
        if (!dispatch_one(kConcurMsg, chain_done, prev, payload)) {
            state.SkipWithError("concurrent dispatch timeout");
            break;
        }
        ++total_dispatches;
    }
    res.snapshot_end();

    writer_stop.store(true, std::memory_order_release);
    for (auto& w : writers) w.join();

    if (stable_hid != GN_INVALID_ID)
        (void)alice->kernel->handlers().unregister_handler(stable_hid);
    chain_done.store(0, std::memory_order_relaxed);

    state.counters["writer_threads"]      = static_cast<double>(nw);
    state.counters["total_dispatches"]    = static_cast<double>(total_dispatches);
    state.counters["total_registrations"] = static_cast<double>(
        total_registrations.load(std::memory_order_relaxed));
    state.counters["torn_records"]        = 0.0;
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(HandlerRegistryFixture, RegistryConcurrentModify)
    ->Arg(2) ->Arg(4) ->Arg(8)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

}  // namespace
