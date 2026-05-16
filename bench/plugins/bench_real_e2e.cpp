// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_real_e2e.cpp
/// @brief  Production-shape bench (A.2 from the master plan).
///
/// Every other bench under `bench/plugins/*` wires a link plugin to
/// the `LinkStub` test fixture — no security provider, no protocol
/// layer. The numbers it produces are an upper bound, not the cost
/// an operator-facing `send()` actually pays. This file closes that
/// gap: it boots a real `gn::core::Kernel`, registers the production
/// stack (gnet protocol layer + dlopen'd noise security provider +
/// transport plugin), and measures the same ping/pong round-trip the
/// operator code path runs.
///
/// Case names carry the `RealFixture/` prefix so
/// `bench/comparison/runners/aggregate.py` routes them into the
/// `## Real — production-shape echo` section instead of mixing them
/// with the parody matrix.

#include "../bench_harness.hpp"

#include <bench/test_bench_helper.hpp>

#include <plugins/links/tcp/tcp.hpp>
#include <plugins/links/udp/udp.hpp>
#include <plugins/links/ipc/ipc.hpp>

#include <benchmark/benchmark.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

#ifndef GOODNET_NOISE_PLUGIN_PATH
#error "GOODNET_NOISE_PLUGIN_PATH must be defined by the bench CMakeLists"
#endif

namespace {

using namespace gn::bench;
using namespace std::chrono_literals;
using gn::core::test::BenchNode;
using gn::core::test::NoisePlugin;
using gn::core::test::RxCounter;
using gn::core::test::RxEchoResponder;
using gn::core::test::register_rx;
using gn::core::test::register_echo_responder;

constexpr std::uint32_t kPingMsgId = 0xBE11E700u;
constexpr std::uint32_t kPongMsgId = 0xBE11E701u;

/// Process-scoped noise plugin handle. Leaked intentionally —
/// google-benchmark registers fixture instances with `atexit`,
/// and a function-local static `NoisePlugin` would destruct
/// (running `dlclose`) BEFORE benchmark's fixture cleanup tries
/// to call `plugin_unregister` / `plugin_shutdown` through
/// function pointers from the now-unmapped `.so`. Leaking the
/// handle lets the OS unmap the page at process exit, after
/// every fixture has already finished walking its destructor.
NoisePlugin& process_noise() {
    static NoisePlugin* const instance =
        new NoisePlugin{GOODNET_NOISE_PLUGIN_PATH};
    return *instance;
}

/// Templated bench fixture — one instantiation per transport. The
/// kernel + noise + handler bring-up runs once (`ready` guard) and
/// is reused across every google-benchmark run on the fixture, so
/// the loop body measures steady-state send/recv only, not boot.
template <class Link>
struct RealFixtureBase : public ::benchmark::Fixture {
    void common_setup(const std::string& listen_uri,
                      std::string* out_dial_uri) {
        if (ready) return;
        NoisePlugin& noise_ref = process_noise();
        if (!noise_ref.ok()) return;
        alice = std::make_unique<BenchNode<Link>>(noise_ref, "alice", scheme);
        bob   = std::make_unique<BenchNode<Link>>(noise_ref, "bob",   scheme);

        /// Two handler shapes registered:
        ///  * one-way leg — alice listens on kPingMsgId, counts arrivals
        ///    (used by `run_send_recv` to measure send→handler-fire).
        ///  * echo leg — alice listens on kPingMsgId (same id; the
        ///    one-way handler returns CONSUMED, but for echo cases the
        ///    responder is installed instead), echoes payload back to
        ///    bob under kPongMsgId. Bob listens on kPongMsgId to close
        ///    the round-trip in `run_echo_roundtrip`.
        /// Both handlers can coexist — the registry dispatches by
        /// (namespace_id, msg_id) and same msg_id collides on alice,
        /// so the fixture registers one shape at SetUp time per its
        /// `setup_echo` flag. Bob unconditionally registers the pong
        /// counter; an absent pong (one-way case) just leaves bob.rx
        /// untouched.
        if (setup_echo) {
            rx_echo_hid = register_echo_responder(*alice->kernel,
                kPingMsgId, kPongMsgId, &alice->api, echo_resp);
            pong_hid    = register_rx(*bob->kernel, kPongMsgId, pong);
        } else {
            rx_hid = register_rx(*alice->kernel, kPingMsgId, rx);
        }

        if (alice->link->listen(listen_uri) != GN_OK) return;
        const auto resolved = resolve_dial_uri(listen_uri);
        if (resolved.empty()) return;
        if (out_dial_uri) *out_dial_uri = resolved;
        if (bob->link->connect(resolved) != GN_OK) return;

        if (!BenchNode<Link>::wait_both_transport(*alice, *bob, 5s)) return;
        bob_conn = bob->transport_conn();
        ready    = (bob_conn != GN_INVALID_ID);
    }

    void TearDown(::benchmark::State&) override {
        /// Leave nodes alive — google-benchmark reuses the same
        /// fixture across iterations. Final teardown happens at
        /// process exit via the fixture's dtor.
    }

    /// Resolve a `*:0` placeholder URI to the kernel-assigned
    /// endpoint. TCP/UDP go through `listen_port`; IPC's path is
    /// stable so it returns the URI as-is.
    virtual std::string resolve_dial_uri(const std::string& listen_uri) = 0;

    /// Field order matters for destruction. `rx` is the handler's
    /// `self` pointer — registered into alice's kernel. Alice's
    /// destructor walks her HandlerRegistry and may dispatch a
    /// final pending envelope through the handler's vtable, so
    /// `rx` MUST outlive `alice`. C++ destroys members in reverse
    /// declaration order, so declaring `rx` BEFORE `alice` keeps
    /// alice destructing first.
    /// Field order matters: handler `self` pointers (`rx`, `pong`,
    /// `echo_resp`) MUST outlive `alice` / `bob`. C++ destroys in
    /// reverse declaration order; declaring them first means they
    /// destruct last. `setup_echo` is set by subclass ctor before
    /// `common_setup` runs; default `false` = one-way path.
    const char* scheme       = nullptr;
    bool        setup_echo   = false;
    RxCounter                           rx;
    RxCounter                           pong;
    RxEchoResponder                     echo_resp;
    std::unique_ptr<BenchNode<Link>>    alice;
    std::unique_ptr<BenchNode<Link>>    bob;
    gn_handler_id_t                     rx_hid       = GN_INVALID_ID;
    gn_handler_id_t                     pong_hid     = GN_INVALID_ID;
    gn_handler_id_t                     rx_echo_hid  = GN_INVALID_ID;
    gn_conn_id_t                        bob_conn     = GN_INVALID_ID;
    bool                                ready        = false;
};

/// Bench body — bob sends one envelope per iteration through the
/// production stack (host_api send → gnet frame → noise encrypt →
/// link write); alice's rx counter advances on arrival; latency is
/// sampled from `send` entry to counter step. One-way path covers
/// every operator-facing layer; doubling it approximates RTT.
template <class Fixture>
void run_send_recv(Fixture& f, ::benchmark::State& state) {
    if (!f.ready) {
        state.SkipWithError("real-mode bring-up failed");
        return;
    }
    const std::size_t payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    RoundTripMeter   meter;
    ResourceCounters res;
    res.snapshot_start();

    std::uint64_t prev_rx = f.rx.rx_count.load(std::memory_order_acquire);
    gn_result_t   last_err = GN_OK;

    for ([[maybe_unused]] auto _ : state) {  // NOLINT
        const auto t0 = std::chrono::steady_clock::now();
        const gn_result_t rc = f.bob->api.send(
            f.bob->api.host_ctx, f.bob_conn, kPingMsgId,
            payload.data(), payload.size());
        if (rc != GN_OK) {
            last_err = rc;
            /// Backpressure: yield and retry under the same
            /// iteration slot. Tail-burst payloads hit this; the
            /// per-conn send queue drains via the IO strand on
            /// the next reactor tick.
            std::this_thread::sleep_for(50us);
            continue;
        }
        /// Tight busy-wait with `pause` — loopback wire-time is
        /// microseconds; the SDK `wait_for` 5ms tick would dominate
        /// the sample. Bounded by a 2s deadline so a stuck conn
        /// surfaces as a skip rather than a hang.
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        bool arrived = false;
        while (std::chrono::steady_clock::now() < deadline) {
            if (f.rx.rx_count.load(std::memory_order_acquire) > prev_rx) {
                arrived = true;
                break;
            }
            asm volatile("pause" ::: "memory");
        }
        if (!arrived) {
            state.SkipWithError("rx arrival timeout");
            break;
        }
        const auto t1 = std::chrono::steady_clock::now();
        meter.record(static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                t1 - t0).count()));
        prev_rx = f.rx.rx_count.load(std::memory_order_acquire);
    }

    res.snapshot_end();
    state.counters["last_err"] = static_cast<double>(last_err);
    state.SetBytesProcessed(
        static_cast<std::int64_t>(meter.size()) *
        static_cast<std::int64_t>(payload_size));
    report_latency(state, meter);
    report_resources(state, res);
}

/// Echo round-trip body — track А shape that matches libp2p / iroh
/// echo runners. Bob sends `kPingMsgId`; alice's `RxEchoResponder`
/// fires `api->send(env->conn_id, kPongMsgId, payload)` back; bob's
/// pong counter advances on arrival. Latency captured T0=ping-send
/// → T1=pong-receive. Two passes through the production stack
/// (encrypt + decrypt + protocol-frame on each side per direction),
/// so the figure is symmetric with `libp2p-echo`'s `write_all →
/// read` loop in `bench/comparison/p2p/libp2p-echo/src/main.rs`.
template <class Fixture>
void run_echo_roundtrip(Fixture& f, ::benchmark::State& state) {
    if (!f.ready) {
        state.SkipWithError("real-mode bring-up failed");
        return;
    }
    if (!f.setup_echo) {
        state.SkipWithError("fixture not configured for echo (setup_echo=false)");
        return;
    }
    const std::size_t payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    RoundTripMeter   meter;
    ResourceCounters res;
    res.snapshot_start();

    std::uint64_t prev_pong = f.pong.rx_count.load(std::memory_order_acquire);
    gn_result_t   last_err  = GN_OK;

    for ([[maybe_unused]] auto _ : state) {  // NOLINT
        const auto t0 = std::chrono::steady_clock::now();
        const gn_result_t rc = f.bob->api.send(
            f.bob->api.host_ctx, f.bob_conn, kPingMsgId,
            payload.data(), payload.size());
        if (rc != GN_OK) {
            last_err = rc;
            std::this_thread::sleep_for(50us);
            continue;
        }
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        bool arrived = false;
        while (std::chrono::steady_clock::now() < deadline) {
            if (f.pong.rx_count.load(std::memory_order_acquire) > prev_pong) {
                arrived = true;
                break;
            }
            asm volatile("pause" ::: "memory");
        }
        if (!arrived) {
            state.SkipWithError("pong arrival timeout");
            break;
        }
        const auto t1 = std::chrono::steady_clock::now();
        meter.record(static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                t1 - t0).count()));
        prev_pong = f.pong.rx_count.load(std::memory_order_acquire);
    }

    res.snapshot_end();
    state.counters["last_err"] = static_cast<double>(last_err);
    /// Bytes processed: full RTT moves payload twice (ping + pong),
    /// so report 2× for throughput comparability with libp2p's
    /// bidirectional read+write measurement.
    state.SetBytesProcessed(
        static_cast<std::int64_t>(meter.size()) *
        static_cast<std::int64_t>(payload_size) * 2);
    report_latency(state, meter);
    report_resources(state, res);
}

// ── TCP ─────────────────────────────────────────────────────────────

struct RealFixtureTcp : RealFixtureBase<gn::link::tcp::TcpLink> {
    RealFixtureTcp() { scheme = "tcp"; }
    void SetUp(::benchmark::State&) override {
        common_setup("tcp://127.0.0.1:0", &dial_uri);
    }
    std::string resolve_dial_uri(const std::string&) override {
        const auto port = alice->link->listen_port();
        if (port == 0) return {};
        return "tcp://127.0.0.1:" + std::to_string(port);
    }
    std::string dial_uri;
};

BENCHMARK_DEFINE_F(RealFixtureTcp, TcpEcho)(::benchmark::State& state) {
    run_send_recv(*this, state);
}
BENCHMARK_REGISTER_F(RealFixtureTcp, TcpEcho)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Arg(32768)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

/// Echo round-trip variant — same transport, but alice runs the
/// echo responder instead of the one-way rx counter. Sibling fixture
/// flips `setup_echo=true` before `common_setup` registers handlers.
struct RealFixtureTcpEcho : RealFixtureTcp {
    RealFixtureTcpEcho() { setup_echo = true; }
};

BENCHMARK_DEFINE_F(RealFixtureTcpEcho, TcpEchoRoundtrip)(::benchmark::State& state) {
    run_echo_roundtrip(*this, state);
}
BENCHMARK_REGISTER_F(RealFixtureTcpEcho, TcpEchoRoundtrip)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Arg(32768)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

// TODO(track-A-followup): Real-QUIC echo round-trip.
// QuicLink::listen/connect return GN_ERR_NOT_IMPLEMENTED in
// `plugins/links/quic/quic.cpp:148-156` — QUIC is composer-only
// over a UDP carrier (see `plugins/links/quic/quic.hpp:58-62`).
// A Real-mode QUIC fixture needs `BenchNode` extended with a
// LinkCarrier + `set_server_credentials` + `composer_listen` /
// `composer_connect` bring-up path. Deferred to its own slice;
// once landed, register `RealFixtureQuicEcho/QuicEchoRoundtrip`
// here with the same Arg sweep so the aggregator's `## А.` section
// shows the iroh-comparable row.

// ── UDP ─────────────────────────────────────────────────────────────
//
// UDP's MTU cap (`plugins/links/udp/udp.hpp::kDefaultMtu = 1200`)
// rejects sends > 1200 bytes by default, so the bench stops at 1024.
// Raising the cap is a configure-time knob and is out of scope here.

struct RealFixtureUdp : RealFixtureBase<gn::link::udp::UdpLink> {
    RealFixtureUdp() { scheme = "udp"; }
    void SetUp(::benchmark::State&) override {
        common_setup("udp://127.0.0.1:0", &dial_uri);
    }
    std::string resolve_dial_uri(const std::string&) override {
        const auto port = alice->link->listen_port();
        if (port == 0) return {};
        return "udp://127.0.0.1:" + std::to_string(port);
    }
    std::string dial_uri;
};

BENCHMARK_DEFINE_F(RealFixtureUdp, UdpEcho)(::benchmark::State& state) {
    run_send_recv(*this, state);
}
BENCHMARK_REGISTER_F(RealFixtureUdp, UdpEcho)
    ->Arg(64)
    ->Arg(1024)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

struct RealFixtureUdpEcho : RealFixtureUdp {
    RealFixtureUdpEcho() { setup_echo = true; }
};

BENCHMARK_DEFINE_F(RealFixtureUdpEcho, UdpEchoRoundtrip)(::benchmark::State& state) {
    run_echo_roundtrip(*this, state);
}
BENCHMARK_REGISTER_F(RealFixtureUdpEcho, UdpEchoRoundtrip)
    ->Arg(64)
    ->Arg(1024)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

// ── IPC (AF_UNIX) ───────────────────────────────────────────────────
//
// Unique socket path per process so concurrent bench runs from the
// same checkout do not collide on `EADDRINUSE`. `unlink`'d on
// fixture destruction via IpcLink::shutdown().

struct RealFixtureIpc : RealFixtureBase<gn::link::ipc::IpcLink> {
    RealFixtureIpc() {
        scheme = "ipc";
        char tmpl[] = "/tmp/gnbench-XXXXXX";
        const int fd = ::mkstemp(tmpl);
        if (fd >= 0) { ::close(fd); ::unlink(tmpl); }
        sock_path = std::string(tmpl) + ".sock";
    }
    void SetUp(::benchmark::State&) override {
        common_setup("ipc://" + sock_path, &dial_uri);
    }
    std::string resolve_dial_uri(const std::string& listen_uri) override {
        return listen_uri;  // path-based, no port resolution
    }
    std::string sock_path;
    std::string dial_uri;
};

BENCHMARK_DEFINE_F(RealFixtureIpc, IpcEcho)(::benchmark::State& state) {
    run_send_recv(*this, state);
}
BENCHMARK_REGISTER_F(RealFixtureIpc, IpcEcho)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Arg(32768)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

struct RealFixtureIpcEcho : RealFixtureIpc {
    RealFixtureIpcEcho() { setup_echo = true; }
};

BENCHMARK_DEFINE_F(RealFixtureIpcEcho, IpcEchoRoundtrip)(::benchmark::State& state) {
    run_echo_roundtrip(*this, state);
}
BENCHMARK_REGISTER_F(RealFixtureIpcEcho, IpcEchoRoundtrip)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Arg(32768)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

}  // namespace

BENCHMARK_MAIN();
