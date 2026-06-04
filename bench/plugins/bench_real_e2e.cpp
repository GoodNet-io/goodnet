// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_real_e2e.cpp
/// @brief  Production-shape end-to-end bench.
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
#include "../carrier_bridges.hpp"

#include <bench/test_bench_helper.hpp>

#include <plugins/links/quic/quic.hpp>
#include <plugins/links/tcp/tcp.hpp>
#include <plugins/links/udp/udp.hpp>
#include <plugins/links/ipc/ipc.hpp>

#include "../../plugins/links/tls/tests/support/test_self_signed_cert.hpp"


#include <sdk/conn_events.h>
#include <sdk/extensions/link.h>
#include <sdk/trust.h>

#include <benchmark/benchmark.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <unistd.h>
#include <unordered_map>

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
    /// `state.iterations()` (not `meter.size()`) — matches the
    /// shape `bench_udp.cpp::EchoRoundtrip` and every other plugin
    /// bench in the tree. `meter.size()` skips iterations that
    /// `continue`'d on backpressure, which silently zeroes the
    /// `bytes_per_second` column whenever the per-conn send queue
    /// stalls for a tick at the start of a run — the loop already
    /// retries those iterations, so the bytes legitimately moved
    /// through the stack are `iterations × payload`. Aggregator
    /// drops rows with `bytes_per_second == 0` (see
    /// `aggregate.py:is_real_row → emit_perf_table`), so under
    /// `meter.size() == 0` the case produced no report row even
    /// though every iteration was timed.
    state.SetBytesProcessed(
        static_cast<std::int64_t>(state.iterations()) *
        static_cast<std::int64_t>(payload_size));
    report_latency(state, meter);
    report_resources(state, res);
}

/// Echo round-trip body — matches the shape libp2p / iroh echo
/// runners use, so the round-trip numbers are directly
/// comparable. Bob sends `kPingMsgId`; alice's `RxEchoResponder`
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
    /// bidirectional read+write measurement. Use `state.iterations()`
    /// (not `meter.size()`) for the same reason `run_send_recv`
    /// does — the aggregator drops zero-throughput rows and a
    /// transient stall at start of the run would otherwise leave
    /// the case unreported.
    state.SetBytesProcessed(
        static_cast<std::int64_t>(state.iterations()) *
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

// ── QUIC ────────────────────────────────────────────────────────────
//
// QUIC is composer-only: it layers over a UDP carrier instead of
// calling notify_connect / notify_inbound_bytes directly. QuicBenchNode
// bridges the composer surface back into the real kernel by maintaining
// kern_id ↔ comp_id maps and forwarding in both directions.

struct QuicBenchNode {
    std::unique_ptr<gn::core::Kernel>                    kernel = std::make_unique<gn::core::Kernel>();
    std::shared_ptr<gn::plugins::gnet::GnetProtocol>     proto  = std::make_shared<gn::plugins::gnet::GnetProtocol>();
    gn::core::PluginContext                              ctx;
    host_api_t                                           api{};
    void*                                                noise_self = nullptr;
    NoisePlugin*                                         np         = nullptr;
    gn::PublicKey                                        local_pk{};

    std::shared_ptr<gn::link::quic::QuicLink>            quic;
    gn::bench::BenchKernel                               udp_bench_kernel;
    gn::bench::CarrierBridge<gn::link::udp::UdpLink>    udp_bridge;
    gn_link_id_t                                         link_id    = GN_INVALID_ID;
    gn_subscription_id_t                                 accept_tok = GN_INVALID_SUBSCRIPTION_ID;

    mutable std::mutex                                   bridge_mu;
    std::unordered_map<gn_conn_id_t, gn_conn_id_t>       kern_to_comp;
    std::unordered_map<gn_conn_id_t, gn_conn_id_t>       comp_to_kern;
    gn_link_vtable_t                                     quic_vtable{};

    QuicBenchNode(NoisePlugin& noise, std::string name, bool with_noise = true)
        : np(&noise) {
        ctx.plugin_name = std::move(name);
        ctx.kernel      = kernel.get();

        gn::core::protocol_layer_id_t proto_id = gn::core::kInvalidProtocolLayerId;
        (void)kernel->protocol_layers().register_layer(proto, &proto_id);

        if (with_noise) {
            auto ident = gn::core::identity::NodeIdentity::generate(/*expiry*/0);
            if (ident) {
                local_pk = ident->device().public_key();
                kernel->identities().add(local_pk);
                kernel->set_node_identity(std::move(*ident));
            }
        }

        api = gn::core::build_host_api(ctx);
        api.limits = +[](void*) noexcept -> const gn_limits_t* {
            static const gn_limits_t kBench{};
            return &kBench;
        };

        if (with_noise && np->ok()) {
            (void)np->plugin_init(&api, &noise_self);
            if (noise_self) (void)np->plugin_reg(noise_self);
        }

        udp_bridge.plugin->set_host_api(&udp_bench_kernel.api);
        udp_bridge.plugin->set_mtu(65000);
        if (api.register_extension) {
            (void)api.register_extension(api.host_ctx, "gn.link.udp",
                                          GN_EXT_LINK_VERSION, &udp_bridge.vt);
        }

        quic = std::make_shared<gn::link::quic::QuicLink>();
        quic->set_host_api(&api);
        quic->set_verify_peer(false);

        quic_vtable        = {};
        quic_vtable.api_size = sizeof(quic_vtable);
        static thread_local const char* s_scheme;
        s_scheme           = "quic";
        quic_vtable.scheme = +[](void*) noexcept -> const char* { return s_scheme; };
        quic_vtable.send   = &s_send;
        quic_vtable.send_batch = +[](void*, gn_conn_id_t,
                                      const gn_byte_span_t*, std::size_t) {
            return GN_ERR_NOT_IMPLEMENTED;
        };
        quic_vtable.disconnect       = &s_disconnect;
        quic_vtable.listen           = +[](void*, const char*) { return GN_ERR_NOT_IMPLEMENTED; };
        quic_vtable.connect          = +[](void*, const char*) { return GN_ERR_NOT_IMPLEMENTED; };
        quic_vtable.extension_name   = +[](void*) noexcept -> const char*  { return nullptr; };
        quic_vtable.extension_vtable = +[](void*) noexcept -> const void*  { return nullptr; };
        quic_vtable.destroy          = +[](void*) noexcept                 {};

        gn_register_meta_t mt{};
        mt.api_size = sizeof(gn_register_meta_t);
        mt.name     = "quic";
        if (api.register_vtable) {
            (void)api.register_vtable(api.host_ctx, GN_REGISTER_LINK, &mt,
                                       &quic_vtable, this, &link_id);
        }
    }

    QuicBenchNode(const QuicBenchNode&)            = delete;
    QuicBenchNode& operator=(const QuicBenchNode&) = delete;

    ~QuicBenchNode() {
        if (accept_tok != GN_INVALID_SUBSCRIPTION_ID && quic) {
            (void)quic->composer_unsubscribe_accept(accept_tok);
        }
        if (quic) quic->shutdown();
        udp_bridge.plugin->shutdown();
        if (noise_self && np && np->ok()) {
            (void)np->plugin_unreg(noise_self);
            np->plugin_shut(noise_self);
            noise_self = nullptr;
        }
    }

    gn_conn_id_t bridge_conn(gn_conn_id_t comp_id, std::string_view peer_uri,
                              gn_handshake_role_t role,
                              gn_trust_class_t trust = GN_TRUST_LOOPBACK) {
        std::uint8_t zero_pk[GN_PUBLIC_KEY_BYTES] = {};
        const std::string uri_str(peer_uri);
        gn_conn_id_t kern_id = GN_INVALID_ID;
        if (!api.notify_connect) {
            std::fprintf(stderr, "[bridge_conn] notify_connect is null\n");
            return GN_INVALID_ID;
        }
        const gn_result_t rc = api.notify_connect(
            api.host_ctx, zero_pk, uri_str.c_str(),
            trust, role, &kern_id);
        if (rc != GN_OK || kern_id == GN_INVALID_ID) {
            std::fprintf(stderr, "[bridge_conn] notify_connect failed rc=%d kern_id=%llu uri=%s\n",
                rc, (unsigned long long)kern_id, uri_str.c_str());
            return GN_INVALID_ID;
        }
        {
            std::lock_guard lk(bridge_mu);
            kern_to_comp[kern_id] = comp_id;
            comp_to_kern[comp_id] = kern_id;
        }
        (void)quic->composer_subscribe_data(comp_id, &s_data, this);
        if (api.kick_handshake) {
            (void)api.kick_handshake(api.host_ctx, kern_id);
        }
        return kern_id;
    }

    static gn_result_t s_send(void* self, gn_conn_id_t kid,
                               const std::uint8_t* b, std::size_t n) {
        if (!self || (!b && n > 0)) return GN_ERR_NULL_ARG;
        auto* node = static_cast<QuicBenchNode*>(self);
        gn_conn_id_t comp_id = GN_INVALID_ID;
        {
            std::lock_guard lk(node->bridge_mu);
            auto it = node->kern_to_comp.find(kid);
            if (it == node->kern_to_comp.end()) return GN_ERR_NOT_FOUND;
            comp_id = it->second;
        }
        return node->quic->send(comp_id, std::span<const std::uint8_t>(b, n));
    }

    static gn_result_t s_disconnect(void* self, gn_conn_id_t kid) {
        if (!self) return GN_ERR_NULL_ARG;
        auto* node = static_cast<QuicBenchNode*>(self);
        gn_conn_id_t comp_id = GN_INVALID_ID;
        {
            std::lock_guard lk(node->bridge_mu);
            auto it = node->kern_to_comp.find(kid);
            if (it == node->kern_to_comp.end()) return GN_ERR_NOT_FOUND;
            comp_id = it->second;
        }
        return node->quic->disconnect(comp_id);
    }

    static void s_data(void* user, gn_conn_id_t comp_id,
                        const std::uint8_t* b, std::size_t n) {
        auto* node = static_cast<QuicBenchNode*>(user);
        if (!node || !node->api.notify_inbound_bytes) return;
        gn_conn_id_t kern_id = GN_INVALID_ID;
        {
            std::lock_guard lk(node->bridge_mu);
            auto it = node->comp_to_kern.find(comp_id);
            if (it == node->comp_to_kern.end()) return;
            kern_id = it->second;
        }
        (void)node->api.notify_inbound_bytes(node->api.host_ctx, kern_id, b, n);
    }

    [[nodiscard]] gn_conn_id_t transport_conn() const {
        for (gn_conn_id_t id = 1; id <= 8; ++id) {
            if (auto s = kernel->sessions().find(id);
                s && s->phase() == ::gn::core::SecurityPhase::Transport) {
                return id;
            }
        }
        return GN_INVALID_ID;
    }

    static bool wait_both_transport(const QuicBenchNode& a, const QuicBenchNode& b,
                                     std::chrono::milliseconds timeout) {
        return ::gn::sdk::test::wait_for(
            [&] {
                return a.transport_conn() != GN_INVALID_ID
                    && b.transport_conn() != GN_INVALID_ID;
            }, timeout);
    }

    // For link-only (no Noise): any established connection record suffices.
    [[nodiscard]] gn_conn_id_t any_conn() const {
        std::lock_guard lk(bridge_mu);
        if (kern_to_comp.empty()) return GN_INVALID_ID;
        return kern_to_comp.begin()->first;
    }

    static bool wait_both_connected(const QuicBenchNode& a, const QuicBenchNode& b,
                                     std::chrono::milliseconds timeout) {
        return ::gn::sdk::test::wait_for(
            [&] {
                const bool a_ok = [&]{ std::lock_guard lk(a.bridge_mu); return !a.kern_to_comp.empty(); }();
                const bool b_ok = [&]{ std::lock_guard lk(b.bridge_mu); return !b.kern_to_comp.empty(); }();
                return a_ok && b_ok;
            }, timeout);
    }
};

struct RealFixtureQuicEcho : public ::benchmark::Fixture {
    bool              setup_echo  = true;
    RxCounter         pong;
    RxEchoResponder   echo_resp;
    std::unique_ptr<QuicBenchNode> alice;
    std::unique_ptr<QuicBenchNode> bob;
    gn_handler_id_t   pong_hid     = GN_INVALID_ID;
    gn_handler_id_t   rx_echo_hid  = GN_INVALID_ID;
    gn_conn_id_t      bob_conn     = GN_INVALID_ID;
    bool              ready        = false;

    void SetUp(::benchmark::State&) override {
        if (ready) return;
        NoisePlugin& noise_ref = process_noise();
        if (!noise_ref.ok()) return;

        alice = std::make_unique<QuicBenchNode>(noise_ref, "alice");
        bob   = std::make_unique<QuicBenchNode>(noise_ref, "bob");

        rx_echo_hid = register_echo_responder(*alice->kernel,
            kPingMsgId, kPongMsgId, &alice->api, echo_resp);
        pong_hid    = register_rx(*bob->kernel, kPongMsgId, pong);

        std::string cert, key;
        if (!gn::tests::support::generate_self_signed(cert, key)) {
            std::fprintf(stderr, "[QuicBenchNode] generate_self_signed failed\n");
            return;
        }
        alice->quic->set_server_credentials(cert, key);

        const gn_result_t rc_sub = alice->quic->composer_subscribe_accept(
            +[](void* user, gn_conn_id_t comp_id, const char* peer_uri) {
                auto* node = static_cast<QuicBenchNode*>(user);
                // QuicLink provides the UDP-layer peer address ("udp://…").
                // Rewrite the scheme to "quic" so rec->scheme matches the
                // vtable registered under that name in the link registry.
                std::string uri = "quic://127.0.0.1:0";
                if (peer_uri) {
                    std::string_view raw(peer_uri);
                    const auto sep = raw.find("://");
                    if (sep != std::string_view::npos)
                        uri = "quic://" + std::string(raw.substr(sep + 3));
                }
                node->bridge_conn(comp_id, uri, GN_ROLE_RESPONDER);
            },
            alice.get(), &alice->accept_tok);
        if (rc_sub != GN_OK) {
            std::fprintf(stderr, "[QuicBenchNode] composer_subscribe_accept failed rc=%d\n", rc_sub);
            return;
        }

        gn_result_t rc_listen = alice->quic->composer_listen("quic://127.0.0.1:0");
        if (rc_listen != GN_OK) {
            std::fprintf(stderr, "[QuicBenchNode] composer_listen failed rc=%d\n", rc_listen);
            return;
        }
        std::uint16_t port = 0;
        if (alice->quic->composer_listen_port(&port) != GN_OK || port == 0) {
            std::fprintf(stderr, "[QuicBenchNode] composer_listen_port failed port=%u\n", port);
            return;
        }

        gn_conn_id_t bob_comp_id = GN_INVALID_ID;
        const std::string dial_uri = "quic://127.0.0.1:" + std::to_string(port);
        gn_result_t rc_connect = bob->quic->composer_connect(dial_uri, &bob_comp_id);
        if (rc_connect != GN_OK) {
            std::fprintf(stderr, "[QuicBenchNode] composer_connect failed rc=%d\n", rc_connect);
            return;
        }
        bob->bridge_conn(bob_comp_id, dial_uri, GN_ROLE_INITIATOR);

        if (!QuicBenchNode::wait_both_transport(*alice, *bob, 10s)) {
            std::fprintf(stderr, "[QuicBenchNode] wait_both_transport timed out (alice=%llu bob=%llu)\n",
                (unsigned long long)alice->transport_conn(),
                (unsigned long long)bob->transport_conn());
            return;
        }
        bob_conn = bob->transport_conn();
        ready    = (bob_conn != GN_INVALID_ID);
    }

    void TearDown(::benchmark::State&) override {}
};

BENCHMARK_DEFINE_F(RealFixtureQuicEcho, QuicEchoRoundtrip)(::benchmark::State& state) {
    run_echo_roundtrip(*this, state);
}
BENCHMARK_REGISTER_F(RealFixtureQuicEcho, QuicEchoRoundtrip)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Arg(32768)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

// ── QUIC TLS-only (no Noise) ─────────────────────────────────────────
//
// Same QUIC TLS 1.3 transport as RealFixtureQuicEcho but with the Noise
// security session layer disabled.  Nodes exchange gnet frames directly
// inside QUIC streams — no Noise XX handshake, no extra AEAD on top of
// QUIC TLS.  Matches iroh's stack (QUIC TLS 1.3, no layer-5 AEAD), so
// the round-trip numbers are 1:1 comparable.

struct RealFixtureQuicTlsEcho : public ::benchmark::Fixture {
    bool              setup_echo  = true;
    RxCounter         pong;
    RxEchoResponder   echo_resp;
    std::unique_ptr<QuicBenchNode> alice;
    std::unique_ptr<QuicBenchNode> bob;
    gn_handler_id_t   pong_hid     = GN_INVALID_ID;
    gn_handler_id_t   rx_echo_hid  = GN_INVALID_ID;
    gn_conn_id_t      bob_conn     = GN_INVALID_ID;
    bool              ready        = false;

    void SetUp(::benchmark::State&) override {
        if (ready) return;
        NoisePlugin& noise_ref = process_noise();

        alice = std::make_unique<QuicBenchNode>(noise_ref, "alice_tls", false);
        bob   = std::make_unique<QuicBenchNode>(noise_ref, "bob_tls",   false);

        rx_echo_hid = register_echo_responder(*alice->kernel,
            kPingMsgId, kPongMsgId, &alice->api, echo_resp);
        pong_hid    = register_rx(*bob->kernel, kPongMsgId, pong);

        std::string cert, key;
        if (!gn::tests::support::generate_self_signed(cert, key)) {
            std::fprintf(stderr, "[QuicTlsBenchNode] generate_self_signed failed\n");
            return;
        }
        alice->quic->set_server_credentials(cert, key);

        const gn_result_t rc_sub = alice->quic->composer_subscribe_accept(
            +[](void* user, gn_conn_id_t comp_id, const char* peer_uri) {
                auto* node = static_cast<QuicBenchNode*>(user);
                std::string uri = "quic://127.0.0.1:0";
                if (peer_uri) {
                    std::string_view raw(peer_uri);
                    const auto sep = raw.find("://");
                    if (sep != std::string_view::npos)
                        uri = "quic://" + std::string(raw.substr(sep + 3));
                }
                node->bridge_conn(comp_id, uri, GN_ROLE_RESPONDER);
            },
            alice.get(), &alice->accept_tok);
        if (rc_sub != GN_OK) {
            std::fprintf(stderr, "[QuicTlsBenchNode] composer_subscribe_accept failed rc=%d\n", rc_sub);
            return;
        }

        gn_result_t rc_listen = alice->quic->composer_listen("quic://127.0.0.1:0");
        if (rc_listen != GN_OK) {
            std::fprintf(stderr, "[QuicTlsBenchNode] composer_listen failed rc=%d\n", rc_listen);
            return;
        }
        std::uint16_t port = 0;
        if (alice->quic->composer_listen_port(&port) != GN_OK || port == 0) {
            std::fprintf(stderr, "[QuicTlsBenchNode] composer_listen_port failed port=%u\n", port);
            return;
        }

        gn_conn_id_t bob_comp_id = GN_INVALID_ID;
        const std::string dial_uri = "quic://127.0.0.1:" + std::to_string(port);
        gn_result_t rc_connect = bob->quic->composer_connect(dial_uri, &bob_comp_id);
        if (rc_connect != GN_OK) {
            std::fprintf(stderr, "[QuicTlsBenchNode] composer_connect failed rc=%d\n", rc_connect);
            return;
        }
        bob->bridge_conn(bob_comp_id, dial_uri, GN_ROLE_INITIATOR);

        if (!QuicBenchNode::wait_both_connected(*alice, *bob, 10s)) {
            std::fprintf(stderr, "[QuicTlsBenchNode] wait_both_connected timed out\n");
            return;
        }
        bob_conn = bob->any_conn();
        ready    = (bob_conn != GN_INVALID_ID);
    }

    void TearDown(::benchmark::State&) override {}
};

BENCHMARK_DEFINE_F(RealFixtureQuicTlsEcho, QuicTlsEchoRoundtrip)(::benchmark::State& state) {
    run_echo_roundtrip(*this, state);
}
BENCHMARK_REGISTER_F(RealFixtureQuicTlsEcho, QuicTlsEchoRoundtrip)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Arg(32768)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

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
