/// @file   examples/bench/main.cpp
/// @brief  Throughput benchmark — two GoodNet kernels in one process,
///         talking over TCP under a Noise XX handshake. Bob loops
///         `host_api->send(...)` against Alice as fast as the kernel
///         accepts. Reports payload Gbps; intended as the rebuild's
///         baseline measurement vs the legacy 11 Gbit/s reference.
///
/// Usage:
///         goodnet-bench [count] [size_kb] [conns]
///         goodnet-bench 100000 64 1
///         goodnet-bench 200000 64 4

#include <core/identity/node_identity.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/plugin/plugin_manager.hpp>
#include <core/util/log.hpp>

#include <plugins/protocols/gnet/protocol.hpp>
#include <plugins/links/tcp/tcp.hpp>

#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/types.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

#ifndef GOODNET_NOISE_PLUGIN_PATH
/// Build-time `-D GOODNET_NOISE_PLUGIN_PATH=...` (set by
/// `examples/bench/CMakeLists.txt`) points the bench at the noise
/// plugin's `.so`. Clang-tidy invocations that lack the define would
/// reject the source with `#error`; substituting an obviously-bad
/// stub keeps the analyser happy while still failing loudly at
/// startup if the build configuration ever forgets to set it.
#define GOODNET_NOISE_PLUGIN_PATH "/nonexistent/noise.so"
#endif

namespace {

using namespace std::chrono_literals;
using gn::core::Kernel;
using gn::core::PluginContext;
using gn::core::PluginManager;
using gn::core::SecurityPhase;
using gn::core::build_host_api;
using gn::plugins::gnet::GnetProtocol;
using TcpLink = gn::link::tcp::TcpLink;

constexpr std::uint32_t kDemoMsgId = 0xC0FFEEu;

/// Thin C-ABI link vtable that hands kernel-side calls down to the
/// in-tree `TcpLink`. Listen / connect run through `TcpLink` directly
/// because the demo wants the resolved port back from `listen_port()`.
gn_result_t tcp_send(void* self, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) {
    if (!self || (!bytes && size > 0)) return GN_ERR_NULL_ARG;
    return static_cast<TcpLink*>(self)->send(
        conn, std::span<const std::uint8_t>(bytes, size));
}

/// Route batched sends through `TcpLink::send_batch` so the all-or-
/// nothing hard-cap check fires once per batch — the kernel's scalar
/// fallback (when `send_batch` is `NOT_IMPLEMENTED`) accepts a partial
/// prefix then surfaces `LIMIT_REACHED`, and the drainer parks the
/// **whole** wire batch with the same reserved nonces. On retry the
/// already-sent prefix replays under fresh recv nonces, breaking the
/// AEAD MAC and tripping the link's failure threshold. Per
/// `docs/contracts/link.en.md` §3 send_batch is "one logical write".
gn_result_t tcp_send_batch(void* self, gn_conn_id_t conn,
                            const gn_byte_span_t* batch, std::size_t count) {
    if (!self) return GN_ERR_NULL_ARG;
    if (count > 0 && !batch) return GN_ERR_NULL_ARG;
    std::vector<std::span<const std::uint8_t>> frames;
    frames.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        frames.emplace_back(batch[i].bytes, batch[i].size);
    }
    return static_cast<TcpLink*>(self)->send_batch(
        conn, std::span<const std::span<const std::uint8_t>>(frames));
}

gn_result_t tcp_disconnect(void* self, gn_conn_id_t conn) {
    if (!self) return GN_ERR_NULL_ARG;
    return static_cast<TcpLink*>(self)->disconnect(conn);
}

const char* tcp_scheme(void*)                                                 { return "tcp"; }
gn_result_t tcp_listen_unused(void*, const char*)                              { return GN_ERR_NOT_IMPLEMENTED; }
gn_result_t tcp_connect_unused(void*, const char*)                             { return GN_ERR_NOT_IMPLEMENTED; }
const char* tcp_ext_name(void*)                                                { return nullptr; }
const void* tcp_ext_vtable(void*)                                              { return nullptr; }
void        tcp_destroy(void*)                                                 {}

const gn_link_vtable_t kTcpVtable = []() {
    gn_link_vtable_t v{};
    v.api_size         = sizeof(v);
    v.scheme           = &tcp_scheme;
    v.listen           = &tcp_listen_unused;
    v.connect          = &tcp_connect_unused;
    v.send             = &tcp_send;
    v.send_batch       = &tcp_send_batch;
    v.disconnect       = &tcp_disconnect;
    v.extension_name   = &tcp_ext_name;
    v.extension_vtable = &tcp_ext_vtable;
    v.destroy          = &tcp_destroy;
    return v;
}();

/// One side of the conversation. Owns its kernel, its node identity,
/// its TCP transport instance, and the noise security plugin (loaded
/// through `PluginManager`, which handles dlopen + symbol resolution
/// + lifecycle drain on shutdown).
struct Node {
    Kernel                          kernel;
    std::shared_ptr<GnetProtocol>   proto = std::make_shared<GnetProtocol>();
    std::shared_ptr<TcpLink>        tcp   = std::make_shared<TcpLink>();
    PluginContext                   host_ctx;
    host_api_t                      api{};
    PluginManager                   plugins{kernel};

    explicit Node(std::string name) {
        gn::core::protocol_layer_id_t proto_id =
            gn::core::kInvalidProtocolLayerId;
        (void)kernel.protocol_layers().register_layer(proto, &proto_id);

        if (auto ident = gn::core::identity::NodeIdentity::generate(0)) {
            kernel.identities().add(ident->device().public_key());
            kernel.set_node_identity(std::move(*ident));
        } else {
            std::cerr << "[demo] node identity generation failed\n";
            std::exit(1);
        }

        host_ctx.plugin_name = std::move(name);
        host_ctx.kernel      = &kernel;
        api                  = build_host_api(host_ctx);
        tcp->set_host_api(&api);

        gn_link_id_t tid = GN_INVALID_ID;
        if (kernel.links().register_link(
                "tcp", "", &kTcpVtable, tcp.get(), &tid) != GN_OK) {
            std::cerr << "[demo] register_link(tcp) failed\n";
            std::exit(1);
        }

        const std::vector<std::string> noise_paths{GOODNET_NOISE_PLUGIN_PATH};
        std::string diag;
        if (plugins.load(std::span<const std::string>(noise_paths), &diag)
                != GN_OK) {
            std::cerr << "[demo] noise plugin load failed: " << diag << "\n";
            std::exit(1);
        }
    }

    ~Node() {
        /// Shut TCP first so every live connection closes and the
        /// kernel-side `SecuritySession` records get destroyed
        /// synchronously through `notify_disconnect`. Then
        /// `plugins.shutdown()` drains its now-free anchor instantly.
        if (tcp) tcp->shutdown();
        plugins.shutdown();
    }
};

bool wait_until(const std::function<bool()>& pred,
                 std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(10ms);
    }
    return false;
}

}  // namespace

int main(int argc, char** argv) {
    /// The kernel logger defaults to a build-aware level (Release =
    /// info, Debug = debug) and a Release-only console floor of WARN.
    /// The demo wants the kernel's INFO startup markers visible in
    /// either build, so push the console sink to `info` and lift the
    /// logger level to match. Operators running `goodnet run` get the
    /// same behaviour through the `log.console_level = "info"` knob in
    /// `dist/example/node.json`.
    {
        gn::log::LogConfig lc;
        lc.level         = "info";
        lc.console_level = "info";
        (void)gn::log::init_with(lc);
    }

    /// CLI args: count size_kb conns. Defaults are tuned for a quick
    /// loopback measurement that completes in a couple of seconds.
    std::uint64_t count    = 100000;
    std::size_t   size_kb  = 64;
    std::size_t   conns    = 1;
    if (argc > 1) count   = std::strtoull(argv[1], nullptr, 10);
    if (argc > 2) size_kb = std::strtoul (argv[2], nullptr, 10);
    if (argc > 3) conns   = std::strtoul (argv[3], nullptr, 10);

    Node alice("alice");
    Node bob  ("bob");

    /// Clamp `payload_size` so the default `size_kb=64` (which produces
    /// 65536 — one byte over the 64 KiB frame cap minus the 14-byte
    /// fixed gnet header) does not bounce every send with
    /// `GN_ERR_PAYLOAD_TOO_LARGE`. The protocol layer enforces the
    /// stricter ceiling — gnet reserves both optional public-key fields
    /// in its worst-case header, so the live cap is
    /// `max_frame_bytes - 14 - 2*32 = 65458` rather than the loose
    /// kernel-side `max_payload_bytes = 65522`. Bench picks the
    /// stricter of the two so the message is wire-legal under whichever
    /// gate trips first.
    std::size_t payload_size = size_kb * 1024;
    const std::size_t kernel_cap = bob.api.limits != nullptr
        ? static_cast<std::size_t>(
              bob.api.limits(bob.api.host_ctx)->max_payload_bytes)
        : 0u;
    const std::size_t protocol_cap = bob.proto != nullptr
        ? bob.proto->max_payload_size()
        : 0u;
    std::size_t cap = 0;
    if (kernel_cap != 0 && protocol_cap != 0) {
        cap = std::min(kernel_cap, protocol_cap);
    } else if (kernel_cap != 0) {
        cap = kernel_cap;
    } else if (protocol_cap != 0) {
        cap = protocol_cap;
    }
    if (cap != 0 && payload_size > cap) {
        std::cout << "[bench] requested " << payload_size
                  << "B exceeds payload ceiling " << cap
                  << " (kernel " << kernel_cap
                  << " ∩ protocol " << protocol_cap
                  << "); clamping payload\n";
        payload_size = cap;
    }

    std::cout << "[bench] count=" << count
              << " size=" << payload_size << "B"
              << " conns=" << conns
              << " noise=" << GOODNET_NOISE_PLUGIN_PATH << "\n";

    /// Counting consumer — Alice's handler tallies bytes seen so the
    /// run can report wire ↔ payload symmetry at the end.
    struct Consumer { std::atomic<std::uint64_t> bytes{0};
                      std::atomic<std::uint64_t> pkts{0}; };
    Consumer consumer;

    auto consume_cb = [](void* self, const gn_message_t* env) -> gn_propagation_t {
        auto* c = static_cast<Consumer*>(self);
        c->bytes.fetch_add(env->payload_size, std::memory_order_relaxed);
        c->pkts.fetch_add(1, std::memory_order_relaxed);
        return GN_PROPAGATION_CONSUMED;
    };

    gn_handler_vtable_t vt{};
    vt.api_size       = sizeof(vt);
    vt.handle_message = consume_cb;
    gn_handler_id_t hid = GN_INVALID_ID;
    if (alice.kernel.handlers().register_handler(
            "gnet-v1", kDemoMsgId, /*priority*/128,
            &vt, &consumer, &hid) != GN_OK) {
        std::cerr << "[bench] alice.register_handler failed\n";
        return 1;
    }

    if (alice.tcp->listen("tcp://127.0.0.1:0") != GN_OK) {
        std::cerr << "[bench] alice.listen failed\n";
        return 1;
    }
    const auto port = alice.tcp->listen_port();
    const std::string uri = "tcp://127.0.0.1:" + std::to_string(port);
    std::cout << "[bench] alice listening on " << uri << "\n";

    /// Dial all connections.
    for (std::size_t i = 0; i < conns; ++i) {
        if (bob.tcp->connect(uri) != GN_OK) {
            std::cerr << "[bench] bob.connect #" << i << " failed\n";
            return 1;
        }
    }

    /// Wait for every conn to reach Transport phase.
    if (!wait_until([&] {
            std::size_t up = 0;
            for (gn_conn_id_t id = 1; id <= conns + 8; ++id) {
                auto s = bob.kernel.sessions().find(id);
                if (s && s->phase() == SecurityPhase::Transport) ++up;
            }
            return up >= conns;
        }, 10s)) {
        std::cerr << "[bench] handshake timeout — only "
                  << bob.kernel.sessions().size() << " sessions up\n";
        return 1;
    }

    std::vector<gn_conn_id_t> bob_conns;
    for (gn_conn_id_t id = 1; id <= conns + 8 && bob_conns.size() < conns; ++id) {
        auto s = bob.kernel.sessions().find(id);
        if (s && s->phase() == SecurityPhase::Transport) bob_conns.push_back(id);
    }
    if (bob_conns.size() < conns) {
        std::cerr << "[bench] only " << bob_conns.size() << "/" << conns
                  << " transport-phase sessions found\n";
        return 1;
    }

    /// Random payload — every loop iteration sends the same bytes.
    /// libsodium picks the bytes; nothing here cares about the
    /// content, only the size on the wire.
    std::vector<std::uint8_t> payload(payload_size);
    for (std::size_t i = 0; i < payload_size; ++i) {
        payload[i] = static_cast<std::uint8_t>(i);
    }

    struct Worker {
        std::atomic<std::uint64_t> sent{0};
        std::atomic<std::uint64_t> bp  {0};
    };
    std::vector<Worker> workers(conns);
    std::atomic<bool> stop{false};
    const std::uint64_t per_conn = count / conns;

    std::cout << "[bench] running — payload=" << payload_size << "B"
              << " per_conn=" << per_conn << " conns=" << conns << "\n";

    auto t_start = std::chrono::steady_clock::now();

    std::vector<std::thread> threads;
    threads.reserve(conns);
    for (std::size_t i = 0; i < conns; ++i) {
        threads.emplace_back([&, i, conn = bob_conns[i]] {
            while (!stop.load(std::memory_order_relaxed)) {
                if (per_conn > 0 &&
                    workers[i].sent.load(std::memory_order_relaxed) >= per_conn)
                    break;
                auto rc = bob.api.send(bob.api.host_ctx, conn, kDemoMsgId,
                                       payload.data(), payload.size());
                if (rc == GN_OK) {
                    workers[i].sent.fetch_add(1, std::memory_order_relaxed);
                } else if (rc == GN_ERR_LIMIT_REACHED) {
                    workers[i].bp.fetch_add(1, std::memory_order_relaxed);
                    std::this_thread::sleep_for(std::chrono::microseconds(50));
                } else {
                    /// Non-recoverable: connection torn down (NOT_FOUND
                    /// after `notify_disconnect`), encrypt failed, etc.
                    std::cerr << "[bench] worker " << i
                              << " send failed rc=" << rc
                              << " after sent=" << workers[i].sent.load()
                              << " bp=" << workers[i].bp.load() << "\n";
                    break;
                }
                /// Light pacing — without it the loopback TCP write
                /// queue overflows asio's internal cap and asio
                /// surfaces the failure as `notify_disconnect`, which
                /// surfaces here as NOT_FOUND on the next send.
                /// Remove once TCP plugin has its own kernel-side
                /// SendQueueManager (Phase 2 of the perf parity plan).
                if ((workers[i].sent.load() & 0xFF) == 0) {
                    std::this_thread::yield();
                }
            }
        });
    }

    for (auto& t : threads) t.join();

    auto t_end = std::chrono::steady_clock::now();
    const double elapsed =
        std::chrono::duration<double>(t_end - t_start).count();

    std::uint64_t total_sent = 0, total_bp = 0;
    for (auto& w : workers) {
        total_sent += w.sent.load();
        total_bp   += w.bp.load();
    }
    const std::uint64_t total_bytes = total_sent * payload_size;
    const double payload_gbps =
        static_cast<double>(total_bytes) * 8.0 / elapsed / 1e9;

    /// Drain a moment so Alice's consumer catches up; gives a more
    /// honest received-bytes number than reading mid-flight.
    std::this_thread::sleep_for(200ms);
    const std::uint64_t recv_bytes = consumer.bytes.load();
    const std::uint64_t recv_pkts  = consumer.pkts.load();

    std::cout << "\n[bench] sent " << total_sent << " pkts ("
              << total_bytes << " B) in " << elapsed << " s\n"
              << "[bench] payload throughput = "
              << payload_gbps << " Gbps\n"
              << "[bench] backpressure events = " << total_bp << "\n"
              << "[bench] consumer received " << recv_pkts << " pkts ("
              << recv_bytes << " B)\n";

    return 0;
}
