/// @file   examples/bench/main.cpp
/// @brief  Throughput benchmark — two GoodNet kernels in one process,
///         talking over TCP or UDP under Noise XX. Reports payload Gbps,
///         ctx-switches, and handshake time.
///
/// Usage:
///         goodnet-bench [tcp|udp] [count] [size_kb] [conns] [--workers=N] [--cpu=mask]
///         goodnet-bench tcp 100000 64 4 --workers=4 --cpu=p-cores
///         goodnet-bench udp 200000 1  4
///         goodnet-bench 100000 64 1          (legacy: tcp default)

#include <core/identity/node_identity.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/plugin/plugin_manager.hpp>
#include <core/util/log.hpp>

#include <plugins/protocols/gnet/protocol.hpp>
#include <plugins/links/tcp/tcp.hpp>
#include <plugins/links/udp/udp.hpp>

#include <sdk/cpp/convenience.hpp>
#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/types.h>

#ifndef __EMSCRIPTEN__
#include <stdexec/execution.hpp>
#include <exec/start_detached.hpp>
#include <exec/static_thread_pool.hpp>
namespace exec = experimental::execution;
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <sys/resource.h>
#include <sys/time.h>
#include <dirent.h>

#ifndef GOODNET_NOISE_PLUGIN_PATH
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
using UdpLink = gn::link::udp::UdpLink;

constexpr std::uint32_t kDemoMsgId = 0xC0FFEEu;

// ── TCP vtable ────────────────────────────────────────────────────────────

gn_result_t tcp_send(void* self, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) {
    if (!self || (!bytes && size > 0)) return GN_ERR_NULL_ARG;
    return static_cast<TcpLink*>(self)->send(
        conn, std::span<const std::uint8_t>(bytes, size));
}

gn_result_t tcp_send_batch(void* self, gn_conn_id_t conn,
                            const gn_byte_span_t* batch, std::size_t count) {
    if (!self) return GN_ERR_NULL_ARG;
    if (count > 0 && !batch) return GN_ERR_NULL_ARG;
    std::vector<std::span<const std::uint8_t>> frames;
    frames.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
        frames.emplace_back(batch[i].bytes, batch[i].size);
    return static_cast<TcpLink*>(self)->send_batch(
        conn, std::span<const std::span<const std::uint8_t>>(frames));
}

gn_result_t tcp_disconnect(void* self, gn_conn_id_t conn) {
    if (!self) return GN_ERR_NULL_ARG;
    return static_cast<TcpLink*>(self)->disconnect(conn);
}

const char* tcp_scheme(void*)                    { return "tcp"; }
gn_result_t tcp_noop_listen(void*, const char*)  { return GN_ERR_NOT_IMPLEMENTED; }
gn_result_t tcp_noop_connect(void*, const char*) { return GN_ERR_NOT_IMPLEMENTED; }
const char* tcp_ext_name(void*)                  { return nullptr; }
const void* tcp_ext_vtable(void*)                { return nullptr; }
void        tcp_destroy(void*)                   {}

const gn_link_vtable_t kTcpVtable = []() {
    gn_link_vtable_t v{};
    v.api_size         = sizeof(v);
    v.scheme           = &tcp_scheme;
    v.listen           = &tcp_noop_listen;
    v.connect          = &tcp_noop_connect;
    v.send             = &tcp_send;
    v.send_batch       = &tcp_send_batch;
    v.disconnect       = &tcp_disconnect;
    v.extension_name   = &tcp_ext_name;
    v.extension_vtable = &tcp_ext_vtable;
    v.destroy          = &tcp_destroy;
    return v;
}();

// ── UDP vtable ────────────────────────────────────────────────────────────

gn_result_t udp_send(void* self, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) {
    if (!self || (!bytes && size > 0)) return GN_ERR_NULL_ARG;
    return static_cast<UdpLink*>(self)->send(
        conn, std::span<const std::uint8_t>(bytes, size));
}

gn_result_t udp_send_batch(void* self, gn_conn_id_t conn,
                            const gn_byte_span_t* batch, std::size_t count) {
    if (!self) return GN_ERR_NULL_ARG;
    if (count > 0 && !batch) return GN_ERR_NULL_ARG;
    std::vector<std::span<const std::uint8_t>> frames;
    frames.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
        frames.emplace_back(batch[i].bytes, batch[i].size);
    return static_cast<UdpLink*>(self)->send_batch(
        conn, std::span<const std::span<const std::uint8_t>>(frames));
}

gn_result_t udp_disconnect(void* self, gn_conn_id_t conn) {
    if (!self) return GN_ERR_NULL_ARG;
    return static_cast<UdpLink*>(self)->disconnect(conn);
}

const char* udp_scheme(void*)                    { return "udp"; }
gn_result_t udp_noop_listen(void*, const char*)  { return GN_ERR_NOT_IMPLEMENTED; }
gn_result_t udp_noop_connect(void*, const char*) { return GN_ERR_NOT_IMPLEMENTED; }
const char* udp_ext_name(void*)                  { return nullptr; }
const void* udp_ext_vtable(void*)                { return nullptr; }
void        udp_destroy(void*)                   {}

const gn_link_vtable_t kUdpVtable = []() {
    gn_link_vtable_t v{};
    v.api_size         = sizeof(v);
    v.scheme           = &udp_scheme;
    v.listen           = &udp_noop_listen;
    v.connect          = &udp_noop_connect;
    v.send             = &udp_send;
    v.send_batch       = &udp_send_batch;
    v.disconnect       = &udp_disconnect;
    v.extension_name   = &udp_ext_name;
    v.extension_vtable = &udp_ext_vtable;
    v.destroy          = &udp_destroy;
    return v;
}();

// ── Node ─────────────────────────────────────────────────────────────────

struct Node {
    Kernel                         kernel;
    std::shared_ptr<GnetProtocol>  proto = std::make_shared<GnetProtocol>();
    std::shared_ptr<TcpLink>       tcp;
    std::shared_ptr<UdpLink>       udp;
    PluginContext                  host_ctx;
    host_api_t                     api{};
    PluginManager                  plugins{kernel};

    explicit Node(std::string name, bool use_udp,
                  std::size_t max_conns,
                  asio::io_context* ext_ioc = nullptr) {
        gn::core::protocol_layer_id_t proto_id =
            gn::core::kInvalidProtocolLayerId;
        (void)kernel.protocol_layers().register_layer(proto, &proto_id);

        if (auto ident = gn::core::identity::NodeIdentity::generate(0)) {
            kernel.identities().add(ident->device().public_key());
            kernel.set_node_identity(std::move(*ident));
        } else {
            std::cerr << "[bench] node identity generation failed\n";
            std::exit(1);
        }

        host_ctx.plugin_name = std::move(name);
        host_ctx.kernel      = &kernel;
        api = build_host_api(host_ctx);
        // Raise max_connections so large conn counts don't hit the server limit.
        // Must use reload_config_merge (not config().merge_json) so set_limits() is called.
        // Only raise above the default (4096) to avoid triggering the
        // max_outbound_connections > max_connections validation error.
        constexpr std::size_t kDefaultMaxConns = 4096;
        const std::size_t target_conns = std::max(max_conns * 2 + 64, kDefaultMaxConns);
        if (target_conns > kDefaultMaxConns) {
            (void)kernel.reload_config_merge(
                "{\"limits\":{\"max_connections\":"
                + std::to_string(target_conns) + "}}");
        }

        gn_link_id_t tid = GN_INVALID_ID;
        if (use_udp) {
            udp = ext_ioc
                ? std::make_shared<UdpLink>(*ext_ioc)
                : std::make_shared<UdpLink>();
            udp->set_host_api(&api);
            if (kernel.links().register_link(
                    "udp", "", &kUdpVtable, udp.get(), &tid) != GN_OK) {
                std::cerr << "[bench] register_link(udp) failed\n";
                std::exit(1);
            }
        } else {
            tcp = std::make_shared<TcpLink>();
            tcp->set_host_api(&api);
            if (kernel.links().register_link(
                    "tcp", "", &kTcpVtable, tcp.get(), &tid) != GN_OK) {
                std::cerr << "[bench] register_link(tcp) failed\n";
                std::exit(1);
            }
        }

        const std::vector<std::string> noise_paths{GOODNET_NOISE_PLUGIN_PATH};
        std::string diag;
        if (plugins.load(std::span<const std::string>(noise_paths), &diag)
                != GN_OK) {
            std::cerr << "[bench] noise plugin load failed: " << diag << "\n";
            std::exit(1);
        }
    }

    ~Node() {
        if (tcp) tcp->shutdown();
        if (udp) udp->shutdown();
        plugins.shutdown();
    }

    [[nodiscard]] std::uint16_t listen_port() const noexcept {
        if (tcp) return tcp->listen_port();
        if (udp) return udp->listen_port();
        return 0;
    }

    [[nodiscard]] gn_result_t listen(const std::string& uri) {
        if (tcp) return tcp->listen(uri);
        if (udp) return udp->listen(uri);
        return GN_ERR_NULL_ARG;
    }

    [[nodiscard]] gn_result_t connect(const std::string& uri) {
        if (tcp) return tcp->connect(uri);
        if (udp) return udp->connect(uri);
        return GN_ERR_NULL_ARG;
    }
};

std::size_t count_open_fds() noexcept {
    DIR* d = ::opendir("/proc/self/fd");
    if (!d) return 0;
    std::size_t n = 0;
    while (::readdir(d)) ++n;
    ::closedir(d);
    return n > 2 ? n - 2 : 0; // subtract . and ..
}

bool wait_until(const std::function<bool()>& pred,
                 std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(10ms);
    }
    return false;
}

} // namespace

int main(int argc, char** argv) {
    {
        gn::log::LogConfig lc;
        lc.level         = "warn";
        lc.console_level = "warn";
        (void)gn::log::init_with(lc);
    }

    // Arg parsing: [tcp|udp] [count] [size_kb] [conns] [--workers=N] [--cpu=mask] [--sweep]
    bool          use_udp    = false;
    bool          sweep_mode = false;
    std::uint64_t count      = 100000;
    std::size_t   size_kb    = 64;
    std::size_t   conns      = 1;
    unsigned      workers    = std::max(1u, std::thread::hardware_concurrency() / 2);
    const char*   cpu_mask   = nullptr;
    char          cpu_mask_buf[256]{};

    int positional = 0;
    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if (arg == "tcp")      { use_udp = false;    continue; }
        if (arg == "udp")      { use_udp = true;     continue; }
        if (arg == "--sweep")  { sweep_mode = true;  continue; }
        if (arg.starts_with("--workers=")) {
            workers = static_cast<unsigned>(
                std::strtoul(arg.data() + 10, nullptr, 10));
            continue;
        }
        if (arg.starts_with("--cpu=")) {
            std::strncpy(cpu_mask_buf, arg.data() + 6, sizeof(cpu_mask_buf) - 1);
            cpu_mask = cpu_mask_buf;
            continue;
        }
        // Positional numerics: count, size_kb, conns
        switch (positional++) {
            case 0: count   = std::strtoull(argv[i], nullptr, 10); break;
            case 1: size_kb = std::strtoul (argv[i], nullptr, 10); break;
            case 2: conns   = std::strtoul (argv[i], nullptr, 10); break;
            default: break;
        }
    }

    // ── UDP adaptive sweep (goodnet-bench udp --sweep) ───────────────────────
    if (use_udp && sweep_mode) {
        const std::vector<std::size_t> targets = {1, 10, 100, 1000, 10000};
        std::printf("[sweep] udp conn scale  noise=%s\n\n", GOODNET_NOISE_PLUGIN_PATH);
        std::printf("%-8s  %-14s  %-8s  %-10s  %-12s  %s\n",
            "conns", "handshake_ms", "fds", "rss_mb", "ms/conn", "status");
        std::fflush(stdout);

        for (const std::size_t N : targets) {
            {
                struct rlimit rl{};
                getrlimit(RLIMIT_NOFILE, &rl);
                const rlim_t needed = static_cast<rlim_t>(N + 1024);
                if (rl.rlim_cur < needed) {
                    rl.rlim_cur = std::min(needed, rl.rlim_max);
                    setrlimit(RLIMIT_NOFILE, &rl);
                }
            }

            asio::io_context shared_ioc;
            auto work_guard = asio::make_work_guard(shared_ioc);
            const unsigned n_threads = std::max(4u, workers);
            std::vector<std::thread> ioc_threads;
            ioc_threads.reserve(n_threads);
            for (unsigned i = 0; i < n_threads; ++i)
                ioc_threads.emplace_back([&shared_ioc]{ shared_ioc.run(); });

            Node alice("alice", true, N);
            // Allow high burst: all N Bob sockets share src IP 127.0.0.1.
            (void)alice.kernel.reload_config_merge(
                "{\"udp\":{\"new_conn_rate\":1000000,\"new_conn_burst\":"
                + std::to_string(N + 1000) + "}}");
            if (alice.listen("udp://127.0.0.1:0") != GN_OK) {
                std::fprintf(stderr, "[sweep] alice.listen failed\n");
                work_guard.reset();
                for (auto& t : ioc_threads) t.join();
                break;
            }
            const std::string uri =
                "udp://127.0.0.1:" + std::to_string(alice.listen_port());

            std::vector<std::unique_ptr<Node>> bobs;
            bobs.reserve(N);
            for (std::size_t i = 0; i < N; ++i)
                bobs.push_back(std::make_unique<Node>(
                    "bob-" + std::to_string(i), true, 1, &shared_ioc));

            const auto t0 = std::chrono::steady_clock::now();
            bool any_fail = false;
            for (auto& bob : bobs) {
                if (bob->connect(uri) != GN_OK) { any_fail = true; break; }
            }

            const auto timeout = std::chrono::milliseconds(
                std::max<std::uint64_t>(30'000, N * 10));
            const bool ok = !any_fail && wait_until([&] {
                std::size_t done = 0;
                for (auto& bob : bobs)
                    for (gn_conn_id_t id = 1; id <= 8; ++id)
                        if (auto s = bob->kernel.sessions().find(id);
                            s && s->phase() == SecurityPhase::Transport)
                            { ++done; break; }
                return done >= N;
            }, timeout);

            const double ms = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - t0).count();
            const std::size_t fds = count_open_fds();
            struct rusage ru{};
            getrusage(RUSAGE_SELF, &ru);
            const double rss = static_cast<double>(ru.ru_maxrss) / 1024.0;

            std::printf("%-8zu  %-14.1f  %-8zu  %-10.1f  %-12.3f  %s\n",
                N, ms, fds, rss,
                N > 0 ? ms / static_cast<double>(N) : 0.0,
                ok ? "ok" : (any_fail ? "CONN_ERR" : "TIMEOUT"));
            std::fflush(stdout);

            for (auto& bob : bobs)
                if (bob->udp) bob->udp->shutdown();
            bobs.clear();
            work_guard.reset();
            for (auto& t : ioc_threads) if (t.joinable()) t.join();

            if (!ok) break;
        }
        return 0;
    }

    // UDP MTU clamp: kernel maximum datagram payload is 1200B (kDefaultMtu).
    if (use_udp && size_kb > 1) {
        std::cout << "[bench] udp: clamping size_kb " << size_kb << " → 1\n";
        size_kb = 1;
    }
    // UDP uses a single shared socket per link: all "connections" to the same
    // endpoint appear as one session.  Force conns=1 to avoid confusion.
    if (use_udp && conns > 1) {
        std::cout << "[bench] udp: clamping conns " << conns << " → 1 (single shared socket)\n";
        conns = 1;
    }

    // Raise RLIMIT_NOFILE so large conn counts don't hit the default 1024 limit.
    {
        struct rlimit rl{};
        getrlimit(RLIMIT_NOFILE, &rl);
        const rlim_t needed = static_cast<rlim_t>(conns * 3 + 512);
        if (rl.rlim_cur < needed) {
            rl.rlim_cur = std::min(needed, rl.rlim_max);
            setrlimit(RLIMIT_NOFILE, &rl);
        }
    }

    std::cout << "[bench] transport=" << (use_udp ? "udp" : "tcp")
              << " count=" << count
              << " size_kb=" << size_kb
              << " conns=" << conns
              << " workers=" << workers
              << (cpu_mask ? std::string(" cpu=") + cpu_mask : "")
              << " noise=" << GOODNET_NOISE_PLUGIN_PATH << "\n";

    Node alice("alice", use_udp, conns);
    Node bob  ("bob",   use_udp, conns);

    // Payload size clamping.
    std::size_t payload_size = size_kb * 1024;
    const std::size_t kernel_cap = bob.api.limits
        ? static_cast<std::size_t>(bob.api.limits(bob.api.host_ctx)->max_payload_bytes)
        : 0u;
    const std::size_t protocol_cap = bob.proto ? bob.proto->max_payload_size() : 0u;
    std::size_t cap = (kernel_cap && protocol_cap) ? std::min(kernel_cap, protocol_cap)
                    : (kernel_cap ? kernel_cap : protocol_cap);
    if (cap && payload_size > cap) {
        std::cout << "[bench] clamping payload " << payload_size << " → " << cap << "B\n";
        payload_size = cap;
    }

    // Counting consumer on Alice's side.
    struct Consumer {
        std::atomic<std::uint64_t> bytes{0};
        std::atomic<std::uint64_t> pkts{0};
    } consumer;

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
            "gnet-v1", kDemoMsgId, 128, &vt, &consumer, &hid) != GN_OK) {
        std::cerr << "[bench] alice.register_handler failed\n";
        return 1;
    }

    // Listen + connect.
    const std::string scheme = use_udp ? "udp" : "tcp";
    if (alice.listen(scheme + "://127.0.0.1:0") != GN_OK) {
        std::cerr << "[bench] alice.listen failed\n";
        return 1;
    }
    // For TCP: distribute connections across multiple Alice ports to bypass
    // per-destination ephemeral port exhaustion (~64K ports max per dst).
    constexpr std::size_t kConnsPerPort = 60000;
    const std::size_t num_ports = use_udp ? 1
        : std::max(std::size_t{1}, (conns + kConnsPerPort - 1) / kConnsPerPort);

    std::vector<std::string> alice_uris;
    std::vector<std::shared_ptr<TcpLink>> alice_extra_links; // keep alive for benchmark lifetime
    alice_uris.push_back(scheme + "://127.0.0.1:" + std::to_string(alice.listen_port()));
    std::cout << "[bench] alice listening on " << alice_uris[0] << "\n";

    // Open additional Alice listeners if needed.
    for (std::size_t p = 1; p < num_ports; ++p) {
        if (!use_udp) {
            auto extra = std::make_shared<TcpLink>();
            extra->set_host_api(&alice.api);
            if (extra->listen("tcp://127.0.0.1:0") != GN_OK) {
                std::cerr << "[bench] alice extra listen #" << p << " failed\n";
                return 1;
            }
            alice_uris.push_back("tcp://127.0.0.1:" + std::to_string(extra->listen_port()));
            std::cout << "[bench] alice extra port " << p << ": " << alice_uris.back() << "\n";
            alice_extra_links.push_back(std::move(extra));
        }
    }

    for (std::size_t i = 0; i < conns; ++i) {
        const std::string& uri = alice_uris[i % alice_uris.size()];
        if (bob.connect(uri) != GN_OK) {
            std::cerr << "[bench] bob.connect #" << i << " failed\n";
            return 1;
        }
    }

    // Scale timeout with connection count: at least 30s, +1ms per conn.
    const auto handshake_timeout = std::chrono::milliseconds(
        std::max(std::uint64_t{30000},
                 static_cast<std::uint64_t>(conns)));

    // Wait for handshake + measure it.
    auto t_handshake_start = std::chrono::steady_clock::now();
    if (!wait_until([&] {
            std::size_t up = 0;
            const gn_conn_id_t id_limit = static_cast<gn_conn_id_t>(conns * 2 + 64);
            for (gn_conn_id_t id = 1; id <= id_limit; ++id) {
                auto s = bob.kernel.sessions().find(id);
                if (s && s->phase() == SecurityPhase::Transport) ++up;
            }
            return up >= conns;
        }, handshake_timeout)) {
        std::cerr << "[bench] handshake timeout — "
                  << bob.kernel.sessions().size() << " bob sessions, "
                  << alice.kernel.sessions().size() << " alice sessions\n";
        if (alice.udp) {
            auto s = alice.udp->stats();
            std::cerr << "  alice udp: frames_in=" << s.frames_in
                      << " bytes_in=" << s.bytes_in
                      << " frames_out=" << s.frames_out
                      << " bytes_out=" << s.bytes_out
                      << " conns=" << s.active_connections << "\n";
        }
        if (bob.udp) {
            auto s = bob.udp->stats();
            std::cerr << "  bob   udp: frames_in=" << s.frames_in
                      << " bytes_in=" << s.bytes_in
                      << " frames_out=" << s.frames_out
                      << " bytes_out=" << s.bytes_out
                      << " conns=" << s.active_connections << "\n";
        }
        const gn_conn_id_t lim = static_cast<gn_conn_id_t>(conns * 2 + 64);
        for (gn_conn_id_t id = 1; id <= lim; ++id) {
            auto sb = bob.kernel.sessions().find(id);
            if (sb) std::cerr << "  bob  sess " << id
                              << " phase=" << static_cast<int>(sb->phase()) << "\n";
            auto sa = alice.kernel.sessions().find(id);
            if (sa) std::cerr << "  alice sess " << id
                              << " phase=" << static_cast<int>(sa->phase()) << "\n";
        }
        return 1;
    }
    const double handshake_ms =
        std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t_handshake_start).count();

    std::vector<gn_conn_id_t> bob_conns;
    const gn_conn_id_t id_limit = static_cast<gn_conn_id_t>(conns * 2 + 64);
    for (gn_conn_id_t id = 1; id <= id_limit && bob_conns.size() < conns; ++id) {
        auto s = bob.kernel.sessions().find(id);
        if (s && s->phase() == SecurityPhase::Transport) bob_conns.push_back(id);
    }
    if (bob_conns.size() < conns) {
        std::cerr << "[bench] only " << bob_conns.size() << "/" << conns
                  << " transport-phase sessions\n";
        return 1;
    }

    std::cout << "[bench] handshake done in " << handshake_ms << " ms"
              << " (" << conns << " sessions)"
              << " fds=" << count_open_fds() << "\n";

    std::vector<std::uint8_t> payload(payload_size);
    for (std::size_t i = 0; i < payload_size; ++i)
        payload[i] = static_cast<std::uint8_t>(i);

    std::cout << "[bench] running — payload=" << payload_size << "B"
              << " per_conn=" << count / conns << " conns=" << conns << "\n";

    // getrusage snapshot before the bench loop.
    struct rusage ru_before{};
    getrusage(RUSAGE_SELF, &ru_before);

    const std::uint64_t per_conn = count / conns;
    std::atomic<std::uint64_t> global_sent{0};
    std::atomic<std::uint64_t> global_bp{0};
    std::atomic<std::size_t>   chains_done{0};

    std::mutex          done_mu;
    std::condition_variable done_cv;

    auto t_start = std::chrono::steady_clock::now();

#ifndef __EMSCRIPTEN__
    exec::static_thread_pool pool(static_cast<std::uint32_t>(workers));
    auto sched = pool.get_scheduler();

    for (gn_conn_id_t cid : bob_conns) {
        exec::start_detached(
            stdexec::on(sched, stdexec::just())
            | stdexec::then([&, cid] {
                std::uint64_t sent = 0, bp = 0;
                while (per_conn == 0 || sent < per_conn) {
                    const auto rc = gn::send(&bob.api, cid, kDemoMsgId,
                                             std::span<const std::uint8_t>(payload));
                    if (rc == GN_OK) {
                        ++sent;
                    } else if (rc == GN_ERR_LIMIT_REACHED) {
                        ++bp;
                        std::this_thread::sleep_for(std::chrono::microseconds(50));
                    } else {
                        break;
                    }
                }
                global_sent.fetch_add(sent, std::memory_order_relaxed);
                global_bp.fetch_add(bp, std::memory_order_relaxed);
                if (chains_done.fetch_add(1, std::memory_order_acq_rel) + 1 == conns) {
                    done_cv.notify_one();
                }
            })
        );
    }

    {
        std::unique_lock lk(done_mu);
        done_cv.wait(lk, [&] { return chains_done.load() == conns; });
    }
#else
    // Emscripten fallback: one-threaded sequential loop.
    for (gn_conn_id_t cid : bob_conns) {
        std::uint64_t sent = 0, bp = 0;
        while (per_conn == 0 || sent < per_conn) {
            const auto rc = gn::send(&bob.api, cid, kDemoMsgId,
                                     std::span<const std::uint8_t>(payload));
            if (rc == GN_OK) { ++sent; }
            else if (rc == GN_ERR_LIMIT_REACHED) { ++bp; }
            else break;
        }
        global_sent.fetch_add(sent, std::memory_order_relaxed);
        global_bp.fetch_add(bp, std::memory_order_relaxed);
    }
#endif

    auto t_end = std::chrono::steady_clock::now();
    const double elapsed =
        std::chrono::duration<double>(t_end - t_start).count();

    struct rusage ru_after{};
    getrusage(RUSAGE_SELF, &ru_after);
    const long vcsw  = ru_after.ru_nvcsw  - ru_before.ru_nvcsw;
    const long ivcsw = ru_after.ru_nivcsw - ru_before.ru_nivcsw;
    const double cpu_s =
        static_cast<double>(ru_after.ru_utime.tv_sec  - ru_before.ru_utime.tv_sec)
      + static_cast<double>(ru_after.ru_utime.tv_usec - ru_before.ru_utime.tv_usec) * 1e-6
      + static_cast<double>(ru_after.ru_stime.tv_sec  - ru_before.ru_stime.tv_sec)
      + static_cast<double>(ru_after.ru_stime.tv_usec - ru_before.ru_stime.tv_usec) * 1e-6;

    const std::uint64_t total_sent  = global_sent.load();
    const std::uint64_t total_bp    = global_bp.load();
    const std::uint64_t total_bytes = total_sent * payload_size;
    const double payload_gbps =
        static_cast<double>(total_bytes) * 8.0 / elapsed / 1e9;

    std::this_thread::sleep_for(200ms);
    const std::uint64_t recv_bytes = consumer.bytes.load();
    const std::uint64_t recv_pkts  = consumer.pkts.load();

    std::cout << "\n[bench] sent " << total_sent << " pkts ("
              << total_bytes << " B) in " << elapsed << " s\n"
              << "[bench] payload throughput = " << payload_gbps << " Gbps\n"
              << "[bench] backpressure events = " << total_bp << "\n"
              << "[bench] consumer received " << recv_pkts << " pkts ("
              << recv_bytes << " B)\n"
              << "[bench] ctx-switches vol=" << vcsw
              << " invol=" << ivcsw << "\n"
              << "[bench] cpu time = " << cpu_s << " s"
              << " (" << (elapsed > 0 ? cpu_s / elapsed : 0) << " cores)\n"
              << "[bench] handshake = " << handshake_ms << " ms\n";

    return 0;
}
