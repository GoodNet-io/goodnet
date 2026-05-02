/// @file   examples/two_node/main.cpp
/// @brief  Two GoodNet kernels in one process, talking over TCP under
///         a Noise XX handshake. The shortest path from `nix run .#demo`
///         to "two endpoints established a confidential channel and
///         exchanged a frame", suitable as the first thing a user runs
///         after `git clone`.
///
/// The binary owns both ends of the conversation so it does not need a
/// peer to run. The wire path is real: separate `Kernel` instances,
/// the noise security plugin loaded through `dlopen`, the in-tree TCP
/// transport listening on a 127.0.0.1 ephemeral port, the on-disk
/// `goodnet_security_noise.so` driving the AEAD.

#include <core/identity/node_identity.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <plugins/protocols/gnet/protocol.hpp>
#include <plugins/links/tcp/tcp.hpp>

#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/link.h>
#include <sdk/types.h>

#include <dlfcn.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

#ifndef GOODNET_NOISE_PLUGIN_PATH
#error "GOODNET_NOISE_PLUGIN_PATH must be defined to locate the noise .so"
#endif

namespace {

using namespace std::chrono_literals;
using gn::PublicKey;
using gn::core::Kernel;
using gn::core::PluginContext;
using gn::core::SecurityPhase;
using gn::core::build_host_api;
using gn::plugins::gnet::GnetProtocol;
using TcpLink = gn::link::tcp::TcpLink;

constexpr std::uint32_t kDemoMsgId = 0xC0FFEEu;

/// dlopen wrapper for the noise plugin shared object. Both kernels
/// share one .so handle but each gets its own provider `self` from
/// `gn_plugin_init` — Noise state is per-instance.
struct NoisePlugin {
    using SdkVersionFn = void        (*)(std::uint32_t*, std::uint32_t*, std::uint32_t*);
    using InitFn       = gn_result_t (*)(const host_api_t*, void**);
    using RegFn        = gn_result_t (*)(void*);
    using UnregFn      = gn_result_t (*)(void*);
    using ShutFn       = void        (*)(void*);

    void*        handle      = nullptr;
    SdkVersionFn sdk_version = nullptr;
    InitFn       plugin_init = nullptr;
    RegFn        plugin_reg  = nullptr;
    UnregFn      plugin_unreg = nullptr;
    ShutFn       plugin_shut = nullptr;

    NoisePlugin() {
        handle = ::dlopen(GOODNET_NOISE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL);
        if (!handle) return;
        sdk_version = reinterpret_cast<SdkVersionFn>(
            ::dlsym(handle, "gn_plugin_sdk_version"));
        plugin_init = reinterpret_cast<InitFn>(
            ::dlsym(handle, "gn_plugin_init"));
        plugin_reg = reinterpret_cast<RegFn>(
            ::dlsym(handle, "gn_plugin_register"));
        plugin_unreg = reinterpret_cast<UnregFn>(
            ::dlsym(handle, "gn_plugin_unregister"));
        plugin_shut = reinterpret_cast<ShutFn>(
            ::dlsym(handle, "gn_plugin_shutdown"));
    }
    NoisePlugin(const NoisePlugin&) = delete;
    NoisePlugin& operator=(const NoisePlugin&) = delete;
    ~NoisePlugin() { if (handle) ::dlclose(handle); }
};

/// Thin C-ABI shim that hands kernel-side calls to the C++ TCP
/// transport. Only `send` and `disconnect` are reached on this path —
/// listen / connect run through the C++ API directly because the
/// demo wants the resolved port number from `listen_port()`.
const char* tcp_scheme(void*) { return "tcp"; }

gn_result_t tcp_send(void* self, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) {
    if (!self || (!bytes && size > 0)) return GN_ERR_NULL_ARG;
    return static_cast<TcpLink*>(self)->send(
        conn, std::span<const std::uint8_t>(bytes, size));
}

gn_result_t tcp_send_batch(void*, gn_conn_id_t, const gn_byte_span_t*,
                            std::size_t) {
    return GN_ERR_NOT_IMPLEMENTED;
}

gn_result_t tcp_disconnect(void* self, gn_conn_id_t conn) {
    if (!self) return GN_ERR_NULL_ARG;
    return static_cast<TcpLink*>(self)->disconnect(conn);
}

gn_result_t tcp_listen_unused(void*, const char*) { return GN_ERR_NOT_IMPLEMENTED; }
gn_result_t tcp_connect_unused(void*, const char*) { return GN_ERR_NOT_IMPLEMENTED; }
const char* tcp_ext_name(void*) { return nullptr; }
const void* tcp_ext_vtable(void*) { return nullptr; }
void        tcp_destroy(void*) {}

gn_link_vtable_t make_tcp_vtable() {
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
}

const gn_link_vtable_t kTcpVtable = make_tcp_vtable();

/// Receiver state for the demo handler. `wait_for_message` blocks
/// until the kernel routes one envelope through `handle_message`.
struct InboxState {
    std::mutex              mu;
    std::condition_variable cv;
    bool                    received = false;
    std::vector<std::uint8_t> payload;
};

gn_propagation_t handler_consume(void* self, const gn_message_t* env) {
    auto* inbox = static_cast<InboxState*>(self);
    {
        std::lock_guard lk(inbox->mu);
        inbox->payload.assign(env->payload, env->payload + env->payload_size);
        inbox->received = true;
    }
    inbox->cv.notify_all();
    return GN_PROPAGATION_CONSUMED;
}

/// One side of the conversation. Owns its kernel, its NodeIdentity,
/// its TCP transport instance, and one provider `self` allocated by
/// the noise plugin.
struct Node {
    std::unique_ptr<Kernel>       kernel = std::make_unique<Kernel>();
    std::shared_ptr<GnetProtocol> proto  = std::make_shared<GnetProtocol>();
    std::shared_ptr<TcpLink> tcp    = std::make_shared<TcpLink>();
    PluginContext                 plugin_ctx;
    host_api_t                    api{};
    void*                         noise_self = nullptr;
    NoisePlugin*                  plugin     = nullptr;
    PublicKey                     local_pk{};

    Node(NoisePlugin& p, std::string name) : plugin(&p) {
        plugin_ctx.plugin_name = std::move(name);
        plugin_ctx.kernel      = kernel.get();

        kernel->set_protocol_layer(proto);

        if (auto ident = gn::core::identity::NodeIdentity::generate(0)) {
            local_pk = ident->device().public_key();
            kernel->identities().add(local_pk);
            kernel->set_node_identity(std::move(*ident));
        }

        api = build_host_api(plugin_ctx);

        if (plugin->plugin_init(&api, &noise_self) != GN_OK) {
            std::cerr << "noise plugin_init failed\n";
            std::exit(1);
        }
        if (plugin->plugin_reg(noise_self) != GN_OK) {
            std::cerr << "noise plugin_register failed\n";
            std::exit(1);
        }

        tcp->set_host_api(&api);
        gn_link_id_t tid = GN_INVALID_ID;
        gn_register_meta_t mt{};
        mt.api_size = sizeof(gn_register_meta_t);
        mt.name     = "tcp";
        if (api.register_vtable(api.host_ctx, GN_REGISTER_LINK, &mt,
                                 &kTcpVtable, tcp.get(), &tid) != GN_OK) {
            std::cerr << "register_vtable(LINK, tcp) failed\n";
            std::exit(1);
        }
    }

    ~Node() {
        if (noise_self && plugin) {
            plugin->plugin_unreg(noise_self);
            plugin->plugin_shut(noise_self);
        }
        if (tcp) tcp->shutdown();
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

bool find_transport_session(Kernel& k, gn_conn_id_t* out_id) {
    for (gn_conn_id_t id = 1; id <= 8; ++id) {
        auto s = k.sessions().find(id);
        if (s && s->phase() == SecurityPhase::Transport) {
            *out_id = id;
            return true;
        }
    }
    return false;
}

}  // namespace

int main() {
    std::cout << "[demo] GoodNet two-node quickstart\n"
              << "[demo] booting noise plugin from\n"
              << "       " << GOODNET_NOISE_PLUGIN_PATH << "\n";

    NoisePlugin plugin;
    if (!plugin.handle || !plugin.plugin_init || !plugin.plugin_reg ||
        !plugin.plugin_unreg || !plugin.plugin_shut)
    {
        std::cerr << "[demo] noise.so not loadable; check build tree\n";
        return 1;
    }

    auto alice = std::make_unique<Node>(plugin, "alice");
    auto bob   = std::make_unique<Node>(plugin, "bob");

    InboxState alice_inbox;
    gn_handler_vtable_t vt{};
    vt.api_size       = sizeof(gn_handler_vtable_t);
    vt.handle_message = &handler_consume;
    gn_handler_id_t hid = GN_INVALID_ID;
    gn_register_meta_t hmt{};
    hmt.api_size = sizeof(gn_register_meta_t);
    hmt.name     = "gnet-v1";
    hmt.msg_id   = kDemoMsgId;
    hmt.priority = 128;
    if (alice->api.register_vtable(alice->api.host_ctx, GN_REGISTER_HANDLER,
                                    &hmt, &vt, &alice_inbox, &hid) != GN_OK) {
        std::cerr << "[demo] alice.register_vtable(HANDLER) failed\n";
        return 1;
    }

    if (alice->tcp->listen("tcp://127.0.0.1:0") != GN_OK) {
        std::cerr << "[demo] alice.listen failed\n";
        return 1;
    }
    const auto port = alice->tcp->listen_port();
    std::cout << "[demo] alice listening on tcp://127.0.0.1:" << port << "\n";

    const std::string uri = "tcp://127.0.0.1:" + std::to_string(port);
    std::cout << "[demo] bob   dialling   " << uri << "\n";
    if (bob->tcp->connect(uri) != GN_OK) {
        std::cerr << "[demo] bob.connect failed\n";
        return 1;
    }

    /// The handshake completes asynchronously on each side's TCP
    /// strand; the demo just polls until both sessions reach
    /// Transport phase or the budget is exhausted.
    if (!wait_until([&] {
            return alice->kernel->sessions().size() == 1 &&
                   bob->kernel->sessions().size()   == 1;
        }, 3s)) {
        std::cerr << "[demo] timeout: sessions never allocated\n";
        return 1;
    }

    if (!wait_until([&] {
            for (gn_conn_id_t id = 1; id <= 8; ++id) {
                auto a = alice->kernel->sessions().find(id);
                auto b = bob->kernel->sessions().find(id);
                if (a && a->phase() == SecurityPhase::Transport &&
                    b && b->phase() == SecurityPhase::Transport) {
                    return true;
                }
            }
            return false;
        }, 5s)) {
        std::cerr << "[demo] timeout: handshake stalled\n";
        return 1;
    }
    std::cout << "[demo] noise XX completed; transport phase active\n";

    gn_conn_id_t bob_conn = GN_INVALID_ID;
    if (!find_transport_session(*bob->kernel, &bob_conn)) {
        std::cerr << "[demo] no transport-phase session on bob's side\n";
        return 1;
    }

    const std::string greeting = "hello from bob";
    std::cout << "[demo] bob   send  msg_id=0x" << std::hex << kDemoMsgId
              << std::dec << " payload=\"" << greeting << "\"\n";

    const auto rc = bob->api.send(
        bob->api.host_ctx, bob_conn, kDemoMsgId,
        reinterpret_cast<const std::uint8_t*>(greeting.data()),
        greeting.size());
    if (rc != GN_OK) {
        std::cerr << "[demo] bob.send failed rc=" << rc << "\n";
        return 1;
    }

    {
        std::unique_lock lk(alice_inbox.mu);
        if (!alice_inbox.cv.wait_for(lk, 3s,
                [&] { return alice_inbox.received; })) {
            std::cerr << "[demo] timeout: alice never received the message\n";
            return 1;
        }
    }
    const std::string echoed(
        reinterpret_cast<const char*>(alice_inbox.payload.data()),
        alice_inbox.payload.size());
    std::cout << "[demo] alice recv payload=\"" << echoed << "\"\n";

    /// Tear down: the kernels' TCP workers join in `Node::~Node`, the
    /// noise providers run `handshake_close` on every active session.
    bob.reset();
    alice.reset();
    std::cout << "[demo] ok\n";
    return 0;
}
