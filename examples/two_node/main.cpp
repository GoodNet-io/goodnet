/// @file   examples/two_node/main.cpp
/// @brief  Two GoodNet kernels in one process, talking over TCP under
///         a Noise XX handshake. The shortest path from `nix run .#demo`
///         to "two endpoints established a confidential channel and
///         exchanged a frame", suitable as the first thing a user runs
///         after `git clone`.

#include <core/identity/node_identity.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/plugin/plugin_manager.hpp>

#include <plugins/protocols/gnet/protocol.hpp>
#include <plugins/links/tcp/tcp.hpp>

#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/types.h>

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
#error "GOODNET_NOISE_PLUGIN_PATH must be defined to locate the noise .so"
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

/// Receiver state for the demo handler. `wait_for_message` blocks
/// until the kernel routes one envelope through `handle_message`.
struct Inbox {
    std::mutex                mu;
    std::condition_variable   cv;
    std::vector<std::uint8_t> payload;
    bool                      received = false;
};

gn_propagation_t handler_consume(void* self, const gn_message_t* env) {
    auto* inbox = static_cast<Inbox*>(self);
    {
        std::lock_guard lk(inbox->mu);
        inbox->payload.assign(env->payload, env->payload + env->payload_size);
        inbox->received = true;
    }
    inbox->cv.notify_all();
    return GN_PROPAGATION_CONSUMED;
}

/// Thin C-ABI link vtable that hands kernel-side calls down to the
/// in-tree `TcpLink`. Listen / connect run through `TcpLink` directly
/// because the demo wants the resolved port back from `listen_port()`.
gn_result_t tcp_send(void* self, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) {
    if (!self || (!bytes && size > 0)) return GN_ERR_NULL_ARG;
    return static_cast<TcpLink*>(self)->send(
        conn, std::span<const std::uint8_t>(bytes, size));
}

gn_result_t tcp_disconnect(void* self, gn_conn_id_t conn) {
    if (!self) return GN_ERR_NULL_ARG;
    return static_cast<TcpLink*>(self)->disconnect(conn);
}

const char* tcp_scheme(void*)                                                 { return "tcp"; }
gn_result_t tcp_listen_unused(void*, const char*)                              { return GN_ERR_NOT_IMPLEMENTED; }
gn_result_t tcp_connect_unused(void*, const char*)                             { return GN_ERR_NOT_IMPLEMENTED; }
gn_result_t tcp_batch_unused(void*, gn_conn_id_t, const gn_byte_span_t*, std::size_t) { return GN_ERR_NOT_IMPLEMENTED; }
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
    v.send_batch       = &tcp_batch_unused;
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
        kernel.set_protocol_layer(proto);

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
                "tcp", &kTcpVtable, tcp.get(), &tid) != GN_OK) {
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
        plugins.shutdown();
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
              << "[demo] noise plugin: " << GOODNET_NOISE_PLUGIN_PATH << "\n";

    Node alice("alice");
    Node bob  ("bob");

    Inbox alice_inbox;
    gn_handler_vtable_t vt{};
    vt.api_size       = sizeof(vt);
    vt.handle_message = &handler_consume;

    gn_handler_id_t hid = GN_INVALID_ID;
    if (alice.kernel.handlers().register_handler(
            "gnet-v1", kDemoMsgId, /*priority*/128,
            &vt, &alice_inbox, &hid) != GN_OK) {
        std::cerr << "[demo] alice.register_handler failed\n";
        return 1;
    }

    if (alice.tcp->listen("tcp://127.0.0.1:0") != GN_OK) {
        std::cerr << "[demo] alice.listen failed\n";
        return 1;
    }
    const auto port = alice.tcp->listen_port();
    std::cout << "[demo] alice listening on tcp://127.0.0.1:" << port << "\n";

    const std::string uri = "tcp://127.0.0.1:" + std::to_string(port);
    std::cout << "[demo] bob   dialling   " << uri << "\n";
    if (bob.tcp->connect(uri) != GN_OK) {
        std::cerr << "[demo] bob.connect failed\n";
        return 1;
    }

    /// Wait for both sides to reach the Transport phase. The Noise XX
    /// handshake completes asynchronously on each side's TCP strand;
    /// until both `Transport` flags raise the encrypted send path is
    /// not yet open.
    if (!wait_until([&] {
            for (gn_conn_id_t id = 1; id <= 8; ++id) {
                auto a = alice.kernel.sessions().find(id);
                auto b = bob.kernel.sessions().find(id);
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
    if (!find_transport_session(bob.kernel, &bob_conn)) {
        std::cerr << "[demo] no transport-phase session on bob's side\n";
        return 1;
    }

    const std::string greeting = "hello from bob";
    std::cout << "[demo] bob   send  msg_id=0x" << std::hex << kDemoMsgId
              << std::dec << " payload=\"" << greeting << "\"\n";

    if (bob.api.send(bob.api.host_ctx, bob_conn, kDemoMsgId,
                      reinterpret_cast<const std::uint8_t*>(greeting.data()),
                      greeting.size()) != GN_OK) {
        std::cerr << "[demo] bob.send failed\n";
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

    std::cout << "[demo] ok\n";
    return 0;
}
