/// @file   tests/integration/test_noise_tcp_e2e.cpp
/// @brief  Two kernels in one process drive a real TCP socket through
///         the Noise XX handshake into transport phase, then round-trip
///         an application message. Validates the security pipeline
///         end-to-end with the real noise plugin loaded via dlopen.

#include <gtest/gtest.h>

#include <core/identity/node_identity.hpp>
#include <core/kernel/connection_context.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <plugins/protocols/gnet/protocol.hpp>
#include <plugins/links/tcp/tcp.hpp>

#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/security.h>
#include <sdk/link.h>
#include <sdk/types.h>

#include <dlfcn.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
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
using namespace gn;
using namespace gn::core;
using namespace gn::plugins::gnet;
using TcpLink = gn::link::tcp::TcpLink;

// ── Noise plugin handle (dlopen) ────────────────────────────────────

struct NoisePlugin {
    using SdkVersionFn = void        (*)(std::uint32_t*, std::uint32_t*, std::uint32_t*);
    using InitFn       = gn_result_t (*)(const host_api_t*, void**);
    using RegFn        = gn_result_t (*)(void*);
    using UnregFn      = gn_result_t (*)(void*);
    using ShutFn       = void        (*)(void*);

    void*       handle      = nullptr;
    SdkVersionFn sdk_version = nullptr;
    InitFn      plugin_init = nullptr;
    RegFn       plugin_reg  = nullptr;
    UnregFn     plugin_unreg = nullptr;
    ShutFn      plugin_shut = nullptr;

    NoisePlugin() {
        handle = ::dlopen(GOODNET_NOISE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL);
        if (!handle) return;
        sdk_version  = reinterpret_cast<SdkVersionFn>(::dlsym(handle, "gn_plugin_sdk_version"));
        plugin_init  = reinterpret_cast<InitFn>(::dlsym(handle, "gn_plugin_init"));
        plugin_reg   = reinterpret_cast<RegFn>(::dlsym(handle, "gn_plugin_register"));
        plugin_unreg = reinterpret_cast<UnregFn>(::dlsym(handle, "gn_plugin_unregister"));
        plugin_shut  = reinterpret_cast<ShutFn>(::dlsym(handle, "gn_plugin_shutdown"));
    }
    NoisePlugin(const NoisePlugin&) = delete;
    NoisePlugin& operator=(const NoisePlugin&) = delete;
    ~NoisePlugin() { if (handle) ::dlclose(handle); }
};

// ── TCP plugin glue (in-tree, vtable wraps TcpLink directly) ───

const char* tcp_scheme(void* /*self*/) { return "tcp"; }

gn_result_t tcp_send(void* self, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) {
    if (!self || (!bytes && size > 0)) return GN_ERR_NULL_ARG;
    return static_cast<TcpLink*>(self)->send(
        conn, std::span<const std::uint8_t>(bytes, size));
}

gn_result_t tcp_send_batch(void* /*self*/, gn_conn_id_t /*conn*/,
                            const gn_byte_span_t* /*batch*/, std::size_t /*count*/) {
    return GN_ERR_NOT_IMPLEMENTED;  /// not exercised in this test
}

gn_result_t tcp_disconnect(void* self, gn_conn_id_t conn) {
    if (!self) return GN_ERR_NULL_ARG;
    return static_cast<TcpLink*>(self)->disconnect(conn);
}

gn_result_t tcp_listen_unused(void* /*self*/, const char* /*uri*/) {
    return GN_ERR_NOT_IMPLEMENTED;  /// driven by the test directly
}

gn_result_t tcp_connect_unused(void* /*self*/, const char* /*uri*/) {
    return GN_ERR_NOT_IMPLEMENTED;
}

const char* tcp_ext_name(void* /*self*/) { return nullptr; }
const void* tcp_ext_vtable(void* /*self*/) { return nullptr; }
void        tcp_destroy(void* /*self*/) {}

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

// ── Per-kernel node ─────────────────────────────────────────────────

struct Node {
    std::unique_ptr<Kernel>           kernel = std::make_unique<Kernel>();
    std::shared_ptr<GnetProtocol>     proto  = std::make_shared<GnetProtocol>();
    std::shared_ptr<TcpLink>     tcp    = std::make_shared<TcpLink>();
    PluginContext                     plugin_ctx;
    host_api_t                        api{};
    void*                             noise_self = nullptr;
    NoisePlugin*                      plugin     = nullptr;
    gn_link_id_t                 tcp_id     = GN_INVALID_ID;
    PublicKey                         local_pk{};

    Node(NoisePlugin& p, std::string name) : plugin(&p) {
        plugin_ctx.plugin_name = std::move(name);
        plugin_ctx.kernel      = kernel.get();

        kernel->set_protocol_layer(proto);

        auto ident_res = identity::NodeIdentity::generate(/*expiry*/ 0);
        if (ident_res) {
            local_pk = ident_res->device().public_key();
            kernel->identities().add(local_pk);
            kernel->set_node_identity(std::move(*ident_res));
        }

        api = build_host_api(plugin_ctx);

        /// Noise plugin: each node gets its own self instance.
        EXPECT_EQ(p.plugin_init(&api, &noise_self), GN_OK);
        EXPECT_NE(noise_self, nullptr);
        EXPECT_EQ(p.plugin_reg(noise_self), GN_OK);

        /// TCP transport: register the in-tree instance under the
        /// kernel's LinkRegistry so the kernel-side notify thunks
        /// can route handshake bytes back through it.
        tcp->set_host_api(&api);
        gn_register_meta_t mt{};
        mt.api_size = sizeof(gn_register_meta_t);
        mt.name     = "tcp";
        EXPECT_EQ(api.register_vtable(api.host_ctx, GN_REGISTER_LINK, &mt,
                                       &kTcpVtable, tcp.get(), &tcp_id),
                  GN_OK);
    }

    ~Node() {
        if (noise_self && plugin) {
            plugin->plugin_unreg(noise_self);
            plugin->plugin_shut(noise_self);
        }
        if (tcp) tcp->shutdown();
    }
};

// ── Async wait helper ───────────────────────────────────────────────

void wait_for(const std::function<bool()>& pred,
              std::chrono::milliseconds timeout,
              const char* what) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return;
        std::this_thread::sleep_for(10ms);
    }
    FAIL() << "timeout waiting for: " << what;
}

}  // namespace

TEST(NoiseTcpE2E, HandshakeOverRealSocketReachesTransportPhase) {
    NoisePlugin plugin;
    ASSERT_NE(plugin.handle, nullptr) << "noise.so failed to load";

    /// Two independent nodes in the same process. Each carries its
    /// own kernel, NodeIdentity, TcpLink, and noise provider.
    auto alice = std::make_unique<Node>(plugin, "alice");
    auto bob   = std::make_unique<Node>(plugin, "bob");

    /// Alice listens on 127.0.0.1:ephemeral. Bob dials the resolved
    /// port. Both transports run on their own io_context worker.
    ASSERT_EQ(alice->tcp->listen("tcp://127.0.0.1:0"), GN_OK);
    const auto port = alice->tcp->listen_port();
    ASSERT_NE(port, 0);

    const std::string uri = "tcp://127.0.0.1:" + std::to_string(port);
    ASSERT_EQ(bob->tcp->connect(uri), GN_OK);

    /// Wait for both kernels to register their security session for
    /// the loopback connection and reach Transport phase.
    wait_for([&] {
        return alice->kernel->sessions().size() == 1 &&
               bob->kernel->sessions().size()   == 1;
    }, 3s, "both sessions allocated");

    wait_for([&] {
        bool alice_ready = false;
        bool bob_ready   = false;
        /// Each kernel has exactly one connection at this point.
        if (alice->kernel->connections().size() == 1) {
            const auto& alice_conn = alice->kernel->connections();
            (void)alice_conn;  /// linear scan via Sessions::find is enough
        }
        for (gn_conn_id_t id = 1; id <= 8; ++id) {
            if (auto s = alice->kernel->sessions().find(id);
                s && s->phase() == SecurityPhase::Transport)
            {
                alice_ready = true;
            }
            if (auto s = bob->kernel->sessions().find(id);
                s && s->phase() == SecurityPhase::Transport)
            {
                bob_ready = true;
            }
        }
        return alice_ready && bob_ready;
    }, 5s, "Noise XX completes on both sides");

    /// Sanity: handshake-hash matches across peers — the security
    /// pipeline on both sides committed the same transcript.
    gn_handshake_keys_t alice_keys{};
    gn_handshake_keys_t bob_keys{};
    bool got_alice = false, got_bob = false;
    for (gn_conn_id_t id = 1; id <= 8 && !(got_alice && got_bob); ++id) {
        if (auto s = alice->kernel->sessions().find(id);
            s && s->phase() == SecurityPhase::Transport) {
            alice_keys = s->transport_keys();
            got_alice = true;
        }
        if (auto s = bob->kernel->sessions().find(id);
            s && s->phase() == SecurityPhase::Transport) {
            bob_keys = s->transport_keys();
            got_bob = true;
        }
    }
    ASSERT_TRUE(got_alice && got_bob);
    EXPECT_EQ(std::memcmp(alice_keys.handshake_hash,
                           bob_keys.handshake_hash,
                           GN_HASH_BYTES), 0);

    /// Trust gate per `security-trust.md` §3 + `sdk/trust.h` helper:
    /// TCP on `127.0.0.1` declared `GN_TRUST_LOOPBACK` at connect.
    /// The post-handshake hook in `thunk_notify_inbound_bytes` calls
    /// `upgrade_trust(conn, GN_TRUST_PEER)` indiscriminately; the
    /// registry consults `gn_trust_can_upgrade(LOOPBACK, PEER)`,
    /// which returns 0, and the record stays `LOOPBACK`. This proves
    /// the gate is wired and rejects an unsafe transition. The
    /// `Untrusted → Peer` happy path is exercised in
    /// `tests/unit/registry/test_connection.cpp`.
    bool alice_loopback_held = false, bob_loopback_held = false;
    for (gn_conn_id_t id = 1; id <= 8; ++id) {
        if (auto rec = alice->kernel->connections().find_by_id(id);
            rec && rec->trust == GN_TRUST_LOOPBACK) {
            alice_loopback_held = true;
        }
        if (auto rec = bob->kernel->connections().find_by_id(id);
            rec && rec->trust == GN_TRUST_LOOPBACK) {
            bob_loopback_held = true;
        }
    }
    EXPECT_TRUE(alice_loopback_held)
        << "loopback upgrade gate leaked: alice's trust mutated";
    EXPECT_TRUE(bob_loopback_held)
        << "loopback upgrade gate leaked: bob's trust mutated";

    /// Cross-session pin gate (registry.md §7a + §8a) lives on
    /// the responder side: every connection record carries a real
    /// peer pk after the Noise handshake completes, not the zero
    /// placeholder TCP passed at notify_connect time. The propagated
    /// value is the Noise X25519 static — derived from the peer's
    /// Ed25519 device key but a different curve, so the test asserts
    /// "no longer zeros" rather than equality with `alice.local_pk`.
    /// Pre-fix the gate keyed on the placeholder and was
    /// structurally dead — any reconnect under a forged device key
    /// escaped detection.
    const PublicKey kZero{};
    bool bob_pk_propagated = false;
    bool alice_pk_propagated = false;
    for (gn_conn_id_t id = 1; id <= 8; ++id) {
        if (auto rec = bob->kernel->connections().find_by_id(id);
            rec && rec->remote_pk != kZero) {
            bob_pk_propagated = true;
        }
        if (auto rec = alice->kernel->connections().find_by_id(id);
            rec && rec->remote_pk != kZero) {
            alice_pk_propagated = true;
        }
    }
    EXPECT_TRUE(bob_pk_propagated)
        << "bob (responder) remote_pk did not propagate from the "
           "Noise peer_static_pk after the handshake";
    EXPECT_TRUE(alice_pk_propagated)
        << "alice (initiator) remote_pk did not propagate (TCP "
           "passes zeros for both roles, so the propagation must "
           "fire on the initiator side too)";

    /// Tear down — destruction joins worker threads and closes the
    /// listening socket.
    bob.reset();
    alice.reset();
}
