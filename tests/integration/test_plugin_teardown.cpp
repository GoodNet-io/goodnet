/// @file   tests/integration/test_plugin_teardown.cpp
/// @brief  Regression pin: full e2e teardown leaks no plugin anchor.
///
/// `PluginManager::drain_anchor` reports
///   `did not quiesce within Nms (in_flight=0); leaking dlclose handle`
/// when a stale `shared_ptr<void> lifetime_anchor` outlives every
/// in-flight call into plugin code. The classic source is
/// `TcpLink::shutdown()` dropping pending strand-bound continuations
/// — including the read-completion path that fires `notify_disconnect`
/// — through `ioc_.stop()` before they run, so kernel-side
/// `SessionRegistry` keeps live `SecuritySession` records past tcp
/// shutdown and each session holds the noise plugin's anchor.
///
/// The test runs the same shape as `examples/two_node`: two kernels,
/// a real noise plugin, a real Noise XX handshake, one frame
/// exchanged, then teardown. After teardown it asserts that **every**
/// kernel-side anchor holder has dropped — `pm.leaked_handles() == 0`,
/// `kernel.security().is_active() == false`, `sessions().size() == 0`,
/// `connections().size() == 0`. Any future change that reverts the
/// synchronous-notify path in `TcpLink::shutdown()` (or any other
/// regression that strands a `lifetime_anchor` copy past unload)
/// fires this test.

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

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

#ifndef GOODNET_NOISE_PLUGIN_PATH
#error "GOODNET_NOISE_PLUGIN_PATH must be defined by the build system"
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

constexpr std::uint32_t kMsgId = 0xBEEFu;

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

struct Node {
    Kernel                          kernel;
    std::shared_ptr<GnetProtocol>   proto = std::make_shared<GnetProtocol>();
    std::shared_ptr<TcpLink>        tcp   = std::make_shared<TcpLink>();
    PluginContext                   host_ctx;
    host_api_t                      api{};
    PluginManager                   plugins{kernel};

    explicit Node(std::string name) {
        kernel.set_protocol_layer(proto);
        auto ident = gn::core::identity::NodeIdentity::generate(0);
        if (ident) {
            kernel.identities().add(ident->device().public_key());
            kernel.set_node_identity(std::move(*ident));
        }
        host_ctx.plugin_name = std::move(name);
        host_ctx.kernel      = &kernel;
        api                  = build_host_api(host_ctx);
        tcp->set_host_api(&api);

        gn_link_id_t tid = GN_INVALID_ID;
        EXPECT_EQ(kernel.links().register_link(
            "tcp", &kTcpVtable, tcp.get(), &tid), GN_OK);

        const std::vector<std::string> noise_paths{GOODNET_NOISE_PLUGIN_PATH};
        std::string diag;
        EXPECT_EQ(plugins.load(std::span<const std::string>(noise_paths), &diag),
                  GN_OK) << diag;
    }
};

bool wait_until(const std::function<bool()>& pred,
                 std::chrono::milliseconds timeout = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(10ms);
    }
    return false;
}

bool find_transport(Kernel& k, gn_conn_id_t* out) {
    for (gn_conn_id_t id = 1; id <= 8; ++id) {
        auto s = k.sessions().find(id);
        if (s && s->phase() == SecurityPhase::Transport) {
            *out = id;
            return true;
        }
    }
    return false;
}

}  // namespace

TEST(PluginTeardown, NoiseTcpE2EDrainsCleanly) {
    auto alice = std::make_unique<Node>("alice");
    auto bob   = std::make_unique<Node>("bob");

    Inbox alice_inbox;
    gn_handler_vtable_t vt{};
    vt.api_size       = sizeof(vt);
    vt.handle_message = &handler_consume;

    gn_handler_id_t hid = GN_INVALID_ID;
    ASSERT_EQ(alice->kernel.handlers().register_handler(
        "gnet-v1", kMsgId, /*priority*/128, &vt, &alice_inbox, &hid),
        GN_OK);

    ASSERT_EQ(alice->tcp->listen("tcp://127.0.0.1:0"), GN_OK);
    const auto port = alice->tcp->listen_port();
    ASSERT_GT(port, 0u);

    const std::string uri =
        "tcp://127.0.0.1:" + std::to_string(port);
    ASSERT_EQ(bob->tcp->connect(uri), GN_OK);

    ASSERT_TRUE(wait_until([&] {
        for (gn_conn_id_t id = 1; id <= 8; ++id) {
            auto a = alice->kernel.sessions().find(id);
            auto b = bob->kernel.sessions().find(id);
            if (a && a->phase() == SecurityPhase::Transport &&
                b && b->phase() == SecurityPhase::Transport) return true;
        }
        return false;
    }));

    gn_conn_id_t bob_conn = GN_INVALID_ID;
    ASSERT_TRUE(find_transport(bob->kernel, &bob_conn));

    const std::string greeting = "ping";
    ASSERT_EQ(bob->api.send(bob->api.host_ctx, bob_conn, kMsgId,
                              reinterpret_cast<const std::uint8_t*>(greeting.data()),
                              greeting.size()),
              GN_OK);

    {
        std::unique_lock lk(alice_inbox.mu);
        ASSERT_TRUE(alice_inbox.cv.wait_for(lk, 3s,
            [&] { return alice_inbox.received; }));
    }

    /// Tear down in the demo order: TCP first (synchronous
    /// `notify_disconnect` per session), plugins second. Then assert
    /// that EVERY kernel-side anchor holder dropped — the regression
    /// guard from `link.md` §7 + `plugin-lifetime.md` §4.
    bob->tcp->shutdown();
    bob->plugins.shutdown();
    EXPECT_EQ(bob->plugins.leaked_handles(), 0u)
        << "bob: PluginManager leaked a dlclose handle past drain — "
           "a stored lifetime_anchor outlived the plugin";
    EXPECT_FALSE(bob->kernel.security().is_active())
        << "bob: security registry still active post-shutdown";
    EXPECT_EQ(bob->kernel.sessions().size(), 0u)
        << "bob: kernel SessionRegistry kept live SecuritySession past tcp shutdown";

    alice->tcp->shutdown();
    alice->plugins.shutdown();
    EXPECT_EQ(alice->plugins.leaked_handles(), 0u)
        << "alice: PluginManager leaked a dlclose handle past drain";
    EXPECT_FALSE(alice->kernel.security().is_active())
        << "alice: security registry still active post-shutdown";
    EXPECT_EQ(alice->kernel.sessions().size(), 0u)
        << "alice: kernel SessionRegistry kept live SecuritySession past tcp shutdown";

    bob.reset();
    alice.reset();
}
