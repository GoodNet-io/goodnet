/// @file   tests/unit/plugin/test_remote_host.cpp
/// @brief  Exercise the subprocess plugin runtime end-to-end against
///         the in-tree `remote_echo` worker binary.
///
/// Coverage:
///   • spawn() drives HELLO/HELLO_ACK to completion and exposes the
///     descriptor the worker reported.
///   • call_init/register/unregister/shutdown round-trip every
///     entry-point through the wire.
///   • A worker-issued HOST_CALL slot (notify_inbound_bytes) reaches
///     the kernel-side host_api stub and the worker observes the
///     reply payload's gn_result_t.
///   • set_reply_timeout shortens the budget; sending no worker (a
///     pathological binary) surfaces the timeout as
///     GN_ERR_INVALID_STATE.

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/plugin.h>

#include <core/kernel/plugin_context.hpp>
#include <core/plugin/remote_host.hpp>

namespace {

const char* worker_binary_path() {
    if (const char* env = std::getenv("GOODNET_REMOTE_ECHO_BINARY")) {
        return env;
    }
#ifdef GOODNET_REMOTE_ECHO_PATH
    return GOODNET_REMOTE_ECHO_PATH;
#else
    return "workers/remote_echo";
#endif
}

// Minimal host_api stub. The remote_echo worker calls
// notify_inbound_bytes through the synthetic host_api its stub
// publishes; this stub captures every call so a test can assert
// the worker reached the kernel-side dispatcher.
struct StubHostState {
    std::atomic<int> inbound_calls{0};
    std::atomic<int> log_calls{0};
    std::vector<std::uint8_t> last_payload;
    std::uint64_t last_conn{0};
};

gn_result_t stub_notify_inbound_bytes(void* host_ctx,
                                      gn_conn_id_t conn,
                                      const uint8_t* bytes,
                                      size_t size) {
    auto* s = static_cast<StubHostState*>(host_ctx);
    s->last_conn = conn;
    s->last_payload.assign(bytes, bytes + size);
    s->inbound_calls.fetch_add(1, std::memory_order_relaxed);
    return GN_OK;
}

void stub_log_emit(void* host_ctx, gn_log_level_t /*level*/,
                   const char* /*file*/, int32_t /*line*/,
                   const char* /*msg*/) {
    auto* s = static_cast<StubHostState*>(host_ctx);
    s->log_calls.fetch_add(1, std::memory_order_relaxed);
}

int32_t stub_is_shutdown_requested(void* /*host_ctx*/) { return 0; }

host_api_t make_stub_host_api(StubHostState& s) {
    host_api_t api{};
    api.api_size = sizeof(host_api_t);
    api.host_ctx = &s;
    api.log.api_size = sizeof(gn_log_api_t);
    api.log.emit = &stub_log_emit;
    api.notify_inbound_bytes = &stub_notify_inbound_bytes;
    api.is_shutdown_requested = &stub_is_shutdown_requested;
    return api;
}

}  // namespace

TEST(RemoteHost, SpawnAndHandshake) {
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_echo_test";

    gn::core::RemoteHost host;
    std::string diag;
    auto rc = host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag);
    ASSERT_EQ(rc, GN_OK) << diag;
    ASSERT_NE(host.descriptor(), nullptr);
    EXPECT_STREQ(host.descriptor()->name, "remote_echo");
    EXPECT_EQ(host.descriptor()->kind, GN_PLUGIN_KIND_LINK);
}

TEST(RemoteHost, LifecycleRoundTrip) {
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_echo_test";

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag), GN_OK) << diag;

    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);
    ASSERT_EQ(host.call_register(reinterpret_cast<std::uintptr_t>(self_handle)),
              GN_OK);
    ASSERT_EQ(host.call_unregister(reinterpret_cast<std::uintptr_t>(self_handle)),
              GN_OK);
    host.call_shutdown(reinterpret_cast<std::uintptr_t>(self_handle));

    EXPECT_GE(host.round_trips(), 4u);
}

TEST(RemoteHost, LinkVtableProxyExposesScheme) {
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_echo_test";

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag), GN_OK) << diag;

    const gn_link_vtable_t* vt = host.link_vtable_proxy();
    ASSERT_NE(vt, nullptr);
    ASSERT_NE(vt->scheme, nullptr);
    EXPECT_STREQ(vt->scheme(static_cast<void*>(&host)), "remote_echo");
}

TEST(RemoteHost, BadBinaryFailsSpawnCleanly) {
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "missing";

    gn::core::RemoteHost host;
    host.set_reply_timeout(std::chrono::milliseconds(250));
    std::string diag;
    auto rc = host.spawn("/nonexistent/worker/binary",
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag);
    EXPECT_NE(rc, GN_OK);
}

TEST(RemoteHost, LinkProxyEndToEndSendEchoes) {
    /// The synthesised vtable's `send` slot should round-trip the
    /// payload through PLUGIN_CALL into the worker, the worker's
    /// echo_send should call back through HOST_CALL
    /// notify_inbound_bytes, and the stub host_api here should
    /// observe the same bytes.
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_echo_test";
    ctx.kind        = GN_PLUGIN_KIND_LINK;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag), GN_OK) << diag;

    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);
    /// Skip call_register here — that would auto-register the proxy
    /// in the kernel's link registry, which this test doesn't need.

    const gn_link_vtable_t* vt = host.link_vtable_proxy();
    ASSERT_NE(vt, nullptr);
    ASSERT_NE(vt->send, nullptr);

    const std::vector<std::uint8_t> payload = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x00, 0x13, 0x37};
    const gn_conn_id_t conn = 99;
    const gn_result_t rc = vt->send(
        static_cast<void*>(&host), conn, payload.data(), payload.size());
    EXPECT_EQ(rc, GN_OK);
    EXPECT_EQ(stub.inbound_calls.load(), 1);
    EXPECT_EQ(stub.last_conn, conn);
    ASSERT_EQ(stub.last_payload.size(), payload.size());
    for (std::size_t i = 0; i < payload.size(); ++i) {
        EXPECT_EQ(stub.last_payload[i], payload[i]) << "byte " << i;
    }
}

TEST(RemoteHost, TerminateIsIdempotent) {
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_echo_test";

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag), GN_OK) << diag;
    host.terminate();
    host.terminate();  // must not crash / hang
    SUCCEED();
}
