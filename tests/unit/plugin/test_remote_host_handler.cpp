/// @file   tests/unit/plugin/test_remote_host_handler.cpp
/// @brief  End-to-end exercise of the subprocess HANDLER proxy slots.
///
/// Spawns the in-tree `remote_handler_stub` worker, dispatches an
/// envelope through `RemoteHost::handler_vtable_proxy`, and asserts
/// the worker's `handle_message` ran and routed the payload back
/// through `host_api.notify_inbound_bytes`.

#include <array>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/plugin.h>
#include <sdk/types.h>

#include <core/kernel/plugin_context.hpp>
#include <core/plugin/remote_host.hpp>

namespace {

const char* worker_binary_path() {
    if (const char* env = std::getenv("GOODNET_REMOTE_HANDLER_STUB_BINARY")) {
        return env;
    }
#ifdef GOODNET_REMOTE_HANDLER_STUB_PATH
    return GOODNET_REMOTE_HANDLER_STUB_PATH;
#else
    return "workers/remote_handler_stub";
#endif
}

struct StubHostState {
    std::atomic<int> inbound_calls{0};
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

void stub_log_emit(void* /*host_ctx*/, gn_log_level_t /*level*/,
                   const char* /*file*/, int32_t /*line*/,
                   const char* /*msg*/) {}

int32_t stub_is_shutdown_requested(void* /*host_ctx*/) { return 0; }

host_api_t make_stub_host_api(StubHostState& s) {
    host_api_t api{};
    api.api_size = sizeof(host_api_t);
    api.host_ctx = &s;
    api.log.api_size = sizeof(gn_log_api_t);
    api.log.emit = &stub_log_emit;
    api.is_shutdown_requested = &stub_is_shutdown_requested;
    api.notify_inbound_bytes = &stub_notify_inbound_bytes;
    return api;
}

}  // namespace

TEST(RemoteHostHandler, ProxyExposesProtocolId) {
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_handler_stub_test";
    ctx.kind        = GN_PLUGIN_KIND_HANDLER;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag), GN_OK) << diag;

    const gn_handler_vtable_t* vt = host.handler_vtable_proxy();
    ASSERT_NE(vt, nullptr);
    ASSERT_NE(vt->protocol_id, nullptr);
    EXPECT_STREQ(vt->protocol_id(static_cast<void*>(&host)),
                 "remote_handler_stub");
}

TEST(RemoteHostHandler, SupportedMsgIdsRoundTrips) {
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_handler_stub_test";
    ctx.kind        = GN_PLUGIN_KIND_HANDLER;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag), GN_OK) << diag;

    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);

    const gn_handler_vtable_t* vt = host.handler_vtable_proxy();
    ASSERT_NE(vt, nullptr);
    ASSERT_NE(vt->supported_msg_ids, nullptr);

    const std::uint32_t* ids = nullptr;
    size_t count = 0;
    vt->supported_msg_ids(static_cast<void*>(&host), &ids, &count);
    ASSERT_EQ(count, 1u);
    ASSERT_NE(ids, nullptr);
    EXPECT_EQ(ids[0], 0xC0DEu);
}

TEST(RemoteHostHandler, HandleMessageDispatches) {
    /// The stub's `handle_message` echoes the envelope's payload
    /// back through `host_api.notify_inbound_bytes`. Driving an
    /// envelope through the proxy must land in the stub's host_api
    /// thunk on the kernel side and surface the same bytes.
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_handler_stub_test";
    ctx.kind        = GN_PLUGIN_KIND_HANDLER;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag), GN_OK) << diag;
    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);

    const gn_handler_vtable_t* vt = host.handler_vtable_proxy();
    ASSERT_NE(vt, nullptr);
    ASSERT_NE(vt->handle_message, nullptr);

    const std::vector<std::uint8_t> payload = {0x41, 0x42, 0x43, 0x44};
    gn_message_t env{};
    env.api_size = sizeof(gn_message_t);
    std::memset(env.sender_pk, 0x77, GN_PUBLIC_KEY_BYTES);
    std::memset(env.receiver_pk, 0x00, GN_PUBLIC_KEY_BYTES);
    env.msg_id = 0xC0DE;
    env.payload = payload.data();
    env.payload_size = payload.size();
    env.conn_id = 7;

    const gn_propagation_t rc = vt->handle_message(
        static_cast<void*>(&host), &env);
    EXPECT_EQ(rc, GN_PROPAGATION_CONSUMED);
    EXPECT_EQ(stub.inbound_calls.load(), 1);
    EXPECT_EQ(stub.last_conn, env.conn_id);
    ASSERT_EQ(stub.last_payload.size(), payload.size());
    for (size_t i = 0; i < payload.size(); ++i) {
        EXPECT_EQ(stub.last_payload[i], payload[i]) << "byte " << i;
    }
}

TEST(RemoteHostHandler, UnknownMsgIdContinues) {
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_handler_stub_test";
    ctx.kind        = GN_PLUGIN_KIND_HANDLER;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag), GN_OK) << diag;
    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);

    const gn_handler_vtable_t* vt = host.handler_vtable_proxy();
    ASSERT_NE(vt, nullptr);

    const std::vector<std::uint8_t> payload = {0x99};
    gn_message_t env{};
    env.api_size = sizeof(gn_message_t);
    env.msg_id = 0xDEADBEEFu;  // not in supported list
    env.payload = payload.data();
    env.payload_size = payload.size();

    EXPECT_EQ(vt->handle_message(static_cast<void*>(&host), &env),
              GN_PROPAGATION_CONTINUE);
    EXPECT_EQ(stub.inbound_calls.load(), 0);
}

TEST(RemoteHostHandler, OnInitAndOnShutdownAreInvocable) {
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_handler_stub_test";
    ctx.kind        = GN_PLUGIN_KIND_HANDLER;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag), GN_OK) << diag;
    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);

    const gn_handler_vtable_t* vt = host.handler_vtable_proxy();
    ASSERT_NE(vt, nullptr);
    ASSERT_NE(vt->on_init, nullptr);
    ASSERT_NE(vt->on_shutdown, nullptr);
    vt->on_init(static_cast<void*>(&host));
    vt->on_shutdown(static_cast<void*>(&host));
    SUCCEED();
}
