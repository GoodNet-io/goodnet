/// @file   plugins/workers/remote_echo/tests/test_remote_echo_slots.cpp
/// @brief  Verify the host-call slot wiring used by remote LINK plugins
///         lands end-to-end through the kernel-side `RemoteHost`
///         dispatcher.
///
/// The slots in question (notify_connect 0x13, notify_disconnect 0x14,
/// register_vtable 0x15, unregister_vtable 0x16) used to return
/// GN_ERR_NOT_IMPLEMENTED on the kernel side and crash on the worker
/// side (NULL function pointers in the synthetic host_api).
///
/// `notify_connect` is now driven by the in-tree `remote_echo` worker's
/// `echo_connect` slot — it has no real handshake, so it materialises
/// the conn immediately and the HOST_CALL crosses on every `connect`.
/// The proxy's `send_batch` slot is now non-null and routes back to
/// scalar `send` PLUGIN_CALLs.
///
/// `notify_disconnect`, `register_vtable`, `unregister_vtable` over
/// the wire are exercised by tests that ship their own stress worker;
/// in this binary we cover the kernel-side auto-register pair through
/// `call_register` / `call_unregister`, which uses the same
/// `register_vtable` host_api slot the wire dispatcher would route to.

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/plugin.h>
#include <sdk/trust.h>

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

struct StubHost {
    std::atomic<int>          connect_calls{0};
    std::atomic<int>          disconnect_calls{0};
    std::atomic<int>          register_calls{0};
    std::atomic<int>          unregister_calls{0};
    std::atomic<gn_conn_id_t> next_conn_id{1000};

    std::string               last_connect_uri;
    gn_trust_class_t          last_connect_trust{GN_TRUST_UNTRUSTED};
    gn_handshake_role_t       last_connect_role{GN_ROLE_INITIATOR};
    gn_conn_id_t              last_disconnect_conn{0};
    gn_result_t               last_disconnect_reason{GN_OK};

    gn_register_kind_t        last_register_kind{GN_REGISTER_LINK};
    std::string               last_register_name;
    std::uint64_t             last_unregister_id{0};
};

gn_result_t stub_notify_connect(void* host_ctx,
                                const uint8_t /*pk*/[GN_PUBLIC_KEY_BYTES],
                                const char* uri,
                                gn_trust_class_t trust,
                                gn_handshake_role_t role,
                                gn_conn_id_t* out_conn) {
    auto* s = static_cast<StubHost*>(host_ctx);
    s->last_connect_uri   = uri != nullptr ? std::string(uri) : std::string();
    s->last_connect_trust = trust;
    s->last_connect_role  = role;
    *out_conn = s->next_conn_id.fetch_add(1);
    s->connect_calls.fetch_add(1, std::memory_order_relaxed);
    return GN_OK;
}

gn_result_t stub_notify_disconnect(void* host_ctx,
                                   gn_conn_id_t conn,
                                   gn_result_t reason) {
    auto* s = static_cast<StubHost*>(host_ctx);
    s->last_disconnect_conn   = conn;
    s->last_disconnect_reason = reason;
    s->disconnect_calls.fetch_add(1, std::memory_order_relaxed);
    return GN_OK;
}

gn_result_t stub_register_vtable(void* host_ctx,
                                 gn_register_kind_t kind,
                                 const gn_register_meta_t* meta,
                                 const void* /*vtable*/,
                                 void* /*self*/,
                                 std::uint64_t* out_id) {
    auto* s = static_cast<StubHost*>(host_ctx);
    s->last_register_kind = kind;
    if (meta != nullptr && meta->name != nullptr) {
        s->last_register_name = meta->name;
    }
    /// Pack a unique id with the kind in the top 4 bits, matching the
    /// shape host_api.h documents.
    const std::uint64_t kind_bits =
        static_cast<std::uint64_t>(kind) & 0xFu;
    *out_id = (kind_bits << 60) |
              (static_cast<std::uint64_t>(
                   s->register_calls.fetch_add(1) + 1) & 0x0FFFFFFFFFFFFFFFull);
    return GN_OK;
}

gn_result_t stub_unregister_vtable(void* host_ctx, std::uint64_t id) {
    auto* s = static_cast<StubHost*>(host_ctx);
    s->last_unregister_id = id;
    s->unregister_calls.fetch_add(1, std::memory_order_relaxed);
    return GN_OK;
}

void stub_log_emit(void* /*host_ctx*/, gn_log_level_t /*level*/,
                   const char* /*file*/, int32_t /*line*/,
                   const char* /*msg*/) {}

int32_t stub_is_shutdown_requested(void* /*host_ctx*/) { return 0; }

gn_result_t stub_notify_inbound_bytes(void* /*host_ctx*/,
                                      gn_conn_id_t /*conn*/,
                                      const uint8_t* /*bytes*/,
                                      size_t /*size*/) {
    return GN_OK;
}

host_api_t make_host_api(StubHost& s) {
    host_api_t api{};
    api.api_size = sizeof(host_api_t);
    api.host_ctx = &s;
    api.log.api_size           = sizeof(gn_log_api_t);
    api.log.emit               = &stub_log_emit;
    api.is_shutdown_requested  = &stub_is_shutdown_requested;
    api.notify_inbound_bytes   = &stub_notify_inbound_bytes;
    api.notify_connect         = &stub_notify_connect;
    api.notify_disconnect      = &stub_notify_disconnect;
    api.register_vtable        = &stub_register_vtable;
    api.unregister_vtable      = &stub_unregister_vtable;
    return api;
}

}  // namespace

/// `echo_connect` now calls `notify_connect` directly (the echo worker
/// has no real handshake, so the conn must materialise immediately).
/// Driving it through the proxy vtable exercises the kernel HOST_CALL
/// path for slot 0x13 end-to-end.
TEST(RemoteEchoSlots, ConnectRoundTripsNotifyConnect) {
    StubHost stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_echo_slot_test";
    ctx.kind        = GN_PLUGIN_KIND_LINK;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_host_api(stub), diag), GN_OK) << diag;

    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);

    const gn_link_vtable_t* vt = host.link_vtable_proxy();
    ASSERT_NE(vt, nullptr);
    ASSERT_NE(vt->connect, nullptr);
    ASSERT_NE(vt->send_batch, nullptr);

    ASSERT_EQ(vt->connect(static_cast<void*>(&host), "remote_echo://test"),
              GN_OK);
    EXPECT_EQ(stub.connect_calls.load(), 1);
    EXPECT_EQ(stub.last_connect_uri, "remote_echo://test");
    EXPECT_EQ(stub.last_connect_trust, GN_TRUST_LOOPBACK);
    EXPECT_EQ(stub.last_connect_role, GN_ROLE_INITIATOR);
}

/// `call_register` triggers the kernel-side auto-register of the link
/// proxy. The synthetic vtable's `send_batch` slot loops over each
/// frame; driving it confirms the proxy publishes a non-NULL pointer
/// for the slot and that the loop reaches the worker.
TEST(RemoteEchoSlots, SendBatchProxyRoundTrips) {
    StubHost stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_echo_slot_test";
    ctx.kind        = GN_PLUGIN_KIND_LINK;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_host_api(stub), diag), GN_OK) << diag;

    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);

    const gn_link_vtable_t* vt = host.link_vtable_proxy();
    ASSERT_NE(vt, nullptr);
    ASSERT_NE(vt->send_batch, nullptr);

    /// Each frame routes through the worker's `echo_send`, which feeds
    /// it back via `notify_inbound_bytes`. We don't capture payload
    /// content here — `LinkProxyEndToEndSendEchoes` already covers that
    /// — we only assert the batch loop reaches all entries without
    /// surfacing an error.
    const std::vector<std::uint8_t> a = {0x01, 0x02, 0x03};
    const std::vector<std::uint8_t> b = {0x10, 0x20};
    gn_byte_span_t spans[2] = {
        {a.data(), a.size()},
        {b.data(), b.size()}
    };
    EXPECT_EQ(vt->send_batch(static_cast<void*>(&host), 42, spans, 2), GN_OK);
}

/// `call_register` exercises both the kernel-side auto-register (which
/// publishes the synthesised link proxy under the worker's name) and
/// `call_unregister` (which mirrors it through `unregister_vtable`).
/// The stub captures every call so the test can assert the kernel
/// routed both directions.
TEST(RemoteEchoSlots, RegisterUnregisterRoundTrip) {
    StubHost stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_echo_slot_test";
    ctx.kind        = GN_PLUGIN_KIND_LINK;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_host_api(stub), diag), GN_OK) << diag;

    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);

    const std::uint64_t self_u =
        reinterpret_cast<std::uintptr_t>(self_handle);

    ASSERT_EQ(host.call_register(self_u), GN_OK);
    EXPECT_GE(stub.register_calls.load(), 1);
    EXPECT_EQ(stub.last_register_kind, GN_REGISTER_LINK);
    EXPECT_EQ(stub.last_register_name, "remote_echo");

    ASSERT_EQ(host.call_unregister(self_u), GN_OK);
    EXPECT_GE(stub.unregister_calls.load(), 1);
    EXPECT_NE(stub.last_unregister_id, 0u);
}
