/// @file   tests/unit/util/test_convenience.cpp
/// @brief  Compile-time + smoke tests for `sdk/cpp/convenience.hpp`.
///
/// The header is the C++ analog of `sdk/convenience.h`'s C macros.
/// The test ensures every helper signature is callable through the
/// fixture and returns `GN_OK` for the no-op shape — full behavioural
/// coverage of the underlying thunks lives in the per-feature test
/// files; this one exists to catch a header-shape regression without
/// pulling in the kernel.

#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <vector>

#include <sdk/cpp/convenience.hpp>

namespace {

/// Stub host_api that records every call. The fixture binds a single
/// member function pointer per slot; the helpers must reach the
/// matching slot through `host_ctx`.
struct StubHost {
    int send_calls         = 0;
    int disconnect_calls   = 0;
    int register_calls     = 0;
    int unregister_calls   = 0;
    int find_pk_calls      = 0;
    int get_endpoint_calls = 0;
    int config_get_calls   = 0;
    int limits_calls       = 0;
    int inject_calls       = 0;
    int register_ext_calls = 0;
    int query_ext_calls    = 0;

    /// Last `kind` passed to `register_vtable`, so the fixture can
    /// confirm the helper steered it to handler vs link.
    gn_register_kind_t last_register_kind = GN_REGISTER_HANDLER;

    static gn_result_t s_send(void* ctx, gn_conn_id_t,
                               std::uint32_t,
                               const std::uint8_t*, std::size_t) {
        static_cast<StubHost*>(ctx)->send_calls++;
        return GN_OK;
    }
    static gn_result_t s_disconnect(void* ctx, gn_conn_id_t) {
        static_cast<StubHost*>(ctx)->disconnect_calls++;
        return GN_OK;
    }
    static gn_result_t s_register(void* ctx, gn_register_kind_t kind,
                                   const gn_register_meta_t*,
                                   const void*, void*,
                                   std::uint64_t* out_id) {
        auto* h = static_cast<StubHost*>(ctx);
        h->register_calls++;
        h->last_register_kind = kind;
        if (out_id) *out_id = 42;
        return GN_OK;
    }
    static gn_result_t s_unregister(void* ctx, std::uint64_t) {
        static_cast<StubHost*>(ctx)->unregister_calls++;
        return GN_OK;
    }
    static gn_result_t s_find_pk(void* ctx,
                                   const std::uint8_t[GN_PUBLIC_KEY_BYTES],
                                   gn_conn_id_t* out) {
        static_cast<StubHost*>(ctx)->find_pk_calls++;
        if (out) *out = 7;
        return GN_OK;
    }
    static gn_result_t s_get_endpoint(void* ctx, gn_conn_id_t,
                                        gn_endpoint_t*) {
        static_cast<StubHost*>(ctx)->get_endpoint_calls++;
        return GN_OK;
    }
    static gn_result_t s_config_get(void* ctx, const char*,
                                     gn_config_value_type_t,
                                     std::size_t, void*, void**,
                                     void (**)(void*, void*)) {
        static_cast<StubHost*>(ctx)->config_get_calls++;
        return GN_OK;
    }
    static const gn_limits_t* s_limits(void* ctx) {
        static_cast<StubHost*>(ctx)->limits_calls++;
        static gn_limits_t L{};
        return &L;
    }
    static gn_result_t s_inject(void* ctx, gn_inject_layer_t,
                                  gn_conn_id_t, std::uint32_t,
                                  const std::uint8_t*, std::size_t) {
        static_cast<StubHost*>(ctx)->inject_calls++;
        return GN_OK;
    }
    static gn_result_t s_register_ext(void* ctx, const char*,
                                        std::uint32_t, const void*) {
        static_cast<StubHost*>(ctx)->register_ext_calls++;
        return GN_OK;
    }
    static gn_result_t s_query_ext(void* ctx, const char*,
                                     std::uint32_t, const void** out_vt) {
        static_cast<StubHost*>(ctx)->query_ext_calls++;
        if (out_vt) *out_vt = nullptr;
        return GN_OK;
    }

    host_api_t make_api() {
        host_api_t a{};
        a.api_size                  = sizeof(host_api_t);
        a.host_ctx                  = this;
        a.send                      = &s_send;
        a.disconnect                = &s_disconnect;
        a.register_vtable           = &s_register;
        a.unregister_vtable         = &s_unregister;
        a.find_conn_by_pk           = &s_find_pk;
        a.get_endpoint              = &s_get_endpoint;
        a.config_get                = &s_config_get;
        a.limits                    = &s_limits;
        a.inject                    = &s_inject;
        a.register_extension        = &s_register_ext;
        a.query_extension_checked   = &s_query_ext;
        return a;
    }
};

}  // namespace

TEST(SdkCppConvenience, MessagingForwardsToHostCtx) {
    StubHost h;
    auto api = h.make_api();

    const std::uint8_t bytes[] = {1, 2, 3};
    EXPECT_EQ(gn::send(&api, /*conn=*/1, /*msg_id=*/0xBEEF,
                        std::span<const std::uint8_t>(bytes)),
              GN_OK);
    EXPECT_EQ(gn::disconnect(&api, /*conn=*/1), GN_OK);
    EXPECT_EQ(h.send_calls, 1);
    EXPECT_EQ(h.disconnect_calls, 1);
}

TEST(SdkCppConvenience, RegisterRoutesByKind) {
    StubHost h;
    auto api = h.make_api();

    gn_handler_id_t hid = GN_INVALID_ID;
    EXPECT_EQ(gn::register_handler(&api, "gnet-v1", /*msg_id=*/0xBEEF,
                                     /*priority=*/128,
                                     /*vtable=*/nullptr, /*self=*/nullptr,
                                     &hid),
              GN_OK);
    EXPECT_EQ(h.last_register_kind, GN_REGISTER_HANDLER);

    gn_link_id_t lid = GN_INVALID_ID;
    EXPECT_EQ(gn::register_link(&api, "tcp",
                                  /*vtable=*/nullptr, /*self=*/nullptr,
                                  &lid),
              GN_OK);
    EXPECT_EQ(h.last_register_kind, GN_REGISTER_LINK);

    EXPECT_EQ(gn::unregister_handler(&api, hid), GN_OK);
    EXPECT_EQ(gn::unregister_link(&api, lid), GN_OK);
    EXPECT_EQ(h.register_calls, 2);
    EXPECT_EQ(h.unregister_calls, 2);
}

TEST(SdkCppConvenience, ConfigGetTypedSlots) {
    StubHost h;
    auto api = h.make_api();

    std::int64_t i64 = 0;
    EXPECT_EQ(gn::config_get_int64(&api, "k.i", &i64), GN_OK);
    std::int32_t b = 0;
    EXPECT_EQ(gn::config_get_bool(&api, "k.b", &b), GN_OK);
    double d = 0.0;
    EXPECT_EQ(gn::config_get_double(&api, "k.d", &d), GN_OK);
    std::size_t n = 0;
    EXPECT_EQ(gn::config_get_array_size(&api, "k.arr", &n), GN_OK);

    char* str = nullptr;
    void* ud  = nullptr;
    void (*fr)(void*, void*) = nullptr;
    EXPECT_EQ(gn::config_get_string(&api, "k.s", &str, &ud, &fr), GN_OK);

    EXPECT_EQ(h.config_get_calls, 5);
}

TEST(SdkCppConvenience, ExtensionTypedQueryReturnsNullOnMiss) {
    StubHost h;
    auto api = h.make_api();

    /// The stub's query writes nullptr; the typed wrapper returns
    /// nullptr accordingly. A real consumer would compare the result
    /// before dereferencing.
    struct FakeApi { uint32_t api_size; };
    const FakeApi* result = gn::query_extension_typed<FakeApi>(
        &api, "fake", /*version=*/1u);
    EXPECT_EQ(result, nullptr);
    EXPECT_EQ(h.query_ext_calls, 1);
}

TEST(SdkCppConvenience, InjectForwardsLayerKind) {
    StubHost h;
    auto api = h.make_api();

    const std::uint8_t bytes[] = {0xAA};
    EXPECT_EQ(gn::inject_external_message(&api, /*source=*/3,
                                            /*msg_id=*/0xC0DE,
                                            std::span<const std::uint8_t>(bytes)),
              GN_OK);
    EXPECT_EQ(gn::inject_frame(&api, /*source=*/3,
                                 std::span<const std::uint8_t>(bytes)),
              GN_OK);
    EXPECT_EQ(h.inject_calls, 2);
}
