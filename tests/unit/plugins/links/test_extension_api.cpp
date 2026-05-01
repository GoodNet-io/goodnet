/// @file   tests/unit/plugins/links/test_extension_api.cpp
/// @brief  `gn.link.<scheme>` extension API surface — every
///         baseline transport publishes the same vtable shape under
///         the convention prefix and the steady slots produce live
///         data; composer slots return the documented
///         `GN_ERR_NOT_IMPLEMENTED` so consumers get a deterministic
///         "not yet" signal rather than a NULL slot.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <span>

#include <core/kernel/kernel.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/registry/extension.hpp>

#include <plugins/links/ipc/ipc.hpp>
#include <plugins/links/tcp/tcp.hpp>
#include <plugins/links/udp/udp.hpp>

#include <sdk/extensions/link.h>
#include <sdk/types.h>

namespace {

using namespace gn::core;

/// In-tree fixture: stand up a kernel + a single PluginContext +
/// host_api_t whose register_* thunks publish to the kernel
/// registries. The plugin's transport class is instantiated here
/// and registered the same way `gn_plugin_register` would do it
/// inside a real plugin's macro-generated entry.
struct ExtensionFixture {
    Kernel               k;
    PluginContext        ctx;
    host_api_t           api{};

    ExtensionFixture() {
        ctx.kernel        = &k;
        ctx.kind          = GN_PLUGIN_KIND_LINK;
        ctx.plugin_name   = "fixture";
        ctx.plugin_anchor = std::make_shared<PluginAnchor>();
        api               = build_host_api(ctx);
    }
};

template <class T>
struct TransportInstance {
    std::shared_ptr<T>     transport;
    gn_link_caps_t    caps{};
    gn_link_api_t     ext_vtable{};
    gn_link_id_t      transport_id = GN_INVALID_ID;
    std::string            ext_name;

    explicit TransportInstance(ExtensionFixture& f, const std::string& scheme) {
        transport = std::make_shared<T>();
        transport->set_host_api(&f.api);
        caps      = T::capabilities();
        ext_name  = std::string{"gn.link."} + scheme;

        /// Set up an extension vtable that mimics the macro's layout.
        /// The fixture-side helpers below cast the `ctx` field back
        /// to this struct so the slots can reach the transport.
        ext_vtable               = gn_link_api_t{};
        ext_vtable.api_size      = sizeof(gn_link_api_t);
        ext_vtable.get_stats     = &TransportInstance::ext_get_stats;
        ext_vtable.get_capabilities = &TransportInstance::ext_get_caps;
        ext_vtable.send          = &TransportInstance::ext_send;
        ext_vtable.send_batch    = &TransportInstance::ext_send_batch;
        ext_vtable.close         = &TransportInstance::ext_close;
        ext_vtable.listen        = &TransportInstance::ext_unimpl_listen;
        ext_vtable.connect       = &TransportInstance::ext_unimpl_connect;
        ext_vtable.subscribe_data = &TransportInstance::ext_unimpl_subscribe;
        ext_vtable.unsubscribe_data = &TransportInstance::ext_unimpl_unsubscribe;
        ext_vtable.ctx           = this;

        EXPECT_EQ(f.api.register_extension(
            f.ctx.kernel ? &f.ctx : nullptr,
            ext_name.c_str(), GN_EXT_TRANSPORT_VERSION,
            &ext_vtable), GN_OK);
    }

    static gn_result_t ext_get_stats(void* c, gn_link_stats_t* out) {
        if (!c || !out) return GN_ERR_NULL_ARG;
        auto* self = static_cast<TransportInstance*>(c);
        auto s = self->transport->stats();
        std::memset(out, 0, sizeof(*out));
        out->bytes_in           = s.bytes_in;
        out->bytes_out          = s.bytes_out;
        out->frames_in          = s.frames_in;
        out->frames_out         = s.frames_out;
        out->active_connections = s.active_connections;
        return GN_OK;
    }
    static gn_result_t ext_get_caps(void* c, gn_link_caps_t* out) {
        if (!c || !out) return GN_ERR_NULL_ARG;
        *out = static_cast<TransportInstance*>(c)->caps;
        return GN_OK;
    }
    static gn_result_t ext_send(void* c, gn_conn_id_t conn,
                                 const std::uint8_t* b, std::size_t n) {
        if (!c) return GN_ERR_NULL_ARG;
        return static_cast<TransportInstance*>(c)->transport->send(
            conn, std::span<const std::uint8_t>(b, n));
    }
    static gn_result_t ext_send_batch(void*, gn_conn_id_t,
                                       const gn_byte_span_t*, std::size_t) {
        return GN_OK;  /// fixture path: no real batches
    }
    static gn_result_t ext_close(void* c, gn_conn_id_t conn, int) {
        if (!c) return GN_ERR_NULL_ARG;
        return static_cast<TransportInstance*>(c)->transport->disconnect(conn);
    }
    static gn_result_t ext_unimpl_listen(void*, const char*) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static gn_result_t ext_unimpl_connect(void*, const char*,
                                           gn_conn_id_t*) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static gn_result_t ext_unimpl_subscribe(void*, gn_conn_id_t,
                                             gn_link_data_callback_t,
                                             void*) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static gn_result_t ext_unimpl_unsubscribe(void*, gn_conn_id_t) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
};

template <class T>
const gn_link_api_t* lookup_extension(ExtensionFixture& f,
                                            const std::string& name) {
    const void* raw = nullptr;
    if (f.api.query_extension_checked(&f.ctx, name.c_str(),
                                       GN_EXT_TRANSPORT_VERSION,
                                       &raw) != GN_OK) {
        return nullptr;
    }
    return static_cast<const gn_link_api_t*>(raw);
}

} // namespace

TEST(TransportExtensionApi, TcpExposesStreamCapabilities) {
    ExtensionFixture f;
    TransportInstance<gn::link::tcp::TcpLink> tcp(f, "tcp");

    auto* api = lookup_extension<gn::link::tcp::TcpLink>(
        f, "gn.link.tcp");
    ASSERT_NE(api, nullptr);
    ASSERT_NE(api->get_capabilities, nullptr);

    gn_link_caps_t caps{};
    EXPECT_EQ(api->get_capabilities(api->ctx, &caps), GN_OK);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_STREAM);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_RELIABLE);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_ORDERED);
    EXPECT_FALSE(caps.flags & GN_LINK_CAP_DATAGRAM);
}

TEST(TransportExtensionApi, IpcAdvertisesLocalOnly) {
    ExtensionFixture f;
    TransportInstance<gn::link::ipc::IpcLink> ipc(f, "ipc");

    auto* api = lookup_extension<gn::link::ipc::IpcLink>(
        f, "gn.link.ipc");
    ASSERT_NE(api, nullptr);

    gn_link_caps_t caps{};
    ASSERT_EQ(api->get_capabilities(api->ctx, &caps), GN_OK);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_LOCAL_ONLY);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_STREAM);
}

TEST(TransportExtensionApi, UdpAdvertisesDatagram) {
    ExtensionFixture f;
    TransportInstance<gn::link::udp::UdpLink> udp(f, "udp");

    auto* api = lookup_extension<gn::link::udp::UdpLink>(
        f, "gn.link.udp");
    ASSERT_NE(api, nullptr);

    gn_link_caps_t caps{};
    ASSERT_EQ(api->get_capabilities(api->ctx, &caps), GN_OK);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_DATAGRAM);
    EXPECT_FALSE(caps.flags & GN_LINK_CAP_STREAM);
    EXPECT_GT(caps.max_payload, 0u)
        << "UDP must surface an MTU; 0 means unlimited which is wrong here";
}

TEST(TransportExtensionApi, ZeroStatsForBrandNewTransport) {
    /// The transport hasn't seen any traffic; every counter must be
    /// exactly zero. Useful for monitors that subtract baselines.
    ExtensionFixture f;
    TransportInstance<gn::link::tcp::TcpLink> tcp(f, "tcp");

    auto* api = lookup_extension<gn::link::tcp::TcpLink>(
        f, "gn.link.tcp");
    ASSERT_NE(api, nullptr);

    gn_link_stats_t stats{};
    EXPECT_EQ(api->get_stats(api->ctx, &stats), GN_OK);
    EXPECT_EQ(stats.bytes_in, 0u);
    EXPECT_EQ(stats.bytes_out, 0u);
    EXPECT_EQ(stats.frames_in, 0u);
    EXPECT_EQ(stats.frames_out, 0u);
    EXPECT_EQ(stats.active_connections, 0u);
}

TEST(TransportExtensionApi, ComposerSlotsReturnNotImplemented) {
    /// Slots reserved for L2 composition (WSS/TLS/ICE) must return
    /// `GN_ERR_NOT_IMPLEMENTED` deterministically until a composer
    /// plugin extends the contract — see `link.md` §8.
    ExtensionFixture f;
    TransportInstance<gn::link::tcp::TcpLink> tcp(f, "tcp");

    auto* api = lookup_extension<gn::link::tcp::TcpLink>(
        f, "gn.link.tcp");
    ASSERT_NE(api, nullptr);

    EXPECT_EQ(api->listen(api->ctx, "tcp://127.0.0.1:0"),
              GN_ERR_NOT_IMPLEMENTED);
    gn_conn_id_t out = GN_INVALID_ID;
    EXPECT_EQ(api->connect(api->ctx, "tcp://127.0.0.1:0", &out),
              GN_ERR_NOT_IMPLEMENTED);
    EXPECT_EQ(out, GN_INVALID_ID);
    EXPECT_EQ(api->subscribe_data(api->ctx, 1, nullptr, nullptr),
              GN_ERR_NOT_IMPLEMENTED);
    EXPECT_EQ(api->unsubscribe_data(api->ctx, 1),
              GN_ERR_NOT_IMPLEMENTED);
}

TEST(TransportExtensionApi, NullArgsRejected) {
    ExtensionFixture f;
    TransportInstance<gn::link::tcp::TcpLink> tcp(f, "tcp");

    auto* api = lookup_extension<gn::link::tcp::TcpLink>(
        f, "gn.link.tcp");
    ASSERT_NE(api, nullptr);

    EXPECT_EQ(api->get_stats(nullptr, nullptr), GN_ERR_NULL_ARG);
    gn_link_stats_t s{};
    EXPECT_EQ(api->get_stats(nullptr, &s), GN_ERR_NULL_ARG);
    EXPECT_EQ(api->get_stats(api->ctx, nullptr), GN_ERR_NULL_ARG);
}
