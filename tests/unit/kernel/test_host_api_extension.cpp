/// @file   tests/unit/kernel/test_host_api_extension.cpp
/// @brief  ext_provides prefix gate and unregister ownership (W8).

#include <gtest/gtest.h>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/host_api.h>
#include <sdk/types.h>

using gn::core::Kernel;
using gn::core::PluginContext;
using gn::core::build_host_api;

namespace {

const int kVtable = 0;

struct ExtHarness {
    Kernel      kernel;
    PluginContext ctx;
    host_api_t  api{};

    explicit ExtHarness(std::vector<std::string> provides = {}) {
        ctx.plugin_name  = "test-plugin";
        ctx.kind         = GN_PLUGIN_KIND_HANDLER;
        ctx.kernel       = &kernel;
        ctx.ext_provides = std::move(provides);
        api = build_host_api(ctx);
    }
};

}  // namespace

TEST(HostApiExtension, EmptyExtProvidesBlocksNonUnknownKind) {
    ExtHarness h;
    EXPECT_EQ(h.api.register_extension(h.api.host_ctx,
                                        "gn.anything", 0x010000, &kVtable),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(HostApiExtension, UnknownKindBypassesExtProvidesGate) {
    Kernel kernel;
    PluginContext ctx;
    ctx.plugin_name = "operator";
    ctx.kind        = GN_PLUGIN_KIND_UNKNOWN;
    ctx.kernel      = &kernel;
    auto api = build_host_api(ctx);
    EXPECT_EQ(api.register_extension(api.host_ctx,
                                      "gn.anything", 0x010000, &kVtable),
              GN_OK);
}

TEST(HostApiExtension, DeclaredPrefixAllowsExactName) {
    ExtHarness h({"gn.heartbeat"});
    EXPECT_EQ(h.api.register_extension(h.api.host_ctx,
                                        "gn.heartbeat", 0x010000, &kVtable),
              GN_OK);
}

TEST(HostApiExtension, DeclaredPrefixAllowsSuffixedName) {
    ExtHarness h({"gn.link."});
    EXPECT_EQ(h.api.register_extension(h.api.host_ctx,
                                        "gn.link.ice", 0x010000, &kVtable),
              GN_OK);
}

TEST(HostApiExtension, UndeclaredNameRejected) {
    ExtHarness h({"gn.heartbeat"});
    EXPECT_EQ(h.api.register_extension(h.api.host_ctx,
                                        "gn.link.ice", 0x010000, &kVtable),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(HostApiExtension, NonOwnerCannotUnregister) {
    Kernel kernel;

    PluginContext ctx_a;
    ctx_a.plugin_name  = "plugin-a";
    ctx_a.kind         = GN_PLUGIN_KIND_HANDLER;
    ctx_a.kernel       = &kernel;
    ctx_a.ext_provides = {"gn.heartbeat"};
    auto api_a = build_host_api(ctx_a);

    PluginContext ctx_b;
    ctx_b.plugin_name  = "plugin-b";
    ctx_b.kind         = GN_PLUGIN_KIND_HANDLER;
    ctx_b.kernel       = &kernel;
    auto api_b = build_host_api(ctx_b);

    ASSERT_EQ(api_a.register_extension(api_a.host_ctx,
                                        "gn.heartbeat", 0x010000, &kVtable),
              GN_OK);
    EXPECT_EQ(api_b.unregister_extension(api_b.host_ctx, "gn.heartbeat"),
              GN_ERR_NOT_FOUND);
    EXPECT_EQ(api_a.unregister_extension(api_a.host_ctx, "gn.heartbeat"),
              GN_OK);
}
