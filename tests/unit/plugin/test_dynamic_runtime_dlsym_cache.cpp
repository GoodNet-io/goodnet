/// @file   tests/unit/plugin/test_dynamic_runtime_dlsym_cache.cpp
/// @brief  DynamicRuntime caches gn_plugin_* pointers across dispatch.
///
/// Drives DynamicRuntime directly against the in-tree null security
/// provider .so. Walks the load → init → register → unregister →
/// shutdown sequence N times and asserts the runtime's lifetime
/// `dlsym` tally does not move past the load-time count.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <core/kernel/kernel.hpp>
#include <core/plugin/plugin_manager.hpp>
#include <core/plugin/plugin_manifest.hpp>
#include <core/plugin/remote_host.hpp>
#include <core/plugin/runtimes/dynamic.hpp>

#ifndef GOODNET_NULL_PLUGIN_PATH
#error "GOODNET_NULL_PLUGIN_PATH must be defined by the build system"
#endif

using namespace gn::core;

namespace {

PluginLoadContext make_ctx(Kernel& k, const PluginManifest& mf) {
    PluginLoadContext ctx{};
    ctx.kernel = &k;
    ctx.manifest = &mf;
    ctx.manifest_required = false;
    return ctx;
}

}  // namespace

TEST(DynamicRuntime_DlsymCache, ResolvesEverySymbolDuringLoad) {
    Kernel k;
    PluginManifest mf;
    DynamicRuntime rt;

    PluginInstance inst{};
    std::string diag;
    ASSERT_EQ(rt.load(GOODNET_NULL_PLUGIN_PATH, make_ctx(k, mf), inst, diag),
              GN_OK) << diag;

    EXPECT_NE(inst.symbols.sdk_version,     nullptr);
    EXPECT_NE(inst.symbols.init,            nullptr);
    EXPECT_NE(inst.symbols.register_self,   nullptr);
    EXPECT_NE(inst.symbols.unregister_self, nullptr);
    EXPECT_NE(inst.symbols.shutdown,        nullptr);

    rt.close(inst, /*drained=*/true);
}

TEST(DynamicRuntime_DlsymCache, RepeatedDispatchDoesNotReResolve) {
    Kernel k;
    PluginManifest mf;
    DynamicRuntime rt;

    PluginInstance inst{};
    std::string diag;
    ASSERT_EQ(rt.load(GOODNET_NULL_PLUGIN_PATH, make_ctx(k, mf), inst, diag),
              GN_OK) << diag;

    const auto after_load = rt.dlsym_call_count();
    /// `load` resolves six symbols (sdk_version, init, register,
    /// unregister, shutdown, descriptor); any value past the
    /// load-time figure on later dispatch means the cache leaked.
    EXPECT_EQ(after_load, 6u);

    ASSERT_EQ(rt.init(inst), GN_OK);
    ASSERT_EQ(rt.register_plugin(inst), GN_OK);

    constexpr int kCycles = 64;
    for (int i = 0; i < kCycles; ++i) {
        rt.unregister(inst);
        (void)rt.register_plugin(inst);
    }
    rt.unregister(inst);
    rt.shutdown(inst);

    EXPECT_EQ(rt.dlsym_call_count(), after_load)
        << "register/unregister/shutdown must hit the cached pointer; "
           "any growth past the load-time tally re-resolves symbols";

    rt.close(inst, /*drained=*/true);
}

TEST(DynamicRuntime_DlsymCache, CacheClearsOnDlclose) {
    Kernel k;
    PluginManifest mf;
    DynamicRuntime rt;

    PluginInstance inst{};
    std::string diag;
    ASSERT_EQ(rt.load(GOODNET_NULL_PLUGIN_PATH, make_ctx(k, mf), inst, diag),
              GN_OK) << diag;
    ASSERT_NE(inst.symbols.init, nullptr);

    rt.close(inst, /*drained=*/true);

    EXPECT_EQ(inst.symbols.init,            nullptr);
    EXPECT_EQ(inst.symbols.register_self,   nullptr);
    EXPECT_EQ(inst.symbols.unregister_self, nullptr);
    EXPECT_EQ(inst.symbols.shutdown,        nullptr);
    EXPECT_EQ(inst.symbols.sdk_version,     nullptr);
    EXPECT_EQ(inst.so_handle, nullptr);
}
