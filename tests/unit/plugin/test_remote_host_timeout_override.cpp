/// @file   tests/unit/plugin/test_remote_host_timeout_override.cpp
/// @brief  Per-slot reply-timeout override coverage for `RemoteHost`.
///
/// Coverage:
///   • `set_reply_timeout_for_slot` clamps the slot-specific wait
///     budget below the unscoped default — slow worker reply on the
///     overridden slot surfaces as a timeout.
///   • An override on one slot does not affect other slots — a
///     sibling slot continues to wait up to the unscoped budget.
///   • `clear_reply_timeout_overrides` restores the unscoped default.
///
/// The `remote_slow_stub` worker reads `GOODNET_SLOW_STUB_INIT_MS`
/// and `GOODNET_SLOW_STUB_REGISTER_MS` from the environment and
/// sleeps in `on_init` / `on_register` respectively.

#include <chrono>
#include <cstdlib>
#include <span>
#include <string>

#include <gtest/gtest.h>

#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/plugin.h>
#include <sdk/remote/slots.h>
#include <sdk/security.h>

#include <core/kernel/plugin_context.hpp>
#include <core/plugin/remote_host.hpp>

namespace {

const char* slow_worker_binary_path() {
    if (const char* env = std::getenv("GOODNET_REMOTE_SLOW_STUB_BINARY")) {
        return env;
    }
#ifdef GOODNET_REMOTE_SLOW_STUB_PATH
    return GOODNET_REMOTE_SLOW_STUB_PATH;
#else
    return "workers/remote_slow_stub";
#endif
}

struct StubHostState {
    int dummy = 0;
};

void stub_log_emit(void*, gn_log_level_t, const char*, int32_t, const char*) {}

int32_t stub_is_shutdown_requested(void*) { return 0; }

host_api_t make_stub_host_api(StubHostState& s) {
    host_api_t api{};
    api.api_size = sizeof(host_api_t);
    api.host_ctx = &s;
    api.log.api_size = sizeof(gn_log_api_t);
    api.log.emit = &stub_log_emit;
    api.is_shutdown_requested = &stub_is_shutdown_requested;
    return api;
}

class SlowStubScopedEnv {
public:
    SlowStubScopedEnv(const char* name, const char* value)
        : name_(name) {
        ::setenv(name_, value, 1);
    }
    ~SlowStubScopedEnv() { ::unsetenv(name_); }
    SlowStubScopedEnv(const SlowStubScopedEnv&) = delete;
    SlowStubScopedEnv& operator=(const SlowStubScopedEnv&) = delete;
private:
    const char* name_;
};

}  // namespace

TEST(RemoteHostTimeoutOverride, OverrideAppliedToSlot) {
    SlowStubScopedEnv reg_sleep("GOODNET_SLOW_STUB_REGISTER_MS", "400");

    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_slow_stub_test";
    ctx.kind        = GN_PLUGIN_KIND_LINK;

    gn::core::RemoteHost host;
    host.set_reply_timeout(std::chrono::seconds{5});
    host.set_reply_timeout_for_slot(
        static_cast<std::uint16_t>(GN_WIRE_SLOT_PLUGIN_REGISTER),
        std::chrono::milliseconds{100});

    std::string diag;
    ASSERT_EQ(host.spawn(slow_worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag), GN_OK) << diag;

    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);

    const auto t0 = std::chrono::steady_clock::now();
    const gn_result_t rc =
        host.call_register(reinterpret_cast<std::uintptr_t>(self_handle));
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    EXPECT_NE(rc, GN_OK);
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed),
              std::chrono::milliseconds{350});
}

TEST(RemoteHostTimeoutOverride, OverrideDoesNotAffectOtherSlots) {
    SlowStubScopedEnv init_sleep("GOODNET_SLOW_STUB_INIT_MS", "200");

    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_slow_stub_test";
    ctx.kind        = GN_PLUGIN_KIND_LINK;

    gn::core::RemoteHost host;
    host.set_reply_timeout(std::chrono::seconds{5});
    host.set_reply_timeout_for_slot(
        static_cast<std::uint16_t>(GN_WIRE_SLOT_PLUGIN_REGISTER),
        std::chrono::milliseconds{50});

    std::string diag;
    ASSERT_EQ(host.spawn(slow_worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag), GN_OK) << diag;

    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);
    EXPECT_NE(self_handle, nullptr);
}

TEST(RemoteHostTimeoutOverride, ClearRemovesOverride) {
    SlowStubScopedEnv reg_sleep("GOODNET_SLOW_STUB_REGISTER_MS", "200");

    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_slow_stub_test";
    ctx.kind        = GN_PLUGIN_KIND_LINK;

    gn::core::RemoteHost host;
    host.set_reply_timeout(std::chrono::seconds{5});
    host.set_reply_timeout_for_slot(
        static_cast<std::uint16_t>(GN_WIRE_SLOT_PLUGIN_REGISTER),
        std::chrono::milliseconds{50});
    host.clear_reply_timeout_overrides();

    std::string diag;
    ASSERT_EQ(host.spawn(slow_worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(stub), diag), GN_OK) << diag;

    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);
    ASSERT_EQ(host.call_register(reinterpret_cast<std::uintptr_t>(self_handle)),
              GN_OK);
}
