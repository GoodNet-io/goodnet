/// @file   tests/unit/kernel/test_register_vtable.cpp
/// @brief  `host_api->register_vtable` / `unregister_vtable`
///         argument validation, enum-tag rejection, and
///         kind-tag tampering on the returned id. Per
///         `host-api.md` §2 / `handler-registration.md` §2 /
///         `link.md` §6.

#include <gtest/gtest.h>

#include <cstring>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace {

using namespace gn::core;

struct Harness {
    Kernel        kernel;
    PluginContext plugin_ctx;
    host_api_t    api{};

    Harness() {
        plugin_ctx.plugin_name   = "register-vtable-test";
        plugin_ctx.kind          = GN_PLUGIN_KIND_HANDLER;
        plugin_ctx.kernel        = &kernel;
        plugin_ctx.plugin_anchor =
            std::make_shared<gn::core::PluginAnchor>();
        api = build_host_api(plugin_ctx);
    }

    static gn_propagation_t do_nothing(void*, const gn_message_t*) {
        return GN_PROPAGATION_CONSUMED;
    }

    [[nodiscard]] gn_handler_vtable_t make_handler_vtable() const {
        gn_handler_vtable_t vt{};
        vt.api_size       = sizeof(gn_handler_vtable_t);
        vt.handle_message = &do_nothing;
        return vt;
    }

    [[nodiscard]] gn_register_meta_t make_handler_meta(
        const char* name = "gnet-v1",
        std::uint32_t msg_id = 0x42,
        std::uint8_t priority = 128) const {
        gn_register_meta_t m{};
        m.api_size = sizeof(gn_register_meta_t);
        m.name     = name;
        m.msg_id   = msg_id;
        m.priority = priority;
        return m;
    }
};

}  // namespace

TEST(RegisterVtable, HandlerHappyPath) {
    Harness h;
    auto vt   = h.make_handler_vtable();
    auto meta = h.make_handler_meta();

    std::uint64_t id = 0;
    ASSERT_EQ(h.api.register_vtable(h.api.host_ctx, GN_REGISTER_HANDLER,
                                     &meta, &vt, nullptr, &id),
              GN_OK);
    EXPECT_NE(id, 0u);
    EXPECT_EQ(h.kernel.handlers().size(), 1u);

    /// The returned id carries the kind tag in its top 4 bits;
    /// `unregister_vtable(id)` decodes it and dispatches to
    /// `HandlerRegistry::unregister_handler` without naming
    /// the kind a second time.
    EXPECT_EQ(h.api.unregister_vtable(h.api.host_ctx, id), GN_OK);
    EXPECT_EQ(h.kernel.handlers().size(), 0u);
}

TEST(RegisterVtable, RejectsUnknownKind) {
    /// Every kind outside the declared enumerators must surface as
    /// `GN_ERR_INVALID_ENVELOPE` *before* any per-arg validation —
    /// even when args would otherwise trip NULL_ARG. This mirrors
    /// the thunk_subscribe / thunk_config_get convention.
    Harness h;

    std::uint64_t id = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    EXPECT_EQ(h.api.register_vtable(h.api.host_ctx,
                                     static_cast<gn_register_kind_t>(99),
                                     /*meta*/ nullptr,
                                     /*vtable*/ nullptr,
                                     nullptr, &id),
              GN_ERR_INVALID_ENVELOPE);
#pragma GCC diagnostic pop
    EXPECT_EQ(id, 0u);
}

TEST(RegisterVtable, RejectsNullMeta) {
    Harness h;
    auto vt = h.make_handler_vtable();

    std::uint64_t id = 0;
    EXPECT_EQ(h.api.register_vtable(h.api.host_ctx, GN_REGISTER_HANDLER,
                                     /*meta*/ nullptr, &vt, nullptr, &id),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(id, 0u);
}

TEST(RegisterVtable, RejectsApiSizeTooSmall) {
    /// An older SDK that built `gn_register_meta_t` with a smaller
    /// shape than the current kernel's view fails the size-prefix
    /// check from `abi-evolution.md` §3a.
    Harness h;
    auto vt   = h.make_handler_vtable();
    auto meta = h.make_handler_meta();
    meta.api_size = 4;  /// declares ancient SDK that predates the
                        /// minimum-accepted layout.

    std::uint64_t id = 0;
    EXPECT_EQ(h.api.register_vtable(h.api.host_ctx, GN_REGISTER_HANDLER,
                                     &meta, &vt, nullptr, &id),
              GN_ERR_VERSION_MISMATCH);
    EXPECT_EQ(id, 0u);
}

TEST(RegisterVtable, UnregisterRejectsTamperedKindTag) {
    /// The id encodes the kind in its top 4 bits. Flipping the tag
    /// to an unused kind must not match any real registration on
    /// either kernel registry — kernel returns `GN_ERR_NOT_FOUND`
    /// rather than silently unregistering the wrong record.
    Harness h;
    auto vt   = h.make_handler_vtable();
    auto meta = h.make_handler_meta();

    std::uint64_t id = 0;
    ASSERT_EQ(h.api.register_vtable(h.api.host_ctx, GN_REGISTER_HANDLER,
                                     &meta, &vt, nullptr, &id),
              GN_OK);

    constexpr std::uint64_t kKindMask = std::uint64_t{0xF} << 60;
    const std::uint64_t tampered =
        (id & ~kKindMask) | (std::uint64_t{3} << 60);
    EXPECT_EQ(h.api.unregister_vtable(h.api.host_ctx, tampered),
              GN_ERR_NOT_FOUND);

    /// The original record is still live: the real id unregisters
    /// cleanly without `GN_ERR_NOT_FOUND`.
    EXPECT_EQ(h.api.unregister_vtable(h.api.host_ctx, id), GN_OK);
}
