/// @file   tests/integration/test_inject_limits.cpp
/// @brief  Per-source rate limiter on the host_api inject paths.
///
/// Drives `inject_external_message` and `inject_frame` through the
/// host_api thunks and verifies that the kernel's `inject_rate_limiter`
/// (per `host-api.md` §8) refuses traffic past the bucket budget with
/// `GN_ERR_LIMIT_REACHED`. The bucket is reconfigured to a tight,
/// non-refilling shape so the assertion runs deterministically under
/// sanitizer slowdown without depending on wall-clock timing.

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <core/kernel/connection_context.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/registry/connection.hpp>

#include <plugins/protocols/gnet/protocol.hpp>

#include <sdk/cpp/types.hpp>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace {

using namespace gn;
using namespace gn::core;
using namespace gn::plugins::gnet;

/// Kernel + GnetProtocol + handler-kind plugin context. Inject thunks
/// run as if invoked by a handler/bridge plugin per `host-api.md` §8.
struct InjectHarness {
    std::unique_ptr<Kernel>       kernel = std::make_unique<Kernel>();
    std::shared_ptr<GnetProtocol> proto  = std::make_shared<GnetProtocol>();
    PluginContext                 plugin_ctx;
    host_api_t                    api{};

    InjectHarness() {
        kernel->set_protocol_layer(proto);
        plugin_ctx.plugin_name = "inject-limits-test";
        plugin_ctx.kind        = GN_PLUGIN_KIND_HANDLER;
        plugin_ctx.kernel      = kernel.get();
        api = build_host_api(plugin_ctx);
    }

    /// Insert one connection record directly into the registry; the
    /// returned id is the source argument for inject_*. `notify_connect`
    /// is reserved for transport-kind plugins, so the registry is
    /// populated through its public mutator instead.
    [[nodiscard]] gn_conn_id_t install_source(const PublicKey&  remote_pk,
                                              std::string_view  uri) {
        const gn_conn_id_t id = kernel->connections().alloc_id();
        ConnectionRecord rec;
        rec.id               = id;
        rec.remote_pk        = remote_pk;
        rec.uri              = std::string(uri);
        rec.trust            = GN_TRUST_PEER;
        rec.role             = GN_ROLE_RESPONDER;
        rec.transport_scheme = "test";
        EXPECT_EQ(kernel->connections().insert_with_index(std::move(rec)),
                  GN_OK);
        return id;
    }

    /// Reconfigure the kernel's per-source inject limiter to a bucket
    /// of @p burst tokens with @p rate refill (tokens per second).
    /// `rate=0` makes the bucket non-refilling so the test sees the
    /// budget go from `burst` to zero across exactly `burst` calls.
    void install_tight_bucket(double rate, double burst) {
        kernel->inject_rate_limiter().reset(rate, burst);
    }
};

/// Build a broadcast-flagged GNET frame from @p sender_pk so the
/// deframer can decode it without a local identity on the receiver.
/// `frame()` requires a non-zero msg_id and sender_pk; ctx.local /
/// ctx.remote are unused on the broadcast path.
[[nodiscard]] std::vector<std::uint8_t>
make_broadcast_frame(GnetProtocol&     proto,
                     const PublicKey&  sender_pk,
                     std::uint32_t     msg_id) {
    gn_connection_context_t ctx{};
    gn_message_t msg{};
    msg.msg_id = msg_id;
    std::memcpy(msg.sender_pk, sender_pk.data(), GN_PUBLIC_KEY_BYTES);
    /// receiver_pk left zero → broadcast flag set by frame().
    msg.payload      = nullptr;
    msg.payload_size = 0;

    auto framed = proto.frame(ctx, msg);
    EXPECT_TRUE(framed.has_value());
    if (framed.has_value()) {
        return *framed;
    }
    return {};
}

}  // namespace

// ── inject_external_message ────────────────────────────────────────

TEST(InjectLimits, MessageInjectionHitsRateLimiter) {
    InjectHarness h;

    PublicKey peer_pk;
    peer_pk.fill(0xAB);
    const gn_conn_id_t source =
        h.install_source(peer_pk, "test://inject-msg");

    /// Tight bucket: three tokens, no refill. Three GN_OK calls drain
    /// the budget; the fourth must surface GN_ERR_LIMIT_REACHED.
    h.install_tight_bucket(/*rate*/ 0.0, /*burst*/ 3.0);

    const std::uint8_t payload[] = {0x01, 0x02, 0x03};
    constexpr std::uint32_t kMsgId = 0x77;

    EXPECT_EQ(h.api.inject_external_message(h.api.host_ctx, source,
                                             kMsgId,
                                             payload, sizeof(payload)),
              GN_OK);
    EXPECT_EQ(h.api.inject_external_message(h.api.host_ctx, source,
                                             kMsgId,
                                             payload, sizeof(payload)),
              GN_OK);
    EXPECT_EQ(h.api.inject_external_message(h.api.host_ctx, source,
                                             kMsgId,
                                             payload, sizeof(payload)),
              GN_OK);

    EXPECT_EQ(h.api.inject_external_message(h.api.host_ctx, source,
                                             kMsgId,
                                             payload, sizeof(payload)),
              GN_ERR_LIMIT_REACHED);
}

// ── inject_frame ───────────────────────────────────────────────────

TEST(InjectLimits, FrameInjectionHitsRateLimiter) {
    InjectHarness h;

    PublicKey peer_pk;
    peer_pk.fill(0xCD);
    const gn_conn_id_t source =
        h.install_source(peer_pk, "test://inject-frame");

    h.install_tight_bucket(/*rate*/ 0.0, /*burst*/ 3.0);

    /// A broadcast-flagged frame with the source connection's remote
    /// pk as sender — deframe succeeds without needing a local
    /// identity on the kernel. frame() runs once; the same byte
    /// buffer feeds every inject_frame call.
    const auto frame_bytes =
        make_broadcast_frame(*h.proto, peer_pk, /*msg_id*/ 0x42);
    ASSERT_FALSE(frame_bytes.empty());

    EXPECT_EQ(h.api.inject_frame(h.api.host_ctx, source,
                                  frame_bytes.data(), frame_bytes.size()),
              GN_OK);
    EXPECT_EQ(h.api.inject_frame(h.api.host_ctx, source,
                                  frame_bytes.data(), frame_bytes.size()),
              GN_OK);
    EXPECT_EQ(h.api.inject_frame(h.api.host_ctx, source,
                                  frame_bytes.data(), frame_bytes.size()),
              GN_OK);

    EXPECT_EQ(h.api.inject_frame(h.api.host_ctx, source,
                                  frame_bytes.data(), frame_bytes.size()),
              GN_ERR_LIMIT_REACHED);
}
