/// @file   tests/integration/test_inject_limits.cpp
/// @brief  Per-source rate limiter on the host_api inject paths.
///
/// Drives `inject(LAYER_MESSAGE)` and `inject(LAYER_FRAME)` through the
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
#include <tests/util/protocol_setup.hpp>
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
        gn::test::util::register_default_protocol(*kernel, proto);
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
        rec.scheme      = "test";
        /// Broadcast injection paths carry EXPLICIT_SENDER, which the
        /// `plugins/protocols/gnet/docs/wire-format.md` §5 relay-capability gate rejects on a
        /// regular peer connection. The test fixture grants relay
        /// capability so the rate-limiter is the only thing on the
        /// rejection path.
        rec.allows_relay     = true;
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

// ── inject (LAYER_MESSAGE) ───────────────────────────────────────────────

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

    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                                             kMsgId,
                                             payload, sizeof(payload)),
              GN_OK);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                                             kMsgId,
                                             payload, sizeof(payload)),
              GN_OK);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                                             kMsgId,
                                             payload, sizeof(payload)),
              GN_OK);

    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                                             kMsgId,
                                             payload, sizeof(payload)),
              GN_ERR_LIMIT_REACHED);
}

// ── inject (LAYER_FRAME) ─────────────────────────────────────────────────

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
    /// buffer feeds every inject FRAME call.
    const auto frame_bytes =
        make_broadcast_frame(*h.proto, peer_pk, /*msg_id*/ 0x42);
    ASSERT_FALSE(frame_bytes.empty());

    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_FRAME, source, 0,
                                  frame_bytes.data(), frame_bytes.size()),
              GN_OK);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_FRAME, source, 0,
                                  frame_bytes.data(), frame_bytes.size()),
              GN_OK);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_FRAME, source, 0,
                                  frame_bytes.data(), frame_bytes.size()),
              GN_OK);

    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_FRAME, source, 0,
                                  frame_bytes.data(), frame_bytes.size()),
              GN_ERR_LIMIT_REACHED);
}

// ── per-pk keyed bucket (host-api.md §8): a bridge that disconnects ──
// ── and re-opens the connection cannot skip the rate limit by ────────────
// ── acquiring a fresh `gn_conn_id_t` ─────────────────────────────────────

TEST(InjectLimits, PerPkBucketSurvivesConnReopen) {
    InjectHarness h;

    PublicKey peer_pk;
    peer_pk.fill(0xEF);
    const gn_conn_id_t first_source =
        h.install_source(peer_pk, "test://inject-reopen-1");

    /// Tight bucket: drain it through `first_source`.
    h.install_tight_bucket(/*rate*/ 0.0, /*burst*/ 3.0);

    const std::uint8_t payload[] = {0xAA};
    constexpr std::uint32_t kMsgId = 0x55;

    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, first_source,
                                             kMsgId, payload, sizeof(payload)),
              GN_OK);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, first_source,
                                             kMsgId, payload, sizeof(payload)),
              GN_OK);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, first_source,
                                             kMsgId, payload, sizeof(payload)),
              GN_OK);

    /// Simulate disconnect: erase the registry record. The peer's pk
    /// is unchanged — only the `gn_conn_id_t` is gone.
    EXPECT_EQ(h.kernel->connections().erase_with_index(first_source),
              GN_OK);

    /// Reopen under the same `peer_pk`. A bucket keyed on `conn_id`
    /// would now be a fresh, full bucket; the per-pk implementation
    /// must remember the drained state for this peer identity.
    const gn_conn_id_t second_source =
        h.install_source(peer_pk, "test://inject-reopen-2");
    ASSERT_NE(second_source, first_source)
        << "alloc_id is monotonic; reopened conn must not reuse the id";

    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, second_source,
                                             kMsgId, payload, sizeof(payload)),
              GN_ERR_LIMIT_REACHED)
        << "bucket keyed on remote_pk must persist across conn_id reuse";
}

// ── argument validation does not consume a token ─────────────────────────
//
// A rejected call (NULL_ARG, INVALID_ENVELOPE, PAYLOAD_TOO_LARGE,
// unknown layer enum) must surface its diagnostic without debiting
// the per-source bucket; otherwise a misbehaving plugin's own bad
// inputs become a DoS against legitimate inject traffic from the same
// source.

TEST(InjectLimits, ValidationFailureDoesNotConsumeToken) {
    InjectHarness h;
    PublicKey peer_pk;
    peer_pk.fill(0x77);
    const gn_conn_id_t source =
        h.install_source(peer_pk, "test://inject-noburn");

    /// Tight bucket: exactly three tokens, no refill.
    h.install_tight_bucket(/*rate*/ 0.0, /*burst*/ 3.0);

    /// Cap MESSAGE size to a value that the test deliberately exceeds.
    gn_limits_t lim{};
    lim.max_payload_bytes = 8;
    lim.max_frame_bytes   = 8;
    h.kernel->set_limits(lim);

    const std::vector<std::uint8_t> oversized(32, 0xAA);
    const std::uint8_t small[] = {1};
    constexpr std::uint32_t kMsgId = 0x42;

    /// Each rejected call below would silently drain the bucket if
    /// the kernel consumed a token before the validation branch.

    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                            /*msg_id=*/0, small, sizeof(small)),
              GN_ERR_INVALID_ENVELOPE);

    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                            kMsgId, oversized.data(), oversized.size()),
              GN_ERR_PAYLOAD_TOO_LARGE);

    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_FRAME, source, 0,
                            /*bytes=*/nullptr, 0),
              GN_ERR_NULL_ARG);

    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_FRAME, source, 0,
                            oversized.data(), oversized.size()),
              GN_ERR_PAYLOAD_TOO_LARGE);

    /// Out-of-range enum cast is the point of the assertion: the
    /// kernel must reject unknown layer values without consuming a
    /// token, so we deliberately ignore the analyzer's warning.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    EXPECT_EQ(h.api.inject(h.api.host_ctx,
                            static_cast<gn_inject_layer_t>(99),
                            source, kMsgId, small, sizeof(small)),
              GN_ERR_INVALID_ENVELOPE);
#pragma GCC diagnostic pop

    /// Restore generous size limits so the three valid sends below
    /// don't trip the size cap.
    gn_limits_t open{};
    open.max_payload_bytes = 1 << 20;
    open.max_frame_bytes   = 1 << 20;
    h.kernel->set_limits(open);

    /// Bucket must still hold three tokens. Three accepted calls
    /// drain it; the fourth surfaces GN_ERR_LIMIT_REACHED.
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                            kMsgId, small, sizeof(small)),
              GN_OK);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                            kMsgId, small, sizeof(small)),
              GN_OK);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                            kMsgId, small, sizeof(small)),
              GN_OK);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                            kMsgId, small, sizeof(small)),
              GN_ERR_LIMIT_REACHED);
}

// ── kernel without a protocol layer does not consume tokens ──────────────
//
// `inject` returns `GN_ERR_NOT_IMPLEMENTED` when no protocol layer is
// attached. The bucket must stay full so the kernel does not leak
// tokens against a misconfiguration.

TEST(InjectLimits, MissingProtocolLayerDoesNotConsumeToken) {
    /// Standalone harness that deliberately skips registering a
    /// protocol layer; the kernel surfaces NOT_IMPLEMENTED before
    /// the rate-limit bucket is consulted.
    Kernel kernel;
    PluginContext plugin_ctx;
    plugin_ctx.plugin_name = "inject-noproto-test";
    plugin_ctx.kind        = GN_PLUGIN_KIND_HANDLER;
    plugin_ctx.kernel      = &kernel;
    host_api_t api = build_host_api(plugin_ctx);

    PublicKey peer_pk;
    peer_pk.fill(0x88);
    const gn_conn_id_t source = kernel.connections().alloc_id();
    {
        ConnectionRecord rec;
        rec.id              = source;
        rec.remote_pk       = peer_pk;
        rec.uri             = "test://inject-noproto";
        rec.trust           = GN_TRUST_PEER;
        rec.role            = GN_ROLE_RESPONDER;
        rec.scheme     = "test";
        ASSERT_EQ(kernel.connections().insert_with_index(std::move(rec)),
                  GN_OK);
    }

    kernel.inject_rate_limiter().reset(/*rate*/ 0.0, /*burst*/ 1.0);

    const std::uint8_t payload[] = {0xCC};
    constexpr std::uint32_t kMsgId = 0x33;

    /// Exhaust nothing: the protocol layer is null, the kernel has to
    /// surface NOT_IMPLEMENTED before the bucket sees the call.
    EXPECT_EQ(api.inject(api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                          kMsgId, payload, sizeof(payload)),
              GN_ERR_NOT_IMPLEMENTED);

    /// Re-attach a protocol layer; the bucket must still hold its one
    /// token. If the previous call drained it, the next call surfaces
    /// LIMIT_REACHED — which fails this assertion.
    auto proto = std::make_shared<GnetProtocol>();
    gn::test::util::register_default_protocol(kernel, proto);
    EXPECT_EQ(api.inject(api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                          kMsgId, payload, sizeof(payload)),
              GN_OK);
}

// ── drop counters fire alongside per-cap rejections ───────────────────────
//
// Per `metrics.md` §3 every drop site bumps a `drop.<reason>` counter
// next to its structured warn line. The cap rejections in `inject`
// pair with `GN_DROP_PAYLOAD_TOO_LARGE` (MESSAGE), `GN_DROP_FRAME_TOO_LARGE`
// (FRAME), and the rate-limit branch with `GN_DROP_RATE_LIMITED`.

TEST(InjectLimits, MessagePayloadAboveCapBumpsDropCounter) {
    InjectHarness h;
    PublicKey peer_pk;
    peer_pk.fill(0x55);
    const gn_conn_id_t source =
        h.install_source(peer_pk, "test://inject-msg-cap");

    /// Tight cap so a small over-cap payload trips the check.
    gn_limits_t L = h.kernel->limits();
    L.max_payload_bytes = 16;
    h.kernel->set_limits(L);

    const std::vector<std::uint8_t> over_cap(64, 0xAA);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                            /*msg_id*/ 0x42,
                            over_cap.data(), over_cap.size()),
              GN_ERR_PAYLOAD_TOO_LARGE);
    EXPECT_EQ(h.kernel->metrics().value("drop.payload_too_large"), 1u);
}

TEST(InjectLimits, FrameAboveCapBumpsFrameTooLargeCounter) {
    InjectHarness h;
    PublicKey peer_pk;
    peer_pk.fill(0x66);
    const gn_conn_id_t source =
        h.install_source(peer_pk, "test://inject-frame-cap");

    gn_limits_t L = h.kernel->limits();
    L.max_frame_bytes = 16;
    h.kernel->set_limits(L);

    const std::vector<std::uint8_t> over_cap(64, 0xBB);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_FRAME, source,
                            /*msg_id*/ 0,
                            over_cap.data(), over_cap.size()),
              GN_ERR_PAYLOAD_TOO_LARGE);
    EXPECT_EQ(h.kernel->metrics().value("drop.frame_too_large"), 1u);
}

TEST(InjectLimits, RateLimitDropBumpsRateLimitedCounter) {
    InjectHarness h;
    PublicKey peer_pk;
    peer_pk.fill(0x77);
    const gn_conn_id_t source =
        h.install_source(peer_pk, "test://inject-rate-limit");

    /// Drain the bucket immediately — zero-rate refill, single burst
    /// token. The first inject succeeds; the second is the metric site.
    h.kernel->inject_rate_limiter().reset(/*rate*/ 0.0, /*burst*/ 1.0);

    const std::uint8_t payload[] = {0x42};
    constexpr std::uint32_t kMsgId = 0x99;

    ASSERT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                            kMsgId, payload, sizeof(payload)),
              GN_OK);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, source,
                            kMsgId, payload, sizeof(payload)),
              GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(h.kernel->metrics().value("drop.rate_limited"), 1u);
}
