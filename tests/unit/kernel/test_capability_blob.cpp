/// @file   tests/unit/kernel/test_capability_blob.cpp
/// @brief  CapabilityBlobBus unit tests — subscribe / unsubscribe /
///         on_inbound fan-out invariants.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <vector>

#include <core/kernel/capability_blob.hpp>

using gn::core::CapabilityBlobBus;

namespace {

/// Per-test capture state — counts, last payload, last conn,
/// destructor signal.
struct Capture {
    std::atomic<int>          calls{0};
    std::atomic<int>          destructors{0};
    gn_conn_id_t              last_conn = GN_INVALID_ID;
    std::int64_t              last_expires = 0;
    std::vector<std::uint8_t> last_blob;
};

void on_blob(void* user_data, gn_conn_id_t conn,
              const std::uint8_t* blob, std::size_t size,
              std::int64_t expires) {
    auto* c = static_cast<Capture*>(user_data);
    c->calls.fetch_add(1);
    c->last_conn    = conn;
    c->last_expires = expires;
    c->last_blob.assign(blob, blob + size);
}

void on_destroy(void* user_data) {
    auto* c = static_cast<Capture*>(user_data);
    c->destructors.fetch_add(1);
}

/// Compose a wire payload: 8-byte BE expiry prefix + blob.
std::vector<std::uint8_t> wire(std::int64_t expires,
                                std::span<const std::uint8_t> blob) {
    std::vector<std::uint8_t> out(8 + blob.size());
    const auto u = static_cast<std::uint64_t>(expires);
    out[0] = static_cast<std::uint8_t>((u >> 56) & 0xFFu);
    out[1] = static_cast<std::uint8_t>((u >> 48) & 0xFFu);
    out[2] = static_cast<std::uint8_t>((u >> 40) & 0xFFu);
    out[3] = static_cast<std::uint8_t>((u >> 32) & 0xFFu);
    out[4] = static_cast<std::uint8_t>((u >> 24) & 0xFFu);
    out[5] = static_cast<std::uint8_t>((u >> 16) & 0xFFu);
    out[6] = static_cast<std::uint8_t>((u >>  8) & 0xFFu);
    out[7] = static_cast<std::uint8_t>( u        & 0xFFu);
    std::memcpy(out.data() + 8, blob.data(), blob.size());
    return out;
}

}  // namespace

// ── Subscribe / fan-out roundtrip ────────────────────────────────────────

TEST(CapabilityBlobBus, FanOutToOneSubscriberDecodesPrefix) {
    CapabilityBlobBus bus;
    Capture cap;
    const auto id = bus.subscribe(&on_blob, &cap, &on_destroy);
    ASSERT_NE(id, GN_INVALID_SUBSCRIPTION_ID);

    const std::uint8_t blob[] = {0xDE, 0xAD, 0xBE, 0xEF};
    auto payload = wire(/*expires*/ 1234567890,
                        std::span<const std::uint8_t>(blob));
    bus.on_inbound(/*from_conn*/ 7, payload.data(), payload.size());

    EXPECT_EQ(cap.calls.load(), 1);
    EXPECT_EQ(cap.last_conn, 7u);
    EXPECT_EQ(cap.last_expires, 1234567890);
    ASSERT_EQ(cap.last_blob.size(), 4u);
    EXPECT_EQ(cap.last_blob[0], 0xDE);
    EXPECT_EQ(cap.last_blob[3], 0xEF);
    EXPECT_EQ(bus.subscriber_count(), 1u);

    EXPECT_TRUE(bus.unsubscribe(id));
    EXPECT_EQ(cap.destructors.load(), 1);
    EXPECT_EQ(bus.subscriber_count(), 0u);
}

TEST(CapabilityBlobBus, FanOutToMultipleSubscribersAllReceive) {
    CapabilityBlobBus bus;
    Capture a;
    Capture b;
    const auto id_a = bus.subscribe(&on_blob, &a, &on_destroy);
    const auto id_b = bus.subscribe(&on_blob, &b, &on_destroy);
    ASSERT_NE(id_a, GN_INVALID_SUBSCRIPTION_ID);
    ASSERT_NE(id_b, GN_INVALID_SUBSCRIPTION_ID);

    const std::uint8_t blob[] = {1, 2, 3};
    auto payload = wire(42,
                        std::span<const std::uint8_t>(blob));
    bus.on_inbound(/*from_conn*/ 99, payload.data(), payload.size());

    EXPECT_EQ(a.calls.load(), 1);
    EXPECT_EQ(b.calls.load(), 1);
    EXPECT_EQ(a.last_expires, 42);
    EXPECT_EQ(b.last_expires, 42);
}

TEST(CapabilityBlobBus, ShortPayloadDropped) {
    CapabilityBlobBus bus;
    Capture cap;
    [[maybe_unused]] const auto id =
        bus.subscribe(&on_blob, &cap, &on_destroy);

    /// Payload shorter than the 8-byte expiry prefix is dropped
    /// silently; subscribers see no event.
    const std::uint8_t too_short[] = {0, 1, 2, 3};
    bus.on_inbound(1, too_short, sizeof(too_short));
    EXPECT_EQ(cap.calls.load(), 0);
}

TEST(CapabilityBlobBus, UnsubscribeMissingReturnsFalse) {
    CapabilityBlobBus bus;
    EXPECT_FALSE(bus.unsubscribe(static_cast<gn_subscription_id_t>(42)));
}

TEST(CapabilityBlobBus, DestructorRunsLeftoverDestroyers) {
    Capture cap;
    {
        CapabilityBlobBus bus;
        [[maybe_unused]] const auto id =
            bus.subscribe(&on_blob, &cap, &on_destroy);
        /// Bus goes out of scope without unsubscribe — destructor
        /// must still run the destroyer so the plugin's
        /// `user_data` doesn't leak.
    }
    EXPECT_EQ(cap.destructors.load(), 1);
}
