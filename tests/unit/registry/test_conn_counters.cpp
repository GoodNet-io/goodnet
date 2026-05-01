/// @file   tests/unit/registry/test_conn_counters.cpp
/// @brief  Per-connection counter wiring on `ConnectionRegistry`.
///
/// `find_by_id` must reflect every `add_inbound` / `add_outbound`
/// / `set_pending_bytes` call. Counters allocated on insert and
/// reaped on erase. Calls on missing ids are silent no-ops.

#include <gtest/gtest.h>

#include <core/registry/connection.hpp>

#include <sdk/types.h>

using namespace gn::core;

namespace {

ConnectionRecord make_rec(gn_conn_id_t id, std::string_view uri,
                           std::uint8_t pk_byte) {
    ConnectionRecord r;
    r.id    = id;
    r.uri   = uri;
    r.trust = GN_TRUST_LOOPBACK;
    r.role  = GN_ROLE_RESPONDER;
    r.link_scheme = "tcp";
    r.remote_pk[0] = pk_byte;
    return r;
}

}  // namespace

TEST(ConnCounters, AddInboundShowsThroughFindById) {
    ConnectionRegistry r;
    ASSERT_EQ(r.insert_with_index(make_rec(1, "tcp://1", 0x01)), GN_OK);

    r.add_inbound(1, /*bytes=*/100, /*frames=*/2);
    r.add_inbound(1, /*bytes=*/50, /*frames=*/1);

    auto rec = r.find_by_id(1);
    ASSERT_TRUE(rec.has_value());
    if (rec.has_value()) {
        const auto& got = *rec;
        EXPECT_EQ(got.bytes_in, 150u);
        EXPECT_EQ(got.frames_in, 3u);
        EXPECT_EQ(got.bytes_out, 0u);
        EXPECT_EQ(got.frames_out, 0u);
    }
}

TEST(ConnCounters, AddOutboundIsSeparateFromInbound) {
    ConnectionRegistry r;
    ASSERT_EQ(r.insert_with_index(make_rec(7, "tcp://7", 0x07)), GN_OK);

    r.add_outbound(7, /*bytes=*/200, /*frames=*/1);
    r.add_inbound(7, /*bytes=*/64, /*frames=*/1);

    auto rec = r.find_by_id(7);
    ASSERT_TRUE(rec.has_value());
    if (rec.has_value()) {
        const auto& got = *rec;
        EXPECT_EQ(got.bytes_out, 200u);
        EXPECT_EQ(got.frames_out, 1u);
        EXPECT_EQ(got.bytes_in, 64u);
        EXPECT_EQ(got.frames_in, 1u);
    }
}

TEST(ConnCounters, SetPendingBytesIsAbsoluteNotAdditive) {
    ConnectionRegistry r;
    ASSERT_EQ(r.insert_with_index(make_rec(11, "tcp://11", 0x0B)), GN_OK);

    r.set_pending_bytes(11, 1024);
    r.set_pending_bytes(11, 512);

    auto rec = r.find_by_id(11);
    ASSERT_TRUE(rec.has_value());
    if (rec.has_value()) {
        EXPECT_EQ(rec->pending_queue_bytes, 512u)
            << "set_pending_bytes is a store, not a fetch_add";
    }
}

TEST(ConnCounters, EraseRemovesCounters) {
    ConnectionRegistry r;
    ASSERT_EQ(r.insert_with_index(make_rec(13, "tcp://13", 0x0D)), GN_OK);
    r.add_inbound(13, 99, 9);
    ASSERT_EQ(r.erase_with_index(13), GN_OK);

    /// Counter calls on a freshly-erased id silently no-op; the
    /// shard counters slot is gone.
    r.add_inbound(13, 5, 1);
    /// Re-insert under the same id and verify counters start fresh.
    ASSERT_EQ(r.insert_with_index(make_rec(13, "tcp://13", 0x0D)), GN_OK);
    auto rec = r.find_by_id(13);
    ASSERT_TRUE(rec.has_value());
    if (rec.has_value()) {
        EXPECT_EQ(rec->bytes_in, 0u);
        EXPECT_EQ(rec->frames_in, 0u);
    }
}

TEST(ConnCounters, NoOpOnMissingId) {
    ConnectionRegistry r;
    /// Calls on an id that was never inserted are silent —
    /// transports may publish stale counters during teardown
    /// races.
    r.add_inbound(42, 100, 1);
    r.add_outbound(42, 200, 2);
    r.set_pending_bytes(42, 1024);
    /// `find_by_id` of a missing id stays `nullopt`.
    EXPECT_FALSE(r.find_by_id(42).has_value());
}

TEST(ConnCounters, FindByPkPicksUpCounters) {
    /// `find_by_pk` chains into `find_by_id`, so counters surface
    /// through every alternate index too.
    ConnectionRegistry r;
    auto rec = make_rec(21, "tcp://21", 0x21);
    ASSERT_EQ(r.insert_with_index(rec), GN_OK);

    r.add_inbound(21, 333, 3);

    gn::PublicKey pk{};
    pk[0] = 0x21;
    auto via_pk = r.find_by_pk(pk);
    ASSERT_TRUE(via_pk.has_value());
    if (via_pk.has_value()) {
        EXPECT_EQ(via_pk->bytes_in, 333u);
        EXPECT_EQ(via_pk->frames_in, 3u);
    }
}
