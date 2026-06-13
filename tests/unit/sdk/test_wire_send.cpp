/// @file   tests/unit/sdk/test_wire_send.cpp
/// @brief  Covers `gn::sdk::wire_send<Schema>` and the `GN_SEND` macro.
///
/// Pins:
///   1. Type-safe dispatch: `Schema::msg_id` and `Schema::serialize` called.
///   2. Correct bytes forwarded to `host_api->send`.
///   3. Null `api` guard returns `GN_ERR_NULL_ARG`.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>

#include <sdk/cpp/send.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace {

// ── Minimal schema ──────────────────────────────────────────────────────────

struct PingValue {
    std::uint32_t seq;
};

struct PingSchema {
    using value_type = PingValue;
    static constexpr std::uint32_t msg_id = 0x55AA;
    static constexpr std::size_t   size   = 4;

    static std::array<std::uint8_t, size> serialize(const value_type& v) noexcept {
        std::array<std::uint8_t, 4> out{};
        out[0] = static_cast<std::uint8_t>((v.seq >> 24) & 0xFF);
        out[1] = static_cast<std::uint8_t>((v.seq >> 16) & 0xFF);
        out[2] = static_cast<std::uint8_t>((v.seq >>  8) & 0xFF);
        out[3] = static_cast<std::uint8_t>((v.seq      ) & 0xFF);
        return out;
    }

    static std::optional<value_type>
    parse(std::span<const std::uint8_t> b) noexcept {
        if (b.size() != 4) return std::nullopt;
        return PingValue{
            (std::uint32_t(b[0]) << 24) | (std::uint32_t(b[1]) << 16) |
            (std::uint32_t(b[2]) <<  8) |  std::uint32_t(b[3])
        };
    }
};

static_assert(gn::wire::WireSchema<PingSchema>);

// ── Stub host_api ───────────────────────────────────────────────────────────

struct SendCapture {
    gn_conn_id_t              last_conn   = GN_INVALID_ID;
    std::uint32_t             last_msg_id = 0;
    std::vector<std::uint8_t> last_payload;
    int                       call_count  = 0;
};

host_api_t make_stub_api(SendCapture* cap) {
    host_api_t api{};
    api.host_ctx = cap;
    api.send = [](void* ctx, gn_conn_id_t conn, std::uint32_t msg_id,
                   const uint8_t* data, size_t size) -> gn_result_t {
        auto* c = static_cast<SendCapture*>(ctx);
        c->last_conn   = conn;
        c->last_msg_id = msg_id;
        c->last_payload.assign(data, data + size);
        c->call_count++;
        return GN_OK;
    };
    return api;
}

// ── Tests ───────────────────────────────────────────────────────────────────

TEST(WireSend, ForwardsCorrectMsgIdAndPayload) {
    SendCapture cap;
    host_api_t  api = make_stub_api(&cap);
    const gn_conn_id_t conn{42};

    const PingValue ping{0xDEADBEEF};
    ASSERT_EQ(gn::sdk::wire_send<PingSchema>(&api, conn, ping), GN_OK);

    EXPECT_EQ(cap.call_count,   1);
    EXPECT_EQ(cap.last_conn,    conn);
    EXPECT_EQ(cap.last_msg_id,  PingSchema::msg_id);

    ASSERT_EQ(cap.last_payload.size(), 4u);
    auto parsed = PingSchema::parse(std::span{cap.last_payload});
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->seq, ping.seq);
}

TEST(WireSend, NullApiReturnsNullArg) {
    const PingValue ping{1};
    EXPECT_EQ(gn::sdk::wire_send<PingSchema>(nullptr, gn_conn_id_t{1}, ping),
              GN_ERR_NULL_ARG);
}

TEST(WireSend, GnSendMacroCallsCheckedSend) {
    SendCapture cap;
    host_api_t  api = make_stub_api(&cap);
    const gn_conn_id_t conn{7};

    const PingValue ping{0x1234};
    ASSERT_EQ(GN_SEND(&api, conn, PingSchema, ping), GN_OK);

    EXPECT_EQ(cap.call_count,  1);
    EXPECT_EQ(cap.last_msg_id, PingSchema::msg_id);
}

} // namespace
