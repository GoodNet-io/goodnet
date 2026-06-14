/// @file   tests/unit/security/test_noise_reorder.cpp
/// @brief  InlineCrypto datagram mode: sliding window replay protection.

#include <gtest/gtest.h>

#include <core/security/inline_crypto.hpp>

#include <sdk/security.h>
#include <sdk/types.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

using gn::core::InlineCrypto;
using gn::core::ReplayWindow;

gn_handshake_keys_t make_keys(std::uint8_t send_fill,
                               std::uint8_t recv_fill,
                               std::uint64_t initial_send = 0,
                               std::uint64_t initial_recv = 0) noexcept {
    gn_handshake_keys_t k{};
    k.api_size = sizeof(k);
    std::memset(k.send_cipher_key, send_fill, GN_CIPHER_KEY_BYTES);
    std::memset(k.recv_cipher_key, recv_fill, GN_CIPHER_KEY_BYTES);
    k.initial_send_nonce = initial_send;
    k.initial_recv_nonce = initial_recv;
    return k;
}

struct DatagramPair {
    InlineCrypto alice;
    InlineCrypto bob;

    DatagramPair() {
        alice.enable_datagram_mode();
        bob.enable_datagram_mode();
        auto k = make_keys(0x55, 0xAA);
        EXPECT_TRUE(alice.seed(k));
        auto k2 = make_keys(0xAA, 0x55);
        EXPECT_TRUE(bob.seed(k2));
    }
};

}  // namespace

TEST(ReplayWindow, AcceptsSequentialNonces) {
    ReplayWindow w;
    for (std::uint64_t n = 0; n < 200; ++n) {
        EXPECT_TRUE(w.check_and_record(n)) << "nonce=" << n;
    }
}

TEST(ReplayWindow, RejectsReplays) {
    ReplayWindow w;
    EXPECT_TRUE(w.check_and_record(5));
    EXPECT_FALSE(w.check_and_record(5));
    EXPECT_TRUE(w.check_and_record(6));
    EXPECT_FALSE(w.check_and_record(6));
    EXPECT_FALSE(w.check_and_record(5));
}

TEST(ReplayWindow, AcceptsOOOWithinWindow) {
    ReplayWindow w;
    EXPECT_TRUE(w.check_and_record(10));
    EXPECT_TRUE(w.check_and_record(7));
    EXPECT_TRUE(w.check_and_record(9));
    EXPECT_TRUE(w.check_and_record(8));
    EXPECT_FALSE(w.check_and_record(7));
    EXPECT_FALSE(w.check_and_record(9));
}

TEST(ReplayWindow, RejectsTooOld) {
    ReplayWindow w;
    w.check_and_record(100);
    EXPECT_FALSE(w.check_and_record(0));
    EXPECT_FALSE(w.check_and_record(35));
    EXPECT_TRUE(w.check_and_record(37));
}

TEST(ReplayWindow, WindowEdge) {
    ReplayWindow w;
    w.check_and_record(63);
    EXPECT_TRUE(w.check_and_record(0));
    EXPECT_FALSE(w.check_and_record(0));

    w.check_and_record(64);
    EXPECT_FALSE(w.check_and_record(0));
}

TEST(InlineCryptoDatagramMode, EnabledBeforeSeed) {
    InlineCrypto c;
    c.enable_datagram_mode();
    EXPECT_TRUE(c.datagram_mode());
    EXPECT_FALSE(c.seeded());
    auto k = make_keys(0x11, 0x22);
    EXPECT_TRUE(c.seed(k));
    EXPECT_TRUE(c.seeded());
}

TEST(InlineCryptoDatagramMode, RoundTrip) {
    DatagramPair p;

    const std::vector<std::uint8_t> plain{'h', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> wire;
    ASSERT_EQ(p.alice.encrypt(plain, wire), GN_OK);
    EXPECT_EQ(wire.size(), InlineCrypto::kNonceWireBytes + plain.size() + InlineCrypto::kTagBytes);

    std::vector<std::uint8_t> back;
    ASSERT_EQ(p.bob.decrypt(wire, back), GN_OK);
    EXPECT_EQ(back, plain);
}

TEST(InlineCryptoDatagramMode, OOODelivery) {
    DatagramPair p;

    const std::vector<std::uint8_t> payloads[] = {
        {0x00}, {0x01}, {0x02}, {0x03}, {0x04},
    };
    std::vector<std::uint8_t> frames[5];
    for (int i = 0; i < 5; ++i) {
        ASSERT_EQ(p.alice.encrypt(payloads[i], frames[i]), GN_OK);
    }

    const int order[] = {2, 0, 4, 1, 3};
    for (int idx : order) {
        std::vector<std::uint8_t> out;
        EXPECT_EQ(p.bob.decrypt(frames[idx], out), GN_OK) << "frame " << idx;
        EXPECT_EQ(out, payloads[idx]);
    }
}

TEST(InlineCryptoDatagramMode, ReplayRejected) {
    DatagramPair p;

    const std::vector<std::uint8_t> plain{1, 2, 3};
    std::vector<std::uint8_t> wire;
    ASSERT_EQ(p.alice.encrypt(plain, wire), GN_OK);

    std::vector<std::uint8_t> out;
    ASSERT_EQ(p.bob.decrypt(wire, out), GN_OK);
    EXPECT_EQ(p.bob.decrypt(wire, out), GN_ERR_INVALID_ENVELOPE);
}

TEST(InlineCryptoDatagramMode, TooOldRejected) {
    DatagramPair p;

    const std::vector<std::uint8_t> plain{0xAB};
    std::vector<std::uint8_t> old_frame;
    ASSERT_EQ(p.alice.encrypt(plain, old_frame), GN_OK);

    for (int i = 0; i < 64; ++i) {
        std::vector<std::uint8_t> frame, out;
        ASSERT_EQ(p.alice.encrypt(plain, frame), GN_OK);
        ASSERT_EQ(p.bob.decrypt(frame, out), GN_OK);
    }

    std::vector<std::uint8_t> out;
    EXPECT_EQ(p.bob.decrypt(old_frame, out), GN_ERR_INVALID_ENVELOPE);
}

TEST(InlineCryptoDatagramMode, TamperedNonceRejected) {
    DatagramPair p;

    const std::vector<std::uint8_t> plain{1, 2, 3};
    std::vector<std::uint8_t> wire;
    ASSERT_EQ(p.alice.encrypt(plain, wire), GN_OK);

    wire[0] ^= 0xFF;

    std::vector<std::uint8_t> out;
    EXPECT_EQ(p.bob.decrypt(wire, out), GN_ERR_INVALID_ENVELOPE);
}

TEST(InlineCryptoDatagramMode, StreamModeUnchanged) {
    InlineCrypto alice, bob;
    auto ka = make_keys(0x77, 0x88);
    auto kb = make_keys(0x88, 0x77);
    ASSERT_TRUE(alice.seed(ka));
    ASSERT_TRUE(bob.seed(kb));

    EXPECT_FALSE(alice.datagram_mode());
    EXPECT_FALSE(bob.datagram_mode());

    const std::vector<std::uint8_t> plain{5, 6, 7};
    std::vector<std::uint8_t> cipher;
    ASSERT_EQ(alice.encrypt(plain, cipher), GN_OK);
    EXPECT_EQ(cipher.size(), plain.size() + InlineCrypto::kTagBytes);

    std::vector<std::uint8_t> back;
    ASSERT_EQ(bob.decrypt(cipher, back), GN_OK);
    EXPECT_EQ(back, plain);
}
