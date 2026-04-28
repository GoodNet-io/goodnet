/// @file   tests/unit/security/test_session.cpp
/// @brief  SecuritySession state machine + Sessions map.

#include <gtest/gtest.h>

#include <core/security/session.hpp>

#include <sdk/security.h>
#include <sdk/types.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

using gn::core::SecuritySession;
using gn::core::SecurityPhase;
using gn::core::Sessions;

/// Inline pass-through provider — handshake is a single no-op step,
/// encrypt/decrypt copy plaintext to a fresh allocation paired with
/// `free`. Mirrors the null security plugin's surface without needing
/// a dlopen.
struct FakeProvider {
    int handshake_open_calls = 0;
    int handshake_step_calls = 0;
    int handshake_close_calls = 0;
    int encrypt_calls = 0;
    int decrypt_calls = 0;
    bool complete_immediately = true;

    static gn_result_t open(void* self, gn_conn_id_t,
                             gn_trust_class_t, gn_handshake_role_t,
                             const std::uint8_t*, const std::uint8_t*,
                             const std::uint8_t*,
                             void** out_state) {
        if (!out_state) return GN_ERR_NULL_ARG;
        ++static_cast<FakeProvider*>(self)->handshake_open_calls;
        *out_state = nullptr;
        return GN_OK;
    }

    static gn_result_t step(void* self, void*,
                             const std::uint8_t*, std::size_t,
                             gn_secure_buffer_t* out) {
        ++static_cast<FakeProvider*>(self)->handshake_step_calls;
        if (out) {
            out->bytes = nullptr;
            out->size = 0;
            out->free_fn = nullptr;
        }
        return GN_OK;
    }

    static int complete(void* self, void*) {
        return static_cast<FakeProvider*>(self)->complete_immediately ? 1 : 0;
    }

    static gn_result_t export_keys(void*, void*, gn_handshake_keys_t* out) {
        if (!out) return GN_ERR_NULL_ARG;
        std::memset(out, 0, sizeof(*out));
        return GN_OK;
    }

    static void free_buf(std::uint8_t* p) { std::free(p); }

    static gn_result_t copy_through(const std::uint8_t* in, std::size_t n,
                                     gn_secure_buffer_t* out) {
        if (!out) return GN_ERR_NULL_ARG;
        if (n == 0) {
            out->bytes = nullptr;
            out->size = 0;
            out->free_fn = nullptr;
            return GN_OK;
        }
        auto* heap = static_cast<std::uint8_t*>(std::malloc(n));
        if (!heap) return GN_ERR_OUT_OF_MEMORY;
        std::memcpy(heap, in, n);
        out->bytes = heap;
        out->size = n;
        out->free_fn = &FakeProvider::free_buf;
        return GN_OK;
    }

    static gn_result_t encrypt(void* self, void*,
                                const std::uint8_t* p, std::size_t n,
                                gn_secure_buffer_t* out) {
        ++static_cast<FakeProvider*>(self)->encrypt_calls;
        return copy_through(p, n, out);
    }

    static gn_result_t decrypt(void* self, void*,
                                const std::uint8_t* c, std::size_t n,
                                gn_secure_buffer_t* out) {
        ++static_cast<FakeProvider*>(self)->decrypt_calls;
        return copy_through(c, n, out);
    }

    static void close(void* self, void*) {
        ++static_cast<FakeProvider*>(self)->handshake_close_calls;
    }
};

gn_security_provider_vtable_t make_vtable() {
    gn_security_provider_vtable_t v{};
    v.api_size              = sizeof(gn_security_provider_vtable_t);
    v.handshake_open        = &FakeProvider::open;
    v.handshake_step        = &FakeProvider::step;
    v.handshake_complete    = &FakeProvider::complete;
    v.export_transport_keys = &FakeProvider::export_keys;
    v.encrypt               = &FakeProvider::encrypt;
    v.decrypt               = &FakeProvider::decrypt;
    v.handshake_close       = &FakeProvider::close;
    return v;
}

constexpr std::uint8_t kZeroSk[GN_PRIVATE_KEY_BYTES] = {};
constexpr std::uint8_t kZeroPk[GN_PUBLIC_KEY_BYTES]  = {};

} // namespace

// ── SecuritySession ─────────────────────────────────────────────────

TEST(SecuritySession, OpenInitialPhaseIsHandshake) {
    FakeProvider prov;
    prov.complete_immediately = false;
    auto vt = make_vtable();
    SecuritySession session;
    EXPECT_EQ(session.open(&vt, &prov, /*conn*/ 1,
                            GN_TRUST_LOOPBACK, GN_ROLE_INITIATOR,
                            std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES>(kZeroSk),
                            std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(kZeroPk),
                            std::span<const std::uint8_t>{}),
              GN_OK);
    EXPECT_EQ(session.phase(), SecurityPhase::Handshake);
    EXPECT_EQ(prov.handshake_open_calls, 1);
}

TEST(SecuritySession, AdvanceHandshakeTransitionsToTransportOnComplete) {
    FakeProvider prov;
    prov.complete_immediately = true;
    auto vt = make_vtable();
    SecuritySession session;
    ASSERT_EQ(session.open(&vt, &prov, 1,
                            GN_TRUST_LOOPBACK, GN_ROLE_INITIATOR,
                            std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES>(kZeroSk),
                            std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(kZeroPk),
                            std::span<const std::uint8_t>{}),
              GN_OK);
    std::vector<std::uint8_t> out_msg;
    EXPECT_EQ(session.advance_handshake({}, out_msg), GN_OK);
    EXPECT_EQ(session.phase(), SecurityPhase::Transport);
    EXPECT_TRUE(out_msg.empty());
}

TEST(SecuritySession, AdvanceRejectedAfterTransition) {
    FakeProvider prov;
    auto vt = make_vtable();
    SecuritySession session;
    ASSERT_EQ(session.open(&vt, &prov, 1,
                            GN_TRUST_LOOPBACK, GN_ROLE_INITIATOR,
                            std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES>(kZeroSk),
                            std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(kZeroPk),
                            std::span<const std::uint8_t>{}),
              GN_OK);
    std::vector<std::uint8_t> tmp;
    ASSERT_EQ(session.advance_handshake({}, tmp), GN_OK);
    /// After completion further handshake calls return INVALID_ENVELOPE.
    EXPECT_NE(session.advance_handshake({}, tmp), GN_OK);
}

TEST(SecuritySession, EncryptDecryptRoundTripInTransportPhase) {
    FakeProvider prov;
    auto vt = make_vtable();
    SecuritySession session;
    ASSERT_EQ(session.open(&vt, &prov, 1,
                            GN_TRUST_LOOPBACK, GN_ROLE_INITIATOR,
                            std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES>(kZeroSk),
                            std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(kZeroPk),
                            std::span<const std::uint8_t>{}),
              GN_OK);
    std::vector<std::uint8_t> tmp;
    ASSERT_EQ(session.advance_handshake({}, tmp), GN_OK);

    const std::vector<std::uint8_t> plain{1, 2, 3, 4, 5};
    std::vector<std::uint8_t> cipher;
    EXPECT_EQ(session.encrypt_transport(plain, cipher), GN_OK);
    EXPECT_EQ(cipher, plain);  /// pass-through provider copies bytes
    EXPECT_EQ(prov.encrypt_calls, 1);

    std::vector<std::uint8_t> back;
    EXPECT_EQ(session.decrypt_transport(cipher, back), GN_OK);
    EXPECT_EQ(back, plain);
    EXPECT_EQ(prov.decrypt_calls, 1);
}

TEST(SecuritySession, EncryptRejectedDuringHandshake) {
    FakeProvider prov;
    prov.complete_immediately = false;
    auto vt = make_vtable();
    SecuritySession session;
    ASSERT_EQ(session.open(&vt, &prov, 1,
                            GN_TRUST_LOOPBACK, GN_ROLE_INITIATOR,
                            std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES>(kZeroSk),
                            std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(kZeroPk),
                            std::span<const std::uint8_t>{}),
              GN_OK);
    std::vector<std::uint8_t> out;
    EXPECT_NE(session.encrypt_transport({}, out), GN_OK);
    EXPECT_NE(session.decrypt_transport({}, out), GN_OK);
}

TEST(SecuritySession, CloseInvokesHandshakeCloseOnce) {
    FakeProvider prov;
    auto vt = make_vtable();
    {
        SecuritySession session;
        ASSERT_EQ(session.open(&vt, &prov, 1,
                                GN_TRUST_LOOPBACK, GN_ROLE_INITIATOR,
                                std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES>(kZeroSk),
                                std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(kZeroPk),
                                std::span<const std::uint8_t>{}),
                  GN_OK);
        session.close();
        EXPECT_EQ(prov.handshake_close_calls, 1);
        session.close();  /// idempotent — handshake_close not called twice
        EXPECT_EQ(prov.handshake_close_calls, 1);
    }
    /// Destruction after explicit close() does not call handshake_close again.
    EXPECT_EQ(prov.handshake_close_calls, 1);
}

// ── Sessions ────────────────────────────────────────────────────────

TEST(Sessions, CreateAndFindReturnsSameHandle) {
    FakeProvider prov;
    auto vt = make_vtable();
    Sessions sessions;

    gn_result_t rc = GN_OK;
    auto a = sessions.create(
        /*conn*/ 7, &vt, &prov,
        GN_TRUST_LOOPBACK, GN_ROLE_INITIATOR,
        std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES>(kZeroSk),
        std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(kZeroPk),
        std::span<const std::uint8_t>{}, rc);
    ASSERT_EQ(rc, GN_OK);
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(sessions.find(7).get(), a.get());
    EXPECT_EQ(sessions.size(), 1u);
}

TEST(Sessions, FindUnknownConnReturnsEmptyHandle) {
    Sessions sessions;
    EXPECT_EQ(sessions.find(99), nullptr);
}

TEST(Sessions, CreateRejectsDuplicateConn) {
    FakeProvider prov;
    auto vt = make_vtable();
    Sessions sessions;

    gn_result_t rc = GN_OK;
    auto first = sessions.create(
        /*conn*/ 11, &vt, &prov,
        GN_TRUST_LOOPBACK, GN_ROLE_INITIATOR,
        std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES>(kZeroSk),
        std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(kZeroPk),
        std::span<const std::uint8_t>{}, rc);
    ASSERT_EQ(rc, GN_OK);
    ASSERT_NE(first, nullptr);

    /// Second `create()` with the same `conn` must fail. A silent
    /// overwrite would orphan the existing session — borrowers
    /// holding `shared_ptr` continue to encrypt against the old
    /// keys while new callers see a freshly-keyed handshake;
    /// payloads diverge.
    auto second = sessions.create(
        /*conn*/ 11, &vt, &prov,
        GN_TRUST_LOOPBACK, GN_ROLE_RESPONDER,
        std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES>(kZeroSk),
        std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(kZeroPk),
        std::span<const std::uint8_t>{}, rc);
    EXPECT_EQ(rc, GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(second, nullptr);
    EXPECT_EQ(sessions.find(11).get(), first.get());
    EXPECT_EQ(sessions.size(), 1u);
}

TEST(Sessions, DestroyClearsAndCallsHandshakeClose) {
    FakeProvider prov;
    auto vt = make_vtable();
    Sessions sessions;

    gn_result_t rc = GN_OK;
    (void)sessions.create(7, &vt, &prov,
                            GN_TRUST_LOOPBACK, GN_ROLE_INITIATOR,
                            std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES>(kZeroSk),
                            std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(kZeroPk),
                            std::span<const std::uint8_t>{}, rc);
    ASSERT_EQ(rc, GN_OK);
    sessions.destroy(7);
    EXPECT_EQ(sessions.find(7), nullptr);
    EXPECT_EQ(sessions.size(), 0u);
    EXPECT_EQ(prov.handshake_close_calls, 1);
}

TEST(Sessions, DestroyUnknownIsNoop) {
    Sessions sessions;
    sessions.destroy(42);  /// must not crash; nothing to remove
    EXPECT_EQ(sessions.size(), 0u);
}
