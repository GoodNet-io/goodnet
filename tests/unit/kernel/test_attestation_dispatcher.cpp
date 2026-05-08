/// @file   tests/unit/kernel/test_attestation_dispatcher.cpp
/// @brief  Unit coverage for the attestation dispatcher's pure
///         compose_payload / verify_payload helpers.
///
/// The dispatcher's send-self / on-inbound paths integrate with the
/// kernel's transport, security, and protocol-layer machinery; those
/// flows are exercised in the integration suite. The tests here
/// pin the wire-layout invariants and the per-step rejection logic
/// per `docs/contracts/attestation.md` §2 / §5.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include <core/identity/attestation.hpp>
#include <core/identity/keypair.hpp>
#include <core/identity/node_identity.hpp>
#include <core/kernel/attestation_dispatcher.hpp>
#include <core/kernel/conn_event.hpp>
#include <core/kernel/kernel.hpp>
#include <core/registry/connection.hpp>

namespace {

using gn::core::AttestationDispatcher;
using gn::core::identity::Attestation;
using gn::core::identity::NodeIdentity;
using gn::core::identity::kAttestationBytes;

constexpr std::int64_t kFarFuture = 4'000'000'000;  // ~ year 2096
constexpr std::int64_t kNow       = 1'800'000'000;  // ~ year 2027
constexpr std::int64_t kPast      = 1'500'000'000;  // ~ year 2017

/// Deterministic 32-byte binding for tests.
std::array<std::uint8_t, GN_HASH_BYTES> make_binding(std::uint8_t fill) {
    std::array<std::uint8_t, GN_HASH_BYTES> out{};
    out.fill(fill);
    return out;
}

NodeIdentity make_identity(std::int64_t expiry = kFarFuture) {
    auto id = NodeIdentity::generate(expiry);
    EXPECT_TRUE(id.has_value()) << "fresh NodeIdentity::generate failed";
    return std::move(*id);
}

} // namespace

TEST(AttestationDispatcher_Compose, EmitsCanonicalLayout) {
    auto identity = make_identity();
    const auto binding = make_binding(0x42);

    auto payload = AttestationDispatcher::compose_payload(identity, binding);
    ASSERT_TRUE(payload.has_value());
    ASSERT_EQ(payload->size(), AttestationDispatcher::kPayloadBytes);

    // Cert prefix must round-trip through Attestation::from_bytes.
    std::span<const std::uint8_t, kAttestationBytes> cert_span{
        payload->data(), kAttestationBytes};
    auto parsed = Attestation::from_bytes(cert_span);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->user_pk,    identity.user().public_key());
    EXPECT_EQ(parsed->device_pk,  identity.device().public_key());

    // Binding bytes are placed verbatim at offset 136.
    EXPECT_EQ(0, std::memcmp(payload->data() + kAttestationBytes,
                              binding.data(), GN_HASH_BYTES));
}

TEST(AttestationDispatcher_Verify, AcceptsLocallyComposedPayload) {
    auto identity = make_identity();
    const auto binding = make_binding(0x11);

    auto payload = AttestationDispatcher::compose_payload(identity, binding);
    ASSERT_TRUE(payload.has_value());

    gn::PublicKey user_pk{};
    gn::PublicKey device_pk{};
    const auto outcome = AttestationDispatcher::verify_payload(
        std::span<const std::uint8_t>(*payload), binding, kNow,
        user_pk, device_pk);

    EXPECT_EQ(outcome, AttestationDispatcher::Outcome::Ok);
    EXPECT_EQ(user_pk,   identity.user().public_key());
    EXPECT_EQ(device_pk, identity.device().public_key());
}

TEST(AttestationDispatcher_Verify, RejectsWrongSize) {
    std::vector<std::uint8_t> short_payload(
        AttestationDispatcher::kPayloadBytes - 1, 0);
    const auto binding = make_binding(0x00);
    gn::PublicKey u{}, d{};
    EXPECT_EQ(AttestationDispatcher::verify_payload(
                  short_payload, binding, kNow, u, d),
              AttestationDispatcher::Outcome::BadSize);

    std::vector<std::uint8_t> long_payload(
        AttestationDispatcher::kPayloadBytes + 1, 0);
    EXPECT_EQ(AttestationDispatcher::verify_payload(
                  long_payload, binding, kNow, u, d),
              AttestationDispatcher::Outcome::BadSize);
}

TEST(AttestationDispatcher_Verify, RejectsBindingMismatch) {
    auto identity = make_identity();
    const auto good_binding = make_binding(0x77);
    const auto bad_binding  = make_binding(0x88);

    auto payload = AttestationDispatcher::compose_payload(identity, good_binding);
    ASSERT_TRUE(payload.has_value());

    gn::PublicKey u{}, d{};
    EXPECT_EQ(AttestationDispatcher::verify_payload(
                  *payload, bad_binding, kNow, u, d),
              AttestationDispatcher::Outcome::BindingMismatch);
}

TEST(AttestationDispatcher_Verify, RejectsTamperedCert) {
    auto identity = make_identity();
    const auto binding = make_binding(0x33);

    auto payload = AttestationDispatcher::compose_payload(identity, binding);
    ASSERT_TRUE(payload.has_value());
    // Flip a byte inside the cert region (any of the first 136
    // bytes). This invalidates the cert's own signature; the §5
    // signature verify step (using the parsed device_pk over
    // cert||binding) is the one that fires first because the
    // outer signature was computed over the **original** bytes.
    (*payload)[5] ^= 0xff;

    gn::PublicKey u{}, d{};
    EXPECT_EQ(AttestationDispatcher::verify_payload(
                  *payload, binding, kNow, u, d),
              AttestationDispatcher::Outcome::BadSignature);
}

TEST(AttestationDispatcher_Verify, RejectsTamperedSignature) {
    auto identity = make_identity();
    const auto binding = make_binding(0x44);

    auto payload = AttestationDispatcher::compose_payload(identity, binding);
    ASSERT_TRUE(payload.has_value());
    // Flip a byte in the trailing 64-byte signature.
    (*payload)[AttestationDispatcher::kPayloadBytes - 1] ^= 0x01;

    gn::PublicKey u{}, d{};
    EXPECT_EQ(AttestationDispatcher::verify_payload(
                  *payload, binding, kNow, u, d),
              AttestationDispatcher::Outcome::BadSignature);
}

TEST(AttestationDispatcher_Verify, RejectsExpiredCert) {
    auto identity = make_identity(kFarFuture);  // not expired by clock
    const auto binding = make_binding(0x55);

    auto payload = AttestationDispatcher::compose_payload(identity, binding);
    ASSERT_TRUE(payload.has_value());

    gn::PublicKey u{}, d{};
    // Now is "after" the cert's expiry by passing a future time.
    EXPECT_EQ(AttestationDispatcher::verify_payload(
                  *payload, binding, kFarFuture + 1, u, d),
              AttestationDispatcher::Outcome::ExpiredOrInvalidCert);
}

TEST(AttestationDispatcher_Verify, RejectsCertEmittedWithPastExpiry) {
    auto identity = make_identity(kPast);  // already past at "now"
    const auto binding = make_binding(0x66);

    auto payload = AttestationDispatcher::compose_payload(identity, binding);
    ASSERT_TRUE(payload.has_value());

    gn::PublicKey u{}, d{};
    EXPECT_EQ(AttestationDispatcher::verify_payload(
                  *payload, binding, kNow, u, d),
              AttestationDispatcher::Outcome::ExpiredOrInvalidCert);
}

// ── mutual completion ────────────────────────────────────────────────────

namespace {

/// Insert an Untrusted connection record on @p kernel; returns the
/// allocated id. The record carries the minimum fields the upgrade
/// gate reads (`trust`, `remote_pk`).
gn_conn_id_t insert_test_record(gn::core::Kernel& kernel,
                                 gn::PublicKey     remote_pk,
                                 gn_trust_class_t  trust = GN_TRUST_UNTRUSTED) {
    const auto id = kernel.connections().alloc_id();
    gn::core::ConnectionRecord rec;
    rec.id               = id;
    rec.remote_pk        = remote_pk;
    rec.uri              = "test://attestation";
    rec.trust            = trust;
    rec.scheme = "test";
    EXPECT_EQ(kernel.connections().insert_with_index(std::move(rec)), GN_OK);
    return id;
}

} // namespace

TEST(AttestationDispatcher_Mutual, FiresUpgradeWhenBothFlagsSet) {
    /// Both halves of the mutual exchange completed: the dispatcher
    /// promotes the connection to `Peer` and fires
    /// `GN_CONN_EVENT_TRUST_UPGRADED` per `attestation.md` §6.
    gn::core::Kernel kernel;
    gn::PublicKey peer_pk{};
    peer_pk.fill(0xAB);
    gn::PublicKey peer_device{};
    peer_device.fill(0xCD);

    const auto conn = insert_test_record(kernel, peer_pk);

    bool got_upgrade        = false;
    gn_trust_class_t got_trust = GN_TRUST_UNTRUSTED;
    (void)kernel.on_conn_event().subscribe(
        [&](const gn::core::ConnEvent& ev) {
            if (ev.kind == GN_CONN_EVENT_TRUST_UPGRADED) {
                got_upgrade = true;
                got_trust   = ev.trust;
            }
        });

    kernel.attestation_dispatcher().test_seed_and_complete(
        kernel, conn,
        /*our_sent=*/true,
        /*their_received_valid=*/true,
        peer_device);

    EXPECT_TRUE(got_upgrade);
    EXPECT_EQ(got_trust, GN_TRUST_PEER);
    auto rec = kernel.connections().find_by_id(conn);
    ASSERT_NE(rec, nullptr);
    if (rec != nullptr) {
        EXPECT_EQ(rec->trust, GN_TRUST_PEER);
    }
}

TEST(AttestationDispatcher_Mutual, NoUpgradeWhenOnlyOurSent) {
    gn::core::Kernel kernel;
    gn::PublicKey peer_pk{};
    peer_pk.fill(0xA0);

    const auto conn = insert_test_record(kernel, peer_pk);

    bool got_upgrade = false;
    (void)kernel.on_conn_event().subscribe(
        [&](const gn::core::ConnEvent& ev) {
            if (ev.kind == GN_CONN_EVENT_TRUST_UPGRADED) got_upgrade = true;
        });

    kernel.attestation_dispatcher().test_seed_and_complete(
        kernel, conn,
        /*our_sent=*/true,
        /*their_received_valid=*/false);

    EXPECT_FALSE(got_upgrade);
    auto rec = kernel.connections().find_by_id(conn);
    ASSERT_NE(rec, nullptr);
    if (rec != nullptr) {
        EXPECT_EQ(rec->trust, GN_TRUST_UNTRUSTED);
    }
}

TEST(AttestationDispatcher_Mutual, NoUpgradeWhenOnlyTheirReceived) {
    gn::core::Kernel kernel;
    gn::PublicKey peer_pk{};
    peer_pk.fill(0xA1);
    gn::PublicKey peer_device{};
    peer_device.fill(0xC1);

    const auto conn = insert_test_record(kernel, peer_pk);

    bool got_upgrade = false;
    (void)kernel.on_conn_event().subscribe(
        [&](const gn::core::ConnEvent& ev) {
            if (ev.kind == GN_CONN_EVENT_TRUST_UPGRADED) got_upgrade = true;
        });

    kernel.attestation_dispatcher().test_seed_and_complete(
        kernel, conn,
        /*our_sent=*/false,
        /*their_received_valid=*/true,
        peer_device);

    EXPECT_FALSE(got_upgrade);
    auto rec = kernel.connections().find_by_id(conn);
    ASSERT_NE(rec, nullptr);
    if (rec != nullptr) {
        EXPECT_EQ(rec->trust, GN_TRUST_UNTRUSTED);
    }
}

TEST(AttestationDispatcher_Mutual, OnDisconnectClearsState) {
    /// `on_disconnect` drops per-conn flags so a fresh connection
    /// reusing the numeric id starts clean (per `attestation.md` §7).
    gn::core::Kernel kernel;
    gn::core::AttestationDispatcher dispatcher;
    const gn_conn_id_t conn = 42;

    dispatcher.test_seed_and_complete(kernel, conn,
                                       /*our_sent=*/true,
                                       /*their_received_valid=*/false);
    EXPECT_TRUE(dispatcher.our_sent(conn));

    dispatcher.on_disconnect(conn);
    EXPECT_FALSE(dispatcher.our_sent(conn));
    EXPECT_FALSE(dispatcher.their_received_valid(conn));
}

TEST(AttestationDispatcher_Mutual, DuplicateAttestationSameDevicePkSilentlyDropped) {
    /// A second attestation arriving on the same session with the
    /// same device_pk is dropped — no disconnect, no second
    /// upgrade event (per `attestation.md` §5 step 7 same-pk
    /// branch + §9 live re-attestation note).
    gn::core::Kernel kernel;
    gn::core::AttestationDispatcher dispatcher;
    const gn_conn_id_t conn = 99;
    gn::PublicKey pinned{};
    pinned.fill(0xAB);

    /// Seed: their_received_valid = true, pinned_device_pk = pinned.
    dispatcher.test_seed_and_complete(kernel, conn,
                                       /*our_sent=*/false,
                                       /*their_received_valid=*/true,
                                       pinned);
    EXPECT_TRUE(dispatcher.their_received_valid(conn));
}

TEST(AttestationDispatcher_Mutual, LoopbackTrustNotUpgraded) {
    /// `Loopback` is not a target the gate accepts as input; the
    /// dispatcher's promotion call returns LIMIT_REACHED and no
    /// upgrade event fires (per `attestation.md` §4 / §6 — the
    /// dispatcher's no-op path on non-Untrusted classes).
    gn::core::Kernel kernel;
    gn::PublicKey peer_pk{};
    peer_pk.fill(0xA2);
    gn::PublicKey peer_device{};
    peer_device.fill(0xC2);

    const auto conn =
        insert_test_record(kernel, peer_pk, GN_TRUST_LOOPBACK);

    bool got_upgrade = false;
    (void)kernel.on_conn_event().subscribe(
        [&](const gn::core::ConnEvent& ev) {
            if (ev.kind == GN_CONN_EVENT_TRUST_UPGRADED) got_upgrade = true;
        });

    kernel.attestation_dispatcher().test_seed_and_complete(
        kernel, conn,
        /*our_sent=*/true,
        /*their_received_valid=*/true,
        peer_device);

    EXPECT_FALSE(got_upgrade);
    auto rec = kernel.connections().find_by_id(conn);
    ASSERT_NE(rec, nullptr);
    if (rec != nullptr) {
        EXPECT_EQ(rec->trust, GN_TRUST_LOOPBACK);
    }
}
