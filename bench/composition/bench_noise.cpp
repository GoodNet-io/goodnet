// SPDX-License-Identifier: Apache-2.0
/// @file   bench/composition/bench_noise.cpp
/// @brief  Noise XX + IK handshake time + steady-state AEAD
///         throughput, measured directly against the noise plugin
///         primitives (no sockets, no kernel) so the number isolates
///         crypto cost from transport.
///
/// Two binaries' worth of measurement collapsed into one:
///
///   * HandshakeRoundtrip — drives initiator + responder through
///     every pattern message, calls split, captures total wall time.
///     XX = 3 messages = 2 RTTs of crypto + 6 DH ops; IK = 2 messages
///     = 1 RTT + 5 DH ops. Difference is the round-trip saving IK
///     buys when the initiator already knows the responder's static
///     pk.
///
///   * TransportEncryptDecrypt — after split, loops `encrypt + decrypt`
///     on a payload, isolates the ChaChaPoly-IETF AEAD overhead per
///     message. Independent of pattern (XX and IK share the same
///     transport ciphers).

#include "../bench_harness.hpp"

#include <plugins/security/noise/handshake.hpp>
#include <plugins/security/noise/cipher.hpp>

#include <chrono>
#include <cstdint>
#include <span>
#include <vector>

namespace {

using namespace gn::bench;
using gn::noise::CipherState;
using gn::noise::HandshakeState;
using gn::noise::Keypair;
using gn::noise::Pattern;
using gn::noise::generate_keypair;
using gn::noise::AEAD_TAG_BYTES;

// ── Handshake roundtrip ──────────────────────────────────────────

/// Drive every message of a pattern through initiator + responder
/// in lock-step. Returns the elapsed nanoseconds for the full
/// pattern + split on both sides. Empty payload — Noise doesn't
/// care, the bench measures crypto only.
std::uint64_t handshake_roundtrip_ns(Pattern pattern) {
    auto alice_kp = generate_keypair();
    auto bob_kp   = generate_keypair();

    const auto t0 = std::chrono::steady_clock::now();

    /// For IK, the initiator must pre-know the responder's static
    /// pk; that is exactly the DX win the pattern advertises.
    const auto* pre_rs = (pattern == Pattern::IK) ? &bob_kp.pk : nullptr;
    HandshakeState alice(pattern, /*initiator=*/true,  alice_kp, pre_rs);
    HandshakeState bob  (pattern, /*initiator=*/false, bob_kp,   nullptr);

    /// Alternate write/read until both sides complete.
    HandshakeState* writer = &alice;
    HandshakeState* reader = &bob;
    while (!alice.is_complete() || !bob.is_complete()) {
        auto msg = writer->write_message(
            std::span<const std::uint8_t>{});
        if (!msg) return 0;
        auto plain = reader->read_message(std::span<const std::uint8_t>(*msg));
        if (!plain) return 0;
        std::swap(writer, reader);
    }
    /// Split both sides — exercises the same HKDF expand that real
    /// callers run after every handshake.
    auto a_tp = alice.split();
    auto b_tp = bob.split();
    (void)a_tp; (void)b_tp;

    const auto t1 = std::chrono::steady_clock::now();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
}

static void BM_NoiseHandshakeXX(::benchmark::State& state) {
    std::uint64_t total = 0;
    for (auto _ : state) {
        const auto ns = handshake_roundtrip_ns(Pattern::XX);
        if (ns == 0) {
            state.SkipWithError("handshake failed");
            break;
        }
        total += ns;
    }
    state.counters["mean_handshake_ns"] =
        state.iterations() > 0
            ? static_cast<double>(total) / static_cast<double>(state.iterations())
            : 0.0;
}
BENCHMARK(BM_NoiseHandshakeXX)->Unit(::benchmark::kMicrosecond);

static void BM_NoiseHandshakeIK(::benchmark::State& state) {
    std::uint64_t total = 0;
    for (auto _ : state) {
        const auto ns = handshake_roundtrip_ns(Pattern::IK);
        if (ns == 0) {
            state.SkipWithError("handshake failed");
            break;
        }
        total += ns;
    }
    state.counters["mean_handshake_ns"] =
        state.iterations() > 0
            ? static_cast<double>(total) / static_cast<double>(state.iterations())
            : 0.0;
}
BENCHMARK(BM_NoiseHandshakeIK)->Unit(::benchmark::kMicrosecond);

// ── Transport encrypt+decrypt steady state ────────────────────────

/// After a complete XX handshake, drive `encrypt` on the initiator
/// side then `decrypt` on the responder side N times. Isolates the
/// ChaChaPoly AEAD cost per message — independent of which pattern
/// produced the keys (XX + IK share the transport surface).
static void BM_NoiseTransportEncryptDecrypt(::benchmark::State& state) {
    const std::size_t payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    /// Full XX handshake to set up alice.send ↔ bob.recv.
    auto alice_kp = generate_keypair();
    auto bob_kp   = generate_keypair();
    HandshakeState alice(Pattern::XX, true,  alice_kp);
    HandshakeState bob  (Pattern::XX, false, bob_kp);

    HandshakeState* writer = &alice;
    HandshakeState* reader = &bob;
    while (!alice.is_complete() || !bob.is_complete()) {
        auto m = writer->write_message(std::span<const std::uint8_t>{});
        if (!m) { state.SkipWithError("handshake failed"); return; }
        auto p = reader->read_message(std::span<const std::uint8_t>(*m));
        if (!p) { state.SkipWithError("handshake failed"); return; }
        std::swap(writer, reader);
    }
    auto alice_tp = alice.split();
    auto bob_tp   = bob.split();

    /// alice.send encrypts → bob.recv decrypts. Reuse the same
    /// buffer pair across iterations so the loop measures crypto
    /// not allocation.
    std::vector<std::uint8_t> ciphertext;
    ciphertext.reserve(payload_size + AEAD_TAG_BYTES);

    ResourceCounters res;
    res.snapshot_start();
    for (auto _ : state) {
        const auto enc = alice_tp.send.encrypt_with_ad(
            std::span<const std::uint8_t>{}, payload);
        const auto dec = bob_tp.recv.decrypt_with_ad(
            std::span<const std::uint8_t>{},
            std::span<const std::uint8_t>(enc));
        if (!dec) {
            state.SkipWithError("decrypt failed");
            break;
        }
        ::benchmark::DoNotOptimize(dec->data());
    }
    res.snapshot_end();
    state.SetBytesProcessed(
        static_cast<std::int64_t>(state.iterations()) *
        static_cast<std::int64_t>(payload_size));
    report_resources(state, res);
}
BENCHMARK(BM_NoiseTransportEncryptDecrypt)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Arg(65536)
    ->Unit(::benchmark::kMicrosecond);

}  // namespace
