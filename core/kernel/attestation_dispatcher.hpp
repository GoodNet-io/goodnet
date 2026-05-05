/// @file   core/kernel/attestation_dispatcher.hpp
/// @brief  Kernel-internal attestation exchange that gates
///         `Untrusted → Peer` trust upgrade.
///
/// Implements `docs/contracts/attestation.md`. Both peers, on every
/// connection that reaches `Transport` phase with trust class
/// `Untrusted`, exchange a 232-byte payload on system msg_id `0x11`
/// over the secured channel. Successful mutual exchange triggers
/// `connections.upgrade_trust(conn, GN_TRUST_PEER)` and fires
/// `GN_CONN_EVENT_TRUST_UPGRADED`. A peer that fails to verify the
/// other's payload disconnects.
///
/// The dispatcher is provider-agnostic: any security session that
/// exports a `gn_handshake_keys_t::handshake_hash` (per
/// `plugins/security/noise/docs/handshake.md` §2) carries the flow.

#pragma once

#include <cstdint>
#include <ctime>
#include <functional>
#include <mutex>
#include <span>
#include <unordered_map>
#include <vector>

#include <core/identity/attestation.hpp>
#include <core/identity/node_identity.hpp>
#include <core/kernel/system_handler_ids.hpp>
#include <sdk/cpp/types.hpp>
#include <sdk/security.h>
#include <sdk/types.h>

namespace gn::core {

class Kernel;
class SecuritySession;

/// Per-connection attestation flow.
///
/// One instance per kernel (owned by `Kernel`); thread-safe.
class AttestationDispatcher {
public:
    /// Total wire-payload length per `attestation.md` §2:
    /// 136 cert + 32 binding + 64 signature.
    static constexpr std::size_t kPayloadBytes =
        identity::kAttestationBytes        // 136
      + GN_HASH_BYTES                      //  32
      + identity::kEd25519SignatureBytes;  //  64

    /// Clock source returning seconds since Unix epoch. Default
    /// reads `std::time(nullptr)`. Tests inject a deterministic
    /// source per `clock.md` §2.
    using NowSec = std::function<std::int64_t()>;

    AttestationDispatcher();

    AttestationDispatcher(const AttestationDispatcher&)            = delete;
    AttestationDispatcher& operator=(const AttestationDispatcher&) = delete;

    /// Replace the wall-clock source. Cleared between tests.
    void set_clock(NowSec clock) noexcept;

    /// Producer step — `attestation.md` §4.
    ///
    /// Composes the 232-byte payload from the kernel's
    /// `NodeIdentity` and @p session's exported `handshake_hash`,
    /// submits it through the active protocol layer, encrypts via
    /// @p session, and pushes through @p kernel's transport for
    /// @p conn. Marks `our_sent` for @p conn on success. A failure
    /// at any step leaves `our_sent` unset; the caller may retry
    /// (typically by reconnecting on a fresh session).
    ///
    /// Loopback / IntraNode connections are skipped per
    /// `attestation.md` §4 — the dispatcher exits without
    /// allocating per-connection state when the connection record
    /// reports a non-`Untrusted` trust class.
    void send_self(Kernel&            kernel,
                   gn_conn_id_t       conn,
                   SecuritySession&   session) noexcept;

    /// Consumer step — `attestation.md` §5.
    ///
    /// Verifies the 232-byte @p payload against @p session's
    /// `handshake_hash`. On success marks `their_received_valid`
    /// for @p conn and, when paired with `our_sent`, promotes the
    /// connection to `Peer` and fires
    /// `GN_CONN_EVENT_TRUST_UPGRADED`. On failure the connection
    /// is closed via `Kernel::sessions().destroy()` plus
    /// `connections().snapshot_and_erase()` so subscribers see one
    /// `DISCONNECTED` event.
    ///
    /// @returns the `gn_drop_reason_t` that the consumer step
    ///          would publish to the metrics surface, or zero on
    ///          success. Callers (the `notify_inbound_bytes`
    ///          interception point) ignore the value and continue
    ///          with the next envelope; the return is exposed to
    ///          tests that exercise the per-step rejection paths
    ///          deterministically.
    int on_inbound(Kernel&                          kernel,
                   gn_conn_id_t                     conn,
                   SecuritySession&                 session,
                   std::span<const std::uint8_t>    payload) noexcept;

    /// Drop per-connection state. Called from
    /// `notify_disconnect` (per `conn-events.md` §2a) so freshly
    /// allocated ids do not inherit stale flags.
    void on_disconnect(gn_conn_id_t conn) noexcept;

    /// Test inspection — true when the local side has sent its
    /// attestation for @p conn.
    [[nodiscard]] bool our_sent(gn_conn_id_t conn) const noexcept;

    /// Test inspection — true when the peer's attestation has
    /// verified for @p conn.
    [[nodiscard]] bool their_received_valid(gn_conn_id_t conn) const noexcept;

    /// Test seam: directly seed per-connection flags and run the
    /// upgrade check. Production code reaches the same observable
    /// state through `send_self` + `on_inbound`; this entry exists
    /// solely so tests can exercise the gate without standing up a
    /// full security session and protocol-layer pipeline. Calls
    /// from production code are not contractually meaningful.
    void test_seed_and_complete(
        Kernel&                kernel,
        gn_conn_id_t           conn,
        bool                   our_sent,
        bool                   their_received_valid,
        const ::gn::PublicKey& pinned_device_pk = {}) noexcept;

    /// Compose the producer payload for the given identity and
    /// binding. Pure; pulled out so unit tests can assert layout
    /// without driving the kernel send path.
    [[nodiscard]] static ::gn::Result<std::vector<std::uint8_t>>
    compose_payload(const identity::NodeIdentity& identity,
                    std::span<const std::uint8_t, GN_HASH_BYTES> binding) noexcept;

    /// Verify a 232-byte payload against @p binding and @p now.
    /// Pure; pulled out so unit tests can exercise step-by-step
    /// rejection paths without setting up a session.
    ///
    /// @returns zero on success and the `gn_drop_reason_t`-mapped
    ///          int constant matching the failing §5 step
    ///          otherwise. The dispatcher's own enum lives below
    ///          and the values are stable across v1.
    enum class Outcome : int {
        Ok                    = 0,
        BadSize               = 1,
        BindingMismatch       = 2,
        ParseFailed           = 3,
        BadSignature          = 4,
        ExpiredOrInvalidCert  = 5,
        IdentityChange        = 6,
    };

    [[nodiscard]] static Outcome verify_payload(
        std::span<const std::uint8_t>                    payload,
        std::span<const std::uint8_t, GN_HASH_BYTES>     binding,
        std::int64_t                                     now_unix_seconds,
        ::gn::PublicKey&                                 out_user_pk,
        ::gn::PublicKey&                                 out_device_pk) noexcept;

private:
    struct State {
        bool             our_sent              = false;
        bool             their_received_valid  = false;
        ::gn::PublicKey  pinned_device_pk{};
    };

    /// Promote the connection to `Peer` and fire the trust-upgrade
    /// event. No-op when the gate refuses (the registry returns
    /// `GN_ERR_LIMIT_REACHED` on `Loopback`/`IntraNode` records;
    /// the dispatcher logs the metric and proceeds).
    void try_complete_upgrade(Kernel& kernel, gn_conn_id_t conn) noexcept;

    mutable std::mutex                  mu_;
    std::unordered_map<gn_conn_id_t, State> states_;
    NowSec                              clock_;
};

} // namespace gn::core
