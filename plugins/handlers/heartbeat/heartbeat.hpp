// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/handlers/heartbeat/heartbeat.hpp
/// @brief  PING/PONG handler with RTT tracking and STUN-on-the-wire
///         observed-address reflection. Exports the `gn.heartbeat`
///         extension per `sdk/extensions/heartbeat.h`.
///
/// Wire format mirrors the legacy 88-byte packed layout so any
/// existing observer that knows the structure can decode the same
/// bytes; field offsets are pinned by `static_assert`.

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <string>
#include <unordered_map>

#include <sdk/extensions/heartbeat.h>
#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::handler::heartbeat {

/// On-wire identifier for the heartbeat envelope. Reserved in the
/// system message-type window; production deployments should not
/// remap it.
inline constexpr std::uint32_t kHeartbeatMsgId = 0x10;

/// Stable protocol-id this handler binds to.
inline constexpr const char* kProtocolId = "gnet-v1";

inline constexpr std::uint8_t kFlagPing = 0x00;
inline constexpr std::uint8_t kFlagPong = 0x01;

#pragma pack(push, 1)
/// @brief Wire payload for PING/PONG.
struct HeartbeatPayload {
    std::uint64_t timestamp_us;          ///< monotonic-clock value at send
    std::uint32_t seq;                   ///< per-peer monotonic counter
    std::uint8_t  flags;                 ///< @ref kFlagPing / @ref kFlagPong
    std::uint8_t  _pad0[3];              ///< zero on the wire

    /// Reflected observation: the responder fills this with what it
    /// sees as the requester's address; the requester reads it back
    /// to learn its external endpoint (STUN-on-the-wire). Empty on
    /// PING; populated on PONG.
    char          observed_addr[64];     ///< NUL-terminated host literal
    std::uint16_t observed_port;         ///< 0 when observation absent
    std::uint8_t  _pad1[6];              ///< zero on the wire
};
#pragma pack(pop)
static_assert(sizeof(HeartbeatPayload) == 88,
              "HeartbeatPayload wire layout pinned at 88 bytes");

/// Time source for RTT computation. Production binds to
/// `steady_clock`; tests inject a deterministic mock per
/// `clock.md` §2.
using ClockNowUs = std::function<std::uint64_t()>;

/// Default `ClockNowUs` reading microseconds from `steady_clock`.
[[nodiscard]] ClockNowUs default_clock();

/// PING/PONG handler with per-connection RTT and observed-address
/// state. Reactive only — periodic PING emission is left to the
/// orchestrator/test harness via `send_ping(conn)`. The handler
/// implements `gn_handler_vtable_t` directly through the static
/// thunks declared at the bottom of this header.
class HeartbeatHandler {
public:
    explicit HeartbeatHandler(const host_api_t* api,
                               ClockNowUs clock = default_clock());
    ~HeartbeatHandler();

    HeartbeatHandler(const HeartbeatHandler&)            = delete;
    HeartbeatHandler& operator=(const HeartbeatHandler&) = delete;

    /// Process an inbound heartbeat envelope. PING is reflected back
    /// as PONG with the requester's observed endpoint; PONG records
    /// RTT and the peer's reported observation of our own endpoint.
    [[nodiscard]] gn_propagation_t handle_message(const gn_message_t* env);

    /// Send a PING to @p conn. Used by the orchestrator's periodic
    /// driver and by tests; the handler does not own a timer.
    [[nodiscard]] gn_result_t send_ping(gn_conn_id_t conn);

    /// Snapshot the aggregate RTT statistics across every peer that
    /// has produced at least one PONG.
    void snapshot_stats(gn_heartbeat_stats_t* out) const;

    /// Latest RTT for @p conn, in microseconds. Returns -1 when the
    /// connection is unknown or no PONG has been observed.
    [[nodiscard]] int get_rtt(gn_conn_id_t conn,
                              std::uint64_t* out_rtt_us) const;

    /// Latest peer-reported observation of the local node's external
    /// endpoint on @p conn. NUL-terminates @p buf; returns -1 on
    /// unknown / unobserved / truncation.
    [[nodiscard]] int get_observed_address(gn_conn_id_t conn,
                                            char* buf, std::size_t buf_len,
                                            std::uint16_t* port_out) const;

    /// Number of peers tracked. Useful for tests.
    [[nodiscard]] std::size_t peer_count() const noexcept;

    /// Clear all peer state. Idempotent; called from `on_shutdown`
    /// and explicitly by tests for isolation.
    void reset_state() noexcept;

    /// Build the C ABI vtable. The returned reference outlives the
    /// handler; `self` for every entry is `this`.
    [[nodiscard]] const gn_handler_vtable_t& vtable() const noexcept {
        return vtable_;
    }

    /// Build the extension vtable. Same lifetime as the handler.
    [[nodiscard]] const gn_heartbeat_api_t& extension_vtable() const noexcept {
        return ext_vtable_;
    }

private:
    struct PeerState {
        std::atomic<std::uint32_t> seq{0};
        std::atomic<std::uint64_t> last_rtt_us{0};
        std::atomic<std::uint32_t> missed{0};

        mutable std::mutex         mu;
        std::string                observed_addr;
        std::uint16_t              observed_port = 0;
    };

    [[nodiscard]] std::shared_ptr<PeerState> ensure_peer(gn_conn_id_t conn);
    [[nodiscard]] std::shared_ptr<PeerState> find_peer(gn_conn_id_t conn) const;

    /// Build the static vtable wired into `vtable_`.
    static const char* vtable_protocol_id(void* self);
    static void        vtable_supported_msg_ids(void* self,
                                                 const std::uint32_t** out_ids,
                                                 std::size_t* out_count);
    static gn_propagation_t vtable_handle_message(void* self,
                                                   const gn_message_t* env);

    /// Extension thunks bridging C ABI `void*` to `HeartbeatHandler*`.
    static int ext_get_stats(void* ctx, gn_heartbeat_stats_t* out);
    static int ext_get_rtt(void* ctx, gn_conn_id_t conn,
                            std::uint64_t* out_rtt_us);
    static int ext_get_observed_address(void* ctx, gn_conn_id_t conn,
                                         char* buf, std::size_t buf_len,
                                         std::uint16_t* port_out);

    const host_api_t*                                     api_;
    ClockNowUs                                            now_us_;
    gn_handler_vtable_t                                   vtable_{};
    gn_heartbeat_api_t                                    ext_vtable_{};

    mutable std::shared_mutex                             peers_mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<PeerState>> peers_;
};

} // namespace gn::handler::heartbeat
