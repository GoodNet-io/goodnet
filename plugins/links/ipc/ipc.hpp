// SPDX-License-Identifier: MIT
/// @file   plugins/links/ipc/ipc.hpp
/// @brief  Asio AF_UNIX transport plugin per `link.md` §3
///         (AF_UNIX → `Loopback`).
///
/// Single-writer / strand-per-session shape: each connection owns a
/// `asio::strand` that serialises every `async_write_some`
/// against the same socket so the kernel's per-conn ordering
/// guarantee survives concurrent senders. `listen()` chmods the
/// parent directory to `0700` before `bind` so the socket inode is
/// never reachable by other users between the `bind` syscall and
/// the manual permission tightening that would otherwise need to
/// follow it; the socket path is only unlinked when an existing
/// entry is a socket so a typo never clobbers an unrelated file.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/local/stream_protocol.hpp>
#include <asio/strand.hpp>

#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::link::ipc {

class IpcLink : public std::enable_shared_from_this<IpcLink> {
public:
    IpcLink();
    ~IpcLink();

    IpcLink(const IpcLink&)            = delete;
    IpcLink& operator=(const IpcLink&) = delete;

    /// Bind a listening socket at the URI's path (`ipc:///path/to/sock`).
    /// Refuses to overwrite a non-socket path; chmods the parent
    /// directory to 0700 first so the socket inode is never reachable
    /// by other users (TR-C6).
    [[nodiscard]] gn_result_t listen(std::string_view uri);

    /// Connect to an existing listening socket at the URI's path.
    [[nodiscard]] gn_result_t connect(std::string_view uri);

    [[nodiscard]] gn_result_t send(gn_conn_id_t conn,
                                    std::span<const std::uint8_t> bytes);

    [[nodiscard]] gn_result_t send_batch(
        gn_conn_id_t conn,
        std::span<const std::span<const std::uint8_t>> frames);

    [[nodiscard]] gn_result_t disconnect(gn_conn_id_t conn);

    void set_host_api(const host_api_t* api) noexcept;
    void shutdown();

    [[nodiscard]] std::size_t session_count() const noexcept;
    [[nodiscard]] std::string_view socket_path() const noexcept {
        return socket_path_;
    }

    struct Stats {
        std::uint64_t bytes_in            = 0;
        std::uint64_t bytes_out           = 0;
        std::uint64_t frames_in           = 0;
        std::uint64_t frames_out          = 0;
        std::uint64_t active_connections  = 0;
    };
    [[nodiscard]] Stats stats() const noexcept;

    [[nodiscard]] static gn_link_caps_t capabilities() noexcept;

private:
    class Session;

    void start_accept();
    void on_accept(std::shared_ptr<Session> session,
                    const std::error_code& ec);
    void register_session(gn_conn_id_t id, std::shared_ptr<Session> s);
    void erase_session(gn_conn_id_t id);
    [[nodiscard]] std::shared_ptr<Session> find_session(gn_conn_id_t id) const;

    /// Resolve the path from an `ipc://` URI. Empty result means
    /// malformed input.
    [[nodiscard]] static std::string path_from_uri(std::string_view uri);

    asio::io_context                                          ioc_;
    asio::executor_work_guard<asio::io_context::executor_type> work_;
    std::thread                                                      worker_;

    std::optional<asio::local::stream_protocol::acceptor>     acceptor_;
    std::string                                                      socket_path_;
    std::atomic<bool>                                                shutdown_{false};

    mutable std::mutex                                                  sessions_mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>>          sessions_;

    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> frames_in_{0};
    std::atomic<std::uint64_t> frames_out_{0};

    /// Per-connection write-queue thresholds per `backpressure.md`
    /// §1. Zero on any field disables that gate.
    std::uint64_t pending_queue_bytes_low_  = 0;
    std::uint64_t pending_queue_bytes_high_ = 0;
    std::uint64_t pending_queue_bytes_hard_ = 0;

    const host_api_t* api_ = nullptr;
};

}  // namespace gn::link::ipc
