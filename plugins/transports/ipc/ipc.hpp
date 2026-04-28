// SPDX-License-Identifier: MIT
/// @file   plugins/transports/ipc/ipc.hpp
/// @brief  Boost.Asio AF_UNIX transport plugin per `transport.md` §3
///         (AF_UNIX → `Loopback`).
///
/// Same single-writer / strand-per-session shape as TCP — different
/// socket type. The legacy `TR-S1` audit flagged TCP/IPC/WS as
/// almost identical; v1 plays this straight: each transport owns its
/// own implementation now, the duplication will collapse during
/// Спина 11 (Plugin Compression). Listen avoids the TOCTOU class
/// `TR-C6` describes: parent directory is `chmod 0700` before
/// `bind`, the socket path is only unlinked when an existing entry
/// is a socket, and `IPV6_V6ONLY`-style edge cases do not apply.

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

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/strand.hpp>

#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::transport::ipc {

class IpcTransport : public std::enable_shared_from_this<IpcTransport> {
public:
    IpcTransport();
    ~IpcTransport();

    IpcTransport(const IpcTransport&)            = delete;
    IpcTransport& operator=(const IpcTransport&) = delete;

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

private:
    class Session;

    void start_accept();
    void on_accept(std::shared_ptr<Session> session,
                    const boost::system::error_code& ec);
    void register_session(gn_conn_id_t id, std::shared_ptr<Session> s);
    void erase_session(gn_conn_id_t id);
    [[nodiscard]] std::shared_ptr<Session> find_session(gn_conn_id_t id) const;

    /// Resolve the path from an `ipc://` URI. Empty result means
    /// malformed input.
    [[nodiscard]] static std::string path_from_uri(std::string_view uri);

    boost::asio::io_context                                          ioc_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_;
    std::thread                                                      worker_;

    std::optional<boost::asio::local::stream_protocol::acceptor>     acceptor_;
    std::string                                                      socket_path_;
    std::atomic<bool>                                                shutdown_{false};

    mutable std::mutex                                                  sessions_mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>>          sessions_;

    const host_api_t* api_ = nullptr;
};

}  // namespace gn::transport::ipc
