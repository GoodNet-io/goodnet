// SPDX-License-Identifier: MIT
#include "ipc.hpp"

#include <sdk/cpp/uri.hpp>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <deque>
#include <filesystem>
#include <utility>

namespace gn::transport::ipc {
namespace {

constexpr std::size_t kReadBufferSize = 16 * 1024;
namespace local_proto = boost::asio::local;

}  // namespace

// ── Session ─────────────────────────────────────────────────────────

class IpcTransport::Session : public std::enable_shared_from_this<Session> {
public:
    Session(local_proto::stream_protocol::socket sock,
             std::weak_ptr<IpcTransport> transport)
        : socket_(std::move(sock)),
          strand_(socket_.get_executor()),
          transport_(std::move(transport)) {}

    local_proto::stream_protocol::socket& socket() noexcept { return socket_; }

    gn_conn_id_t conn_id = GN_INVALID_ID;

    void start_read() {
        socket_.async_read_some(
            boost::asio::buffer(read_buf_),
            boost::asio::bind_executor(strand_,
                [self = shared_from_this()](
                    const boost::system::error_code& ec, std::size_t n) {
                    auto t = self->transport_.lock();
                    if (!t) return;
                    if (ec) {
                        if (t->api_ && t->api_->notify_disconnect) {
                            t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id,
                                ec == boost::asio::error::eof
                                    ? GN_OK : GN_ERR_NULL_ARG);
                        }
                        t->erase_session(self->conn_id);
                        return;
                    }
                    if (t->api_ && t->api_->notify_inbound_bytes && n > 0) {
                        t->api_->notify_inbound_bytes(
                            t->api_->host_ctx, self->conn_id,
                            self->read_buf_.data(), n);
                    }
                    self->start_read();
                }));
    }

    void do_send(std::span<const std::uint8_t> data) {
        auto buf = std::make_shared<std::vector<std::uint8_t>>(
            data.begin(), data.end());
        boost::asio::dispatch(strand_,
            [self = shared_from_this(), buf = std::move(buf)] {
                self->write_queue_.push_back(std::move(buf));
                self->maybe_start_write();
            });
    }

    void do_send_batch(std::span<const std::span<const std::uint8_t>> frames) {
        std::size_t total = 0;
        for (auto& f : frames) total += f.size();
        auto buf = std::make_shared<std::vector<std::uint8_t>>(total);
        std::size_t offset = 0;
        for (auto& f : frames) {
            std::memcpy(buf->data() + offset, f.data(), f.size());
            offset += f.size();
        }
        boost::asio::dispatch(strand_,
            [self = shared_from_this(), buf = std::move(buf)] {
                self->write_queue_.push_back(std::move(buf));
                self->maybe_start_write();
            });
    }

    void do_close() {
        boost::asio::dispatch(strand_, [self = shared_from_this()] {
            boost::system::error_code ec;
            (void)self->socket_.close(ec);
        });
    }

private:
    void maybe_start_write() {
        if (write_in_flight_ || write_queue_.empty()) return;
        write_in_flight_ = true;
        auto buf = write_queue_.front();
        boost::asio::async_write(socket_, boost::asio::buffer(*buf),
            boost::asio::bind_executor(strand_,
                [self = shared_from_this(), buf](
                    const boost::system::error_code& ec, std::size_t) {
                    self->write_queue_.pop_front();
                    self->write_in_flight_ = false;
                    auto t = self->transport_.lock();
                    if (!t) return;
                    if (ec) {
                        if (t->api_ && t->api_->notify_disconnect) {
                            t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id, GN_ERR_NULL_ARG);
                        }
                        t->erase_session(self->conn_id);
                        return;
                    }
                    self->maybe_start_write();
                }));
    }

    local_proto::stream_protocol::socket                      socket_;
    boost::asio::strand<boost::asio::any_io_executor>         strand_;
    std::weak_ptr<IpcTransport>                               transport_;

    std::array<std::uint8_t, kReadBufferSize>                 read_buf_{};
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>>    write_queue_;
    bool                                                      write_in_flight_ = false;
};

// ── IpcTransport ────────────────────────────────────────────────────

IpcTransport::IpcTransport()
    : ioc_(),
      work_(boost::asio::make_work_guard(ioc_)) {
    worker_ = std::thread([this] { ioc_.run(); });
}

IpcTransport::~IpcTransport() {
    shutdown();
}

void IpcTransport::set_host_api(const host_api_t* api) noexcept {
    api_ = api;
}

std::size_t IpcTransport::session_count() const noexcept {
    std::lock_guard lk(sessions_mu_);
    return sessions_.size();
}

std::string IpcTransport::path_from_uri(std::string_view uri) {
    const auto parts = ::gn::parse_uri(uri);
    if (!parts || !parts->is_path_style()) return {};
    return parts->path;
}

gn_result_t IpcTransport::listen(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;

    const auto path = path_from_uri(uri_sv);
    if (path.empty()) return GN_ERR_NULL_ARG;

    /// Lock the parent directory to owner-only access *before* bind so
    /// the socket inode is never reachable by other users — eliminates
    /// the bind-then-chmod TOCTOU window per audit TR-C6.
    {
        namespace fs = std::filesystem;
        const fs::path parent = fs::path(path).parent_path();
        if (!parent.empty()) {
            std::error_code dir_ec;
            fs::create_directories(parent, dir_ec);
            ::chmod(parent.c_str(), 0700);
        }
    }

    /// Stale leftovers from a crashed run would block bind() with
    /// EADDRINUSE. Unlink only when the path is a socket — refuse to
    /// clobber arbitrary files when the operator pointed at the wrong
    /// place.
    struct ::stat st{};
    if (::stat(path.c_str(), &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) return GN_ERR_NULL_ARG;
        (void)::unlink(path.c_str());
    }

    try {
        local_proto::stream_protocol::endpoint ep(path);
        local_proto::stream_protocol::acceptor acceptor(ioc_, ep);
        socket_path_ = path;
        acceptor_.emplace(std::move(acceptor));
    } catch (const std::exception&) {
        return GN_ERR_NULL_ARG;
    }

    start_accept();
    return GN_OK;
}

void IpcTransport::start_accept() {
    if (shutdown_.load(std::memory_order_acquire) || !acceptor_) return;

    auto session = std::make_shared<Session>(
        local_proto::stream_protocol::socket(ioc_),
        weak_from_this());

    acceptor_->async_accept(session->socket(),
        [weak = std::weak_ptr<IpcTransport>(shared_from_this()), session](
            const boost::system::error_code& ec) {
            if (auto t = weak.lock()) t->on_accept(session, ec);
        });
}

void IpcTransport::on_accept(std::shared_ptr<Session> session,
                              const boost::system::error_code& ec) {
    if (ec || shutdown_.load(std::memory_order_acquire)) return;

    if (api_ && api_->notify_connect) {
        std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};
        gn_conn_id_t conn = GN_INVALID_ID;
        const std::string uri = "ipc://" + socket_path_;
        const gn_result_t rc = api_->notify_connect(
            api_->host_ctx, remote_pk, uri.c_str(), "ipc",
            GN_TRUST_LOOPBACK, GN_ROLE_RESPONDER, &conn);
        if (rc == GN_OK && conn != GN_INVALID_ID) {
            session->conn_id = conn;
            register_session(conn, session);
            session->start_read();
            if (api_->kick_handshake) {
                (void)api_->kick_handshake(api_->host_ctx, conn);
            }
        } else {
            session->do_close();
        }
    } else {
        session->do_close();
    }

    start_accept();
}

gn_result_t IpcTransport::connect(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;

    const auto path = path_from_uri(uri_sv);
    if (path.empty()) return GN_ERR_NULL_ARG;

    auto session = std::make_shared<Session>(
        local_proto::stream_protocol::socket(ioc_),
        weak_from_this());

    const std::string canonical_uri(uri_sv);
    local_proto::stream_protocol::endpoint ep(path);

    session->socket().async_connect(ep,
        [weak = std::weak_ptr<IpcTransport>(shared_from_this()),
         session, canonical_uri](
            const boost::system::error_code& connect_ec) {
            auto t = weak.lock();
            if (!t || t->shutdown_.load(std::memory_order_acquire)) return;
            if (connect_ec) return;
            if (!t->api_ || !t->api_->notify_connect) {
                session->do_close();
                return;
            }
            std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};
            gn_conn_id_t conn = GN_INVALID_ID;
            const gn_result_t rc = t->api_->notify_connect(
                t->api_->host_ctx, remote_pk, canonical_uri.c_str(), "ipc",
                GN_TRUST_LOOPBACK, GN_ROLE_INITIATOR, &conn);
            if (rc != GN_OK || conn == GN_INVALID_ID) {
                session->do_close();
                return;
            }
            session->conn_id = conn;
            t->register_session(conn, session);
            session->start_read();
            if (t->api_->kick_handshake) {
                (void)t->api_->kick_handshake(t->api_->host_ctx, conn);
            }
        });
    return GN_OK;
}

gn_result_t IpcTransport::send(gn_conn_id_t conn,
                                std::span<const std::uint8_t> bytes) {
    auto session = find_session(conn);
    if (!session) return GN_ERR_UNKNOWN_RECEIVER;
    session->do_send(bytes);
    return GN_OK;
}

gn_result_t IpcTransport::send_batch(
    gn_conn_id_t conn,
    std::span<const std::span<const std::uint8_t>> frames) {
    if (frames.empty()) return GN_OK;
    if (frames.size() == 1) return send(conn, frames[0]);
    auto session = find_session(conn);
    if (!session) return GN_ERR_UNKNOWN_RECEIVER;
    session->do_send_batch(frames);
    return GN_OK;
}

gn_result_t IpcTransport::disconnect(gn_conn_id_t conn) {
    std::shared_ptr<Session> session;
    {
        std::lock_guard lk(sessions_mu_);
        auto it = sessions_.find(conn);
        if (it == sessions_.end()) return GN_OK;
        session = std::move(it->second);
        sessions_.erase(it);
    }
    session->do_close();
    return GN_OK;
}

void IpcTransport::register_session(gn_conn_id_t id,
                                     std::shared_ptr<Session> s) {
    std::lock_guard lk(sessions_mu_);
    sessions_[id] = std::move(s);
}

void IpcTransport::erase_session(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    sessions_.erase(id);
}

std::shared_ptr<IpcTransport::Session>
IpcTransport::find_session(gn_conn_id_t id) const {
    std::lock_guard lk(sessions_mu_);
    auto it = sessions_.find(id);
    return (it == sessions_.end()) ? nullptr : it->second;
}

void IpcTransport::shutdown() {
    if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;

    if (acceptor_) {
        boost::system::error_code ec;
        (void)acceptor_->close(ec);
        acceptor_.reset();
    }
    {
        std::lock_guard lk(sessions_mu_);
        for (auto& [_, s] : sessions_) s->do_close();
        sessions_.clear();
    }

    /// Remove the socket inode so a subsequent listen on the same
    /// path does not collide. The unlink is best-effort — any error
    /// here is benign (file already gone, perms revoked).
    if (!socket_path_.empty()) {
        (void)::unlink(socket_path_.c_str());
        socket_path_.clear();
    }

    work_.reset();
    ioc_.stop();
    if (worker_.joinable()) worker_.join();
}

}  // namespace gn::transport::ipc
