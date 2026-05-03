// SPDX-License-Identifier: MIT
/// @file   plugins/links/ipc/ipc.cpp
/// @brief  IPC link plugin — AF_UNIX SOCK_STREAM transport.

#include "ipc.hpp"

#include <sdk/convenience.h>
#include <sdk/cpp/uri.hpp>

#include <asio/bind_executor.hpp>
#include <asio/buffer.hpp>
#include <asio/dispatch.hpp>
#include <asio/post.hpp>
#include <asio/write.hpp>
#include <system_error>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <deque>
#include <exception>
#include <filesystem>
#include <utility>

namespace gn::link::ipc {
namespace {

constexpr std::size_t kReadBufferSize = std::size_t{16} * 1024;
namespace local_proto = asio::local;

}  // namespace

// ── Session ──────────────────────────────────────────────────────────────

class IpcLink::Session : public std::enable_shared_from_this<Session> {
public:
    Session(local_proto::stream_protocol::socket sock,
             std::weak_ptr<IpcLink> transport)
        : socket_(std::move(sock)),
          strand_(socket_.get_executor()),
          transport_(std::move(transport)) {}

    local_proto::stream_protocol::socket& socket() noexcept { return socket_; }

    gn_conn_id_t conn_id = GN_INVALID_ID;

    void start_read() {
        socket_.async_read_some(
            asio::buffer(read_buf_),
            asio::bind_executor(strand_,
                [self = shared_from_this()](
                    const std::error_code& ec, std::size_t n) {
                    auto t = self->transport_.lock();
                    if (!t) return;
                    if (ec) {
                        if (t->api_ && t->api_->notify_disconnect) {
                            t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id,
                                ec == asio::error::eof
                                    ? GN_OK : GN_ERR_NULL_ARG);
                        }
                        t->erase_session(self->conn_id);
                        return;
                    }
                    if (n > 0) {
                        t->bytes_in_.fetch_add(n, std::memory_order_relaxed);
                        t->frames_in_.fetch_add(1, std::memory_order_relaxed);
                        if (t->api_ && t->api_->notify_inbound_bytes) {
                            t->api_->notify_inbound_bytes(
                                t->api_->host_ctx, self->conn_id,
                                self->read_buf_.data(), n);
                        }
                    }
                    self->start_read();
                }));
    }

    void do_send(std::span<const std::uint8_t> data) {
        auto buf = std::make_shared<std::vector<std::uint8_t>>(
            data.begin(), data.end());
        const auto added = buf->size();
        const auto post = bytes_buffered_.fetch_add(
            added, std::memory_order_relaxed) + added;
        maybe_signal_soft(post);
        asio::dispatch(strand_,
            [self = shared_from_this(), buf = std::move(buf)]() mutable {
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
        const auto added = buf->size();
        const auto post = bytes_buffered_.fetch_add(
            added, std::memory_order_relaxed) + added;
        maybe_signal_soft(post);
        asio::dispatch(strand_,
            [self = shared_from_this(), buf = std::move(buf)]() mutable {
                self->write_queue_.push_back(std::move(buf));
                self->maybe_start_write();
            });
    }

    [[nodiscard]] std::uint64_t bytes_buffered() const noexcept {
        return bytes_buffered_.load(std::memory_order_relaxed);
    }

    void maybe_signal_soft(std::uint64_t post) {
        auto t = transport_.lock();
        if (!t) return;
        if (t->pending_queue_bytes_high_ == 0) return;
        if (post <= t->pending_queue_bytes_high_) return;
        bool expected = false;
        if (!soft_signaled_.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel)) {
            return;
        }
        if (t->api_ && t->api_->notify_backpressure) {
            (void)t->api_->notify_backpressure(
                t->api_->host_ctx, conn_id,
                GN_CONN_EVENT_BACKPRESSURE_SOFT, post);
        }
    }
    void maybe_signal_clear(std::uint64_t post) {
        auto t = transport_.lock();
        if (!t) return;
        if (t->pending_queue_bytes_low_ == 0) return;
        if (post >= t->pending_queue_bytes_low_) return;
        bool expected = true;
        if (!soft_signaled_.compare_exchange_strong(
                expected, false, std::memory_order_acq_rel)) {
            return;
        }
        if (t->api_ && t->api_->notify_backpressure) {
            (void)t->api_->notify_backpressure(
                t->api_->host_ctx, conn_id,
                GN_CONN_EVENT_BACKPRESSURE_CLEAR, post);
        }
    }

    /// Close on the strand so the reactor's per-descriptor cleanup
    /// runs without overlapping a pending `async_read_some`. The
    /// `close(ec)` return is best-effort — the FD is gone either way;
    /// route a debug line through `gn_log_debug` so the failure
    /// isn't silent.
    void do_close() {
        asio::dispatch(strand_, [self = shared_from_this()] {
            std::error_code ec;
            if (self->socket_.close(ec)) {
                if (auto t = self->transport_.lock();
                    t && t->api_) {
                    gn_log_debug(t->api_,
                                 "ipc: close failed: %s",
                                 ec.message().c_str());
                }
            }
        });
    }

private:
    void maybe_start_write() {
        if (write_in_flight_ || write_queue_.empty()) return;
        write_in_flight_ = true;
        auto buf = write_queue_.front();
        const std::size_t buf_size = buf->size();
        asio::async_write(socket_, asio::buffer(*buf),
            asio::bind_executor(strand_,
                [self = shared_from_this(), buf, buf_size](
                    const std::error_code& ec, std::size_t n) {
                    self->write_queue_.pop_front();
                    self->write_in_flight_ = false;
                    const auto post = self->bytes_buffered_.fetch_sub(
                        buf_size, std::memory_order_relaxed) - buf_size;
                    self->maybe_signal_clear(post);
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
                    t->bytes_out_.fetch_add(n, std::memory_order_relaxed);
                    t->frames_out_.fetch_add(1, std::memory_order_relaxed);
                    self->maybe_start_write();
                }));
    }

    local_proto::stream_protocol::socket                      socket_;
    asio::strand<asio::any_io_executor>         strand_;
    std::weak_ptr<IpcLink>                               transport_;

    std::array<std::uint8_t, kReadBufferSize>                 read_buf_{};
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>>    write_queue_;
    bool                                                      write_in_flight_ = false;
    std::atomic<std::uint64_t>                                bytes_buffered_{0};
    std::atomic<bool>                                         soft_signaled_{false};
};

// ── IpcLink ──────────────────────────────────────────────────────────────

IpcLink::IpcLink()
    : ioc_(),
      work_(asio::make_work_guard(ioc_)) {
    worker_ = std::thread([this] { ioc_.run(); });
}

IpcLink::~IpcLink() {
    /// Destructors must not throw — `shutdown()` walks the strand
    /// dispatch chain, which can throw `bad_executor` if the
    /// io_context already tore down. Surface the error through the
    /// host log if it is still bound; without a log sink there is
    /// nowhere safe to write from inside a dtor, so the catch only
    /// observes the exception type to satisfy the no-empty-catch
    /// lint without re-throwing.
    try {
        shutdown();
    } catch (const std::exception& e) {
        if (api_) {
            gn_log_warn(api_,
                      "ipc: shutdown threw: %s", e.what());
        }
    } catch (...) {
        if (api_) {
            gn_log_warn(api_,
                      "ipc: shutdown threw non-std exception");
        }
    }
}

void IpcLink::set_host_api(const host_api_t* api) noexcept {
    api_ = api;
    if (api_ != nullptr && api_->limits != nullptr) {
        if (const auto* L = api_->limits(api_->host_ctx); L != nullptr) {
            pending_queue_bytes_low_  = L->pending_queue_bytes_low;
            pending_queue_bytes_high_ = L->pending_queue_bytes_high;
            pending_queue_bytes_hard_ = L->pending_queue_bytes_hard;
        }
    }
}

IpcLink::Stats IpcLink::stats() const noexcept {
    Stats s{};
    s.bytes_in           = bytes_in_.load(std::memory_order_relaxed);
    s.bytes_out          = bytes_out_.load(std::memory_order_relaxed);
    s.frames_in          = frames_in_.load(std::memory_order_relaxed);
    s.frames_out         = frames_out_.load(std::memory_order_relaxed);
    s.active_connections = session_count();
    return s;
}

gn_link_caps_t IpcLink::capabilities() noexcept {
    gn_link_caps_t c{};
    c.flags       = GN_LINK_CAP_STREAM
                  | GN_LINK_CAP_RELIABLE
                  | GN_LINK_CAP_ORDERED
                  | GN_LINK_CAP_LOCAL_ONLY;
    c.max_payload = 0;
    return c;
}

std::size_t IpcLink::session_count() const noexcept {
    std::lock_guard lk(sessions_mu_);
    return sessions_.size();
}

std::string IpcLink::path_from_uri(std::string_view uri) {
    const auto parts = ::gn::parse_uri(uri);
    if (!parts || !parts->is_path_style()) return {};
    return parts->path;
}

namespace {

/// Reject paths with `..` traversal components or NUL bytes. The
/// listen / connect entries trust the operator's URI but a config-
/// reload from a less-trusted source could feed a path that walks
/// out of the intended namespace — e.g. `/var/run/gn/../../etc/`.
[[nodiscard]] bool path_is_normalised(std::string_view path) noexcept {
    namespace fs = std::filesystem;
    if (path.find('\0') != std::string_view::npos) return false;
    for (const auto& comp : fs::path(path)) {
        if (comp == "..") return false;
    }
    return true;
}

}  // namespace

gn_result_t IpcLink::listen(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;

    const auto path = path_from_uri(uri_sv);
    if (path.empty()) return GN_ERR_INVALID_ENVELOPE;
    if (!path_is_normalised(path)) {
        if (api_) {
            gn_log_warn(api_,
                "ipc: listen rejected non-normalised path: %s",
                path.c_str());
        }
        return GN_ERR_INVALID_ENVELOPE;
    }

    /// Lock the parent directory to owner-only access *before* bind so
    /// the socket inode is never reachable by other users — eliminates
    /// the bind-then-chmod TOCTOU window per audit TR-C6.
    {
        namespace fs = std::filesystem;
        const fs::path parent = fs::path(path).parent_path();
        if (!parent.empty()) {
            std::error_code dir_ec;
            fs::create_directories(parent, dir_ec);
            if (::chmod(parent.c_str(), 0700) != 0) {
                /// Best-effort — a parent that already has
                /// looser perms (operator-managed
                /// `/var/run/<service>/`) is OK to bind into; a
                /// parent we can't tighten is a red flag, log and
                /// continue. A future strict mode can promote this
                /// to a hard refusal.
                if (api_) {
                    gn_log_warn(api_,
                        "ipc: chmod 0700 on parent %s failed: %s",
                        parent.c_str(), std::strerror(errno));
                }
            }
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

void IpcLink::start_accept() {
    if (shutdown_.load(std::memory_order_acquire) || !acceptor_) return;

    auto session = std::make_shared<Session>(
        local_proto::stream_protocol::socket(ioc_),
        weak_from_this());

    /// Re-check `acceptor_.has_value()` immediately above the deref —
    /// the lint pass doesn't track the early-return guard at the top
    /// of the function across the intervening `make_shared` call.
    if (!acceptor_.has_value()) return;
    auto& sock = session->socket();
    acceptor_->async_accept(sock,
        [weak = std::weak_ptr<IpcLink>(shared_from_this()),
         session = std::move(session)](
            const std::error_code& ec) mutable {
            if (auto t = weak.lock()) t->on_accept(std::move(session), ec);
        });
}

void IpcLink::on_accept(std::shared_ptr<Session> session,
                              const std::error_code& ec) {
    if (ec || shutdown_.load(std::memory_order_acquire)) return;

    /// SO_PEERCRED gate: refuse cross-UID connects on the IPC
    /// socket. The default policy is "same UID as the listener
    /// process" — the unix-socket parent dir lock to 0700 already
    /// blocks cross-UID dial, but PEERCRED defends against a
    /// privileged peer that bypassed the dir gate (e.g. a
    /// `setuid` helper running as root that connected to a
    /// non-root listener's socket). Future strict mode can
    /// switch to operator-supplied allowlist.
    {
        struct ::ucred cred{};
        ::socklen_t len = sizeof(cred);
        const int fd = session->socket().native_handle();
        if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED,
                          &cred, &len) == 0 &&
            len == sizeof(cred)) {
            const ::uid_t expected_uid = ::geteuid();
            if (cred.uid != expected_uid) {
                if (api_) {
                    gn_log_warn(api_,
                        "ipc: rejected accept from uid=%u (expected=%u, "
                        "pid=%ld) — peer-credential gate",
                        static_cast<unsigned>(cred.uid),
                        static_cast<unsigned>(expected_uid),
                        static_cast<long>(cred.pid));
                }
                session->do_close();
                start_accept();
                return;
            }
        } else {
            /// Kernel without SO_PEERCRED on this socket type —
            /// non-Linux build. The dir-perm gate above is the
            /// only defence; log debug for visibility but accept.
            if (api_) {
                gn_log_debug(api_,
                    "ipc: SO_PEERCRED unavailable: %s",
                    std::strerror(errno));
            }
        }
    }

    if (api_ && api_->notify_connect) {
        std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};
        gn_conn_id_t conn = GN_INVALID_ID;
        const std::string uri = "ipc://" + socket_path_;
        const gn_result_t rc = api_->notify_connect(
            api_->host_ctx, remote_pk, uri.c_str(), "ipc",
            GN_TRUST_LOOPBACK, GN_ROLE_RESPONDER, &conn);
        if (rc == GN_OK && conn != GN_INVALID_ID) {
            session->conn_id = conn;
            session->start_read();
            if (api_->kick_handshake) {
                (void)api_->kick_handshake(api_->host_ctx, conn);
            }
            /// Move-into the session map — ownership transfers to the
            /// registry, so the local `session` is consumed here.
            register_session(conn, std::move(session));
        } else {
            session->do_close();
        }
    } else {
        session->do_close();
    }

    start_accept();
}

gn_result_t IpcLink::connect(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;

    const auto path = path_from_uri(uri_sv);
    if (path.empty()) return GN_ERR_INVALID_ENVELOPE;
    if (!path_is_normalised(path)) {
        if (api_) {
            gn_log_warn(api_,
                "ipc: connect rejected non-normalised path: %s",
                path.c_str());
        }
        return GN_ERR_INVALID_ENVELOPE;
    }

    auto session = std::make_shared<Session>(
        local_proto::stream_protocol::socket(ioc_),
        weak_from_this());

    const std::string canonical_uri(uri_sv);
    local_proto::stream_protocol::endpoint ep(path);

    session->socket().async_connect(ep,
        [weak = std::weak_ptr<IpcLink>(shared_from_this()),
         session, canonical_uri](
            const std::error_code& connect_ec) {
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

gn_result_t IpcLink::send(gn_conn_id_t conn,
                                std::span<const std::uint8_t> bytes) {
    auto session = find_session(conn);
    if (!session) return GN_ERR_NOT_FOUND;
    if (pending_queue_bytes_hard_ != 0 &&
        session->bytes_buffered() + bytes.size() >
            pending_queue_bytes_hard_) {
        if (api_) {
            if (api_->emit_counter) {
                api_->emit_counter(api_->host_ctx, "drop.queue_hard_cap");
            }
            gn_log_warn(api_,
                "ipc.send: queue hard cap — conn=%llu buffered=%zu add=%zu hard=%zu",
                static_cast<unsigned long long>(conn),
                session->bytes_buffered(),
                bytes.size(),
                pending_queue_bytes_hard_);
        }
        return GN_ERR_LIMIT_REACHED;
    }
    session->do_send(bytes);
    return GN_OK;
}

gn_result_t IpcLink::send_batch(
    gn_conn_id_t conn,
    std::span<const std::span<const std::uint8_t>> frames) {
    if (frames.empty()) return GN_OK;
    if (frames.size() == 1) return send(conn, frames[0]);
    auto session = find_session(conn);
    if (!session) return GN_ERR_NOT_FOUND;
    std::size_t total = 0;
    for (const auto& f : frames) total += f.size();
    if (pending_queue_bytes_hard_ != 0 &&
        session->bytes_buffered() + total > pending_queue_bytes_hard_) {
        if (api_) {
            if (api_->emit_counter) {
                api_->emit_counter(api_->host_ctx, "drop.queue_hard_cap");
            }
            gn_log_warn(api_,
                "ipc.send_batch: queue hard cap — conn=%llu buffered=%zu add=%zu hard=%zu",
                static_cast<unsigned long long>(conn),
                session->bytes_buffered(),
                total,
                pending_queue_bytes_hard_);
        }
        return GN_ERR_LIMIT_REACHED;
    }
    session->do_send_batch(frames);
    return GN_OK;
}

gn_result_t IpcLink::disconnect(gn_conn_id_t conn) {
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

void IpcLink::register_session(gn_conn_id_t id,
                                     std::shared_ptr<Session> s) {
    std::lock_guard lk(sessions_mu_);
    sessions_[id] = std::move(s);
}

void IpcLink::erase_session(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    sessions_.erase(id);
}

std::shared_ptr<IpcLink::Session>
IpcLink::find_session(gn_conn_id_t id) const {
    std::lock_guard lk(sessions_mu_);
    auto it = sessions_.find(id);
    return (it == sessions_.end()) ? nullptr : it->second;
}

void IpcLink::shutdown() {
    if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;

    if (acceptor_) {
        std::error_code ec;
        /// `close(ec)` is best-effort on shutdown — the FD is gone
        /// either way. Route the error through `gn_log_debug`;
        /// `api_` may be null when the kernel tore down before
        /// shutdown ran, in which case the macro short-circuits.
        if (acceptor_->close(ec) && api_) {
            gn_log_debug(api_,
                      "ipc: acceptor close failed: %s",
                      ec.message().c_str());
        }
        acceptor_.reset();
    }
    /// Snapshot conn ids under the lock, close each session's
    /// socket synchronously, then notify the kernel side
    /// SYNCHRONOUSLY for each session before stopping the
    /// io_context. `ioc_.stop()` would otherwise drop pending
    /// strand-bound continuations — including the read-completion
    /// path that normally fires `notify_disconnect`. Without sync
    /// notification, kernel-side `ConnectionRegistry` keeps live
    /// records past ipc shutdown, which in turn keeps the security
    /// plugin's lifetime anchor alive past the PluginManager drain
    /// budget. Per `link.md` §9 the shutdown must release every
    /// kernel-observable session before the io_context tear-down.
    std::vector<gn_conn_id_t> live_ids;
    {
        std::lock_guard lk(sessions_mu_);
        live_ids.reserve(sessions_.size());
        for (auto& [id, s] : sessions_) {
            live_ids.push_back(id);
            s->do_close();
        }
        sessions_.clear();
    }

    if (api_ && api_->notify_disconnect) {
        for (const auto id : live_ids) {
            (void)api_->notify_disconnect(api_->host_ctx, id, GN_OK);
        }
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

}  // namespace gn::link::ipc
