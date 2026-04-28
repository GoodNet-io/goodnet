// SPDX-License-Identifier: MIT
#include "tcp.hpp"

#include <sdk/cpp/uri.hpp>

#include <asio/bind_executor.hpp>
#include <asio/buffer.hpp>
#include <asio/dispatch.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/post.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <system_error>

#include <array>
#include <cstring>
#include <deque>
#include <exception>
#include <utility>

namespace gn::transport::tcp {
namespace {

constexpr std::size_t kReadBufferSize = std::size_t{16} * 1024;

}  // namespace

// ── Session ─────────────────────────────────────────────────────────

class TcpTransport::Session : public std::enable_shared_from_this<Session> {
public:
    Session(asio::ip::tcp::socket sock,
             std::weak_ptr<TcpTransport> transport)
        : socket_(std::move(sock)),
          strand_(socket_.get_executor()),
          transport_(std::move(transport)) {}

    asio::ip::tcp::socket& socket() noexcept { return socket_; }

    gn_conn_id_t conn_id = GN_INVALID_ID;

    /// Start the read loop. Each completion deposits bytes via
    /// `host_api->notify_inbound_bytes` and re-arms; closure or error
    /// posts `notify_disconnect`.
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
                                    ? GN_OK
                                    : GN_ERR_NULL_ARG);
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

    /// Enqueue a payload onto the strand-bound write queue and kick
    /// the writer. `asio::async_write` cannot run concurrently
    /// against the same socket: composed `async_write_some` calls
    /// would otherwise interleave bytes on the wire.
    void do_send(std::span<const std::uint8_t> data) {
        auto buf = std::make_shared<std::vector<std::uint8_t>>(
            data.begin(), data.end());
        asio::dispatch(strand_,
            [self = shared_from_this(), buf = std::move(buf)]() mutable {
                self->write_queue_.push_back(std::move(buf));
                self->maybe_start_write();
            });
    }

    /// Coalesce a scatter-gather batch into one buffer so the queue
    /// stays scalar — the memcpy is dwarfed by socket I/O at any
    /// link rate the project ships against.
    void do_send_batch(std::span<const std::span<const std::uint8_t>> frames) {
        std::size_t total = 0;
        for (auto& f : frames) total += f.size();
        auto buf = std::make_shared<std::vector<std::uint8_t>>(total);
        std::size_t offset = 0;
        for (auto& f : frames) {
            std::memcpy(buf->data() + offset, f.data(), f.size());
            offset += f.size();
        }
        asio::dispatch(strand_,
            [self = shared_from_this(), buf = std::move(buf)]() mutable {
                self->write_queue_.push_back(std::move(buf));
                self->maybe_start_write();
            });
    }

    /// Close on the strand so the reactor's per-descriptor cleanup
    /// runs without overlapping a pending `async_read_some`. The
    /// `close(ec)` return is best-effort — the FD is gone either way,
    /// surface a debug log via the transport's `api_->log` so the
    /// failure isn't silent.
    void do_close() {
        asio::dispatch(strand_, [self = shared_from_this()] {
            std::error_code ec;
            if (self->socket_.close(ec)) {
                if (auto t = self->transport_.lock();
                    t && t->api_ && t->api_->log) {
                    t->api_->log(t->api_->host_ctx, GN_LOG_DEBUG,
                                 "tcp: close failed: %s",
                                 ec.message().c_str());
                }
            }
        });
    }

private:
    /// Strand-bound — caller is already on `strand_`.
    void maybe_start_write() {
        if (write_in_flight_ || write_queue_.empty()) return;
        write_in_flight_ = true;
        auto buf = write_queue_.front();
        asio::async_write(socket_, asio::buffer(*buf),
            asio::bind_executor(strand_,
                [self = shared_from_this(), buf](
                    const std::error_code& ec, std::size_t n) {
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
                    t->bytes_out_.fetch_add(n, std::memory_order_relaxed);
                    t->frames_out_.fetch_add(1, std::memory_order_relaxed);
                    self->maybe_start_write();
                }));
    }

    asio::ip::tcp::socket                              socket_;
    asio::strand<asio::any_io_executor>         strand_;
    std::weak_ptr<TcpTransport>                               transport_;

    std::array<std::uint8_t, kReadBufferSize>                 read_buf_{};
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>>    write_queue_;
    bool                                                      write_in_flight_ = false;
};

// ── TcpTransport ────────────────────────────────────────────────────

TcpTransport::TcpTransport()
    : ioc_(),
      work_(asio::make_work_guard(ioc_)) {
    worker_ = std::thread([this] { ioc_.run(); });
}

TcpTransport::~TcpTransport() {
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
        if (api_ && api_->log) {
            api_->log(api_->host_ctx, GN_LOG_WARN,
                      "tcp: shutdown threw: %s", e.what());
        }
    } catch (...) {
        if (api_ && api_->log) {
            api_->log(api_->host_ctx, GN_LOG_WARN,
                      "tcp: shutdown threw non-std exception");
        }
    }
}

void TcpTransport::set_host_api(const host_api_t* api) noexcept {
    api_ = api;
}

std::uint16_t TcpTransport::listen_port() const noexcept {
    return listen_port_.load(std::memory_order_acquire);
}

std::size_t TcpTransport::session_count() const noexcept {
    std::lock_guard lk(sessions_mu_);
    return sessions_.size();
}

TcpTransport::Stats TcpTransport::stats() const noexcept {
    Stats s{};
    s.bytes_in           = bytes_in_.load(std::memory_order_relaxed);
    s.bytes_out          = bytes_out_.load(std::memory_order_relaxed);
    s.frames_in          = frames_in_.load(std::memory_order_relaxed);
    s.frames_out         = frames_out_.load(std::memory_order_relaxed);
    s.active_connections = session_count();
    return s;
}

gn_transport_caps_t TcpTransport::capabilities() noexcept {
    gn_transport_caps_t c{};
    c.flags       = GN_TRANSPORT_CAP_STREAM
                  | GN_TRANSPORT_CAP_RELIABLE
                  | GN_TRANSPORT_CAP_ORDERED;
    c.max_payload = 0;  /// kernel limits.max_frame_bytes is the gate
    return c;
}

gn_trust_class_t TcpTransport::resolve_trust(
    const asio::ip::tcp::endpoint& peer) const noexcept
{
    return peer.address().is_loopback() ? GN_TRUST_LOOPBACK
                                          : GN_TRUST_UNTRUSTED;
}

std::string TcpTransport::endpoint_to_uri(
    const asio::ip::tcp::endpoint& ep)
{
    std::string uri = "tcp://";
    if (ep.address().is_v6()) {
        uri += '[';
        uri += ep.address().to_string();
        uri += ']';
    } else {
        uri += ep.address().to_string();
    }
    uri += ':';
    uri += std::to_string(ep.port());
    return uri;
}

gn_result_t TcpTransport::listen(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;

    const auto parts = ::gn::parse_uri(uri_sv);
    if (!parts || parts->is_path_style()) return GN_ERR_NULL_ARG;

    std::error_code ec;
    const auto addr = asio::ip::make_address(parts->host, ec);
    if (ec) return GN_ERR_NULL_ARG;
    asio::ip::tcp::endpoint ep(addr, parts->port);

    try {
        asio::ip::tcp::acceptor acceptor(ioc_);
        acceptor.open(ep.protocol());
        /// IPv6 wildcard `::` — disable `IPV6_V6ONLY` so dual-stack
        /// listens accept v4-mapped clients on Linux. `set_option`
        /// here is best-effort — pre-Linux-3.x kernels lack the option,
        /// v4-only fallback is the documented behaviour. Specific v6
        /// literals stay v6-only by default.
        if (addr.is_v6() && addr.is_unspecified()) {
            std::error_code v6_ec;
            if (acceptor.set_option(
                    asio::ip::v6_only(false), v6_ec) &&
                api_ && api_->log) {
                api_->log(api_->host_ctx, GN_LOG_DEBUG,
                          "tcp: v6_only(false) failed: %s",
                          v6_ec.message().c_str());
            }
        }
        std::error_code reuse_ec;
        if (acceptor.set_option(
                asio::ip::tcp::acceptor::reuse_address(true),
                reuse_ec) &&
            api_ && api_->log) {
            api_->log(api_->host_ctx, GN_LOG_DEBUG,
                      "tcp: reuse_address(true) failed: %s",
                      reuse_ec.message().c_str());
        }
        acceptor.bind(ep);
        acceptor.listen();
        listen_port_.store(acceptor.local_endpoint().port(),
                            std::memory_order_release);
        acceptor_.emplace(std::move(acceptor));
    } catch (const std::exception&) {
        return GN_ERR_NULL_ARG;
    }

    start_accept();
    return GN_OK;
}

void TcpTransport::start_accept() {
    if (shutdown_.load(std::memory_order_acquire) || !acceptor_) return;

    auto session = std::make_shared<Session>(
        asio::ip::tcp::socket(ioc_),
        weak_from_this());

    /// Re-check `acceptor_.has_value()` immediately above the deref —
    /// the lint pass doesn't track the early-return guard at the top
    /// of the function across the intervening `make_shared` call.
    if (!acceptor_.has_value()) return;
    auto& sock = session->socket();
    acceptor_->async_accept(sock,
        [weak = std::weak_ptr<TcpTransport>(shared_from_this()),
         session = std::move(session)](
            const std::error_code& ec) mutable {
            if (auto t = weak.lock()) t->on_accept(std::move(session), ec);
        });
}

void TcpTransport::on_accept(std::shared_ptr<Session> session,
                              const std::error_code& ec)
{
    if (ec || shutdown_.load(std::memory_order_acquire)) return;

    std::error_code re_ec;
    const auto remote = session->socket().remote_endpoint(re_ec);
    if (re_ec) {
        session->do_close();
        start_accept();
        return;
    }

    if (api_ && api_->notify_connect) {
        std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};  // unknown until handshake
        gn_conn_id_t conn = GN_INVALID_ID;
        const std::string uri = endpoint_to_uri(remote);
        const gn_result_t rc = api_->notify_connect(
            api_->host_ctx, remote_pk, uri.c_str(), "tcp",
            resolve_trust(remote), GN_ROLE_RESPONDER, &conn);
        if (rc == GN_OK && conn != GN_INVALID_ID) {
            session->conn_id = conn;
            session->start_read();
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

gn_result_t TcpTransport::connect(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;

    const auto parts = ::gn::parse_uri(uri_sv);
    if (!parts || parts->is_path_style()) return GN_ERR_NULL_ARG;
    /// `connect`-side rejects port 0 per `uri.md` §5 — the parser
    /// accepts it for ephemeral allocation on the listen path, but
    /// a zero target port is never a real peer.
    if (parts->port == 0) return GN_ERR_NULL_ARG;

    std::error_code ec;
    const auto addr = asio::ip::make_address(parts->host, ec);
    if (ec) return GN_ERR_NULL_ARG;
    asio::ip::tcp::endpoint ep(addr, parts->port);

    auto session = std::make_shared<Session>(
        asio::ip::tcp::socket(ioc_),
        weak_from_this());

    /// Open against the endpoint's protocol family before the
    /// async_connect — a default-constructed socket carries no family,
    /// and Linux silently never completes the connect for IPv6. The
    /// `open(proto, ec)` overload returns the same `error_code` it
    /// stores into `open_ec`; consume the return through the failure
    /// guard.
    std::error_code open_ec;
    if (session->socket().open(ep.protocol(), open_ec)) {
        return GN_ERR_NULL_ARG;
    }

    const std::string canonical_uri(uri_sv);
    session->socket().async_connect(ep,
        [weak = std::weak_ptr<TcpTransport>(shared_from_this()),
         session, canonical_uri, ep](
            const std::error_code& connect_ec) {
            auto t = weak.lock();
            if (!t || t->shutdown_.load(std::memory_order_acquire)) return;
            if (connect_ec) {
                /// Connect failure surfaces through the disconnect
                /// notify path so the kernel's session map cleans up.
                return;
            }
            if (!t->api_ || !t->api_->notify_connect) {
                session->do_close();
                return;
            }
            std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};
            gn_conn_id_t conn = GN_INVALID_ID;
            const gn_result_t rc = t->api_->notify_connect(
                t->api_->host_ctx, remote_pk, canonical_uri.c_str(), "tcp",
                t->resolve_trust(ep), GN_ROLE_INITIATOR, &conn);
            if (rc != GN_OK || conn == GN_INVALID_ID) {
                session->do_close();
                return;
            }
            session->conn_id = conn;
            t->register_session(conn, session);
            session->start_read();
            /// Initiator: drive the first wire message now that the
            /// session is reachable through `conn`.
            if (t->api_->kick_handshake) {
                (void)t->api_->kick_handshake(t->api_->host_ctx, conn);
            }
        });
    return GN_OK;
}

gn_result_t TcpTransport::send(gn_conn_id_t conn,
                                std::span<const std::uint8_t> bytes)
{
    auto session = find_session(conn);
    if (!session) return GN_ERR_UNKNOWN_RECEIVER;
    session->do_send(bytes);
    return GN_OK;
}

gn_result_t TcpTransport::send_batch(
    gn_conn_id_t conn,
    std::span<const std::span<const std::uint8_t>> frames)
{
    if (frames.empty()) return GN_OK;
    if (frames.size() == 1) return send(conn, frames[0]);

    auto session = find_session(conn);
    if (!session) return GN_ERR_UNKNOWN_RECEIVER;
    session->do_send_batch(frames);
    return GN_OK;
}

gn_result_t TcpTransport::disconnect(gn_conn_id_t conn) {
    std::shared_ptr<Session> session;
    {
        std::lock_guard lk(sessions_mu_);
        auto it = sessions_.find(conn);
        if (it == sessions_.end()) return GN_OK;  /// idempotent
        session = std::move(it->second);
        sessions_.erase(it);
    }
    session->do_close();
    return GN_OK;
}

void TcpTransport::register_session(gn_conn_id_t id,
                                     std::shared_ptr<Session> s)
{
    std::lock_guard lk(sessions_mu_);
    sessions_[id] = std::move(s);
}

void TcpTransport::erase_session(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    sessions_.erase(id);
}

std::shared_ptr<TcpTransport::Session>
TcpTransport::find_session(gn_conn_id_t id) const {
    std::lock_guard lk(sessions_mu_);
    auto it = sessions_.find(id);
    return (it == sessions_.end()) ? nullptr : it->second;
}

void TcpTransport::shutdown() {
    if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;

    if (acceptor_) {
        std::error_code ec;
        /// `close(ec)` is best-effort on shutdown — the FD is gone
        /// either way. Surface the error through `api_->log` if the
        /// host bound one, otherwise discard.
        if (acceptor_->close(ec) && api_ && api_->log) {
            api_->log(api_->host_ctx, GN_LOG_DEBUG,
                      "tcp: acceptor close failed: %s",
                      ec.message().c_str());
        }
        acceptor_.reset();
    }

    {
        std::lock_guard lk(sessions_mu_);
        for (auto& [_, s] : sessions_) s->do_close();
        sessions_.clear();
    }

    work_.reset();
    ioc_.stop();
    if (worker_.joinable()) worker_.join();
}

} // namespace gn::transport::tcp
