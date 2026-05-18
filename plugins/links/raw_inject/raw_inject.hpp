// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/raw_inject/raw_inject.hpp
/// @brief  Raw TCP transport that bridges to the kernel through
///         `host_api->inject(GN_INJECT_LAYER_MESSAGE)`.
///
/// SOCKS5-shape: the client speaks plain TCP, the plugin pipes
/// inbound bytes through `inject` as anonymous-source MESSAGE
/// envelopes. The link declares the `raw-v1` protocol layer so the
/// handler's reply is written verbatim to the TCP socket — no GNET
/// framing on either edge.

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
#include <vector>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/strand.hpp>

#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::link::raw_inject {

/// Protocol id the link declares at registration. The `raw-v1`
/// protocol carries no framing; outbound bytes are written through
/// the TCP socket exactly as the handler produced them.
inline constexpr const char kProtocolId[] = "raw-v1";

/// Configuration knobs the plugin reads from the live config tree at
/// init. Defaults match the contract in `README.md`.
struct Config {
    std::string  listen_uri      = "raw-inject://0.0.0.0:9999";
    std::uint32_t default_msg_id = 0x10FF;
    std::uint32_t rate_limit_per_sec = 1000;
    std::uint32_t max_payload    = 65536;
    /// "config" — every inbound chunk injects under `default_msg_id`.
    /// "stream" — first 4 bytes of every inbound chunk are read as
    ///             a big-endian msg_id, the remainder becomes the
    ///             injected payload.
    std::string  encode_msg_id   = "config";
};

class RawInjectLink : public std::enable_shared_from_this<RawInjectLink> {
public:
    RawInjectLink();
    ~RawInjectLink();

    RawInjectLink(const RawInjectLink&)            = delete;
    RawInjectLink& operator=(const RawInjectLink&) = delete;

    [[nodiscard]] gn_result_t listen(std::string_view uri);

    [[nodiscard]] gn_result_t connect(std::string_view uri);

    [[nodiscard]] gn_result_t send(gn_conn_id_t conn,
                                    std::span<const std::uint8_t> bytes);

    [[nodiscard]] gn_result_t send_batch(
        gn_conn_id_t conn,
        std::span<const std::span<const std::uint8_t>> frames);

    [[nodiscard]] gn_result_t disconnect(gn_conn_id_t conn);

    void set_host_api(const host_api_t* api) noexcept;
    void shutdown();

    void set_config(const Config& cfg) noexcept;
    [[nodiscard]] Config config() const noexcept;

    [[nodiscard]] std::uint16_t listen_port() const noexcept;
    [[nodiscard]] std::size_t   session_count() const noexcept;

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
    [[nodiscard]] bool claim_disconnect(gn_conn_id_t id);
    [[nodiscard]] std::shared_ptr<Session> find_session(gn_conn_id_t id) const;

    asio::io_context                                          ioc_;
    asio::executor_work_guard<asio::io_context::executor_type> work_;
    std::vector<std::thread>                                  workers_;

    std::optional<asio::ip::tcp::acceptor> acceptor_;
    std::atomic<std::uint16_t>             listen_port_{0};
    std::atomic<bool>                      shutdown_{false};

    mutable std::mutex                                                   sessions_mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>>           sessions_;
    std::vector<gn_conn_id_t>                                            published_ids_;

    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> frames_in_{0};
    std::atomic<std::uint64_t> frames_out_{0};

    mutable std::mutex cfg_mu_;
    Config              cfg_;

    const host_api_t* api_ = nullptr;
};

}  // namespace gn::link::raw_inject
