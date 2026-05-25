// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/raw_inject/raw_inject.hpp
/// @brief  Raw byte-translator that bridges a foreign-protocol TCP
///         carrier to the kernel through `host_api->inject`.
///
/// L2 composer plugin over `gn.link.tcp`. The plugin owns no
/// socket — every accept / read / write goes through the TCP
/// carrier's extension vtable. Inbound bytes flow as MESSAGE
/// envelopes through `inject(GN_INJECT_LAYER_MESSAGE)`; outbound
/// bytes from the handler reach the foreign client via the TCP
/// carrier's send slot.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <sdk/cpp/link_carrier.hpp>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::link::raw_inject {

/// Protocol id the link declares at registration. The `raw-v1`
/// protocol carries no framing; outbound bytes are written through
/// the TCP carrier exactly as the handler produced them.
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
    /// Handler-registry namespace for dispatch. Must be non-empty.
    /// Examples: "gnet-v1", "mqtt.v1", "sensor.v1".
    std::string  target_ns       = "raw-v1";

    /// When true, inbound data is ZSTD-decompressed before inject and outbound
    /// data from send() is ZSTD-compressed before writing to the carrier.
    bool          zstd_compress         = false;
    std::uint32_t zstd_level            = 3;
    std::uint32_t zstd_max_decompress   = 4u * 1024u * 1024u;
};

class RawInjectLink : public std::enable_shared_from_this<RawInjectLink> {
public:
    RawInjectLink();
    ~RawInjectLink();

    RawInjectLink(const RawInjectLink&)            = delete;
    RawInjectLink& operator=(const RawInjectLink&) = delete;

    [[nodiscard]] gn_result_t listen(std::string_view uri);
    [[nodiscard]] gn_result_t connect(std::string_view uri);

    /// Macro post-register hook. Reads the live `raw_inject.listen`
    /// config + calls `listen()` so the bridge binds its TCP
    /// carrier acceptor as soon as the kernel finishes the link
    /// registration. Pure auto-start convenience — the kernel
    /// could equally call `listen` later through an external slot.
    [[nodiscard]] gn_result_t on_registered();

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
    /// Per-conn state — links the TCP composer id allocated by the
    /// carrier on accept with the kernel-side conn id allocated by
    /// `notify_connect`.
    struct Session {
        gn_conn_id_t carrier_id = GN_INVALID_ID;
        gn_conn_id_t kernel_id  = GN_INVALID_ID;
        std::string  peer_uri;
        bool         zstd_active = false;
    };

    [[nodiscard]] gn_result_t ensure_carrier();

    void on_carrier_accept(gn_conn_id_t carrier_id,
                            std::string_view peer_uri);
    void on_carrier_data(gn_conn_id_t carrier_id,
                          std::span<const std::uint8_t> bytes);

    void dispatch_inject(const std::shared_ptr<Session>& session,
                          std::span<const std::uint8_t> bytes);

    [[nodiscard]] std::shared_ptr<Session>
        session_by_carrier(gn_conn_id_t carrier_id) const;
    [[nodiscard]] std::shared_ptr<Session>
        session_by_kernel(gn_conn_id_t kernel_id) const;

    const host_api_t*                       api_ = nullptr;
    std::atomic<bool>                       shutdown_{false};

    std::optional<gn::sdk::LinkCarrier>     carrier_;
    std::atomic<std::uint16_t>              listen_port_{0};

    mutable std::mutex                                              sessions_mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>>      by_carrier_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>>      by_kernel_;

    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> frames_in_{0};
    std::atomic<std::uint64_t> frames_out_{0};

    mutable std::mutex cfg_mu_;
    Config              cfg_;
};

}  // namespace gn::link::raw_inject
