/// @file   tests/unit/integration/test_raw_inject.cpp
/// @brief  End-to-end inject path: plain TCP client → raw_inject link
///         → kernel inject(MESSAGE) → echo handler → kernel send
///         → raw_inject.send → TCP socket.
///
/// The whole chain runs in one process: a real `Kernel` plus the
/// `raw-v1` protocol layer plus the `raw_inject` link plus a stub
/// handler that echoes its payload back through `host_api->send`.
/// The client uses plain POSIX sockets — no SDK headers — so the
/// success criterion is a byte-for-byte round trip of "hello".

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <tests/util/protocol_setup.hpp>

#include <plugins/links/raw_inject/raw_inject.hpp>
#include <plugins/protocols/raw/raw.hpp>

#include <sdk/cpp/protocol_layer.hpp>
#include <sdk/handler.h>
#include <sdk/link.h>
#include <sdk/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace {

using namespace std::chrono_literals;
using namespace gn;
using namespace gn::core;
using gn::link::raw_inject::RawInjectLink;

/// Adapter that bridges the raw protocol's C vtable into the C++
/// `IProtocolLayer` the kernel registry stores. Mirrors the slim
/// `VtableProtocolLayer` the goodnet kernel keeps for plugin-loaded
/// protocols, narrowed to what this test exercises (frame on the
/// reply path, `allowed_trust_mask` on `notify_connect`'s trust
/// gate, `protocol_id`).
class RawProtocolLayer final : public ::gn::IProtocolLayer {
public:
    RawProtocolLayer()
        : vtable_(::gn::protocol::raw::make_vtable()) {}

    [[nodiscard]] std::string_view protocol_id() const noexcept override {
        return "raw-v1";
    }

    [[nodiscard]] std::size_t max_payload_size() const noexcept override {
        return vtable_.max_payload_size
            ? vtable_.max_payload_size(nullptr) : 0;
    }

    [[nodiscard]] std::uint32_t allowed_trust_mask() const noexcept override {
        return vtable_.allowed_trust_mask
            ? vtable_.allowed_trust_mask(nullptr)
            : ::gn::IProtocolLayer::allowed_trust_mask();
    }

    ::gn::Result<::gn::DeframeResult> deframe(
        ::gn::ConnectionContext& /*ctx*/,
        std::span<const std::uint8_t> /*bytes*/) override {
        /// Inject(MESSAGE) skips deframe, and the reply path does
        /// not call back into deframe either — leave the slot a
        /// success no-op so the registry's invariants stay clean.
        return ::gn::DeframeResult{};
    }

    ::gn::Result<std::vector<std::uint8_t>> frame(
        ::gn::ConnectionContext& ctx,
        const gn_message_t& msg) override {
        std::uint8_t* out_bytes = nullptr;
        std::size_t   out_size  = 0;
        void*         out_ud    = nullptr;
        void (*out_free)(void*, std::uint8_t*) = nullptr;
        const auto rc = vtable_.frame(
            nullptr, &ctx, &msg,
            &out_bytes, &out_size, &out_ud, &out_free);
        if (rc != GN_OK) {
            return std::unexpected{::gn::Error{rc, "raw frame failed"}};
        }
        std::vector<std::uint8_t> v(out_bytes, out_bytes + out_size);
        if (out_free) out_free(out_ud, out_bytes);
        return v;
    }

private:
    gn_protocol_layer_vtable_t vtable_;
};

/// Echo handler: every message it receives, replies on the same conn
/// with the same payload via `host_api->send`.
struct EchoHandler {
    host_api_t*       api = nullptr;
    std::uint32_t     msg_id = 0;
    std::atomic<int>  calls{0};

    static gn_propagation_t handle(void* self, const gn_message_t* env) {
        auto* h = static_cast<EchoHandler*>(self);
        h->calls.fetch_add(1);
        if (h->api && h->api->send) {
            (void)h->api->send(h->api->host_ctx,
                                env->conn_id,
                                h->msg_id,
                                env->payload, env->payload_size);
        }
        return GN_PROPAGATION_CONSUMED;
    }
};

/// Link vtable thunks bridging the raw_inject C++ class into the C
/// ABI shape the kernel calls through `register_vtable`.
struct LinkThunks {
    static const char* scheme(void*) { return "raw-inject"; }
    static gn_result_t listen(void* self, const char* uri) {
        return static_cast<RawInjectLink*>(self)->listen(uri);
    }
    static gn_result_t connect(void* self, const char* uri) {
        return static_cast<RawInjectLink*>(self)->connect(uri);
    }
    static gn_result_t send(void* self, gn_conn_id_t conn,
                             const std::uint8_t* bytes, size_t size) {
        return static_cast<RawInjectLink*>(self)->send(
            conn, std::span<const std::uint8_t>(bytes, size));
    }
    static gn_result_t send_batch(void*, gn_conn_id_t,
                                    const gn_byte_span_t*, size_t) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static gn_result_t disconnect(void* self, gn_conn_id_t conn) {
        return static_cast<RawInjectLink*>(self)->disconnect(conn);
    }
    static const char* extension_name(void*)   { return ""; }
    static const void* extension_vtable(void*) { return nullptr; }
    static void        destroy(void*)          {}

    static gn_link_vtable_t make_vtable() {
        gn_link_vtable_t v{};
        v.api_size         = sizeof(gn_link_vtable_t);
        v.scheme           = &scheme;
        v.listen           = &listen;
        v.connect          = &connect;
        v.send             = &send;
        v.send_batch       = &send_batch;
        v.disconnect       = &disconnect;
        v.extension_name   = &extension_name;
        v.extension_vtable = &extension_vtable;
        v.destroy          = &destroy;
        return v;
    }
};

/// Open a TCP socket to 127.0.0.1:port with a short recv timeout so a
/// silent kernel does not block the test indefinitely.
[[nodiscard]] int connect_with_timeout(std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    timeval tv{};
    tv.tv_sec  = 3;
    tv.tv_usec = 0;
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(0x7F000001);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr),
                  sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

}  // namespace

// ── End-to-end inject round-trip ─────────────────────────────────────────

TEST(RawInjectIntegration, PlainTcpClientRoundTripsThroughInject) {
    /// Kernel + raw-v1 protocol layer (so the connection's protocol
    /// allows opaque-byte passthrough on both edges).
    Kernel kernel;
    auto raw_layer = std::make_shared<RawProtocolLayer>();
    ::gn::test::util::register_default_protocol(kernel, raw_layer);

    PluginContext plugin_ctx;
    plugin_ctx.plugin_name = "raw-inject-e2e";
    plugin_ctx.kernel      = &kernel;
    auto api = build_host_api(plugin_ctx);

    /// Local identity — inject's `build_envelope` reads it as
    /// `receiver_pk`. Anonymous source (`remote_pk` = zero) is the
    /// raw_inject contract for foreign-system clients.
    PublicKey local_pk;
    local_pk.fill(0x11);
    kernel.identities().add(local_pk);

    /// Echo handler under raw-v1 + msg_id 0x10FF.
    EchoHandler echo;
    echo.api    = &api;
    echo.msg_id = 0x10FF;

    gn_handler_vtable_t h_vt{};
    h_vt.api_size       = sizeof(gn_handler_vtable_t);
    h_vt.handle_message = &EchoHandler::handle;

    gn_register_meta_t h_meta{};
    h_meta.api_size = sizeof(gn_register_meta_t);
    h_meta.name     = "raw-v1";
    h_meta.msg_id   = 0x10FF;
    h_meta.priority = 128;

    std::uint64_t hid = 0;
    ASSERT_EQ(api.register_vtable(api.host_ctx, GN_REGISTER_HANDLER,
                                   &h_meta, &h_vt, &echo, &hid),
              GN_OK);

    /// Raw-inject link. Bound to the same host_api the kernel built;
    /// the link calls `notify_connect` / `inject` / `notify_disconnect`
    /// through it.
    auto link = std::make_shared<RawInjectLink>();
    link->set_host_api(&api);

    gn::link::raw_inject::Config cfg;
    cfg.default_msg_id = 0x10FF;
    cfg.encode_msg_id  = "config";
    link->set_config(cfg);

    static auto link_vt = LinkThunks::make_vtable();

    gn_register_meta_t link_meta{};
    link_meta.api_size    = sizeof(gn_register_meta_t);
    link_meta.name        = "raw-inject";
    link_meta.protocol_id = "raw-v1";

    std::uint64_t lid = 0;
    ASSERT_EQ(api.register_vtable(api.host_ctx, GN_REGISTER_LINK,
                                   &link_meta, &link_vt,
                                   link.get(), &lid),
              GN_OK);

    ASSERT_EQ(link->listen("raw-inject://127.0.0.1:0"), GN_OK);
    const auto port = link->listen_port();
    ASSERT_GT(port, 0);

    /// 2. Open a plain POSIX TCP socket, connect to the listen port.
    const int fd = connect_with_timeout(port);
    ASSERT_GE(fd, 0);

    /// Wait for the accept side to register a session — without this
    /// the write below can race the accept loop and the inject pump
    /// has not yet bound `session->conn_id`.
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (link->session_count() == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_GE(link->session_count(), 1u);

    /// 3. Write "hello".
    const char* msg = "hello";
    ASSERT_EQ(::write(fd, msg, 5), 5);

    /// 4. Read back the echoed bytes.
    std::array<char, 16> rx{};
    ssize_t total = 0;
    const auto rx_deadline = std::chrono::steady_clock::now() + 3s;
    while (total < 5 && std::chrono::steady_clock::now() < rx_deadline) {
        ssize_t n = ::read(fd, rx.data() + total, rx.size() - total);
        if (n > 0) total += n;
        else if (n == 0) break;
        else break;
    }

    /// 5. Verify reply equals "hello".
    EXPECT_EQ(echo.calls.load(), 1);
    ASSERT_EQ(total, 5);
    EXPECT_EQ(std::string(rx.data(), rx.data() + total), "hello");

    /// 6. Disconnect cleanly.
    ::close(fd);

    link->shutdown();
    (void)api.unregister_vtable(api.host_ctx, lid);
    (void)api.unregister_vtable(api.host_ctx, hid);
}
