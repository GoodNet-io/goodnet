// SPDX-License-Identifier: Apache-2.0
/// @file   examples/two_node/main.cpp
/// @brief  Two GoodNet kernels in one process, talking over TCP under
///         a Noise XX handshake — using ONLY the public SDK surface
///         (`sdk/core.h` C ABI + `sdk/cpp/*` C++ sugar).
///
/// No `core/*` or `plugins/*` private headers. Mirrors the canonical
/// embedding shape from `apps/gssh/mode_bridge.cpp`:
///
///   create core → install_identity (skipped: ephemeral)
///   → gn_core_init → gn_core_load_plugins_batch (noise + tcp)
///   → subscribe (conn_state + msg) → gn_core_start
///   → listen / connect → pump until message arrives.

#include <sdk/conn_events.h>
#include <sdk/core.h>
#include <sdk/cpp/connect.hpp>
#include <sdk/cpp/link_carrier.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <sodium.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <ios>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifndef GOODNET_NOISE_PLUGIN_PATH
#error "GOODNET_NOISE_PLUGIN_PATH must be defined at build time"
#endif
#ifndef GOODNET_TCP_PLUGIN_PATH
#error "GOODNET_TCP_PLUGIN_PATH must be defined at build time"
#endif

namespace {

using namespace std::chrono_literals;

constexpr std::uint32_t kDemoMsgId = 0xC0FFEEu;

/// Helper: compute SHA-256 of a file into @p out_digest. Matches the
/// digest the kernel's manifest verifier computes inside
/// `gn_core_load_plugin`.
[[nodiscard]] gn_result_t sha256_of_file(const std::string& path,
                                          std::uint8_t out_digest[32]) {
    if (!out_digest) return GN_ERR_NULL_ARG;
    std::ifstream f(path, std::ios::binary);
    if (!f) return GN_ERR_NOT_FOUND;
    if (sodium_init() < 0) return GN_ERR_INTEGRITY_FAILED;

    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    constexpr std::size_t kChunk = 64 * 1024;
    std::vector<unsigned char> buf(kChunk);
    while (f.good()) {
        f.read(reinterpret_cast<char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
        const auto n = f.gcount();
        if (n > 0) {
            crypto_hash_sha256_update(
                &st, buf.data(), static_cast<unsigned long long>(n));
        }
        if (!f.good() && !f.eof()) return GN_ERR_INTEGRITY_FAILED;
    }
    crypto_hash_sha256_final(&st, out_digest);
    return GN_OK;
}

/// Inbound message sink — populated through `gn_core_subscribe`.
struct Inbox {
    std::mutex                mu;
    std::condition_variable   cv;
    std::vector<std::uint8_t> payload;
    bool                      received = false;
};

void on_message(void* ud,
                 gn_conn_id_t /*conn*/,
                 std::uint32_t /*msg_id*/,
                 const std::uint8_t* payload,
                 std::size_t payload_size) {
    auto* inbox = static_cast<Inbox*>(ud);
    if (!inbox || !payload) return;
    {
        std::lock_guard lk(inbox->mu);
        inbox->payload.assign(payload, payload + payload_size);
        inbox->received = true;
    }
    inbox->cv.notify_all();
}

/// Conn-event sink for the dialing side — flips a flag once the
/// Noise handshake lifts trust above `Untrusted`.
struct DialState {
    std::atomic<gn_conn_id_t> conn_id{GN_INVALID_ID};
    std::atomic<bool>         trust_upgraded{false};
    std::atomic<bool>         disconnected{false};
};

void on_conn_event(void* ud, const gn_conn_event_t* ev) {
    auto* s = static_cast<DialState*>(ud);
    if (!s || !ev) return;
    switch (ev->kind) {
        case GN_CONN_EVENT_CONNECTED:
            s->conn_id.store(ev->conn, std::memory_order_release);
            /// Loopback connections may land already above Untrusted
            /// on the synchronous CONNECTED event; treat that as a
            /// green light the same way `gssh/mode_bridge` does.
            if (ev->trust != GN_TRUST_UNTRUSTED) {
                s->trust_upgraded.store(true, std::memory_order_release);
            }
            break;
        case GN_CONN_EVENT_TRUST_UPGRADED:
            s->trust_upgraded.store(true, std::memory_order_release);
            break;
        case GN_CONN_EVENT_DISCONNECTED:
            s->disconnected.store(true, std::memory_order_release);
            break;
        default:
            break;
    }
}

/// Owns one kernel handle + its loaded plugins. Destructor walks
/// `gn_core_destroy` which drives `PreShutdown → Shutdown` and drains
/// every loaded plugin.
class Node {
public:
    explicit Node(std::string name) : name_(std::move(name)) {
        core_ = gn_core_create();
        if (!core_) std::exit(1);

        if (gn_core_init(core_) != GN_OK) {
            std::cerr << "[" << name_ << "] gn_core_init failed\n";
            std::exit(1);
        }

        /// Batch-load noise + tcp so the kernel's PluginManager
        /// composes both registrations in one pass — same shape gssh
        /// uses in `discover_and_load_plugins`.
        const std::string paths[] = {
            GOODNET_NOISE_PLUGIN_PATH,
            GOODNET_TCP_PLUGIN_PATH,
        };
        std::vector<std::uint8_t> digests(2 * 32);
        const char* c_paths[2] = {paths[0].c_str(), paths[1].c_str()};
        for (std::size_t i = 0; i < 2; ++i) {
            if (sha256_of_file(paths[i], digests.data() + i * 32) != GN_OK) {
                std::cerr << "[" << name_ << "] sha256 failed for "
                          << paths[i] << "\n";
                std::exit(1);
            }
        }
        if (const auto rc = gn_core_load_plugins_batch(
                core_, c_paths, digests.data(), 2);
            rc != GN_OK) {
            std::cerr << "[" << name_ << "] plugin batch load failed: "
                      << gn_strerror(rc) << "\n";
            std::exit(1);
        }
    }

    ~Node() {
        if (core_) gn_core_destroy(core_);
    }

    Node(const Node&)            = delete;
    Node& operator=(const Node&) = delete;

    [[nodiscard]] gn_core_t*         core() const noexcept { return core_; }
    [[nodiscard]] const host_api_t*  api()  const noexcept {
        return gn_core_host_api(core_);
    }
    [[nodiscard]] const std::string& name() const noexcept { return name_; }

private:
    std::string name_;
    gn_core_t*  core_ = nullptr;
};

}  // namespace

int main() {
    std::cout << "[demo] GoodNet two-node quickstart\n"
              << "[demo] noise plugin: " << GOODNET_NOISE_PLUGIN_PATH << "\n"
              << "[demo] tcp   plugin: " << GOODNET_TCP_PLUGIN_PATH   << "\n";

    Node alice("alice");
    Node bob  ("bob");

    /// Alice subscribes for the demo msg id BEFORE start so the
    /// callback is in place when the first inbound envelope lands.
    Inbox alice_inbox;
    const std::uint64_t msg_sub = gn_core_subscribe(
        alice.core(), kDemoMsgId, &on_message, &alice_inbox);
    if (msg_sub == 0) {
        std::cerr << "[alice] gn_core_subscribe failed\n";
        return 1;
    }

    /// Bob subscribes to conn-state so we can wait on trust upgrade
    /// before the first `gn_core_send_to`.
    DialState bob_state;
    const std::uint64_t conn_sub = gn_core_on_conn_state(
        bob.core(), &on_conn_event, &bob_state);
    if (conn_sub == 0) {
        std::cerr << "[bob] gn_core_on_conn_state failed\n";
        return 1;
    }

    /// `gn_core_start` walks each kernel from Ready → Running before
    /// any traffic can flow.
    if (gn_core_start(alice.core()) != GN_OK ||
        gn_core_start(bob.core())   != GN_OK) {
        std::cerr << "[demo] gn_core_start failed\n";
        return 1;
    }

    /// Alice listens through the `gn.link.tcp` extension that the
    /// just-loaded tcp plugin published. The carrier owns the
    /// listener for the lifetime of the demo.
    auto alice_listener = gn::sdk::listen_to(
        alice.api(), "tcp://127.0.0.1:0");
    if (!alice_listener) {
        std::cerr << "[alice] listen_to failed\n";
        return 1;
    }
    const auto port = alice_listener->listen_port();
    if (port == 0) {
        std::cerr << "[alice] listen_port returned 0 — composer port "
                     "not exposed by the link plugin\n";
        return 1;
    }
    const std::string uri = "tcp://127.0.0.1:" + std::to_string(port);
    std::cout << "[alice] listening on " << uri << "\n";

    /// Bob dials through `gn_core_connect`. The kernel resolves the
    /// scheme to the same tcp plugin Alice listens on.
    std::cout << "[bob]   dialling   " << uri << "\n";
    gn_conn_id_t bob_conn = GN_INVALID_ID;
    if (const auto rc = gn_core_connect(
            bob.core(), uri.c_str(), /*scheme=*/nullptr, &bob_conn);
        rc != GN_OK) {
        std::cerr << "[bob] connect failed: " << gn_strerror(rc) << "\n";
        return 1;
    }

    /// Wait for Noise XX to lift Bob's side from Untrusted to Peer.
    /// The kernel publishes `TRUST_UPGRADED` once the handshake
    /// completes on the dial strand.
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!bob_state.trust_upgraded.load(std::memory_order_acquire) &&
           !bob_state.disconnected.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }
    if (bob_state.disconnected.load(std::memory_order_acquire)) {
        std::cerr << "[demo] peer disconnected before trust upgrade\n";
        return 1;
    }
    if (!bob_state.trust_upgraded.load(std::memory_order_acquire)) {
        std::cerr << "[demo] timeout: handshake stalled\n";
        return 1;
    }
    std::cout << "[demo] noise XX complete; transport phase active\n";

    /// Some link plugins land `bob_conn` synchronously on the
    /// `gn_core_connect` return; others publish only through the
    /// CONNECTED event. Reach for whichever produced the id.
    if (bob_conn == GN_INVALID_ID) {
        bob_conn = bob_state.conn_id.load(std::memory_order_acquire);
    }
    if (bob_conn == GN_INVALID_ID) {
        std::cerr << "[bob] no connection id observed\n";
        return 1;
    }

    const std::string greeting = "hello from bob";
    std::cout << "[bob]   send  msg_id=0x" << std::hex << kDemoMsgId
              << std::dec << " payload=\"" << greeting << "\"\n";

    if (const auto rc = gn_core_send_to(
            bob.core(), bob_conn, kDemoMsgId,
            reinterpret_cast<const std::uint8_t*>(greeting.data()),
            greeting.size());
        rc != GN_OK) {
        std::cerr << "[bob] send failed: " << gn_strerror(rc) << "\n";
        return 1;
    }

    /// Wait for Alice's subscribe callback to flip the inbox flag.
    {
        std::unique_lock lk(alice_inbox.mu);
        if (!alice_inbox.cv.wait_for(lk, 3s,
                [&] { return alice_inbox.received; })) {
            std::cerr << "[demo] timeout: alice never received the "
                         "message\n";
            return 1;
        }
    }
    const std::string echoed(
        reinterpret_cast<const char*>(alice_inbox.payload.data()),
        alice_inbox.payload.size());
    std::cout << "[alice] recv payload=\"" << echoed << "\"\n";

    gn_core_unsubscribe(alice.core(), msg_sub);
    gn_core_off_conn_state(bob.core(), conn_sub);

    std::cout << "[demo] ok\n";
    return 0;
}
