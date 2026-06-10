// SPDX-License-Identifier: Apache-2.0
/// @file   examples/two_node/main.cpp
/// @brief  Two GoodNet kernels in one process, talking over TCP under
///         a Noise XX handshake — using ONLY the public SDK surface
///         (`sdk/cpp/core.hpp` for lifecycle, `sdk/cpp/*` for the
///         wire path).
///
/// The shape:
///
///   gn::sdk::Core alice(opts);
///   gn::sdk::Core bob  (opts);
///   alice.subscribe(...);  bob.on_conn_state(...) via host_api().
///   gn_core_listen(alice.raw(), "tcp://...:0");      // kernel-path listen
///   gn_core_dial(bob.raw(), "tcp://...:<port>");     // kernel-path connect
///   bob_conn arrives via GN_CONN_EVENT_CONNECTED, bob_trusted via trust event
///   bob.send_to(bob_conn, msg, "hello");
///   ... wait for alice's inbox flag ...

#include <sdk/conn_events.h>
#include <sdk/core.h>
#include <sdk/cpp/core.hpp>
#include <sdk/cpp/errors.hpp>
#include <sdk/cpp/link_carrier.hpp>
#include <sdk/cpp/subscription.hpp>
#include <sdk/gnet.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <span>
#include <string>
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

/// Inbound message sink populated through `Core::subscribe`.
struct Inbox {
    std::mutex                mu;
    std::condition_variable   cv;
    std::vector<std::uint8_t> payload;
    bool                      received = false;
};

}  // namespace

int main() {
    std::cout << "[demo] GoodNet two-node quickstart\n"
              << "[demo] noise plugin: " << GOODNET_NOISE_PLUGIN_PATH << "\n"
              << "[demo] tcp   plugin: " << GOODNET_TCP_PLUGIN_PATH   << "\n";

    try {
        gn::sdk::Core::Options opts;
        opts.plugins = {
            {GOODNET_NOISE_PLUGIN_PATH, {}},  // sha auto-computed
            {GOODNET_TCP_PLUGIN_PATH,   {}},
        };
        gn::sdk::Core alice(opts);
        gn::sdk::Core bob  (opts);

        // Register the gnet-v1 protocol layer on both kernel instances.
        // gn_core_init no longer auto-registers it; the host program owns
        // the protocol composition.
        if (const auto rc = gn_gnet_register_protocol(alice.raw()); rc != GN_OK)
            throw gn::sdk::Error(rc, "alice: gn_gnet_register_protocol");
        if (const auto rc = gn_gnet_register_protocol(bob.raw()); rc != GN_OK)
            throw gn::sdk::Error(rc, "bob: gn_gnet_register_protocol");

        Inbox alice_inbox;
        auto alice_sub = alice.subscribe(
            GN_INVALID_ID, kDemoMsgId,
            [&](gn_conn_id_t, std::span<const std::uint8_t> b) {
                std::lock_guard lk(alice_inbox.mu);
                alice_inbox.payload.assign(b.begin(), b.end());
                alice_inbox.received = true;
                alice_inbox.cv.notify_all();
            });

        std::atomic<gn_conn_id_t> bob_conn{GN_INVALID_ID};
        std::atomic<bool>         bob_trusted{false};
        std::atomic<bool>         bob_disconnected{false};
        auto bob_conn_sub = gn::sdk::Subscription::on_conn_state(
            bob.host_api(),
            [&](const gn_conn_event_t& ev) {
                switch (ev.kind) {
                    case GN_CONN_EVENT_CONNECTED:
                        bob_conn.store(ev.conn, std::memory_order_release);
                        if (ev.trust != GN_TRUST_UNTRUSTED) {
                            bob_trusted.store(true, std::memory_order_release);
                        }
                        break;
                    case GN_CONN_EVENT_TRUST_UPGRADED:
                        bob_trusted.store(true, std::memory_order_release);
                        break;
                    case GN_CONN_EVENT_DISCONNECTED:
                        bob_disconnected.store(true, std::memory_order_release);
                        break;
                    default: break;
                }
            });

        // Use the kernel-path listen (gn_core_listen) so the TCP accept
        // loop calls notify_connect → kick_handshake and the Noise XX
        // handshake runs. Core::listen_to goes through the compositor
        // extension API which bypasses notify_connect.
        if (const auto rc = gn_core_listen(alice.raw(), "tcp://127.0.0.1:0");
                rc != GN_OK) {
            throw gn::sdk::Error(rc, "alice: gn_core_listen");
        }
        // Port is stored in TcpLink::listen_port_ by both kernel and
        // compositor listen paths; composer_listen_port falls back to it.
        auto alice_carrier = gn::sdk::LinkCarrier::query(alice.host_api(), "tcp");
        const auto port = alice_carrier ? alice_carrier->listen_port() : std::uint16_t{0};
        if (port == 0) {
            std::cerr << "[alice] listen_port returned 0\n";
            return 1;
        }
        const std::string uri = "tcp://127.0.0.1:" + std::to_string(port);
        std::cout << "[alice] listening on " << uri << "\n";

        // Use gn_core_dial (kernel-path connect) so Bob's TCP connect
        // callback also calls notify_connect → kick_handshake. The conn id
        // arrives asynchronously via GN_CONN_EVENT_CONNECTED (bob_conn below).
        std::cout << "[bob]   dialling   " << uri << "\n";
        if (const auto rc = gn_core_dial(bob.raw(), uri.c_str()); rc != GN_OK)
            throw gn::sdk::Error(rc, "bob: gn_core_dial");

        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (!bob_trusted.load(std::memory_order_acquire) &&
               !bob_disconnected.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(20ms);
        }
        if (bob_disconnected.load(std::memory_order_acquire)) {
            std::cerr << "[demo] peer disconnected before trust upgrade\n";
            return 1;
        }
        if (!bob_trusted.load(std::memory_order_acquire)) {
            std::cerr << "[demo] timeout: handshake stalled\n";
            return 1;
        }
        std::cout << "[demo] noise XX complete; transport phase active\n";

        // bob_conn is set by the GN_CONN_EVENT_CONNECTED callback above.
        gn_conn_id_t cid = bob_conn.load(std::memory_order_acquire);
        if (cid == GN_INVALID_ID) {
            std::cerr << "[bob] no connection id observed\n";
            return 1;
        }

        const std::string greeting = "hello from bob";
        std::cout << "[bob]   send  msg_id=0x" << std::hex << kDemoMsgId
                  << std::dec << " payload=\"" << greeting << "\"\n";
        bob.send_to(cid, kDemoMsgId,
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(greeting.data()),
                greeting.size()));

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

        std::cout << "[demo] ok\n";
        return 0;
    } catch (const gn::sdk::Error& e) {
        std::fprintf(stderr, "%s\n  hint: %.*s\n",
                     e.what(),
                     static_cast<int>(e.hint().size()), e.hint().data());
        return 1;
    }
}
