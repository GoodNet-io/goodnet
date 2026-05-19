// SPDX-License-Identifier: Apache-2.0
/// @file   examples/hello-echo/client.cpp
/// @brief  Minimal hello-echo client. Public SDK surface only —
///         `sdk/cpp/core.hpp` for the kernel lifecycle, the rest of
///         `sdk/cpp/*` (connect, subscribe) for the dial / receive
///         path. The C ABI in `sdk/core.h` is still under the hood;
///         we just don't unfold it line by line.
///
/// The shape:
///
///   gn::sdk::Core core(opts) →
///   core.connect_to → core.subscribe → session.send → wait.
///
/// Compared to the all-C-ABI shape, `Core` collapses the
/// create + reload_config + install_identity + init +
/// load_plugins_batch + start sequence (plus per-step error
/// printing) into a single statement.

#include <sdk/cpp/core.hpp>
#include <sdk/cpp/errors.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <span>
#include <thread>
#include <vector>

#ifndef GOODNET_NOISE_PLUGIN_PATH
#error "GOODNET_NOISE_PLUGIN_PATH must be defined at build time"
#endif
#ifndef GOODNET_TCP_PLUGIN_PATH
#error "GOODNET_TCP_PLUGIN_PATH must be defined at build time"
#endif

namespace {
constexpr std::uint32_t kEchoMsgId = 0x48454C4Fu;  // 'HELO'
}  // namespace

int main(int argc, char** argv) {
    const char* uri = argc > 1 ? argv[1] : "tcp://127.0.0.1:9100";

    try {
        gn::sdk::Core::Options opts;
        opts.plugins = {
            {GOODNET_NOISE_PLUGIN_PATH, {}},  // hash auto-computed
            {GOODNET_TCP_PLUGIN_PATH,   {}},
        };
        gn::sdk::Core core(opts);

        auto session = core.connect_to(uri);

        std::atomic<bool> received{false};
        std::vector<std::uint8_t> got;
        auto sub = core.subscribe(session.id(), kEchoMsgId,
            [&](gn_conn_id_t, std::span<const std::uint8_t> b) {
                got.assign(b.begin(), b.end());
                received.store(true, std::memory_order_release);
            });

        const char msg[] = "hello";
        (void)session.send(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(msg), sizeof(msg) - 1));

        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(2);
        while (!received.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (received.load(std::memory_order_acquire)) {
            std::fwrite(got.data(), 1, got.size(), stdout);
            std::fputc('\n', stdout);
            return 0;
        }
        std::fprintf(stderr, "no echo within 2s\n");
        return 1;
    } catch (const gn::sdk::Error& e) {
        std::fprintf(stderr, "%s\n  hint: %.*s\n",
                     e.what(),
                     static_cast<int>(e.hint().size()), e.hint().data());
        return 1;
    }
}
