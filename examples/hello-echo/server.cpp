// SPDX-License-Identifier: Apache-2.0
/// @file   examples/hello-echo/server.cpp
/// @brief  Minimal hello-echo server. Public SDK surface only —
///         `sdk/cpp/core.hpp` for the kernel lifecycle, the rest of
///         `sdk/cpp/*` for the bind / receive / echo path.
///
/// The shape:
///
///   gn::sdk::Core core(opts) →
///   core.listen_to → core.subscribe (echo via core.send_to in cb)
///   → core.wait.

#include <sdk/cpp/core.hpp>
#include <sdk/cpp/errors.hpp>

#include <cstdint>
#include <cstdio>
#include <span>

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
    const char* uri = argc > 1 ? argv[1] : "tcp://0.0.0.0:9100";

    try {
        gn::sdk::Core::Options opts;
        opts.plugins = {
            {GOODNET_NOISE_PLUGIN_PATH, {}},
            {GOODNET_TCP_PLUGIN_PATH,   {}},
        };
        gn::sdk::Core core(opts);

        auto sub = core.subscribe(
            GN_INVALID_ID, kEchoMsgId,
            [&core](gn_conn_id_t conn, std::span<const std::uint8_t> b) {
                core.send_to(conn, kEchoMsgId, b);
            });

        auto listener = core.listen_to(uri);
        std::fprintf(stderr, "hello-echo server listening on %s\n", uri);

        core.wait();
        return 0;
    } catch (const gn::sdk::Error& e) {
        std::fprintf(stderr, "%s\n  hint: %.*s\n",
                     e.what(),
                     static_cast<int>(e.hint().size()), e.hint().data());
        return 1;
    }
}
