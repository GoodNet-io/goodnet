// SPDX-License-Identifier: Apache-2.0
/// @file   examples/hello-echo/server.cpp
/// @brief  Minimal hello-echo server. Public SDK surface only —
///         `sdk/core.h` C ABI for the kernel handle, `sdk/cpp/*`
///         (LinkCarrier + listen_to) for the bind / accept path.
///
/// The shape:
///
///   gn_core_create → gn_core_init → gn_core_load_plugins_batch
///   → gn_core_start → gn::sdk::listen_to → gn_core_subscribe
///   (echo via gn_core_send_to inside the message callback).
///
/// NOTE(sdk-extension): `gn_core_listen` is not yet on the C ABI;
///                       agent #56 has it in flight. Until that lands
///                       this server uses the C++ `listen_to` sugar
///                       which goes through the `gn.link.<scheme>`
///                       extension surface — equally public.

#include <sdk/core.h>
#include <sdk/cpp/connect.hpp>
#include <sdk/cpp/link_carrier.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <sodium.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <ios>
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

constexpr std::uint32_t kEchoMsgId = 0x48454C4Fu;  // 'HELO'

[[nodiscard]] gn_result_t sha256_of_file(const std::string& path,
                                          std::uint8_t out_digest[32]) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return GN_ERR_NOT_FOUND;
    if (sodium_init() < 0) return GN_ERR_INTEGRITY_FAILED;
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    std::vector<unsigned char> buf(64 * 1024);
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

struct ServerCtx {
    gn_core_t* core = nullptr;
};

void on_echo(void* ud,
              gn_conn_id_t conn,
              std::uint32_t /*msg*/,
              const std::uint8_t* payload,
              std::size_t payload_size) {
    auto* s = static_cast<ServerCtx*>(ud);
    if (!s || !payload) return;
    /// Bounce the same payload straight back on the kernel msg-id
    /// bus the client subscribes to.
    (void)gn_core_send_to(s->core, conn, kEchoMsgId, payload, payload_size);
}

}  // namespace

int main(int argc, char** argv) {
    const char* uri = argc > 1 ? argv[1] : "tcp://0.0.0.0:9100";

    gn_core_t* core = gn_core_create();
    if (!core) return 1;

    if (gn_core_init(core) != GN_OK) {
        std::fprintf(stderr, "gn_core_init failed\n");
        gn_core_destroy(core);
        return 1;
    }

    const char* paths[] = {GOODNET_NOISE_PLUGIN_PATH, GOODNET_TCP_PLUGIN_PATH};
    std::vector<std::uint8_t> digests(2 * 32);
    for (std::size_t i = 0; i < 2; ++i) {
        if (sha256_of_file(paths[i], digests.data() + i * 32) != GN_OK) {
            std::fprintf(stderr, "sha256 failed for %s\n", paths[i]);
            gn_core_destroy(core);
            return 1;
        }
    }
    if (gn_core_load_plugins_batch(core, paths, digests.data(), 2) != GN_OK) {
        std::fprintf(stderr, "plugin batch load failed\n");
        gn_core_destroy(core);
        return 1;
    }

    ServerCtx ctx{core};
    const std::uint64_t sub = gn_core_subscribe(
        core, kEchoMsgId, &on_echo, &ctx);
    if (sub == 0) {
        std::fprintf(stderr, "gn_core_subscribe failed\n");
        gn_core_destroy(core);
        return 1;
    }

    if (gn_core_start(core) != GN_OK) {
        std::fprintf(stderr, "gn_core_start failed\n");
        gn_core_destroy(core);
        return 1;
    }

    auto listener = gn::sdk::listen_to(gn_core_host_api(core), uri);
    if (!listener) {
        std::fprintf(stderr, "listen_to %s failed\n", uri);
        gn_core_destroy(core);
        return 1;
    }
    std::fprintf(stderr, "hello-echo server listening on %s\n", uri);

    /// Spin on `gn_core_wait` until an external `gn_core_stop` (or
    /// SIGTERM upstream) lands. Pure data path is event-driven; the
    /// main thread has nothing to do past listen.
    gn_core_wait(core);

    gn_core_unsubscribe(core, sub);
    gn_core_destroy(core);
    return 0;
}
