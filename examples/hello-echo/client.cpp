// SPDX-License-Identifier: Apache-2.0
/// @file   examples/hello-echo/client.cpp
/// @brief  Minimal hello-echo client. Public SDK surface only —
///         `sdk/core.h` C ABI for the kernel handle, `sdk/cpp/*` C++
///         sugar for the connect / subscribe path.
///
/// The shape:
///
///   gn_core_create → gn_core_init → gn_core_load_plugins_batch
///   → gn_core_start → gn::sdk::connect_to → send "hello"
///   → gn_core_subscribe for the reply.

#include <sdk/core.h>
#include <sdk/cpp/connect.hpp>
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

struct EchoSink {
    std::atomic<bool>     received{false};
    std::vector<std::uint8_t> payload;
};

void on_echo(void* ud,
              gn_conn_id_t /*conn*/,
              std::uint32_t /*msg*/,
              const std::uint8_t* payload,
              std::size_t payload_size) {
    auto* sink = static_cast<EchoSink*>(ud);
    if (!sink || !payload) return;
    sink->payload.assign(payload, payload + payload_size);
    sink->received.store(true, std::memory_order_release);
}

}  // namespace

int main(int argc, char** argv) {
    const char* uri = argc > 1 ? argv[1] : "tcp://127.0.0.1:9100";

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

    EchoSink sink;
    const std::uint64_t sub = gn_core_subscribe(
        core, kEchoMsgId, &on_echo, &sink);
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

    /// `gn::sdk::connect_to` parses the scheme, queries the matching
    /// `gn.link.<scheme>` extension, and returns a session that owns
    /// the carrier + conn id.
    auto session = gn::sdk::connect_to(gn_core_host_api(core), uri);
    if (!session) {
        std::fprintf(stderr, "connect_to %s failed\n", uri);
        gn_core_destroy(core);
        return 1;
    }

    const char msg[] = "hello";
    if (gn_core_send_to(core, session->id(), kEchoMsgId,
                         reinterpret_cast<const std::uint8_t*>(msg),
                         sizeof(msg) - 1) != GN_OK) {
        std::fprintf(stderr, "send failed\n");
        gn_core_destroy(core);
        return 1;
    }

    /// Wait up to 2 s for the echo reply.
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(2);
    while (!sink.received.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (sink.received.load(std::memory_order_acquire)) {
        std::fwrite(sink.payload.data(), 1, sink.payload.size(), stdout);
        std::fputc('\n', stdout);
    } else {
        std::fprintf(stderr, "no echo within 2s\n");
    }

    gn_core_unsubscribe(core, sub);
    gn_core_destroy(core);
    return sink.received.load() ? 0 : 1;
}
