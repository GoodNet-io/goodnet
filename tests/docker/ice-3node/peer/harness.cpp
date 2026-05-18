// SPDX-License-Identifier: Apache-2.0
//
// 3-node ICE harness binary.
//
// Drives the C ABI from `sdk/core.h` to spin up a kernel, load the
// ICE link plugin (plus dependencies), exchange pubkeys with the
// peer via a shared volume, issue an outbound ICE connect, and
// write a `.done` marker on the first inbound byte. Replaces the
// `goodnetd` daemon for the docker compose ICE scenarios.

// Pin <climits>/<limits.h> at the top: libstdc++ 15.2 has a known bug
// where `<bits/atomic_wait.h>` references INT_MAX without including
// <climits>; same for `<bits/semaphore_base.h>` and _POSIX_SEM_VALUE_MAX.
// Pulling the C headers in first makes the macros available before
// the offending GCC headers fire.
#include <climits>
#include <limits.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <openssl/evp.h>

#include <sdk/conn_events.h>
#include <sdk/core.h>
#include <sdk/types.h>

namespace fs = std::filesystem;
using clk    = std::chrono::steady_clock;

namespace {

// ── Globals shared with subscription callbacks ───────────────────────────

std::string                  g_self_name = "?";
std::atomic<bool>            g_inbound_seen{false};
std::atomic<gn_conn_id_t>    g_active_conn{GN_INVALID_ID};
std::atomic<bool>            g_conn_ready{false};
clk::time_point              g_t0;
std::mutex                   g_log_mu;

double seconds_since_start() {
    const auto now = clk::now();
    return std::chrono::duration<double>(now - g_t0).count();
}

void timed_log(std::string_view msg) {
    std::lock_guard lk(g_log_mu);
    std::printf("[peer-%s] t=%.3fs %.*s\n",
                g_self_name.c_str(),
                seconds_since_start(),
                static_cast<int>(msg.size()),
                msg.data());
    std::fflush(stdout);
}

// ── Helpers ──────────────────────────────────────────────────────────────

std::string getenv_default(const char* name, std::string fallback) {
    if (const char* v = std::getenv(name); v != nullptr && *v) {
        return std::string(v);
    }
    return fallback;
}

std::string slurp(const fs::path& p) {
    std::ifstream f(p);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void hex_encode(const uint8_t* in, size_t n, std::string& out) {
    static const char* lut = "0123456789abcdef";
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out[i * 2]     = lut[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = lut[in[i]        & 0xF];
    }
}

// Atomic file write: tmp file + rename so a reader never observes a
// partial file. The peer poll on the other side reads as soon as the
// inode is visible, so torn writes would break the handshake.
bool write_file_atomic(const fs::path& target, std::string_view body) {
    auto tmp = target;
    tmp += ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f.write(body.data(), static_cast<std::streamsize>(body.size()));
        if (!f) return false;
    }
    std::error_code ec;
    fs::rename(tmp, target, ec);
    return !ec;
}

bool sha256_file(const fs::path& path, uint8_t out[32]) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    char buf[8192];
    while (f) {
        f.read(buf, sizeof(buf));
        const auto n = f.gcount();
        if (n > 0 &&
            EVP_DigestUpdate(ctx, buf, static_cast<size_t>(n)) != 1) {
            EVP_MD_CTX_free(ctx);
            return false;
        }
    }
    unsigned int outlen = 32;
    int rc = EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
    return rc == 1 && outlen == 32;
}

// ── Subscription callbacks ───────────────────────────────────────────────

void on_inbound_msg(void*               /*user_data*/,
                    gn_conn_id_t        conn,
                    uint32_t            msg_id,
                    const uint8_t*      /*payload*/,
                    size_t              payload_size) {
    (void)msg_id;
    (void)conn;
    if (!g_inbound_seen.exchange(true)) {
        std::string m = "first inbound byte (size=";
        m += std::to_string(payload_size);
        m += ")";
        timed_log(m);
    }
}

void on_conn_state(void* /*user_data*/, const gn_conn_event_t* ev) {
    if (ev == nullptr) return;
    if (ev->kind == GN_CONN_EVENT_CONNECTED) {
        if (g_active_conn.load() == GN_INVALID_ID) {
            g_active_conn.store(ev->conn);
        }
        g_conn_ready.store(true);
        timed_log("conn CONNECTED");
    } else if (ev->kind == GN_CONN_EVENT_DISCONNECTED) {
        timed_log("conn DISCONNECTED");
    } else if (ev->kind == GN_CONN_EVENT_TRUST_UPGRADED) {
        timed_log("conn TRUST_UPGRADED");
    }
}

// ── Plugin manifest entry ────────────────────────────────────────────────

struct PluginSpec {
    std::string name;        ///< human-readable, used for logs only.
    fs::path    path;        ///< filesystem path to the .so.
};

}  // namespace

int main() {
    g_t0 = clk::now();

    const std::string peer_name   = getenv_default("PEER_NAME", "?");
    const std::string wait_peer   = getenv_default("WAIT_FOR_PEER", "B");
    const std::string signal_dir  = getenv_default("SIGNAL_DIR",
                                                   "/var/lib/ice3-signal");
    const std::string config_path = getenv_default("CONFIG",
                                                   "/etc/goodnet/peer.json");
    const std::string plugins_dir = getenv_default("PLUGINS_DIR",
                                                   "/plugins");
    const bool quic_over_ice =
        getenv_default("QUIC_OVER_ICE", "false") == "true";
    const double timeout_s = std::stod(
        getenv_default("HARNESS_TIMEOUT_S", "30"));

    g_self_name = peer_name;

    const fs::path self_pk_path = fs::path(signal_dir) /
                                  (peer_name + ".pk");
    const fs::path peer_pk_path = fs::path(signal_dir) /
                                  (wait_peer + ".pk");
    const fs::path done_path    = fs::path(signal_dir) /
                                  (peer_name + ".done");
    const fs::path fail_path    = fs::path(signal_dir) /
                                  (peer_name + ".fail");

    auto write_fail = [&](std::string_view reason) {
        std::string body(reason);
        body.push_back('\n');
        (void)write_file_atomic(fail_path, body);
    };

    timed_log("start");

    // Read config text from disk.
    std::string config_text;
    try {
        config_text = slurp(config_path);
    } catch (...) {
        timed_log("config slurp threw");
        write_fail("config slurp threw");
        return 1;
    }
    if (config_text.empty()) {
        timed_log("config empty");
        write_fail("config empty");
        return 1;
    }

    // Bring the kernel up + inject the JSON config so plugin code that
    // queries `host_api->config_get("ice.stun_servers", ...)` sees the
    // populated tree at init time.
    gn_core_t* core = gn_core_create();
    if (core == nullptr) {
        timed_log("gn_core_create returned null");
        write_fail("gn_core_create returned null");
        return 1;
    }

    if (gn_result_t rc = gn_core_reload_config_json(core, config_text.c_str());
        rc != GN_OK) {
        std::string m = "gn_core_reload_config_json rc=";
        m += std::to_string(rc);
        timed_log(m);
        write_fail("reload_config_json failed");
        gn_core_destroy(core);
        return 1;
    }

    if (gn_result_t rc = gn_core_init(core); rc != GN_OK) {
        std::string m = "gn_core_init rc=";
        m += std::to_string(rc);
        timed_log(m);
        write_fail("gn_core_init failed");
        gn_core_destroy(core);
        return 1;
    }

    // Publish our pubkey now — the peer is polling the signal dir
    // and the sooner we drop the file the sooner the connectivity
    // dance can begin. The kernel is in `Ready` post-init; `start`
    // is required before inbound bytes route, but pubkey extraction
    // works as soon as the identity is minted (during `init`).
    uint8_t pk[GN_PUBLIC_KEY_BYTES] = {};
    if (gn_result_t rc = gn_core_get_pubkey(core, pk); rc != GN_OK) {
        std::string m = "gn_core_get_pubkey rc=";
        m += std::to_string(rc);
        timed_log(m);
        write_fail("get_pubkey failed");
        gn_core_destroy(core);
        return 1;
    }
    std::string pk_hex;
    hex_encode(pk, GN_PUBLIC_KEY_BYTES, pk_hex);
    if (!write_file_atomic(self_pk_path, pk_hex)) {
        timed_log("write self pk failed");
        write_fail("write self pk failed");
        gn_core_destroy(core);
        return 1;
    }
    timed_log("pubkey published");

    // Plugin set: security (null + noise), link (udp + tcp + ice),
    // optional quic, handler-heartbeat. The order here is the order
    // the manager hands to the service resolver; security must land
    // before link.ice because the security registry is consulted on
    // first session attach.
    std::vector<PluginSpec> specs = {
        {"goodnet_security_null",
            fs::path(plugins_dir) / "libgoodnet_security_null.so"},
        {"goodnet_security_noise",
            fs::path(plugins_dir) / "libgoodnet_security_noise.so"},
        {"goodnet_link_udp",
            fs::path(plugins_dir) / "libgoodnet_link_udp.so"},
        {"goodnet_link_tcp",
            fs::path(plugins_dir) / "libgoodnet_link_tcp.so"},
        {"goodnet_link_ice",
            fs::path(plugins_dir) / "libgoodnet_link_ice.so"},
        {"goodnet_handler_heartbeat",
            fs::path(plugins_dir) / "libgoodnet_handler_heartbeat.so"},
    };
    if (quic_over_ice) {
        specs.insert(specs.end() - 1,
            {"goodnet_link_quic",
             fs::path(plugins_dir) / "libgoodnet_link_quic.so"});
    }

    // Compute SHA-256 for each plugin so `gn_core_load_plugins_batch`
    // can verify integrity. We're loading the *same file* we just
    // hashed; the digest matches by construction unless the file is
    // racing with another writer (it isn't — the image is read-only
    // at runtime).
    std::vector<std::string> paths_owned;
    paths_owned.reserve(specs.size());
    std::vector<const char*> path_ptrs;
    path_ptrs.reserve(specs.size());
    std::vector<uint8_t> digests(specs.size() * 32, 0);
    for (size_t i = 0; i < specs.size(); ++i) {
        if (!sha256_file(specs[i].path, &digests[i * 32])) {
            std::string m = "sha256 failed for " + specs[i].path.string();
            timed_log(m);
            write_fail(m);
            gn_core_destroy(core);
            return 1;
        }
        paths_owned.push_back(specs[i].path.string());
        path_ptrs.push_back(paths_owned.back().c_str());
    }

    if (gn_result_t rc = gn_core_load_plugins_batch(
            core, path_ptrs.data(), digests.data(), path_ptrs.size());
        rc != GN_OK) {
        std::string m = "gn_core_load_plugins_batch rc=";
        m += std::to_string(rc);
        timed_log(m);
        write_fail("plugin batch load failed");
        gn_core_destroy(core);
        return 1;
    }
    timed_log("plugins loaded");

    if (gn_result_t rc = gn_core_start(core); rc != GN_OK) {
        std::string m = "gn_core_start rc=";
        m += std::to_string(rc);
        timed_log(m);
        write_fail("gn_core_start failed");
        gn_core_destroy(core);
        return 1;
    }
    timed_log("kernel running");

    // Subscribe for inbound traffic + connection events. The harness
    // listens on msg_id=1 (the link-ice convention) for the
    // single-byte ping the other side will send once its outbound
    // connect lands. msg_id=0 would be rejected by the kernel as the
    // invalid-envelope sentinel.
    constexpr uint32_t kPingMsgId = 1;
    const uint64_t sub_msg = gn_core_subscribe(core, kPingMsgId,
                                               &on_inbound_msg, nullptr);
    if (sub_msg == 0) {
        timed_log("gn_core_subscribe returned 0");
        write_fail("subscribe failed");
        gn_core_destroy(core);
        return 1;
    }
    const uint64_t sub_state = gn_core_on_conn_state(core,
                                                     &on_conn_state, nullptr);
    if (sub_state == 0) {
        timed_log("gn_core_on_conn_state returned 0");
        write_fail("on_conn_state failed");
        gn_core_unsubscribe(core, sub_msg);
        gn_core_destroy(core);
        return 1;
    }

    // Poll for the peer's pubkey.
    std::string peer_pk_hex;
    {
        const auto deadline = clk::now() +
            std::chrono::duration_cast<clk::duration>(
                std::chrono::duration<double>(timeout_s));
        while (clk::now() < deadline) {
            std::error_code ec;
            if (fs::exists(peer_pk_path, ec)) {
                std::ifstream f(peer_pk_path);
                std::ostringstream ss;
                ss << f.rdbuf();
                std::string content = ss.str();
                // Trim trailing whitespace / newlines (atomic write
                // emits exactly 64 hex chars but defensive trim
                // keeps the parser tolerant).
                while (!content.empty() &&
                       (content.back() == '\n' || content.back() == '\r' ||
                        content.back() == ' '  || content.back() == '\t')) {
                    content.pop_back();
                }
                if (content.size() == 64) {
                    peer_pk_hex = content;
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    if (peer_pk_hex.empty()) {
        timed_log("peer pk timeout");
        write_fail("peer pk timeout");
        gn_core_off_conn_state(core, sub_state);
        gn_core_unsubscribe(core, sub_msg);
        gn_core_destroy(core);
        return 1;
    }
    timed_log("peer pubkey received");

    // Build the connect URI. Both `ice://<peer-pk>` and
    // `quic://<peer-pk>` route through the link plugin registered
    // for the scheme. The kernel parses the prefix itself when
    // `scheme=NULL` is passed.
    const std::string scheme  = quic_over_ice ? "quic" : "ice";
    const std::string uri     = scheme + "://" + peer_pk_hex;

    gn_conn_id_t conn = GN_INVALID_ID;
    if (gn_result_t rc = gn_core_connect(core, uri.c_str(),
                                          scheme.c_str(), &conn);
        rc != GN_OK) {
        std::string m = "gn_core_connect rc=";
        m += std::to_string(rc);
        m += " uri=" + uri;
        timed_log(m);
        write_fail("connect failed");
        gn_core_off_conn_state(core, sub_state);
        gn_core_unsubscribe(core, sub_msg);
        gn_core_destroy(core);
        return 1;
    }
    g_active_conn.store(conn);
    timed_log(std::string("connect issued conn=") + std::to_string(conn));

    // Wait for either:
    //   * our own `CONNECTED` event fires AND we sent a byte to peer
    //     AND we received a byte back (our .done written) AND the peer
    //     wrote its .done.
    //   * timeout — write .fail.
    const fs::path peer_done = fs::path(signal_dir) /
                               (wait_peer + ".done");

    const auto deadline =
        clk::now() + std::chrono::duration_cast<clk::duration>(
                         std::chrono::duration<double>(timeout_s));

    bool ping_sent = false;
    while (clk::now() < deadline) {
        if (g_conn_ready.load() && !ping_sent) {
            const uint8_t one = 0x42;
            const gn_conn_id_t target = g_active_conn.load();
            const gn_result_t rc =
                gn_core_send_to(core, target, kPingMsgId, &one, 1);
            if (rc == GN_OK) {
                ping_sent = true;
                timed_log("sent ping byte");
            } else {
                // Some plugin contracts surface a transient invalid
                // state until the security handshake finishes — keep
                // retrying. A persistent error path is bounded by the
                // outer deadline.
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                continue;
            }
        }
        if (g_inbound_seen.load()) {
            std::error_code ec;
            if (!fs::exists(done_path, ec)) {
                if (write_file_atomic(done_path, "ok\n")) {
                    timed_log(".done written");
                }
            }
            if (fs::exists(peer_done, ec)) {
                timed_log("peer .done observed — exit 0");
                gn_core_off_conn_state(core, sub_state);
                gn_core_unsubscribe(core, sub_msg);
                gn_core_stop(core);
                gn_core_destroy(core);
                return 0;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    timed_log("timeout — writing .fail");
    write_fail("harness timeout");
    gn_core_off_conn_state(core, sub_state);
    gn_core_unsubscribe(core, sub_msg);
    gn_core_stop(core);
    gn_core_destroy(core);
    return 1;
}
