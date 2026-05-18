// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_subprocess.cpp
/// @brief  Subprocess plugin runtime — wire-proxy roundtrip cost.
///
/// rc5 landed the subprocess plugin runtime (SECURITY, HANDLER, LINK
/// proxies through `core/plugin/remote_host`). Every kernel-side
/// vtable call becomes a `GN_WIRE_PLUGIN_CALL` over the spawn
/// socketpair, the worker dispatches into its real vtable, the
/// reply hops back through `GN_WIRE_PLUGIN_REPLY`. The hot loop
/// therefore pays:
///
///   * one `write` to the spawn socketpair (kernel → worker),
///   * scheduler hop to the worker process,
///   * worker dispatch + real-vtable call,
///   * one `write` back through the reader thread,
///   * scheduler hop to the kernel,
///   * one correlator wakeup on the future.
///
/// Three fixtures pin each layer:
///
///   * `HostCallRoundtrip` — `notify_inbound_bytes` from the worker
///     side back into the kernel-side host_api. Canonical HOST_CALL
///     → HOST_REPLY round-trip cost. Driven through the link
///     proxy's `send` slot which the echo worker bounces back
///     through host_api.
///   * `HandlerHandleMessage` — full handler proxy call: kernel
///     issues `handle_message` envelope, worker dispatches it,
///     worker calls `notify_inbound_bytes` back. Two scheduler
///     hops per iteration.
///   * `SecurityEncryptDecrypt` — full handshake bring-up plus
///     transport-phase encrypt + decrypt round trip. Each
///     encrypt/decrypt is one PLUGIN_CALL → PLUGIN_REPLY.

#include "../bench_harness.hpp"

#include <core/kernel/plugin_context.hpp>
#include <core/plugin/remote_host.hpp>

#include <benchmark/benchmark.h>

#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/plugin.h>
#include <sdk/security.h>
#include <sdk/trust.h>
#include <sdk/types.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#ifndef GOODNET_REMOTE_ECHO_PATH
#error "GOODNET_REMOTE_ECHO_PATH must be defined by the bench CMakeLists"
#endif
#ifndef GOODNET_REMOTE_HANDLER_STUB_PATH
#error "GOODNET_REMOTE_HANDLER_STUB_PATH must be defined by the bench CMakeLists"
#endif
#ifndef GOODNET_REMOTE_NOISE_STUB_PATH
#error "GOODNET_REMOTE_NOISE_STUB_PATH must be defined by the bench CMakeLists"
#endif

namespace {

using namespace gn::bench;

/// Worker binary lookup — env override beats compile-time path so a
/// runner that rebuilt the workers in a different dir can point the
/// bench at the new binaries.
[[nodiscard]] const char* worker_path(const char* env_var,
                                       const char* fallback) {
    if (const char* env = std::getenv(env_var)) return env;
    return fallback;
}

/// Shared stub host_api state. The worker's `send` slot bounces the
/// payload through `notify_inbound_bytes`; the stub here captures
/// the byte count and last conn id so the bench can verify the
/// round-trip actually completed (and a future regression that
/// silently drops bytes lands as a counter mismatch).
struct StubHostState {
    std::atomic<std::uint64_t> inbound_calls{0};
    std::atomic<std::uint64_t> inbound_bytes{0};
};

gn_result_t stub_notify_inbound_bytes(void* host_ctx,
                                       gn_conn_id_t /*conn*/,
                                       const uint8_t* /*bytes*/,
                                       size_t size) {
    auto* s = static_cast<StubHostState*>(host_ctx);
    s->inbound_calls.fetch_add(1, std::memory_order_relaxed);
    s->inbound_bytes.fetch_add(size, std::memory_order_relaxed);
    return GN_OK;
}

void stub_log_emit(void* /*host_ctx*/, gn_log_level_t /*level*/,
                    const char* /*file*/, int32_t /*line*/,
                    const char* /*msg*/) {}

int32_t stub_is_shutdown_requested(void* /*host_ctx*/) { return 0; }

[[nodiscard]] host_api_t make_stub_host_api(StubHostState& s) {
    host_api_t api{};
    api.api_size                 = sizeof(host_api_t);
    api.host_ctx                 = &s;
    api.log.api_size             = sizeof(gn_log_api_t);
    api.log.emit                 = &stub_log_emit;
    api.is_shutdown_requested    = &stub_is_shutdown_requested;
    api.notify_inbound_bytes     = &stub_notify_inbound_bytes;
    return api;
}

// ── Host-call round-trip via link proxy ──────────────────────────────
//
// One subprocess spawn per fixture; loop body calls the link
// proxy's `send` slot which the worker bounces back through
// `notify_inbound_bytes`. Each iteration is ONE wire send +
// one PLUGIN_REPLY + one HOST_CALL + one HOST_REPLY — the
// kernel observes the full round trip through the stub.

struct SubprocessLinkFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State& state) override {
        if (ready) return;
        /// Fresh RemoteHost per fixture-SetUp. Gbench reuses the
        /// fixture instance across `Args()` instantiations; without
        /// rebuilding the RemoteHost we'd be calling `spawn` twice on
        /// the same handle (it would early-return INVALID_STATE) or
        /// re-using a torn-down `fd_`. The fresh `host` keeps the
        /// invariants from `core/plugin/remote_host.hpp` intact.
        stub.inbound_calls.store(0);
        stub.inbound_bytes.store(0);
        host  = std::make_unique<gn::core::RemoteHost>();
        ctx   = gn::core::PluginContext{};
        ctx.plugin_name = "bench_remote_echo";
        ctx.kind        = GN_PLUGIN_KIND_LINK;
        std::string diag;
        const auto rc = host->spawn(
            worker_path("GOODNET_REMOTE_ECHO_BINARY",
                         GOODNET_REMOTE_ECHO_PATH),
            std::span<const std::string>(),
            ctx, make_stub_host_api(stub), diag);
        if (rc != GN_OK) {
            state.SkipWithError(("spawn failed: " + diag).c_str());
            return;
        }
        void* self_handle = nullptr;
        if (host->call_init(&self_handle) != GN_OK) {
            state.SkipWithError("call_init failed");
            return;
        }
        vt = host->link_vtable_proxy();
        if (vt == nullptr || vt->send == nullptr) {
            state.SkipWithError("link_vtable_proxy missing send");
            return;
        }
        ready = true;
    }
    void TearDown(::benchmark::State&) override {
        if (host) host->terminate();
        host.reset();
        vt = nullptr;
        ready = false;
    }

    StubHostState                          stub;
    gn::core::PluginContext                ctx;
    std::unique_ptr<gn::core::RemoteHost>  host;
    const gn_link_vtable_t*                vt = nullptr;
    bool                                   ready = false;
};

BENCHMARK_DEFINE_F(SubprocessLinkFixture, HostCallRoundtrip)
    (::benchmark::State& state) {
    if (!ready) return;
    const std::size_t payload_size =
        static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);
    const gn_conn_id_t conn = 0xBE'BC'A'FE;
    const std::uint64_t before = stub.inbound_calls.load();
    ResourceCounters res;
    res.snapshot_start();
    std::size_t completed = 0;
    for ([[maybe_unused]] auto _ : state) {
        const auto rc = vt->send(
            static_cast<void*>(host.get()), conn,
            payload.data(), payload.size());
        if (rc == GN_OK) ++completed;
    }
    res.snapshot_end();
    const std::uint64_t after = stub.inbound_calls.load();
    state.counters["inbound_calls_delta"] =
        static_cast<double>(after - before);
    state.counters["completed_sends"] = static_cast<double>(completed);
    state.SetBytesProcessed(
        static_cast<std::int64_t>(state.iterations()) *
        static_cast<std::int64_t>(payload_size));
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(SubprocessLinkFixture, HostCallRoundtrip)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

// ── Handler-proxy handle_message dispatch ────────────────────────────

struct SubprocessHandlerFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State& state) override {
        if (ready) return;
        stub.inbound_calls.store(0);
        stub.inbound_bytes.store(0);
        host = std::make_unique<gn::core::RemoteHost>();
        ctx  = gn::core::PluginContext{};
        ctx.plugin_name = "bench_remote_handler_stub";
        ctx.kind        = GN_PLUGIN_KIND_HANDLER;
        std::string diag;
        const auto rc = host->spawn(
            worker_path("GOODNET_REMOTE_HANDLER_STUB_BINARY",
                         GOODNET_REMOTE_HANDLER_STUB_PATH),
            std::span<const std::string>(),
            ctx, make_stub_host_api(stub), diag);
        if (rc != GN_OK) {
            state.SkipWithError(("spawn failed: " + diag).c_str());
            return;
        }
        void* self_handle = nullptr;
        if (host->call_init(&self_handle) != GN_OK) {
            state.SkipWithError("call_init failed");
            return;
        }
        vt = host->handler_vtable_proxy();
        if (vt == nullptr || vt->handle_message == nullptr) {
            state.SkipWithError("handler_vtable_proxy missing handle_message");
            return;
        }
        ready = true;
    }
    void TearDown(::benchmark::State&) override {
        if (host) host->terminate();
        host.reset();
        vt = nullptr;
        ready = false;
    }

    StubHostState                          stub;
    gn::core::PluginContext                ctx;
    std::unique_ptr<gn::core::RemoteHost>  host;
    const gn_handler_vtable_t*             vt = nullptr;
    bool                                   ready = false;
};

BENCHMARK_DEFINE_F(SubprocessHandlerFixture, HandlerHandleMessage)
    (::benchmark::State& state) {
    if (!ready) return;
    const std::size_t payload_size =
        static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);
    gn_message_t env{};
    env.api_size = sizeof(gn_message_t);
    std::memset(env.sender_pk, 0x77, GN_PUBLIC_KEY_BYTES);
    std::memset(env.receiver_pk, 0x00, GN_PUBLIC_KEY_BYTES);
    env.msg_id        = 0xC0DE;
    env.payload       = payload.data();
    env.payload_size  = payload.size();
    env.conn_id       = 7;
    ResourceCounters res;
    res.snapshot_start();
    std::size_t consumed = 0;
    for ([[maybe_unused]] auto _ : state) {
        const auto rc = vt->handle_message(
            static_cast<void*>(host.get()), &env);
        if (rc == GN_PROPAGATION_CONSUMED) ++consumed;
    }
    res.snapshot_end();
    state.counters["consumed"] = static_cast<double>(consumed);
    state.SetBytesProcessed(
        static_cast<std::int64_t>(state.iterations()) *
        static_cast<std::int64_t>(payload_size));
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(SubprocessHandlerFixture, HandlerHandleMessage)
    ->Arg(64)
    ->Arg(1024)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

// ── Security-proxy handshake + encrypt/decrypt round trip ────────────

struct SubprocessSecurityFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State& state) override {
        if (ready) return;
        stub.inbound_calls.store(0);
        stub.inbound_bytes.store(0);
        host = std::make_unique<gn::core::RemoteHost>();
        ctx  = gn::core::PluginContext{};
        ctx.plugin_name = "bench_remote_noise_stub";
        ctx.kind        = GN_PLUGIN_KIND_SECURITY;
        std::string diag;
        const auto rc = host->spawn(
            worker_path("GOODNET_REMOTE_NOISE_STUB_BINARY",
                         GOODNET_REMOTE_NOISE_STUB_PATH),
            std::span<const std::string>(),
            ctx, make_stub_host_api(stub), diag);
        if (rc != GN_OK) {
            state.SkipWithError(("spawn failed: " + diag).c_str());
            return;
        }
        void* self_handle = nullptr;
        if (host->call_init(&self_handle) != GN_OK) {
            state.SkipWithError("call_init failed");
            return;
        }
        vt = host->security_vtable_proxy();
        if (vt == nullptr || vt->encrypt == nullptr
            || vt->decrypt == nullptr
            || vt->handshake_open == nullptr) {
            state.SkipWithError("security_vtable_proxy missing slots");
            return;
        }
        std::array<std::uint8_t, GN_PRIVATE_KEY_BYTES> sk{};
        std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES>  pk{};
        if (vt->handshake_open(
                static_cast<void*>(host.get()), 1u,
                GN_TRUST_LOOPBACK, GN_ROLE_INITIATOR,
                sk.data(), pk.data(), nullptr, &state_handle) != GN_OK) {
            state.SkipWithError("handshake_open failed");
            return;
        }
        ready = true;
    }
    void TearDown(::benchmark::State&) override {
        if (state_handle && vt && vt->handshake_close && host) {
            vt->handshake_close(static_cast<void*>(host.get()),
                                state_handle);
        }
        if (host) host->terminate();
        host.reset();
        vt           = nullptr;
        ready        = false;
        state_handle = nullptr;
    }

    StubHostState                            stub;
    gn::core::PluginContext                  ctx;
    std::unique_ptr<gn::core::RemoteHost>    host;
    const gn_security_provider_vtable_t*     vt = nullptr;
    void*                                    state_handle = nullptr;
    bool                                     ready = false;
};

BENCHMARK_DEFINE_F(SubprocessSecurityFixture, SecurityEncryptDecrypt)
    (::benchmark::State& state) {
    if (!ready) return;
    const std::size_t payload_size =
        static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);
    ResourceCounters res;
    res.snapshot_start();
    std::size_t encrypted = 0;
    std::size_t decrypted = 0;
    for ([[maybe_unused]] auto _ : state) {
        gn_secure_buffer_t ct{};
        const auto rc_enc = vt->encrypt(
            static_cast<void*>(host.get()), state_handle,
            payload.data(), payload.size(), &ct);
        if (rc_enc == GN_OK && ct.bytes != nullptr) {
            ++encrypted;
            gn_secure_buffer_t pt{};
            const auto rc_dec = vt->decrypt(
                static_cast<void*>(host.get()), state_handle,
                ct.bytes, ct.size, &pt);
            if (rc_dec == GN_OK) ++decrypted;
            if (pt.bytes && pt.free_fn) {
                pt.free_fn(pt.free_user_data, pt.bytes);
            }
            if (ct.free_fn) {
                ct.free_fn(ct.free_user_data, ct.bytes);
            }
        }
    }
    res.snapshot_end();
    state.counters["encrypted"] = static_cast<double>(encrypted);
    state.counters["decrypted"] = static_cast<double>(decrypted);
    /// Counted bytes are payload × 2 per iter (encrypt + decrypt)
    /// — each side runs the proxy round trip.
    state.SetBytesProcessed(
        static_cast<std::int64_t>(state.iterations()) *
        static_cast<std::int64_t>(payload_size) * 2);
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(SubprocessSecurityFixture, SecurityEncryptDecrypt)
    ->Arg(64)
    ->Arg(1024)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

}  // namespace
