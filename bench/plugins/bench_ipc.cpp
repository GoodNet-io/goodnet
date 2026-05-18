// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_ipc.cpp
/// @brief  IPC link plugin — AF_UNIX SOCK_STREAM throughput / latency.

#include "../bench_harness.hpp"

#include <plugins/links/ipc/ipc.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <thread>

namespace {

using namespace gn::bench;
using gn::link::ipc::IpcLink;
using namespace std::chrono_literals;

/// Per-bench socket path so concurrent runs don't collide; cleaned
/// up in TearDown so /tmp doesn't accumulate stale sockets.
std::string fresh_socket_path() {
    static std::atomic<std::uint64_t> seq{0};
    return std::string("/tmp/goodnet-bench-ipc-")
         + std::to_string(::getpid()) + "-"
         + std::to_string(seq.fetch_add(1));
}

struct IpcFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        socket_path = fresh_socket_path();
        server = std::make_shared<IpcLink>();
        client = std::make_shared<IpcLink>();
        server->set_host_api(&server_kernel.api);
        client->set_host_api(&client_kernel.api);
    }

    void TearDown(::benchmark::State&) override {
        client->shutdown();
        server->shutdown();
        std::error_code ec;
        std::filesystem::remove(socket_path, ec);
        server.reset();
        client.reset();
    }

    BenchKernel              server_kernel;
    BenchKernel              client_kernel;
    std::shared_ptr<IpcLink> server;
    std::shared_ptr<IpcLink> client;
    std::string              socket_path;
};

BENCHMARK_DEFINE_F(IpcFixture, Throughput)(::benchmark::State& state) {
    const std::size_t payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);
    const std::string uri = "ipc://" + socket_path;

    /// Snapshot the connect counter baseline. google-benchmark
    /// re-invokes the bench body multiple times (warmup + real run);
    /// the kernel stub's `connects` accumulates across runs. Picking
    /// `conns.front()` after `>= 1` on the second run would grab the
    /// stale id from the first run whose session is already torn
    /// down — `send(stale)` returns `GN_ERR_NOT_FOUND`. Same shape
    /// as `bench_tcp.cpp::TcpFixture::SetUp`.
    const int connects_before = client_kernel.stub.connects.load();
    const std::size_t conns_before = [&] {
        std::lock_guard lk(client_kernel.stub.mu);
        return client_kernel.stub.conns.size();
    }();
    if (server->listen(uri) != GN_OK) {
        state.SkipWithError("listen failed");
        return;
    }
    if (client->connect(uri) != GN_OK) {
        state.SkipWithError("connect failed");
        return;
    }
    if (!::gn::sdk::test::wait_for_fast(
            [&] {
                return client_kernel.stub.connects.load() - connects_before >= 1;
            }, 1s)) {
        state.SkipWithError("handshake timeout");
        return;
    }
    gn_conn_id_t client_conn = GN_INVALID_ID;
    {
        std::lock_guard lk(client_kernel.stub.mu);
        if (client_kernel.stub.conns.size() > conns_before) {
            client_conn = client_kernel.stub.conns[conns_before];
        }
    }
    if (client_conn == GN_INVALID_ID) {
        state.SkipWithError("no new conn id");
        return;
    }
    /// `client_kernel.stub.connects` increments INSIDE the plugin's
    /// `notify_connect` thunk — IPC's `connect` callback only calls
    /// `register_session(conn, session)` AFTER that thunk returns.
    /// A tight-poll wait above sees the increment within microseconds
    /// and races the session installation; the very first `send` then
    /// returns `GN_ERR_NOT_FOUND`. Probe with a real send until it
    /// stops failing with NOT_FOUND.
    if (!::gn::sdk::test::wait_for_fast(
            [&] {
                return client->send(client_conn,
                    std::span<const std::uint8_t>(payload)) != GN_ERR_NOT_FOUND;
            }, 1s)) {
        state.SkipWithError("session never registered");
        return;
    }

    ResourceCounters res;
    res.snapshot_start();
    std::size_t sent_ok = 0;
    gn_result_t last_err = GN_OK;
    for (auto _ : state) {
        const auto rc = client->send(client_conn,
            std::span<const std::uint8_t>(payload));
        if (rc == GN_OK) {
            ++sent_ok;
        } else {
            last_err = rc;
            /// Backpressure on the per-conn send queue. Yield so the
            /// kernel write pump can drain, then keep the iteration
            /// slot — `SetBytesProcessed` reports offered payload so
            /// the wall-time stays honest. Erroring out on the first
            /// GN_ERR_LIMIT_REACHED was the original bug: every IPC
            /// row in `bench/reports/*.md` reported `—` because
            /// google-benchmark zeroes a SkipWithError row's numbers.
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    }
    res.snapshot_end();
    state.SetBytesProcessed(
        static_cast<std::int64_t>(state.iterations()) *
        static_cast<std::int64_t>(payload_size));
    state.counters["last_err"]  = static_cast<double>(last_err);
    state.counters["sent_ok"]   = static_cast<double>(sent_ok);
    state.counters["sent_skip"] =
        static_cast<double>(static_cast<std::size_t>(state.iterations()) - sent_ok);
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(IpcFixture, Throughput)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Arg(65536)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

}  // namespace
