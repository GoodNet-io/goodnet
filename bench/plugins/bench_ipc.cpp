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

    if (server->listen(uri) != GN_OK) {
        state.SkipWithError("listen failed");
        return;
    }
    if (client->connect(uri) != GN_OK) {
        state.SkipWithError("connect failed");
        return;
    }
    if (!::gn::sdk::test::wait_for(
            [&] { return client_kernel.stub.connects.load() >= 1; }, 1s)) {
        state.SkipWithError("handshake timeout");
        return;
    }
    gn_conn_id_t client_conn;
    {
        std::lock_guard lk(client_kernel.stub.mu);
        client_conn = client_kernel.stub.conns.front();
    }

    ResourceCounters res;
    res.snapshot_start();
    for (auto _ : state) {
        const auto rc = client->send(client_conn,
            std::span<const std::uint8_t>(payload));
        if (rc != GN_OK) {
            state.SkipWithError("send failed mid-loop");
            break;
        }
    }
    res.snapshot_end();
    state.SetBytesProcessed(
        static_cast<std::int64_t>(state.iterations()) *
        static_cast<std::int64_t>(payload_size));
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
