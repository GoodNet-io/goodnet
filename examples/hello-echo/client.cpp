// SPDX-License-Identifier: Apache-2.0
// hello-echo client — connect, send "hello", print echo.
#include <sdk/cpp/connect.hpp>
#include <sdk/cpp/subscription.hpp>
#include <sdk/host_api.h>
#include <cstdio>
#include <cstring>
#include <span>
#include <thread>
#include <chrono>

int main(int argc, char** argv) {
    const char* uri = argc > 1 ? argv[1] : "tcp://127.0.0.1:9100";
    auto* host = gn::sdk::host_api_default();
    auto session = gn::sdk::connect_to(host, uri);
    if (!session) return 1;
    auto sub = gn::sdk::Subscription::on_data(
        host, session->id(),
        [](std::span<const std::uint8_t> b) {
            std::fwrite(b.data(), 1, b.size(), stdout);
        });
    const char msg[] = "hello";
    (void)session->send(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(msg), sizeof(msg) - 1));
    std::this_thread::sleep_for(std::chrono::seconds(1));
    return 0;
}
