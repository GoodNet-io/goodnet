// SPDX-License-Identifier: Apache-2.0
// hello-echo server — accept one connection, echo every frame back.
#include <sdk/cpp/connect.hpp>
#include <sdk/cpp/subscription.hpp>
#include <sdk/host_api.h>
#include <cstdio>
#include <span>
#include <thread>
#include <chrono>

int main(int argc, char** argv) {
    const char* uri = argc > 1 ? argv[1] : "tcp://0.0.0.0:9100";
    auto* host = gn::sdk::host_api_default();  // operator-provided
    auto carrier = gn::sdk::listen_to(host, uri);
    if (!carrier) return 1;
    auto sub = gn::sdk::Subscription::on_data_any(
        host, [&](gn_conn_id_t c, std::span<const std::uint8_t> b) {
            (void)carrier->send(c, b);  // echo
        });
    std::this_thread::sleep_for(std::chrono::hours(24));
    return 0;
}
