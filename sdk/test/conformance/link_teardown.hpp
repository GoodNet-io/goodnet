// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/test/conformance/link_teardown.hpp
/// @brief  `link.md` §9 shutdown conformance — typed-test contract.
///
/// Shared body of `LinkTeardownConformance.ShutdownReleasesEvery
/// Session`. Each link plugin instantiates the suite for its own
/// type from its own `tests/test_<link>_conformance.cpp`, so a
/// failure shows up in that plugin's own `nix run .#test` rather
/// than in a kernel-side cross-plugin runner.
///
/// Per-plugin instantiation site looks like:
///
///     #include <sdk/test/conformance/link_teardown.hpp>
///     #include <my_link/header.hpp>
///
///     template <>
///     struct gn::test::link::conformance::LinkTraits<MyLink> {
///         static constexpr const char* scheme = "my";
///         static std::shared_ptr<MyLink> make() { ... }
///         static std::string listen_uri()         { ... }
///         static std::string connect_uri(uint16_t) { ... }
///         static bool wire_credentials(MyLink&, MyLink&) { ... }
///     };
///
///     INSTANTIATE_TYPED_TEST_SUITE_P(
///         MyLink,
///         gn::test::link::conformance::LinkTeardownConformance,
///         ::testing::Types<MyLink>);
///
/// The `*_P` macro family (parameterised typed test) is used so the
/// `TYPED_TEST_P` body lives in this header without ODR-violating
/// every instantiating translation unit. Each plugin gets its own
/// instantiation suite name (the first macro arg).

#pragma once

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <concepts>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::test::link::conformance {

using namespace std::chrono_literals;

/// Host stub shared across every typed-fixture instantiation.
/// `main_tid` is set by the test before any async work starts; the
/// disconnect callback only increments `on_main_disconnects` when
/// the call lands on that thread, which lets the post-fix `link.md`
/// §9 invariant be checked without racing the worker thread.
struct ConformanceHost {
    std::mutex                  mu;
    std::vector<gn_conn_id_t>   connects;
    std::atomic<int>            disconnects{0};
    std::thread::id             main_tid{};
    std::atomic<int>            on_main_disconnects{0};
    std::atomic<gn_conn_id_t>   next_id{1};

    static gn_result_t s_notify_connect(void* host_ctx,
                                         const std::uint8_t* /*remote_pk*/,
                                         const char* /*uri*/,
                                         gn_trust_class_t /*trust*/,
                                         gn_handshake_role_t /*role*/,
                                         gn_conn_id_t* out_conn) {
        auto* h = static_cast<ConformanceHost*>(host_ctx);
        const auto id = h->next_id.fetch_add(1);
        {
            std::lock_guard lk(h->mu);
            h->connects.push_back(id);
        }
        *out_conn = id;
        return GN_OK;
    }

    static gn_result_t s_notify_inbound(void*, gn_conn_id_t,
                                         const std::uint8_t*, std::size_t) {
        return GN_OK;
    }

    static gn_result_t s_notify_disconnect(void* host_ctx, gn_conn_id_t,
                                            gn_result_t) {
        auto* h = static_cast<ConformanceHost*>(host_ctx);
        h->disconnects.fetch_add(1);
        if (h->main_tid != std::thread::id{} &&
            std::this_thread::get_id() == h->main_tid) {
            h->on_main_disconnects.fetch_add(1);
        }
        return GN_OK;
    }

    static gn_result_t s_kick(void*, gn_conn_id_t) { return GN_OK; }

    host_api_t make_api() {
        host_api_t api{};
        api.api_size              = sizeof(host_api_t);
        api.host_ctx              = this;
        api.notify_connect        = &s_notify_connect;
        api.notify_inbound_bytes  = &s_notify_inbound;
        api.notify_disconnect     = &s_notify_disconnect;
        api.kick_handshake        = &s_kick;
        return api;
    }
};

/// Compile-time interface gate: any type that wants to participate
/// in the conformance suite has to expose the four entry points the
/// fixture exercises. Catches a future plugin that drops `listen()`
/// or renames `shutdown()` at the type level rather than at link
/// time. `listen_port()` is intentionally optional — IPC binds a
/// path, not a port — and consumed through the trait specialisation.
template <class T>
concept LinkPlugin = requires(T t, std::string_view uri,
                              const host_api_t* api) {
    { t.listen(uri) } -> std::same_as<gn_result_t>;
    { t.connect(uri) } -> std::same_as<gn_result_t>;
    { t.shutdown() } -> std::same_as<void>;
    { t.set_host_api(api) } -> std::same_as<void>;
};

/// Per-transport configuration. Each plugin's instantiation site
/// specialises this template to teach the conformance suite how to
/// construct, listen, connect, and (when applicable) wire
/// credentials onto a pair of links.
template <class L>
struct LinkTraits;

inline bool wait_for(auto&& predicate,
                     std::chrono::milliseconds timeout = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return predicate();
}

template <LinkPlugin L>
class LinkTeardownConformance : public ::testing::Test {};

TYPED_TEST_SUITE_P(LinkTeardownConformance);

TYPED_TEST_P(LinkTeardownConformance, ShutdownReleasesEverySession) {
    using Link   = TypeParam;
    using Traits = LinkTraits<Link>;

    ConformanceHost host;
    host.main_tid = std::this_thread::get_id();
    auto api = host.make_api();

    auto server = Traits::make();
    auto client = Traits::make();
    server->set_host_api(&api);
    client->set_host_api(&api);
    ASSERT_TRUE(Traits::wire_credentials(*server, *client))
        << "scheme=" << Traits::scheme
        << ": credential setup failed before listen";

    ASSERT_EQ(server->listen(Traits::listen_uri()), GN_OK)
        << "scheme=" << Traits::scheme << ": listen rejected";
    /// IPC binds a path; TCP-backed plugins bind a kernel-allocated
    /// port that must surface non-zero before a client can dial.
    /// The trait helper builds the connect URI either way.
    std::uint16_t port = 0;
    if constexpr (requires { server->listen_port(); }) {
        port = server->listen_port();
        if (std::string_view{Traits::scheme} != "ipc") {
            ASSERT_GT(port, 0u)
                << "scheme=" << Traits::scheme
                << ": listen did not bind";
        }
    }

    ASSERT_EQ(client->connect(Traits::connect_uri(port)), GN_OK)
        << "scheme=" << Traits::scheme << ": connect rejected";

    ASSERT_TRUE(wait_for([&] {
        std::lock_guard lk(host.mu);
        return host.connects.size() >= 2;
    })) << "scheme=" << Traits::scheme
        << ": both notify_connect did not arrive within timeout";

    int connects = 0;
    {
        std::lock_guard lk(host.mu);
        connects = static_cast<int>(host.connects.size());
    }
    EXPECT_EQ(host.disconnects.load(), 0)
        << "scheme=" << Traits::scheme
        << ": disconnect fired before shutdown";
    EXPECT_EQ(host.on_main_disconnects.load(), 0);

    client->shutdown();
    server->shutdown();

    /// Caller-thread pin: pre-fix the worker thread sometimes
    /// won the race to an EOF-driven async notify before
    /// `ioc_.stop()` returned and sometimes did not — a count-
    /// only assert was flaky on a fast host. Post-fix the
    /// shutdown call walks the live snapshot and fires
    /// `notify_disconnect` itself, so the caller thread always
    /// sees one disconnect per `notify_connect` it observed.
    EXPECT_EQ(host.on_main_disconnects.load(), connects)
        << "scheme=" << Traits::scheme
        << ": shutdown() must fire notify_disconnect "
           "synchronously on the caller thread for every session "
           "published through notify_connect (link.md §9 step 3).";
}

REGISTER_TYPED_TEST_SUITE_P(LinkTeardownConformance,
                            ShutdownReleasesEverySession);

}  // namespace gn::test::link::conformance
