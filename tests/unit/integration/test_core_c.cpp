/// @file   tests/unit/integration/test_core_c.cpp
/// @brief  Host-embedding C ABI surface — drives `sdk/core.h` exactly
///         as a non-C++ host would. Asserts lifecycle ordering, NULL
///         handle defenses, double-init latch, identity availability
///         after init, and the zero-traffic stats baseline.

#include <array>
#include <cstdint>
#include <cstring>
#include <thread>

#include <gtest/gtest.h>

#include <sdk/core.h>
#include <sdk/limits.h>
#include <sdk/types.h>

namespace {

/// Sum the bytes of a 32-byte buffer with bitwise OR; non-zero result
/// proves at least one bit is set somewhere in the key. The kernel's
/// `gn_pk_is_zero` is defined for the same shape but lives in
/// `sdk/types.h` as `static inline`; we keep the local helper inline
/// with the test so the assertion stays visible at the call site.
bool pubkey_is_all_zero(const std::uint8_t pk[GN_PUBLIC_KEY_BYTES]) {
    std::uint8_t acc = 0;
    for (std::size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) {
        acc |= pk[i];
    }
    return acc == 0;
}

}  // namespace

// ── Happy lifecycle ─────────────────────────────────────────────────────────

TEST(CoreC, HappyLifecycleCreateInitStartStopDestroy) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    EXPECT_EQ(gn_core_is_running(core), 0);

    ASSERT_EQ(gn_core_init(core), GN_OK);
    /// `init` walks Load → Wire → Resolve → Ready but does NOT advance
    /// to Running; that step belongs to `gn_core_start`.
    EXPECT_EQ(gn_core_is_running(core), 0);

    ASSERT_EQ(gn_core_start(core), GN_OK);
    EXPECT_EQ(gn_core_is_running(core), 1);

    /// No traffic, no plugins loaded, no providers registered → every
    /// registry is empty.
    EXPECT_EQ(gn_core_connection_count(core), 0u);
    EXPECT_EQ(gn_core_handler_count(core),    0u);
    EXPECT_EQ(gn_core_link_count(core),       0u);

    /// Stop must wake any thread blocked on `gn_core_wait`. We park a
    /// waiter, request stop on the test thread, and join — the join
    /// observes the wake.
    std::thread waiter([core] { gn_core_wait(core); });
    gn_core_stop(core);
    waiter.join();

    EXPECT_EQ(gn_core_is_running(core), 0);

    gn_core_destroy(core);
}

TEST(CoreC, StartIdempotent) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);
    ASSERT_EQ(gn_core_start(core), GN_OK);
    /// Calling `start` on an already-Running kernel returns OK with
    /// no effect per `sdk/core.h` lifecycle documentation.
    EXPECT_EQ(gn_core_start(core), GN_OK);
    EXPECT_EQ(gn_core_is_running(core), 1);
    gn_core_destroy(core);
}

TEST(CoreC, StopIdempotent) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);
    ASSERT_EQ(gn_core_start(core), GN_OK);
    gn_core_stop(core);
    /// Second stop is a no-op; concurrent stops race through a single
    /// compare-and-exchange inside the kernel.
    gn_core_stop(core);
    EXPECT_EQ(gn_core_is_running(core), 0);
    gn_core_destroy(core);
}

// ── Double-init latch ───────────────────────────────────────────────────────

TEST(CoreC, DoubleInitRejectedWithInvalidState) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);
    /// Per `init_done` compare-exchange in `core_c.cpp`: the second
    /// init flips the latch's already-true bit and short-circuits.
    EXPECT_EQ(gn_core_init(core), GN_ERR_INVALID_STATE);
    gn_core_destroy(core);
}

// ── NULL handle defenses ────────────────────────────────────────────────────

TEST(CoreC, NullHandleReturnsNullArg) {
    /// Every entry that takes a `gn_core_t*` and returns a result code
    /// must surface `GN_ERR_NULL_ARG` rather than dereference. NULL is
    /// never the "no handle yet" handshake — the host always pairs
    /// `gn_core_create` with the call site.

    /// Result-returning entries.
    EXPECT_EQ(gn_core_init(nullptr), GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_start(nullptr), GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_reload_config_json(nullptr, "{}"), GN_ERR_NULL_ARG);

    gn_limits_t limits{};
    EXPECT_EQ(gn_core_set_limits(nullptr, &limits), GN_ERR_NULL_ARG);

    std::uint8_t pk_buf[GN_PUBLIC_KEY_BYTES] = {};
    EXPECT_EQ(gn_core_get_pubkey(nullptr, pk_buf), GN_ERR_NULL_ARG);

    gn_conn_id_t out_conn = GN_INVALID_ID;
    EXPECT_EQ(gn_core_connect(nullptr, "tcp://1.2.3.4:9", "tcp", &out_conn),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_listen(nullptr, "tcp://0.0.0.0:0"), GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_send_to(nullptr, /*conn*/ 1, /*msg_id*/ 1, nullptr, 0),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_disconnect(nullptr, /*conn*/ 1), GN_ERR_NULL_ARG);

    gn_stats_t stats{};
    EXPECT_EQ(gn_core_get_stats(nullptr, &stats), GN_ERR_NULL_ARG);

    std::array<std::uint8_t, 32> sha{};
    EXPECT_EQ(gn_core_load_plugin(nullptr, "/nope.so", sha.data()),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_unload_plugin(nullptr, "name"), GN_ERR_NULL_ARG);

    EXPECT_EQ(gn_core_register_extension(nullptr, "ext", 1, /*vt*/ &sha),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_unregister_extension(nullptr, "ext"), GN_ERR_NULL_ARG);

    /// Lookup-shaped entries return NULL / sentinel ids on a NULL
    /// handle rather than a result code; the contract is the same
    /// "do not dereference" guarantee, just expressed in the slot's
    /// natural failure shape.
    EXPECT_EQ(gn_core_limits(nullptr), nullptr);
    EXPECT_EQ(gn_core_host_api(nullptr), nullptr);
    EXPECT_EQ(gn_core_query_extension_checked(nullptr, "anything", 1u),
              nullptr);

    EXPECT_EQ(gn_core_is_running(nullptr), 0);
    EXPECT_EQ(gn_core_connection_count(nullptr), 0u);
    EXPECT_EQ(gn_core_handler_count(nullptr),    0u);
    EXPECT_EQ(gn_core_link_count(nullptr),       0u);

    EXPECT_EQ(gn_core_subscribe(nullptr, /*msg_id*/ 1,
                                /*cb*/ +[](void*, gn_conn_id_t, std::uint32_t,
                                           const std::uint8_t*, std::size_t) {},
                                /*user*/ nullptr),
              0u);
    EXPECT_EQ(gn_core_on_conn_state(nullptr,
                                     +[](void*, const gn_conn_event_t*) {},
                                     /*user*/ nullptr),
              0u);

    /// Void-returning entries simply must not crash on NULL.
    gn_core_destroy(nullptr);
    gn_core_stop(nullptr);
    gn_core_wait(nullptr);
    gn_core_broadcast(nullptr, /*msg_id*/ 1, /*payload*/ nullptr, 0);
    gn_core_unsubscribe(nullptr, /*token*/ 1);
    gn_core_off_conn_state(nullptr, /*token*/ 1);
}

// ── Destroy without stop ────────────────────────────────────────────────────

TEST(CoreC, DestroyWithoutStopCleansUp) {
    /// `gn_core_destroy` is the supported teardown path even when the
    /// host never called `gn_core_stop`; the destructor walks
    /// PreShutdown → Shutdown internally.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);
    ASSERT_EQ(gn_core_start(core), GN_OK);
    EXPECT_EQ(gn_core_is_running(core), 1);
    gn_core_destroy(core);
    /// AddressSanitizer / ThreadSanitizer would flag a leaked or
    /// double-freed handle here; the bare reaching of the test
    /// epilogue is the assertion.
}

TEST(CoreC, DestroyBeforeInit) {
    /// Created but never initialised — destroy must still walk the
    /// teardown path without dereferencing un-built kernel state.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    gn_core_destroy(core);
}

// ── Stats baseline ──────────────────────────────────────────────────────────

TEST(CoreC, GetStatsZeroedAfterStart) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);
    ASSERT_EQ(gn_core_start(core), GN_OK);

    gn_stats_t stats{};
    ASSERT_EQ(gn_core_get_stats(core, &stats), GN_OK);

    /// No traffic, no plugins, no providers — every counter is zero
    /// at this point in the kernel's life, except `extensions_registered`
    /// which carries the kernel-internal `gn.link.capability` surface
    /// the constructor registers for plugin consumption.
    EXPECT_EQ(stats.connections_active,    0u);
    EXPECT_EQ(stats.handlers_registered,   0u);
    EXPECT_EQ(stats.links_registered,      0u);
    EXPECT_EQ(stats.extensions_registered, 1u);
    EXPECT_EQ(stats.bytes_in,              0u);
    EXPECT_EQ(stats.bytes_out,             0u);
    EXPECT_EQ(stats.frames_in,             0u);
    EXPECT_EQ(stats.frames_out,            0u);
    EXPECT_EQ(stats.plugin_dlclose_leaks,  0u);

    gn_core_destroy(core);
}

TEST(CoreC, GetStatsRejectsNonZeroReserved) {
    /// `abi-evolution.en.md` §4: producer-side `_reserved` slots MUST be
    /// zero on entry. A non-zero slot signals stack garbage and the
    /// thunk rejects with `GN_ERR_INVALID_ENVELOPE` rather than
    /// proceeding with an ABI-mismatched struct.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    gn_stats_t stats{};
    int marker = 0;
    stats._reserved[0] = &marker;
    EXPECT_EQ(gn_core_get_stats(core, &stats), GN_ERR_INVALID_ENVELOPE);

    gn_core_destroy(core);
}

// ── Identity ────────────────────────────────────────────────────────────────

TEST(CoreC, GetPubkeyAfterInitNonZero) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {};
    ASSERT_EQ(gn_core_get_pubkey(core, pk), GN_OK);
    /// libsodium-generated Ed25519 device key — a 32-byte all-zero
    /// buffer would be a generation failure or an uninitialised read.
    EXPECT_FALSE(pubkey_is_all_zero(pk));

    gn_core_destroy(core);
}

TEST(CoreC, GetPubkeyBeforeInitRejected) {
    /// Per `sdk/core.h`: identity is generated inside `gn_core_init`.
    /// A read before init has no key to return.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {};
    EXPECT_EQ(gn_core_get_pubkey(core, pk), GN_ERR_INVALID_STATE);

    gn_core_destroy(core);
}

TEST(CoreC, GetPubkeyNullBufferRejected) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);
    EXPECT_EQ(gn_core_get_pubkey(core, /*out_pk*/ nullptr),
              GN_ERR_NULL_ARG);
    gn_core_destroy(core);
}

// ── Network entries with no link loaded ─────────────────────────────────────

TEST(CoreC, ConnectWithoutLinkReturnsNotFound) {
    /// No link plugin was loaded → no `gn.link.tcp` extension exists,
    /// so the `connect` slot reports a missing scheme through
    /// `GN_ERR_NOT_FOUND`. Asserts the entry does not crash on the
    /// happy-path NULL absence of a link extension.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);
    ASSERT_EQ(gn_core_start(core), GN_OK);

    gn_conn_id_t out = GN_INVALID_ID;
    EXPECT_EQ(gn_core_connect(core, "tcp://127.0.0.1:9", /*scheme*/ nullptr, &out),
              GN_ERR_NOT_FOUND);
    EXPECT_EQ(out, GN_INVALID_ID);

    gn_core_destroy(core);
}

TEST(CoreC, ConnectMissingSchemeReturnsNotFound) {
    /// URI without a `://` separator and no explicit scheme → no link
    /// could possibly match.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    gn_conn_id_t out = GN_INVALID_ID;
    EXPECT_EQ(gn_core_connect(core, "no-scheme-here", /*scheme*/ nullptr, &out),
              GN_ERR_NOT_FOUND);

    gn_core_destroy(core);
}

// ── gn_core_listen — public C ABI listen path ───────────────────────────────
//
// `gn_core_listen` mirrors `gn_core_connect`: derives the scheme prefix from
// the URI, resolves the link plugin via `LinkRegistry::find_by_scheme`, and
// forwards to its vtable `listen` slot. The tests below pin the four
// observable behaviours of that path: NULL arg defence, missing scheme,
// no-link-registered, and the happy-path forward into a stub link's vtable.

namespace listen_test {

/// Minimal stub link that records the URIs passed to its `listen` slot.
/// Mirrors the `Loopback` helper in `test_send_loopback.cpp` but exposes
/// only the slots `gn_core_listen` actually drives — every other vtable
/// entry returns `GN_ERR_NOT_IMPLEMENTED` so an accidental call from the
/// wider kernel surface gets caught loud rather than hiding behind a
/// no-op stub.
struct StubLink {
    std::mutex                                mu;
    std::vector<std::string>                  listen_uris;
    std::atomic<int>                          listen_calls{0};
    /// Result the stub returns from `listen`. Tests flip it before
    /// dispatching to assert the C ABI plumbs the link's verdict
    /// back to the caller verbatim.
    std::atomic<gn_result_t>                  listen_result{GN_OK};

    static const char* do_scheme(void*) { return "stublisten"; }

    static gn_result_t do_listen(void* self, const char* uri) {
        auto* s = static_cast<StubLink*>(self);
        s->listen_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lk(s->mu);
            s->listen_uris.emplace_back(uri ? uri : "");
        }
        return s->listen_result.load(std::memory_order_acquire);
    }
    static gn_result_t do_connect(void*, const char*)                { return GN_ERR_NOT_IMPLEMENTED; }
    static gn_result_t do_send(void*, gn_conn_id_t,
                               const std::uint8_t*, std::size_t)    { return GN_ERR_NOT_IMPLEMENTED; }
    static gn_result_t do_send_batch(void*, gn_conn_id_t,
                                     const gn_byte_span_t*, std::size_t) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static gn_result_t do_disconnect(void*, gn_conn_id_t)            { return GN_ERR_NOT_IMPLEMENTED; }
    static const char* do_extension_name(void*)                       { return ""; }
    static const void* do_extension_vtable(void*)                     { return nullptr; }
    static void        do_destroy(void*)                              {}

    static gn_link_vtable_t make_vtable() {
        gn_link_vtable_t v{};
        v.api_size         = sizeof(gn_link_vtable_t);
        v.scheme           = &do_scheme;
        v.listen           = &do_listen;
        v.connect          = &do_connect;
        v.send             = &do_send;
        v.send_batch       = &do_send_batch;
        v.disconnect       = &do_disconnect;
        v.extension_name   = &do_extension_name;
        v.extension_vtable = &do_extension_vtable;
        v.destroy          = &do_destroy;
        return v;
    }
};

inline gn_link_id_t register_stub_link(gn_core_t* core, StubLink& stub,
                                       const gn_link_vtable_t& vt) {
    gn_register_meta_t meta{};
    meta.api_size = sizeof(meta);
    meta.name     = "stublisten";
    return gn_core_register_link(core, &meta, &vt, &stub);
}

}  // namespace listen_test

TEST(CoreListen, NullUriReturnsNullArg) {
    /// Symmetric with the `gn_core_connect` NULL defence; non-NULL handle,
    /// NULL URI must surface `GN_ERR_NULL_ARG` rather than dereference.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    EXPECT_EQ(gn_core_listen(core, /*uri*/ nullptr), GN_ERR_NULL_ARG);

    gn_core_destroy(core);
}

TEST(CoreListen, MissingSchemeReturnsNotFound) {
    /// URI without a `://` separator — the derive-scheme helper returns
    /// an empty view and the entry short-circuits with `NOT_FOUND` (same
    /// shape as `gn_core_connect`'s NULL-scheme + URI-without-prefix).
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    EXPECT_EQ(gn_core_listen(core, "no-scheme-here"), GN_ERR_NOT_FOUND);

    gn_core_destroy(core);
}

TEST(CoreListen, WithoutLinkReturnsNotFound) {
    /// No link plugin registered for the resolved scheme → the registry
    /// lookup misses and the entry surfaces `NOT_FOUND`. Mirrors
    /// `ConnectWithoutLinkReturnsNotFound` for the inbound side.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);
    ASSERT_EQ(gn_core_start(core), GN_OK);

    EXPECT_EQ(gn_core_listen(core, "tcp://0.0.0.0:0"), GN_ERR_NOT_FOUND);

    gn_core_destroy(core);
}

TEST(CoreListen, LifecycleSmokeWithStubLink) {
    /// End-to-end lifecycle: create → init → register stub link →
    /// listen → stop → destroy. The stub captures the URI it was
    /// asked to bind on, so the test asserts the C ABI forwarded
    /// to the vtable slot intact and that teardown completes without
    /// crashing even though no real acceptor exists.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    listen_test::StubLink stub;
    const auto vt = listen_test::StubLink::make_vtable();
    const gn_link_id_t link_id = listen_test::register_stub_link(core, stub, vt);
    ASSERT_NE(link_id, GN_INVALID_LINK_ID);

    ASSERT_EQ(gn_core_start(core), GN_OK);

    /// Conn-state subscription pre-installed: the contract on
    /// `gn_core_listen` says inbound accepted conns surface through
    /// this channel without a new callback shape. The stub does not
    /// actually accept anything, but we install the subscription so
    /// the test pins the «register before listen» discipline the
    /// docstring describes.
    std::atomic<int> conn_events{0};
    const auto conn_sub = gn_core_on_conn_state(
        core,
        +[](void* ud, const gn_conn_event_t* /*ev*/) {
            static_cast<std::atomic<int>*>(ud)->fetch_add(1);
        },
        &conn_events);
    ASSERT_NE(conn_sub, 0u);

    EXPECT_EQ(gn_core_listen(core, "stublisten://1.2.3.4:0"), GN_OK);
    EXPECT_EQ(stub.listen_calls.load(), 1);
    {
        std::lock_guard lk(stub.mu);
        ASSERT_EQ(stub.listen_uris.size(), 1u);
        EXPECT_EQ(stub.listen_uris.front(), "stublisten://1.2.3.4:0");
    }

    /// A second listen on the same scheme forwards again — the entry
    /// is stateless on the C ABI side and trusts the link plugin's
    /// own duplicate-listen policy.
    EXPECT_EQ(gn_core_listen(core, "stublisten://5.6.7.8:9"), GN_OK);
    EXPECT_EQ(stub.listen_calls.load(), 2);

    /// Verdict from the link plugin propagates verbatim. Flip the
    /// stub to a transport-style failure and assert the C ABI does
    /// not mask or remap it.
    stub.listen_result.store(GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(gn_core_listen(core, "stublisten://busy:0"),
              GN_ERR_LIMIT_REACHED);

    gn_core_off_conn_state(core, conn_sub);
    gn_core_destroy(core);
}

TEST(CoreListen, InboundConnEventSurfacesThroughConnState) {
    /// Pin the «inbound accepted conns surface through the existing
    /// conn-state subscription path» contract in `sdk/core.h`. We
    /// drive the kernel's host_api `notify_connect` directly — that's
    /// the slot a real link plugin would call from its accept loop —
    /// and assert the host-side conn-state subscriber sees the event
    /// without `gn_core_listen` having to introduce a new callback
    /// shape. The actual `listen()` call exercises the same scheme
    /// lookup the previous test pinned; this test focuses on the
    /// event-surfacing half of the contract.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    listen_test::StubLink stub;
    const auto vt = listen_test::StubLink::make_vtable();
    const gn_link_id_t link_id = listen_test::register_stub_link(core, stub, vt);
    ASSERT_NE(link_id, GN_INVALID_LINK_ID);

    ASSERT_EQ(gn_core_start(core), GN_OK);

    struct Captured {
        std::atomic<int>          fires{0};
        std::atomic<gn_conn_id_t> last_conn{GN_INVALID_ID};
        std::atomic<int>          last_kind{0};
    } captured;

    const auto sub = gn_core_on_conn_state(
        core,
        +[](void* ud, const gn_conn_event_t* ev) {
            auto* c = static_cast<Captured*>(ud);
            if (ev == nullptr) return;
            c->fires.fetch_add(1);
            c->last_conn.store(ev->conn);
            c->last_kind.store(static_cast<int>(ev->kind));
        },
        &captured);
    ASSERT_NE(sub, 0u);

    /// Bind through the C ABI. The stub's `listen` records the URI but
    /// does not run a real accept loop — the simulated accept below
    /// drives `notify_connect` directly, the same slot a real link's
    /// accept handler would call.
    ASSERT_EQ(gn_core_listen(core, "stublisten://127.0.0.1:0"), GN_OK);
    EXPECT_EQ(stub.listen_calls.load(), 1);
    (void)link_id;  // touched only to assert non-zero registration above

    /// Simulated inbound accept: a real link plugin calls
    /// `host_api->notify_connect` from its acceptor when it admits a
    /// peer. We do the same here so the test pins the «host-side
    /// `gn_core_on_conn_state` subscriber sees accepted conns» half of
    /// the contract without depending on the TCP plugin being part of
    /// the unit-test target.
    const host_api_t* api = gn_core_host_api(core);
    ASSERT_NE(api, nullptr);
    ASSERT_NE(api->notify_connect, nullptr);

    gn_conn_id_t inbound_conn = GN_INVALID_ID;
    std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES] = {};
    const auto rc = api->notify_connect(
        api->host_ctx,
        peer_pk,
        /*uri=*/"stublisten://127.0.0.1:54321",
        GN_TRUST_LOOPBACK,
        GN_ROLE_RESPONDER,
        &inbound_conn);
    ASSERT_EQ(rc, GN_OK);
    ASSERT_NE(inbound_conn, GN_INVALID_ID);

    /// `notify_connect` publishes `CONNECTED` synchronously before
    /// returning, so by the time we look the subscriber has already
    /// fired. No polling needed.
    EXPECT_GE(captured.fires.load(), 1);
    EXPECT_EQ(captured.last_conn.load(), inbound_conn);
    EXPECT_EQ(captured.last_kind.load(),
              static_cast<int>(GN_CONN_EVENT_CONNECTED));

    gn_core_off_conn_state(core, sub);
    gn_core_destroy(core);
}

TEST(CoreC, SendToUnknownConnectionReturnsNotFound) {
    /// The registry has no record for a fabricated conn id, so the
    /// host_api send slot surfaces `GN_ERR_NOT_FOUND` exactly as a
    /// plugin-side send would.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);
    ASSERT_EQ(gn_core_start(core), GN_OK);

    EXPECT_EQ(gn_core_send_to(core, /*conn*/ 9999, /*msg_id*/ 1,
                              /*payload*/ nullptr, 0),
              GN_ERR_NOT_FOUND);
    gn_core_destroy(core);
}

TEST(CoreC, BroadcastWithNoConnectionsIsNoOp) {
    /// Empty connection registry → `for_each` has nothing to walk and
    /// the entry returns without dispatching.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);
    ASSERT_EQ(gn_core_start(core), GN_OK);

    const std::uint8_t payload[] = {0x01, 0x02};
    gn_core_broadcast(core, /*msg_id*/ 1, payload, sizeof(payload));
    EXPECT_EQ(gn_core_connection_count(core), 0u);

    gn_core_destroy(core);
}

// ── Limits accessor ─────────────────────────────────────────────────────────

TEST(CoreC, LimitsAccessorNonNull) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    /// Limits are pre-applied at create time per `sdk/core.h`; the
    /// accessor must surface a borrow before init runs.
    const gn_limits_t* l = gn_core_limits(core);
    ASSERT_NE(l, nullptr);
    /// Default cap published in `sdk/limits.h`.
    EXPECT_EQ(l->max_connections, GN_LIMITS_DEFAULT_MAX_CONNECTIONS);
    gn_core_destroy(core);
}

TEST(CoreC, SetLimitsAfterInitRejected) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);
    /// Limit changes after `Phase::Ready` are rejected per the
    /// "must be called before init" contract.
    gn_limits_t limits{};
    EXPECT_EQ(gn_core_set_limits(core, &limits), GN_ERR_INVALID_STATE);
    gn_core_destroy(core);
}

// ── Version ─────────────────────────────────────────────────────────────────

TEST(CoreC, VersionStringNonEmpty) {
    const char* v = gn_version();
    ASSERT_NE(v, nullptr);
    EXPECT_GT(std::strlen(v), 0u);
}

TEST(CoreC, VersionPackedMatchesSdkMacros) {
    const std::uint32_t expected = gn_version_pack(
        static_cast<std::uint32_t>(GN_SDK_VERSION_MAJOR),
        static_cast<std::uint32_t>(GN_SDK_VERSION_MINOR),
        static_cast<std::uint32_t>(GN_SDK_VERSION_PATCH));
    EXPECT_EQ(gn_version_packed(), expected);
}

// ── host_api accessor ───────────────────────────────────────────────────────

TEST(CoreC, HostApiAccessorReturnsBuiltTable) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    /// Constructor of `gn_core_s` builds the host_api at create time;
    /// the accessor is a borrow into that table.
    const host_api_t* api = gn_core_host_api(core);
    ASSERT_NE(api, nullptr);
    /// The table is fully populated before `gn_core_create` returns;
    /// at minimum the `send` slot the host drives indirectly through
    /// `gn_core_send_to` is non-null.
    EXPECT_NE(api->send, nullptr);
    gn_core_destroy(core);
}

// ── gn_core_query_extension_checked — public C ABI extension lookup ────────

#include <sdk/extensions/link_capability.h>

TEST(CoreC, QueryLinkCapabilityViaPublicCABI) {
    /// External clients (raw-socket adapters, FFI bindings) consume
    /// `gn.link.capability` through the public C ABI lookup, not the
    /// internal `Kernel::extensions()` accessor. This test pins that
    /// the kernel registers the surface during `gn_core_create` and
    /// the public lookup returns a working vtable that produces a
    /// usable snapshot.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    const void* raw = gn_core_query_extension_checked(
        core, GN_EXT_LINK_CAPABILITY, GN_EXT_LINK_CAPABILITY_VERSION);
    ASSERT_NE(raw, nullptr);

    const auto* api =
        static_cast<const gn_link_capability_api_t*>(raw);
    ASSERT_EQ(api->api_size, sizeof(gn_link_capability_api_t));
    ASSERT_NE(api->get, nullptr);

    gn_link_capability_t cap{};
    EXPECT_EQ(api->get(api->ctx, &cap), 0);
    /// Any sane test host can bind at least one socket family.
    EXPECT_TRUE(cap.can_bind_udp_v4 || cap.can_bind_udp_v6 ||
                cap.can_bind_tcp_v4 || cap.can_bind_tcp_v6);

    gn_core_destroy(core);
}

TEST(CoreC, QueryUnknownExtensionReturnsNull) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    EXPECT_EQ(gn_core_query_extension_checked(
                  core, "gn.does.not.exist", 1u),
              nullptr);

    gn_core_destroy(core);
}

TEST(CoreC, QueryWrongVersionReturnsNull) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    /// A producer-version bump beyond the consumer's pin must surface
    /// as a NULL lookup; the consumer cannot safely read fields the
    /// older producer did not emit.
    EXPECT_EQ(gn_core_query_extension_checked(
                  core, GN_EXT_LINK_CAPABILITY, 0xFFFFFFFFu),
              nullptr);

    gn_core_destroy(core);
}

// ── gn_core_register_protocol — C ABI host-side protocol registration ──────

#include <sdk/protocol.h>

namespace {

/// Minimum-viable stub vtable just for the registration path. The
/// kernel only needs `protocol_id` at registration time; deframe /
/// frame are not exercised by these smoke tests.
const char* stub_protocol_id(void*) noexcept { return "stub-test-v1"; }
std::size_t stub_max_payload(void*) noexcept { return 1024; }
std::uint32_t stub_trust_mask(void*) noexcept { return 0xFu; }
void stub_destroy(void*) noexcept { /* no-op */ }
gn_result_t stub_deframe(void*, gn_connection_context_t*,
                          const std::uint8_t*, std::size_t,
                          gn_deframe_result_t*) noexcept {
    return GN_ERR_DEFRAME_INCOMPLETE;
}
gn_result_t stub_frame(void*, gn_connection_context_t*,
                        const gn_message_t*,
                        std::uint8_t**, std::size_t*,
                        void**, void(**)(void*, std::uint8_t*)) noexcept {
    return GN_ERR_NOT_IMPLEMENTED;
}

gn_protocol_layer_vtable_t make_stub_vtable() {
    gn_protocol_layer_vtable_t v{};
    v.api_size           = sizeof(v);
    v.protocol_id        = &stub_protocol_id;
    v.deframe            = &stub_deframe;
    v.frame              = &stub_frame;
    v.max_payload_size   = &stub_max_payload;
    v.destroy            = &stub_destroy;
    v.allowed_trust_mask = &stub_trust_mask;
    return v;
}

}  // namespace

TEST(CoreC, RegisterProtocolAcceptsVtable) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    /// Kernel wraps the supplied vtable in `VtableProtocolLayer` and
    /// stores it in the registry exactly as if it had been registered
    /// through the C++ `protocol_layers().register_layer(...)` path.
    gn_protocol_layer_vtable_t vt = make_stub_vtable();
    EXPECT_EQ(gn_core_register_protocol(core, &vt, /*self*/ nullptr),
              GN_OK);

    gn_core_destroy(core);
}

TEST(CoreC, RegisterProtocolNullArgRejected) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    EXPECT_EQ(gn_core_register_protocol(nullptr, nullptr, nullptr),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_register_protocol(core, nullptr, nullptr),
              GN_ERR_NULL_ARG);

    gn_core_destroy(core);
}

TEST(CoreC, RegisterProtocolApiSizeMismatchRejected) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    /// api_size below the producer's `sizeof(gn_protocol_layer_vtable_t)`
    /// means the consumer's struct is older than the producer's —
    /// `abi-evolution.en.md` §3a says the kernel refuses the registration
    /// instead of letting a partial vtable through.
    gn_protocol_layer_vtable_t vt = make_stub_vtable();
    vt.api_size = 4;
    EXPECT_EQ(gn_core_register_protocol(core, &vt, nullptr),
              GN_ERR_VERSION_MISMATCH);

    gn_core_destroy(core);
}

// ── Multi-protocol coexistence ─────────────────────────────────────────────

#include <core/kernel/kernel.hpp>
#include <core/kernel/core_c_internal.hpp>
#include <core/registry/protocol_layer.hpp>

namespace {

/// Stub vtable B — second `protocol_id` used to prove the registry
/// admits two layers in parallel. Returns its own id so the by-id
/// lookup distinguishes it from the default `gnet-v1` layer the
/// host adds in-tree.
const char* stub_b_protocol_id(void*) noexcept { return "stub-second-v1"; }
std::size_t stub_b_max_payload(void*) noexcept { return 2048; }
std::uint32_t stub_b_trust_mask(void*) noexcept { return 0xFu; }
void stub_b_destroy(void*) noexcept { /* no-op */ }
gn_result_t stub_b_deframe(void*, gn_connection_context_t*,
                            const std::uint8_t*, std::size_t,
                            gn_deframe_result_t* out) noexcept {
    if (out) {
        out->messages       = nullptr;
        out->count          = 0;
        out->bytes_consumed = 0;
    }
    return GN_OK;
}
gn_result_t stub_b_frame(void*, gn_connection_context_t*,
                          const gn_message_t*,
                          std::uint8_t**, std::size_t*,
                          void**, void(**)(void*, std::uint8_t*)) noexcept {
    return GN_ERR_NOT_IMPLEMENTED;
}

gn_protocol_layer_vtable_t make_stub_b_vtable() {
    gn_protocol_layer_vtable_t v{};
    v.api_size           = sizeof(v);
    v.protocol_id        = &stub_b_protocol_id;
    v.deframe            = &stub_b_deframe;
    v.frame              = &stub_b_frame;
    v.max_payload_size   = &stub_b_max_payload;
    v.destroy            = &stub_b_destroy;
    v.allowed_trust_mask = &stub_b_trust_mask;
    return v;
}

}  // namespace

TEST(CoreC, RegisterSecondProtocol) {
    /// Two `gn_core_register_protocol` calls install two coexisting
    /// `IProtocolLayer` adapters. The dispatch path
    /// (`notify_inbound_bytes` in `core/kernel/host_api/notifications.cpp`)
    /// keys its lookup by `ConnectionRecord::protocol_id`, so a connection
    /// stamped with one id must route to its own layer regardless of the
    /// other layer's presence. The cross-protocol envelope isolation
    /// invariant in `protocol-layer.en.md` §4 depends on this: the
    /// registry must hold both adapters by their declared id and the
    /// per-protocol_id lookup must return each one's adapter without
    /// confusion.
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    /// Capture the baseline so we tolerate static-plugin registrations
    /// that may have landed during `gn_core_init` under
    /// `-DGOODNET_STATIC_PLUGINS=ON`.
    const std::size_t baseline = core->kernel.protocol_layers().size();

    gn_protocol_layer_vtable_t vt_a = make_stub_vtable();
    gn_protocol_layer_vtable_t vt_b = make_stub_b_vtable();

    /// Both registrations succeed — the registry keys by `protocol_id`
    /// and the two vtables advertise distinct strings.
    ASSERT_EQ(gn_core_register_protocol(core, &vt_a, /*self*/ nullptr),
              GN_OK);
    ASSERT_EQ(gn_core_register_protocol(core, &vt_b, /*self*/ nullptr),
              GN_OK);

    EXPECT_EQ(core->kernel.protocol_layers().size(), baseline + 2u);

    /// Per-protocol_id lookup recovers each adapter independently. The
    /// dispatch path runs the same `find_by_protocol_id(rec.protocol_id)`
    /// call against its connection record — if either lookup returned
    /// the wrong adapter, an envelope arriving on a `stub-test-v1`
    /// connection would be deframed by `stub-second-v1`'s parser and
    /// vice-versa.
    auto layer_a =
        core->kernel.protocol_layers().find_by_protocol_id("stub-test-v1");
    auto layer_b =
        core->kernel.protocol_layers().find_by_protocol_id("stub-second-v1");
    ASSERT_NE(layer_a, nullptr);
    ASSERT_NE(layer_b, nullptr);
    EXPECT_NE(layer_a.get(), layer_b.get());
    EXPECT_EQ(layer_a->protocol_id(), "stub-test-v1");
    EXPECT_EQ(layer_b->protocol_id(), "stub-second-v1");

    /// Re-registering an already-present `protocol_id` is rejected
    /// with `GN_ERR_LIMIT_REACHED` — the registry treats the id as
    /// a unique key, not a stack.
    gn_protocol_layer_vtable_t vt_a_dup = make_stub_vtable();
    EXPECT_EQ(gn_core_register_protocol(core, &vt_a_dup, /*self*/ nullptr),
              GN_ERR_LIMIT_REACHED);

    gn_core_destroy(core);
}

// ── Plugin unload / hot-reload smoke ───────────────────────────────────────

#include <core/plugin/plugin_manifest.hpp>

#ifdef GOODNET_NULL_PLUGIN_PATH

TEST(CoreC, CoreUnloadReload) {
    /// Drive `gn_core_load_plugin` against the in-tree null security
    /// provider, then `gn_core_unload_plugin` by descriptor name, then
    /// load the same .so again. The second load must succeed — proving
    /// the first round walked the full `unregister → drain → shutdown
    /// → close` chain (an unfinished close would leave `instances_`
    /// non-empty and the second `load()` call would fail with
    /// `GN_ERR_LIMIT_REACHED`).
    auto hash = gn::core::PluginManifest::sha256_of_file(
        GOODNET_NULL_PLUGIN_PATH);
    ASSERT_TRUE(hash.has_value())
        << "could not hash null plugin at " << GOODNET_NULL_PLUGIN_PATH;

    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    ASSERT_EQ(gn_core_load_plugin(core,
                                   GOODNET_NULL_PLUGIN_PATH,
                                   hash->data()),
              GN_OK);

    /// The plugin's descriptor `name` from `plugins/security/null/null.cpp`
    /// is the key `gn_core_unload_plugin` looks up by.
    EXPECT_EQ(gn_core_unload_plugin(core, "goodnet_security_null"),
              GN_OK);

    /// Idempotency: a second unload of the same name reports
    /// `GN_ERR_NOT_FOUND` without crashing.
    EXPECT_EQ(gn_core_unload_plugin(core, "goodnet_security_null"),
              GN_ERR_NOT_FOUND);

    /// Reload — the `PluginManager::active_` flag the manager cleared
    /// at the end of `unload()` admits a fresh `load()` call. The
    /// re-loaded `.so` runs its `gn_plugin_init` + `gn_plugin_register`
    /// against the same kernel handle, so the host can swap the
    /// plugin's code path without dropping any other in-process state.
    ASSERT_EQ(gn_core_load_plugin(core,
                                   GOODNET_NULL_PLUGIN_PATH,
                                   hash->data()),
              GN_OK);

    /// Unknown names continue to report `NOT_FOUND` rather than
    /// silently succeed.
    EXPECT_EQ(gn_core_unload_plugin(core, "no-such-plugin"),
              GN_ERR_NOT_FOUND);

    gn_core_destroy(core);
}

TEST(CoreC, UnloadPluginNullArgRejected) {
    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    EXPECT_EQ(gn_core_unload_plugin(core, /*name*/ nullptr),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_unload_plugin(/*core*/ nullptr, "anything"),
              GN_ERR_NULL_ARG);

    /// Empty name: a string with no chance of matching any
    /// descriptor's `plugin_name`, reported as NOT_FOUND so the
    /// idempotency contract holds for the edge case.
    EXPECT_EQ(gn_core_unload_plugin(core, ""),
              GN_ERR_NOT_FOUND);

    gn_core_destroy(core);
}

#endif  // GOODNET_NULL_PLUGIN_PATH

// ── gn_core_register_runtime — C ABI external runtime kind ──────────────────
//
// Mirrors `sdk/plugin_runtime.h`. The tests below pin the four observable
// behaviours of that path: argument validation, reserved-kind rejection,
// api_size truncation acceptance, init-thunk dispatch on registration, and
// end-to-end load through the registered runtime's `register_plugin` thunk.

#include <sdk/plugin_runtime.h>

#include <core/kernel/core_c_internal.hpp>
#include <core/plugin/plugin_runtime.hpp>
#include <core/plugin/remote_host.hpp>  // PluginInstance carries a unique_ptr<RemoteHost>

namespace runtime_test {

/// Free-function thunks share state through `void* ctx` — kept as
/// free functions (not lambdas-with-captures) so the test exercises
/// the exact C ABI shape a Rust / Go / C host would use.
struct Counters {
    std::atomic<int>           init_calls{0};
    std::atomic<int>           shutdown_calls{0};
    std::atomic<int>           register_calls{0};
    std::atomic<int>           unregister_calls{0};
    std::atomic<gn_result_t>   init_return{GN_OK};
    std::mutex                 mu;
    std::vector<std::string>   last_names;
    std::vector<std::string>   last_paths;
    /// Monotonic instance handle the test thunk hands back to the
    /// kernel. Starts at 1 so the very first mint is non-zero.
    std::atomic<std::uint32_t> next_instance{1};
};

inline gn_result_t do_init(void* ctx) {
    auto* c = static_cast<Counters*>(ctx);
    c->init_calls.fetch_add(1);
    return c->init_return.load();
}

inline gn_result_t do_shutdown(void* ctx) {
    auto* c = static_cast<Counters*>(ctx);
    c->shutdown_calls.fetch_add(1);
    return GN_OK;
}

inline gn_result_t do_register(void* ctx,
                               const char* name,
                               const char* path,
                               gn_plugin_instance_t* out_instance) {
    auto* c = static_cast<Counters*>(ctx);
    c->register_calls.fetch_add(1);
    {
        std::lock_guard lk(c->mu);
        c->last_names.emplace_back(name ? name : "");
        c->last_paths.emplace_back(path ? path : "");
    }
    if (out_instance != nullptr) {
        *out_instance = c->next_instance.fetch_add(1);
    }
    return GN_OK;
}

inline gn_result_t do_unregister(void* ctx, gn_plugin_instance_t /*inst*/) {
    auto* c = static_cast<Counters*>(ctx);
    c->unregister_calls.fetch_add(1);
    return GN_OK;
}

inline gn_plugin_runtime_vtable_t make_vtable() {
    gn_plugin_runtime_vtable_t v{};
    v.api_size        = sizeof(gn_plugin_runtime_vtable_t);
    v.init            = &do_init;
    v.register_plugin = &do_register;
    v.unregister      = &do_unregister;
    v.shutdown        = &do_shutdown;
    return v;
}

}  // namespace runtime_test

TEST(CoreRegisterRuntime, NullArgsReturnInvalid) {
    /// Every NULL combination on the registration entry must surface
    /// `GN_ERR_NULL_ARG` — symmetric with the rest of the C ABI's
    /// «never dereference on a NULL handshake» discipline.
    runtime_test::Counters counters;
    auto vt = runtime_test::make_vtable();

    EXPECT_EQ(gn_core_register_runtime(nullptr, "k", &vt, &counters),
              GN_ERR_NULL_ARG);

    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    EXPECT_EQ(gn_core_register_runtime(core, nullptr, &vt, &counters),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_register_runtime(core, "", &vt, &counters),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_register_runtime(core, "k", nullptr, &counters),
              GN_ERR_NULL_ARG);

    /// The valid combination must NOT have fired any thunks.
    EXPECT_EQ(counters.init_calls.load(),     0);
    EXPECT_EQ(counters.shutdown_calls.load(), 0);

    gn_core_destroy(core);
}

TEST(CoreRegisterRuntime, ReservedKindsReject) {
    /// Built-in kinds ("static", "dynamic", "remote") are populated
    /// by the PluginManager ctor; a host registration attempt under
    /// any of these returns `GN_ERR_LIMIT_REACHED` per the
    /// runtime-registry's duplicate-key policy.
    runtime_test::Counters counters;
    auto vt = runtime_test::make_vtable();

    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    EXPECT_EQ(gn_core_register_runtime(core, "static", &vt, &counters),
              GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(gn_core_register_runtime(core, "dynamic", &vt, &counters),
              GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(gn_core_register_runtime(core, "remote", &vt, &counters),
              GN_ERR_LIMIT_REACHED);

    /// Rejections fired before any thunk ran.
    EXPECT_EQ(counters.init_calls.load(),     0);
    EXPECT_EQ(counters.shutdown_calls.load(), 0);

    gn_core_destroy(core);
}

TEST(CoreRegisterRuntime, SmallApiSizeAccepted) {
    /// A vtable that declares exactly `GN_PLUGIN_RUNTIME_VTABLE_MIN_SIZE`
    /// is the minimum the kernel accepts — anything smaller means the
    /// producer was built against an even older SDK than the one this
    /// header ships. `MIN_SIZE` today covers all four thunks, but a
    /// future minor that appends a fifth thunk lets older hosts keep
    /// working with their original (smaller) `api_size`.
    runtime_test::Counters counters;
    auto vt = runtime_test::make_vtable();
    vt.api_size = GN_PLUGIN_RUNTIME_VTABLE_MIN_SIZE;

    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    EXPECT_EQ(gn_core_register_runtime(core, "minsize", &vt, &counters),
              GN_OK);

    /// A truly truncated vtable — smaller than min — is rejected.
    gn_plugin_runtime_vtable_t too_small{};
    too_small.api_size        = sizeof(std::size_t);  // only the api_size field
    too_small.init            = &runtime_test::do_init;
    too_small.register_plugin = &runtime_test::do_register;
    too_small.unregister      = &runtime_test::do_unregister;
    too_small.shutdown        = &runtime_test::do_shutdown;
    EXPECT_EQ(gn_core_register_runtime(core, "too-small", &too_small, &counters),
              GN_ERR_VERSION_MISMATCH);

    gn_core_destroy(core);
}

TEST(CoreRegisterRuntime, RegistrationCallsInit) {
    /// The runtime-level `init` thunk fires once during
    /// `gn_core_register_runtime`. The paired `shutdown` thunk fires
    /// when the kernel drops the runtime, which happens at
    /// `gn_core_destroy` time (PluginManager dtor walks the runtime
    /// registry).
    runtime_test::Counters counters;
    auto vt = runtime_test::make_vtable();

    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    EXPECT_EQ(counters.init_calls.load(), 0);
    EXPECT_EQ(gn_core_register_runtime(core, "init-counter", &vt, &counters),
              GN_OK);
    EXPECT_EQ(counters.init_calls.load(), 1);

    /// Re-registering the same kind hits the LIMIT_REACHED path and
    /// must NOT fire a second init.
    EXPECT_EQ(gn_core_register_runtime(core, "init-counter", &vt, &counters),
              GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(counters.init_calls.load(), 1);

    /// A non-OK init return rolls back the registration without
    /// firing the paired shutdown — an unpaired teardown would
    /// surprise the host with a release of state it never set up.
    runtime_test::Counters fail_counters;
    fail_counters.init_return.store(GN_ERR_INTEGRITY_FAILED);
    EXPECT_EQ(gn_core_register_runtime(core, "init-fails", &vt, &fail_counters),
              GN_ERR_INTEGRITY_FAILED);
    EXPECT_EQ(fail_counters.init_calls.load(),     1);
    EXPECT_EQ(fail_counters.shutdown_calls.load(), 0);

    gn_core_destroy(core);
    /// Destroy walked the PluginManager dtor which dropped every
    /// registered runtime; the OK-init counter saw its paired
    /// shutdown thunk fire.
    EXPECT_EQ(counters.shutdown_calls.load(), 1);
    /// The fail-init runtime was never owned by the manager — its
    /// shutdown thunk stays at zero.
    EXPECT_EQ(fail_counters.shutdown_calls.load(), 0);
}

TEST(CoreRegisterRuntime, LoadCustomKindEndToEnd) {
    /// End-to-end: register a `"test-runtime"` kind, dispatch through
    /// the kernel's runtime registry, and assert the vtable thunk
    /// saw the entry name + path. This drives the same dispatch path
    /// `PluginManager::open_one` would take if the manifest schema
    /// already supported a free-form `runtime` field. The test
    /// reaches into the C++ runtime registry via the internal core
    /// handle to invoke `load()` directly — the public C ABI for
    /// custom-kind loads will land in a later commit (today the
    /// manifest still only maps to dynamic/static/remote).
    runtime_test::Counters counters;
    auto vt = runtime_test::make_vtable();

    gn_core_t* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    ASSERT_EQ(gn_core_register_runtime(core, "test-runtime", &vt, &counters),
              GN_OK);

    /// Reach through `gn_core_s` to the PluginManager's runtime
    /// registry. `runtime_for` returns a borrowed pointer; the
    /// manager owns the adapter and keeps it alive for the lifetime
    /// of `core`.
    auto* runtime = core->plugins.runtime_for("test-runtime");
    ASSERT_NE(runtime, nullptr);
    EXPECT_EQ(runtime->name(), "test-runtime");

    /// Dispatch a fake load through the runtime. The kernel-internal
    /// `PluginLoadContext` is the only argument we have to pass
    /// directly — the manager builds it the same way during
    /// `open_one`.
    gn::core::PluginInstance inst{};
    gn::core::PluginManifest empty_manifest;
    gn::core::PluginLoadContext lc{
        .kernel = &core->kernel,
        .manifest = &empty_manifest,
        .manifest_required = false,
    };
    std::string diag;
    EXPECT_EQ(runtime->load("/virtual/path/wasm-plugin.wasm", lc, inst, diag),
              GN_OK)
        << "diag: " << diag;

    /// The thunk recorded the canonical entry name + path. The
    /// adapter derives the name from the path's basename minus the
    /// extension; the path is forwarded verbatim.
    EXPECT_EQ(counters.register_calls.load(), 1);
    {
        std::lock_guard lk(counters.mu);
        ASSERT_EQ(counters.last_names.size(), 1u);
        ASSERT_EQ(counters.last_paths.size(), 1u);
        EXPECT_EQ(counters.last_names.front(), "wasm-plugin");
        EXPECT_EQ(counters.last_paths.front(), "/virtual/path/wasm-plugin.wasm");
    }
    /// The adapter wrote a non-zero handle into `inst.self` (smuggled
    /// through as a uintptr_t round-trip).
    EXPECT_NE(inst.self, nullptr);

    /// Tear the fake instance down through the same runtime — the
    /// `unregister` thunk runs once, then `close` is a no-op.
    runtime->unregister(inst);
    EXPECT_EQ(counters.unregister_calls.load(), 1);
    runtime->shutdown(inst);
    runtime->close(inst, /*drained=*/true);

    /// Second unregister is idempotent: `self` was nulled out so the
    /// thunk skips the dispatch.
    runtime->unregister(inst);
    EXPECT_EQ(counters.unregister_calls.load(), 1);

    gn_core_destroy(core);
    EXPECT_EQ(counters.shutdown_calls.load(), 1);
}
