/// @file   tests/integration/test_core_c.cpp
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
    /// at this point in the kernel's life.
    EXPECT_EQ(stats.connections_active,    0u);
    EXPECT_EQ(stats.handlers_registered,   0u);
    EXPECT_EQ(stats.links_registered,      0u);
    EXPECT_EQ(stats.extensions_registered, 0u);
    EXPECT_EQ(stats.bytes_in,              0u);
    EXPECT_EQ(stats.bytes_out,             0u);
    EXPECT_EQ(stats.frames_in,             0u);
    EXPECT_EQ(stats.frames_out,            0u);
    EXPECT_EQ(stats.plugin_dlclose_leaks,  0u);

    gn_core_destroy(core);
}

TEST(CoreC, GetStatsRejectsNonZeroReserved) {
    /// `abi-evolution.md` §4: producer-side `_reserved` slots MUST be
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
    const std::uint32_t expected =
        (static_cast<std::uint32_t>(GN_SDK_VERSION_MAJOR) << 16) |
        (static_cast<std::uint32_t>(GN_SDK_VERSION_MINOR) << 8)  |
         static_cast<std::uint32_t>(GN_SDK_VERSION_PATCH);
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
