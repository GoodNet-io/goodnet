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
