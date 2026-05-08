/// @file   tests/unit/kernel/test_router.cpp
/// @brief  Tests for `gn::core::Router`.
///
/// Pins the routing rules from `docs/contracts/protocol-layer.md` §6
/// and the chain-dispatch order / `on_result` invariants from
/// `docs/contracts/handler-registration.md` §3 + §6.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include <core/kernel/identity_set.hpp>
#include <core/kernel/router.hpp>
#include <core/registry/handler.hpp>
#include <sdk/cpp/types.hpp>
#include <sdk/handler.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

constexpr std::string_view kProtocol = "gnet-v1";

// ── Recording handler stub ───────────────────────────────────────────────

/// State recorded for a single handler instance across dispatches.
struct HandlerRecord {
    std::string                   tag;
    gn_propagation_t              return_value = GN_PROPAGATION_CONTINUE;
    std::atomic<int>              handle_calls{0};
    std::atomic<int>              on_result_calls{0};
    std::atomic<gn_propagation_t> last_on_result{GN_PROPAGATION_CONTINUE};
};

/// Per-test ordering log; records `(tag, kind)` for every callback so
/// tests can assert chain order in addition to call counts.
struct CallLog {
    struct Entry { std::string tag; const char* kind; gn_propagation_t result; };
    std::mutex          mu;
    std::vector<Entry>  entries;

    void push(std::string tag, const char* kind,
              gn_propagation_t result = GN_PROPAGATION_CONTINUE) {
        std::lock_guard lock{mu};
        entries.push_back({std::move(tag), kind, result});
    }
};

/// Self payload for the C-ABI handler. `record` is owned by the test
/// fixture; `log` likewise — both outlive every dispatch we drive.
struct Stub {
    HandlerRecord* record{nullptr};
    CallLog*       log{nullptr};
};

gn_propagation_t stub_handle(void* self, const gn_message_t* env) {
    auto* s = static_cast<Stub*>(self);
    s->record->handle_calls.fetch_add(1, std::memory_order_relaxed);
    s->log->push(s->record->tag, "handle");
    (void)env;
    return s->record->return_value;
}

void stub_on_result(void* self, const gn_message_t* env, gn_propagation_t result) {
    auto* s = static_cast<Stub*>(self);
    s->record->on_result_calls.fetch_add(1, std::memory_order_relaxed);
    s->record->last_on_result.store(result, std::memory_order_relaxed);
    s->log->push(s->record->tag, "on_result", result);
    (void)env;
}

/// Vtable singleton wired to the stub callbacks above. Same vtable
/// pointer for every handler in every test — the per-handler state
/// lives in the `void* self` payload.
const gn_handler_vtable_t* stub_vtable() {
    static const gn_handler_vtable_t vt = []() {
        gn_handler_vtable_t v{};
        v.api_size       = sizeof(gn_handler_vtable_t);
        v.handle_message = &stub_handle;
        v.on_result      = &stub_on_result;
        return v;
    }();
    return &vt;
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Build a deterministic, distinguishable public key.
PublicKey pk_from_byte(std::uint8_t seed) noexcept {
    PublicKey pk{};
    for (std::size_t i = 0; i < pk.size(); ++i) {
        pk[i] = static_cast<std::uint8_t>(seed + i);
    }
    return pk;
}

/// Populate the C envelope from C++ `PublicKey` values.
void fill_envelope(gn_message_t&    env,
                   const PublicKey& sender,
                   const PublicKey& receiver,
                   std::uint32_t    msg_id) noexcept {
    std::memset(&env, 0, sizeof(env));
    std::memcpy(env.sender_pk,   sender.data(),   GN_PUBLIC_KEY_BYTES);
    std::memcpy(env.receiver_pk, receiver.data(), GN_PUBLIC_KEY_BYTES);
    env.msg_id       = msg_id;
    env.payload      = nullptr;
    env.payload_size = 0;
}

/// Test fixture — bundles the registry, identity set, router, and the
/// log. Each test owns its instance.
struct RouterFixture {
    HandlerRegistry  registry;
    LocalIdentityRegistry identities;
    Router           router{identities, registry};
    CallLog          log;
    /// Stable storage for handler payloads and records. Pointers handed
    /// to the registry must outlive every dispatch.
    std::vector<std::unique_ptr<HandlerRecord>> records;
    std::vector<std::unique_ptr<Stub>>          stubs;

    /// Register a recording handler. Returns the record so the test can
    /// poll `handle_calls` / `on_result_calls`.
    HandlerRecord* register_handler(std::uint32_t    msg_id,
                                    std::uint8_t     priority,
                                    std::string      tag,
                                    gn_propagation_t return_value = GN_PROPAGATION_CONTINUE) {
        auto record = std::make_unique<HandlerRecord>();
        record->tag = std::move(tag);
        record->return_value = return_value;

        auto stub = std::make_unique<Stub>();
        stub->record = record.get();
        stub->log    = &log;

        gn_handler_id_t id = GN_INVALID_ID;
        const gn_result_t rc = registry.register_handler(
            kProtocol, msg_id, priority, stub_vtable(), stub.get(), &id);
        EXPECT_EQ(rc, GN_OK);
        EXPECT_NE(id, GN_INVALID_ID);

        HandlerRecord* raw = record.get();
        records.push_back(std::move(record));
        stubs.push_back(std::move(stub));
        return raw;
    }
};

// ── Routing decision tests ───────────────────────────────────────────────

TEST(Router_Decision, DispatchedLocal) {
    RouterFixture f;
    const auto local  = pk_from_byte(0x11);
    const auto sender = pk_from_byte(0x22);
    f.identities.add(local);

    auto* rec = f.register_handler(0x42, 128, "h");

    gn_message_t env{};
    fill_envelope(env, sender, local, 0x42);
    EXPECT_EQ(f.router.route_inbound(kProtocol, env),
              RouteOutcome::DispatchedLocal);
    EXPECT_EQ(rec->handle_calls.load(),    1);
    EXPECT_EQ(rec->on_result_calls.load(), 1);
}

TEST(Router_Decision, DispatchedBroadcast) {
    RouterFixture f;
    const auto sender = pk_from_byte(0x22);
    /// Identities may even be empty — broadcast is decided by
    /// `receiver_pk == ZERO`, not by membership.
    auto* rec = f.register_handler(0x42, 128, "h");

    gn_message_t env{};
    fill_envelope(env, sender, kBroadcastPk, 0x42);
    EXPECT_EQ(f.router.route_inbound(kProtocol, env),
              RouteOutcome::DispatchedBroadcast);
    EXPECT_EQ(rec->handle_calls.load(),    1);
    EXPECT_EQ(rec->on_result_calls.load(), 1);
}

TEST(Router_Decision, DroppedZeroSender) {
    RouterFixture f;
    const auto local = pk_from_byte(0x11);
    f.identities.add(local);
    auto* rec = f.register_handler(0x42, 128, "h");

    gn_message_t env{};
    fill_envelope(env, kBroadcastPk /* sender = ZERO */, local, 0x42);
    EXPECT_EQ(f.router.route_inbound(kProtocol, env),
              RouteOutcome::DroppedZeroSender);
    EXPECT_EQ(rec->handle_calls.load(),    0)
        << "early-reject must precede chain lookup";
    EXPECT_EQ(rec->on_result_calls.load(), 0);
}

TEST(Router_Decision, DroppedInvalidMsgId) {
    RouterFixture f;
    const auto local  = pk_from_byte(0x11);
    const auto sender = pk_from_byte(0x22);
    f.identities.add(local);
    auto* rec = f.register_handler(0x42, 128, "h");

    gn_message_t env{};
    fill_envelope(env, sender, local, /* msg_id = */ 0);
    EXPECT_EQ(f.router.route_inbound(kProtocol, env),
              RouteOutcome::DroppedInvalidMsgId);
    EXPECT_EQ(rec->handle_calls.load(),    0);
    EXPECT_EQ(rec->on_result_calls.load(), 0);
}

TEST(Router_Decision, DroppedUnknownReceiver_NoRelay) {
    RouterFixture f;
    const auto sender   = pk_from_byte(0x22);
    const auto stranger = pk_from_byte(0x33);
    /// Empty identities set, no relay loaded.
    auto* rec = f.register_handler(0x42, 128, "h");

    gn_message_t env{};
    fill_envelope(env, sender, stranger, 0x42);
    EXPECT_FALSE(f.router.relay_available());
    EXPECT_EQ(f.router.route_inbound(kProtocol, env),
              RouteOutcome::DroppedUnknownReceiver);
    EXPECT_EQ(rec->handle_calls.load(),    0)
        << "foreign receiver must not dispatch the local chain";
    EXPECT_EQ(rec->on_result_calls.load(), 0);
}

TEST(Router_Decision, DeferredRelay_RelayAvailable) {
    RouterFixture f;
    const auto sender   = pk_from_byte(0x22);
    const auto stranger = pk_from_byte(0x33);
    auto* rec = f.register_handler(0x42, 128, "h");

    f.router.set_relay_available(true);
    EXPECT_TRUE(f.router.relay_available());

    gn_message_t env{};
    fill_envelope(env, sender, stranger, 0x42);
    EXPECT_EQ(f.router.route_inbound(kProtocol, env),
              RouteOutcome::DeferredRelay);
    EXPECT_EQ(rec->handle_calls.load(),    0)
        << "relay extension owns the envelope; local chain stays untouched";
    EXPECT_EQ(rec->on_result_calls.load(), 0);
}

TEST(Router_Decision, DroppedNoHandler_LocalReceiverEmptyChain) {
    RouterFixture f;
    const auto local  = pk_from_byte(0x11);
    const auto sender = pk_from_byte(0x22);
    f.identities.add(local);
    /// No handlers registered for (kProtocol, 0x42).

    gn_message_t env{};
    fill_envelope(env, sender, local, 0x42);
    EXPECT_EQ(f.router.route_inbound(kProtocol, env),
              RouteOutcome::DroppedNoHandler);
}

TEST(Router_Decision, DroppedNoHandler_BroadcastEmptyChain) {
    RouterFixture f;
    const auto sender = pk_from_byte(0x22);

    gn_message_t env{};
    fill_envelope(env, sender, kBroadcastPk, 0x42);
    EXPECT_EQ(f.router.route_inbound(kProtocol, env),
              RouteOutcome::DroppedNoHandler);
}

TEST(Router_Decision, RejectPropagatesAsRejectedOutcome) {
    RouterFixture f;
    const auto local  = pk_from_byte(0x11);
    const auto sender = pk_from_byte(0x22);
    f.identities.add(local);
    auto* rec = f.register_handler(0x42, 128, "h", GN_PROPAGATION_REJECT);

    gn_message_t env{};
    fill_envelope(env, sender, local, 0x42);
    EXPECT_EQ(f.router.route_inbound(kProtocol, env),
              RouteOutcome::Rejected);
    EXPECT_EQ(rec->handle_calls.load(),    1);
    EXPECT_EQ(rec->on_result_calls.load(), 1);
    EXPECT_EQ(rec->last_on_result.load(),  GN_PROPAGATION_REJECT);
}

// ── Chain priority + propagation ─────────────────────────────────────────

TEST(Router_Chain, PriorityOrderHighestFirst) {
    RouterFixture f;
    const auto local  = pk_from_byte(0x11);
    const auto sender = pk_from_byte(0x22);
    f.identities.add(local);

    /// Register out of priority order to make sure the chain is sorted
    /// by priority, not by registration order.
    auto* mid_rec  = f.register_handler(0x42, 128, "mid");
    auto* high_rec = f.register_handler(0x42, 200, "high");
    auto* low_rec  = f.register_handler(0x42, 100, "low");

    gn_message_t env{};
    fill_envelope(env, sender, local, 0x42);
    EXPECT_EQ(f.router.route_inbound(kProtocol, env),
              RouteOutcome::DispatchedLocal);

    /// All three saw the envelope — they all returned `Continue`.
    EXPECT_EQ(high_rec->handle_calls.load(),    1);
    EXPECT_EQ(mid_rec->handle_calls.load(),     1);
    EXPECT_EQ(low_rec->handle_calls.load(),     1);
    EXPECT_EQ(high_rec->on_result_calls.load(), 1);
    EXPECT_EQ(mid_rec->on_result_calls.load(),  1);
    EXPECT_EQ(low_rec->on_result_calls.load(),  1);

    /// `handle` calls land in priority order.
    std::vector<std::string> handle_tags;
    {
        std::lock_guard lock{f.log.mu};
        for (const auto& e : f.log.entries) {
            if (std::string_view{e.kind} == "handle") {
                handle_tags.push_back(e.tag);
            }
        }
    }
    ASSERT_EQ(handle_tags.size(), 3u);
    EXPECT_EQ(handle_tags[0], "high");
    EXPECT_EQ(handle_tags[1], "mid");
    EXPECT_EQ(handle_tags[2], "low");
}

TEST(Router_Chain, ConsumedStopsLowerPriority) {
    RouterFixture f;
    const auto local  = pk_from_byte(0x11);
    const auto sender = pk_from_byte(0x22);
    f.identities.add(local);

    auto* high_rec = f.register_handler(0x42, 200, "high", GN_PROPAGATION_CONSUMED);
    auto* mid_rec  = f.register_handler(0x42, 128, "mid");
    auto* low_rec  = f.register_handler(0x42, 100, "low");

    gn_message_t env{};
    fill_envelope(env, sender, local, 0x42);
    EXPECT_EQ(f.router.route_inbound(kProtocol, env),
              RouteOutcome::DispatchedLocal);

    /// Top handler ate the envelope; nobody below saw it.
    EXPECT_EQ(high_rec->handle_calls.load(),    1);
    EXPECT_EQ(high_rec->on_result_calls.load(), 1);
    EXPECT_EQ(high_rec->last_on_result.load(),  GN_PROPAGATION_CONSUMED);
    EXPECT_EQ(mid_rec->handle_calls.load(),     0);
    EXPECT_EQ(mid_rec->on_result_calls.load(),  0);
    EXPECT_EQ(low_rec->handle_calls.load(),     0);
    EXPECT_EQ(low_rec->on_result_calls.load(),  0);
}

TEST(Router_Chain, ContinueLetsAllHandlersSeeEnvelope) {
    RouterFixture f;
    const auto local  = pk_from_byte(0x11);
    const auto sender = pk_from_byte(0x22);
    f.identities.add(local);

    auto* a = f.register_handler(0x42, 200, "a", GN_PROPAGATION_CONTINUE);
    auto* b = f.register_handler(0x42, 128, "b", GN_PROPAGATION_CONTINUE);
    auto* c = f.register_handler(0x42, 64,  "c", GN_PROPAGATION_CONTINUE);

    gn_message_t env{};
    fill_envelope(env, sender, local, 0x42);
    EXPECT_EQ(f.router.route_inbound(kProtocol, env),
              RouteOutcome::DispatchedLocal);

    EXPECT_EQ(a->handle_calls.load(),    1);
    EXPECT_EQ(b->handle_calls.load(),    1);
    EXPECT_EQ(c->handle_calls.load(),    1);
    EXPECT_EQ(a->on_result_calls.load(), 1);
    EXPECT_EQ(b->on_result_calls.load(), 1);
    EXPECT_EQ(c->on_result_calls.load(), 1);
}

}  // namespace
}  // namespace gn::core
