/// @file   tests/unit/registry/test_protocol_layer.cpp
/// @brief  GoogleTest unit tests for `gn::core::ProtocolLayerRegistry`.
///
/// Pins the contract from `docs/contracts/protocol-layer.en.md` §4
/// (named registry of one or more layers; default `gnet-v1`; per-link
/// declared selection) plus the cross-protocol envelope isolation
/// invariant covered end-to-end in
/// `tests/unit/integration/test_protocol_layer_isolation.cpp`.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <core/registry/protocol_layer.hpp>
#include <sdk/cpp/protocol_layer.hpp>
#include <sdk/types.h>

namespace gn::core {
namespace {

class StubProtocol : public ::gn::IProtocolLayer {
public:
    explicit StubProtocol(std::string id) noexcept : id_(std::move(id)) {}

    [[nodiscard]] std::string_view protocol_id() const noexcept override {
        return id_;
    }

    ::gn::Result<::gn::DeframeResult> deframe(
        ::gn::ConnectionContext& /*ctx*/,
        std::span<const std::uint8_t> /*bytes*/) override {
        return ::gn::DeframeResult{};
    }

    ::gn::Result<std::vector<std::uint8_t>> frame(
        ::gn::ConnectionContext& /*ctx*/,
        const gn_message_t& /*msg*/) override {
        return std::vector<std::uint8_t>{};
    }

    [[nodiscard]] std::size_t max_payload_size() const noexcept override {
        return std::size_t{64} * 1024;
    }

private:
    std::string id_;
};

// ── argument validation ──────────────────────────────────────────────────

TEST(ProtocolLayerRegistry_Args, RejectsNullLayer) {
    ProtocolLayerRegistry r;
    protocol_layer_id_t id = kInvalidProtocolLayerId;
    EXPECT_EQ(r.register_layer(nullptr, &id), GN_ERR_NULL_ARG);
    EXPECT_EQ(id, kInvalidProtocolLayerId);
    EXPECT_EQ(r.size(), 0u);
}

TEST(ProtocolLayerRegistry_Args, RejectsNullOutId) {
    ProtocolLayerRegistry r;
    auto layer = std::make_shared<StubProtocol>("gnet-v1");
    EXPECT_EQ(r.register_layer(layer, nullptr), GN_ERR_NULL_ARG);
    EXPECT_EQ(r.size(), 0u);
}

TEST(ProtocolLayerRegistry_Args, RejectsEmptyProtocolId) {
    ProtocolLayerRegistry r;
    auto layer = std::make_shared<StubProtocol>("");
    protocol_layer_id_t id = kInvalidProtocolLayerId;
    EXPECT_EQ(r.register_layer(layer, &id), GN_ERR_NULL_ARG);
    EXPECT_EQ(id, kInvalidProtocolLayerId);
}

// ── registration ─────────────────────────────────────────────────────────

TEST(ProtocolLayerRegistry_Register, RegisterTwoLayersRetrievable) {
    ProtocolLayerRegistry r;
    auto gnet = std::make_shared<StubProtocol>("gnet-v1");
    auto raw  = std::make_shared<StubProtocol>("raw-v1");

    protocol_layer_id_t gnet_id = kInvalidProtocolLayerId;
    protocol_layer_id_t raw_id  = kInvalidProtocolLayerId;
    EXPECT_EQ(r.register_layer(gnet, &gnet_id), GN_OK);
    EXPECT_EQ(r.register_layer(raw,  &raw_id),  GN_OK);
    EXPECT_NE(gnet_id, raw_id);
    EXPECT_EQ(r.size(), 2u);

    auto found_gnet = r.find_by_protocol_id("gnet-v1");
    auto found_raw  = r.find_by_protocol_id("raw-v1");
    ASSERT_NE(found_gnet, nullptr);
    ASSERT_NE(found_raw,  nullptr);
    EXPECT_EQ(found_gnet.get(), gnet.get());
    EXPECT_EQ(found_raw.get(),  raw.get());
}

TEST(ProtocolLayerRegistry_Register, DuplicateRegistrationRejected) {
    ProtocolLayerRegistry r;
    auto first  = std::make_shared<StubProtocol>("gnet-v1");
    auto second = std::make_shared<StubProtocol>("gnet-v1");

    protocol_layer_id_t id = kInvalidProtocolLayerId;
    EXPECT_EQ(r.register_layer(first, &id), GN_OK);

    protocol_layer_id_t dup_id = kInvalidProtocolLayerId;
    EXPECT_EQ(r.register_layer(second, &dup_id), GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(dup_id, kInvalidProtocolLayerId);
    EXPECT_EQ(r.size(), 1u);

    /// First layer still installed.
    auto found = r.find_by_protocol_id("gnet-v1");
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found.get(), first.get());
}

// ── lookup ────────────────────────────────────────────────────────────────

TEST(ProtocolLayerRegistry_Lookup, MissReturnsNull) {
    ProtocolLayerRegistry r;
    EXPECT_EQ(r.find_by_protocol_id("ssh-v1"), nullptr);
    EXPECT_EQ(r.find_entry_by_protocol_id("ssh-v1"), std::nullopt);
}

TEST(ProtocolLayerRegistry_Lookup, EntrySnapshotCarriesId) {
    ProtocolLayerRegistry r;
    auto layer = std::make_shared<StubProtocol>("gnet-v1");
    protocol_layer_id_t id = kInvalidProtocolLayerId;
    ASSERT_EQ(r.register_layer(layer, &id), GN_OK);

    auto entry = r.find_entry_by_protocol_id("gnet-v1");
    ASSERT_TRUE(entry.has_value());
    if (entry.has_value()) {
        EXPECT_EQ(entry->id, id);
        EXPECT_EQ(entry->protocol_id, "gnet-v1");
        EXPECT_EQ(entry->layer.get(), layer.get());
    }
}

// ── unregister ───────────────────────────────────────────────────────────

TEST(ProtocolLayerRegistry_Unregister, UnregisterReleases) {
    ProtocolLayerRegistry r;
    auto layer = std::make_shared<StubProtocol>("raw-v1");

    protocol_layer_id_t id = kInvalidProtocolLayerId;
    ASSERT_EQ(r.register_layer(layer, &id), GN_OK);
    ASSERT_NE(r.find_by_protocol_id("raw-v1"), nullptr);

    EXPECT_EQ(r.unregister_layer(id), GN_OK);
    EXPECT_EQ(r.find_by_protocol_id("raw-v1"), nullptr);
    EXPECT_EQ(r.size(), 0u);
}

TEST(ProtocolLayerRegistry_Unregister, UnknownIdRejected) {
    ProtocolLayerRegistry r;
    EXPECT_EQ(r.unregister_layer(0xDEADBEEFu), GN_ERR_NOT_FOUND);
    EXPECT_EQ(r.unregister_layer(kInvalidProtocolLayerId),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(ProtocolLayerRegistry_Unregister, SnapshotOutlivesUnregister) {
    ProtocolLayerRegistry r;
    auto layer = std::make_shared<StubProtocol>("gnet-v1");
    auto* raw_ptr = layer.get();

    protocol_layer_id_t id = kInvalidProtocolLayerId;
    ASSERT_EQ(r.register_layer(std::move(layer), &id), GN_OK);

    /// Snapshot the layer pointer, then unregister. The shared_ptr
    /// must extend the implementation's lifetime so the snapshot
    /// remains dereferenceable after the registry forgot it.
    auto snap = r.find_by_protocol_id("gnet-v1");
    ASSERT_NE(snap, nullptr);

    EXPECT_EQ(r.unregister_layer(id), GN_OK);
    EXPECT_EQ(r.find_by_protocol_id("gnet-v1"), nullptr);

    /// snap is still alive — call a vtable method to prove it.
    EXPECT_EQ(snap->protocol_id(), "gnet-v1");
    EXPECT_EQ(snap.get(), raw_ptr);
}

// ── concurrency ──────────────────────────────────────────────────────────

TEST(ProtocolLayerRegistry_Concurrency, ConcurrentRegisterFindNoRace) {
    ProtocolLayerRegistry r;

    /// Pre-register a stable layer so readers always have a hit.
    auto stable = std::make_shared<StubProtocol>("gnet-v1");
    protocol_layer_id_t stable_id = kInvalidProtocolLayerId;
    ASSERT_EQ(r.register_layer(stable, &stable_id), GN_OK);

    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> hits{0};

    std::thread reader([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            auto found = r.find_by_protocol_id("gnet-v1");
            if (found != nullptr) {
                hits.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    std::thread writer([&] {
        for (int i = 0; i < 256 && !stop.load(std::memory_order_relaxed); ++i) {
            auto layer = std::make_shared<StubProtocol>(
                "transient-" + std::to_string(i));
            protocol_layer_id_t tid = kInvalidProtocolLayerId;
            if (r.register_layer(layer, &tid) == GN_OK) {
                (void)r.unregister_layer(tid);
            }
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    stop.store(true, std::memory_order_relaxed);
    reader.join();
    writer.join();

    EXPECT_GT(hits.load(), 0u);
    EXPECT_EQ(r.find_by_protocol_id("gnet-v1").get(), stable.get());
}

} // namespace
} // namespace gn::core
