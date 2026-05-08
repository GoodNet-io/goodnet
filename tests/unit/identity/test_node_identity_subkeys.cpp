/// @file   tests/unit/identity/test_node_identity_subkeys.cpp
/// @brief  NodeIdentity file format + sub-key registry roundtrip.

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>

#include <core/identity/node_identity.hpp>
#include <core/identity/sub_key_registry.hpp>

using namespace gn::core::identity;

namespace {

constexpr std::int64_t kFarFuture = 9999999999;

std::filesystem::path tmp_path(const char* tag) {
    static int counter = 0;
    auto p = std::filesystem::temp_directory_path() /
             (std::string("gn_id_") + tag + "_" +
              std::to_string(counter++) + ".bin");
    std::filesystem::remove(p);
    return p;
}

}  // namespace

// ── file format roundtrip — bare identity ────────────────────────────────

TEST(NodeIdentityFile, EmptyRegistryRoundtrip) {
    auto orig = NodeIdentity::generate(kFarFuture);
    ASSERT_TRUE(orig.has_value());

    auto path = tmp_path("empty");
    ASSERT_TRUE(NodeIdentity::save_to_file(*orig, path.string()).has_value());

    auto loaded = NodeIdentity::load_from_file(path.string());
    ASSERT_TRUE(loaded.has_value());

    EXPECT_EQ(orig->user().public_key(),   loaded->user().public_key());
    EXPECT_EQ(orig->device().public_key(), loaded->device().public_key());
    EXPECT_EQ(orig->address(),             loaded->address());
    EXPECT_EQ(orig->rotation_counter(),    loaded->rotation_counter());
    EXPECT_TRUE(loaded->sub_keys().entries().empty());

    std::filesystem::remove(path);
}

// ── file format roundtrip — sub-key registry populated ──────────────────

TEST(NodeIdentityFile, SubKeyRoundtrip) {
    auto orig = NodeIdentity::generate(kFarFuture);
    ASSERT_TRUE(orig.has_value());

    /// Insert two sub-keys directly through the registry; v2 file
    /// format must preserve order and carry private bytes through
    /// load → save → load.
    auto kp1 = KeyPair::generate();
    auto kp2 = KeyPair::generate();
    ASSERT_TRUE(kp1.has_value());
    ASSERT_TRUE(kp2.has_value());

    const auto pk1 = kp1->public_key();
    const auto pk2 = kp2->public_key();

    const auto id1 = orig->sub_keys().insert(
        GN_KEY_PURPOSE_SECOND_FACTOR, std::move(*kp1), "yubikey-A", 1234);
    const auto id2 = orig->sub_keys().insert(
        GN_KEY_PURPOSE_RECOVERY, std::move(*kp2), "backup-phrase", 5678);

    auto path = tmp_path("subkeys");
    ASSERT_TRUE(NodeIdentity::save_to_file(*orig, path.string()).has_value());

    auto loaded = NodeIdentity::load_from_file(path.string());
    ASSERT_TRUE(loaded.has_value());

    const auto& entries = loaded->sub_keys().entries();
    ASSERT_EQ(entries.size(), 2u);

    EXPECT_EQ(entries[0].purpose,         GN_KEY_PURPOSE_SECOND_FACTOR);
    EXPECT_EQ(entries[0].label,           "yubikey-A");
    EXPECT_EQ(entries[0].created_unix_ts, 1234);
    EXPECT_EQ(entries[0].kp.public_key(), pk1);

    EXPECT_EQ(entries[1].purpose,         GN_KEY_PURPOSE_RECOVERY);
    EXPECT_EQ(entries[1].label,           "backup-phrase");
    EXPECT_EQ(entries[1].created_unix_ts, 5678);
    EXPECT_EQ(entries[1].kp.public_key(), pk2);

    /// Public ids — purpose-encoded — round-trip too.
    EXPECT_EQ(purpose_of(id1), GN_KEY_PURPOSE_SECOND_FACTOR);
    EXPECT_EQ(purpose_of(id2), GN_KEY_PURPOSE_RECOVERY);

    std::filesystem::remove(path);
}

// ── SubKeyRegistry — find / erase / snapshot ─────────────────────────────

TEST(SubKeyRegistry, FindFirstOfPurposeReturnsRegisteredKp) {
    SubKeyRegistry reg;
    auto kp = KeyPair::generate();
    ASSERT_TRUE(kp.has_value());
    const auto pk = kp->public_key();
    [[maybe_unused]] const auto id = reg.insert(
        GN_KEY_PURPOSE_CAPABILITY_INVOKE, std::move(*kp), "cap-1", 0);

    const auto* found = reg.find_first_of_purpose(GN_KEY_PURPOSE_CAPABILITY_INVOKE);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->public_key(), pk);

    /// Wrong purpose → nullptr, not the first-found-of-any.
    EXPECT_EQ(reg.find_first_of_purpose(GN_KEY_PURPOSE_SECOND_FACTOR),
              nullptr);
}

TEST(SubKeyRegistry, EraseRemovesAndZeroises) {
    SubKeyRegistry reg;
    auto kp = KeyPair::generate();
    ASSERT_TRUE(kp.has_value());
    const auto id = reg.insert(GN_KEY_PURPOSE_RECOVERY,
                                std::move(*kp), "tmp", 0);
    ASSERT_EQ(reg.size(), 1u);
    EXPECT_TRUE(reg.erase(id));
    EXPECT_EQ(reg.size(), 0u);
    /// Erasing a missing id is a no-op false.
    EXPECT_FALSE(reg.erase(id));
}

TEST(SubKeyRegistry, SnapshotMatchesEntries) {
    SubKeyRegistry reg;
    auto kp1 = KeyPair::generate();
    auto kp2 = KeyPair::generate();
    ASSERT_TRUE(kp1.has_value());
    ASSERT_TRUE(kp2.has_value());

    const auto pk1 = kp1->public_key();
    [[maybe_unused]] const auto pk2 = kp2->public_key();
    [[maybe_unused]] const auto id1 = reg.insert(
        GN_KEY_PURPOSE_SECOND_FACTOR, std::move(*kp1), "k1", 100);
    [[maybe_unused]] const auto id2 = reg.insert(
        GN_KEY_PURPOSE_RECOVERY,      std::move(*kp2), "k2", 200);

    gn_key_descriptor_t buf[4]{};
    std::size_t total = 0;
    reg.snapshot(buf, 4, &total);
    EXPECT_EQ(total, 2u);

    EXPECT_EQ(buf[0].purpose, GN_KEY_PURPOSE_SECOND_FACTOR);
    EXPECT_STREQ(buf[0].label, "k1");
    EXPECT_EQ(buf[0].created_unix_ts, 100);

    /// Public-key bytes flow through unchanged; private bytes do
    /// not appear in the descriptor.
    bool match_pk1 = std::memcmp(buf[0].public_key, pk1.data(),
                                  GN_PUBLIC_KEY_BYTES) == 0;
    EXPECT_TRUE(match_pk1);
}

// ── Clone — deep-copy invariant ────────────────────────────────────────

TEST(NodeIdentity_Clone, ProducesIndependentInstance) {
    auto orig = NodeIdentity::generate(kFarFuture);
    ASSERT_TRUE(orig.has_value());

    auto kp = KeyPair::generate();
    ASSERT_TRUE(kp.has_value());
    [[maybe_unused]] const auto id = orig->sub_keys().insert(
        GN_KEY_PURPOSE_SECOND_FACTOR, std::move(*kp), "src", 42);

    auto cloned = orig->clone();
    ASSERT_TRUE(cloned.has_value());

    EXPECT_EQ(orig->user().public_key(),   cloned->user().public_key());
    EXPECT_EQ(orig->device().public_key(), cloned->device().public_key());
    EXPECT_EQ(orig->address(),             cloned->address());
    EXPECT_EQ(orig->sub_keys().entries().size(),
              cloned->sub_keys().entries().size());

    /// Mutate the clone — original must not see the change.
    auto kp2 = KeyPair::generate();
    ASSERT_TRUE(kp2.has_value());
    [[maybe_unused]] const auto id_clone = cloned->sub_keys().insert(
        GN_KEY_PURPOSE_RECOVERY, std::move(*kp2), "cloned-only", 0);
    EXPECT_EQ(orig->sub_keys().entries().size(), 1u);
    EXPECT_EQ(cloned->sub_keys().entries().size(), 2u);
}
