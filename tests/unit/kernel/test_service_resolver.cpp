/// @file   tests/unit/kernel/test_service_resolver.cpp
/// @brief  GoogleTest unit tests for `gn::core::ServiceResolver`.
///
/// Pins the toposort contract from `core/kernel/service_resolver.hpp`:
/// providers come before consumers; a duplicate provider is rejected;
/// an unresolved requirement is rejected; a graph with a cycle is
/// rejected; self-provide (a plugin requires what it itself provides)
/// is permitted. Valid orderings respect every required-before-consumer
/// edge.

#include <gtest/gtest.h>

#include <algorithm>
#include <iterator>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <core/kernel/service_resolver.hpp>
#include <sdk/types.h>

namespace gn::core {
namespace {

/// Convenience: position of @p name in the resolved ordering.
std::size_t pos_of(const std::vector<ServiceDescriptor>& ordered,
                   std::string_view name) {
    for (std::size_t i = 0; i < ordered.size(); ++i) {
        if (ordered[i].plugin_name == name) return i;
    }
    return SIZE_MAX;
}

// ─── empty / trivial inputs ─────────────────────────────────────────

TEST(ServiceResolver_Empty, EmptyInputProducesEmptyOutput) {
    std::vector<ServiceDescriptor> input;
    std::vector<ServiceDescriptor> ordered;
    std::string diag;
    EXPECT_EQ(ServiceResolver::resolve(input, ordered, &diag), GN_OK);
    EXPECT_TRUE(ordered.empty());
    EXPECT_TRUE(diag.empty());
}

TEST(ServiceResolver_Trivial, SinglePluginNoDeps) {
    std::vector<ServiceDescriptor> input = {
        {.plugin_name = "alpha", .ext_requires = {}, .ext_provides = {}},
    };
    std::vector<ServiceDescriptor> ordered;
    EXPECT_EQ(ServiceResolver::resolve(input, ordered), GN_OK);
    ASSERT_EQ(ordered.size(), 1u);
    EXPECT_EQ(ordered[0].plugin_name, "alpha");
}

// ─── linear chain ───────────────────────────────────────────────────

TEST(ServiceResolver_Chain, LinearABCOrder) {
    /// A provides x, B requires x and provides y, C requires y. Result
    /// must list A before B and B before C.
    std::vector<ServiceDescriptor> input = {
        {.plugin_name = "C", .ext_requires = {"y"}, .ext_provides = {}},
        {.plugin_name = "B", .ext_requires = {"x"}, .ext_provides = {"y"}},
        {.plugin_name = "A", .ext_requires = {},     .ext_provides = {"x"}},
    };
    std::vector<ServiceDescriptor> ordered;
    EXPECT_EQ(ServiceResolver::resolve(input, ordered), GN_OK);
    ASSERT_EQ(ordered.size(), 3u);

    const auto pa = pos_of(ordered, "A");
    const auto pb = pos_of(ordered, "B");
    const auto pc = pos_of(ordered, "C");
    EXPECT_LT(pa, pb);
    EXPECT_LT(pb, pc);
}

// ─── diamond ────────────────────────────────────────────────────────

TEST(ServiceResolver_Diamond, ABCDOrder) {
    /// A provides x; B and C require x and provide bx and cx; D
    /// requires bx and cx. Permitted topo orders place A first, D
    /// last; B and C in any relative order.
    std::vector<ServiceDescriptor> input = {
        {.plugin_name = "D", .ext_requires = {"bx", "cx"}, .ext_provides = {}},
        {.plugin_name = "C", .ext_requires = {"x"},          .ext_provides = {"cx"}},
        {.plugin_name = "B", .ext_requires = {"x"},          .ext_provides = {"bx"}},
        {.plugin_name = "A", .ext_requires = {},             .ext_provides = {"x"}},
    };
    std::vector<ServiceDescriptor> ordered;
    EXPECT_EQ(ServiceResolver::resolve(input, ordered), GN_OK);
    ASSERT_EQ(ordered.size(), 4u);

    const auto pa = pos_of(ordered, "A");
    const auto pb = pos_of(ordered, "B");
    const auto pc = pos_of(ordered, "C");
    const auto pd = pos_of(ordered, "D");
    EXPECT_LT(pa, pb);
    EXPECT_LT(pa, pc);
    EXPECT_LT(pb, pd);
    EXPECT_LT(pc, pd);
}

// ─── self-provide ───────────────────────────────────────────────────

TEST(ServiceResolver_SelfProvide, AcceptedAndOrdered) {
    /// A plugin that both provides and requires the same extension is a
    /// degenerate case the contract documents as fine. The toposort
    /// must accept it and order normally.
    std::vector<ServiceDescriptor> input = {
        {.plugin_name = "self", .ext_requires = {"loopback"},
                                  .ext_provides = {"loopback"}},
        {.plugin_name = "other", .ext_requires = {"loopback"},
                                   .ext_provides = {}},
    };
    std::vector<ServiceDescriptor> ordered;
    EXPECT_EQ(ServiceResolver::resolve(input, ordered), GN_OK);
    ASSERT_EQ(ordered.size(), 2u);

    const auto ps = pos_of(ordered, "self");
    const auto po = pos_of(ordered, "other");
    EXPECT_LT(ps, po);
}

// ─── duplicate provider ─────────────────────────────────────────────

TEST(ServiceResolver_Duplicate, RejectedWithDiagnostic) {
    std::vector<ServiceDescriptor> input = {
        {.plugin_name = "A", .ext_requires = {}, .ext_provides = {"shared"}},
        {.plugin_name = "B", .ext_requires = {}, .ext_provides = {"shared"}},
    };
    std::vector<ServiceDescriptor> ordered;
    std::string diag;
    EXPECT_EQ(ServiceResolver::resolve(input, ordered, &diag),
              GN_ERR_LIMIT_REACHED);
    EXPECT_FALSE(diag.empty());
    EXPECT_NE(diag.find("shared"), std::string::npos);
    EXPECT_TRUE(ordered.empty());
}

TEST(ServiceResolver_Duplicate, NullDiagnosticAccepted) {
    std::vector<ServiceDescriptor> input = {
        {.plugin_name = "A", .ext_requires = {}, .ext_provides = {"x"}},
        {.plugin_name = "B", .ext_requires = {}, .ext_provides = {"x"}},
    };
    std::vector<ServiceDescriptor> ordered;
    EXPECT_EQ(ServiceResolver::resolve(input, ordered, nullptr),
              GN_ERR_LIMIT_REACHED);
}

// ─── unresolved requirement ─────────────────────────────────────────

TEST(ServiceResolver_Unresolved, RejectedWithDiagnostic) {
    std::vector<ServiceDescriptor> input = {
        {.plugin_name = "needsX", .ext_requires = {"missing"},
                                   .ext_provides = {}},
    };
    std::vector<ServiceDescriptor> ordered;
    std::string diag;
    EXPECT_EQ(ServiceResolver::resolve(input, ordered, &diag),
              GN_ERR_UNKNOWN_RECEIVER);
    EXPECT_FALSE(diag.empty());
    EXPECT_NE(diag.find("missing"), std::string::npos);
    EXPECT_TRUE(ordered.empty());
}

// ─── cycle ──────────────────────────────────────────────────────────

TEST(ServiceResolver_Cycle, TwoNodeCycleRejected) {
    /// A requires y from B, B requires x from A. The kahn drain stops
    /// before consuming any node — every in_degree stays positive.
    std::vector<ServiceDescriptor> input = {
        {.plugin_name = "A", .ext_requires = {"y"}, .ext_provides = {"x"}},
        {.plugin_name = "B", .ext_requires = {"x"}, .ext_provides = {"y"}},
    };
    std::vector<ServiceDescriptor> ordered;
    std::string diag;
    EXPECT_EQ(ServiceResolver::resolve(input, ordered, &diag),
              GN_ERR_INVALID_ENVELOPE);
    EXPECT_FALSE(diag.empty());
    EXPECT_NE(diag.find("cycle"), std::string::npos);
    EXPECT_TRUE(ordered.empty());
}

TEST(ServiceResolver_Cycle, ThreeNodeCycleRejected) {
    std::vector<ServiceDescriptor> input = {
        {.plugin_name = "A", .ext_requires = {"z"}, .ext_provides = {"x"}},
        {.plugin_name = "B", .ext_requires = {"x"}, .ext_provides = {"y"}},
        {.plugin_name = "C", .ext_requires = {"y"}, .ext_provides = {"z"}},
    };
    std::vector<ServiceDescriptor> ordered;
    EXPECT_EQ(ServiceResolver::resolve(input, ordered),
              GN_ERR_INVALID_ENVELOPE);
}

}  // namespace
}  // namespace gn::core
