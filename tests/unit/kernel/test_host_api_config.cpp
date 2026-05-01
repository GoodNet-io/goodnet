/// @file   tests/unit/kernel/test_host_api_config.cpp
/// @brief  `host_api->config_get` argument validation and type-tag
///         rejection per `host-api.md` §2.

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/host_api.h>
#include <sdk/types.h>

namespace {

using namespace gn::core;

struct ConfigHarness {
    Kernel        kernel;
    PluginContext plugin_ctx;
    host_api_t    api{};

    explicit ConfigHarness(std::string_view json) {
        plugin_ctx.plugin_name = "config-get-test";
        plugin_ctx.kind        = GN_PLUGIN_KIND_HANDLER;
        plugin_ctx.kernel      = &kernel;
        api = build_host_api(plugin_ctx);
        EXPECT_EQ(kernel.config().load_json(std::string(json)), GN_OK);
    }
};

constexpr const char* kSampleJson = R"({
    "scalar_int":  42,
    "scalar_bool": true,
    "scalar_dbl":  0.5,
    "scalar_str":  "hello",
    "arr_int":     [10, 20, 30],
    "arr_str":     ["alpha", "beta"]
})";

}  // namespace

TEST(HostApiConfigGet, ScalarInt64HappyPath) {
    ConfigHarness h{kSampleJson};
    int64_t v = 0;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "scalar_int",
                                GN_CONFIG_VALUE_INT64, GN_CONFIG_NO_INDEX,
                                &v, nullptr),
              GN_OK);
    EXPECT_EQ(v, 42);
}

TEST(HostApiConfigGet, ScalarBoolHappyPath) {
    ConfigHarness h{kSampleJson};
    int32_t v = 0;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "scalar_bool",
                                GN_CONFIG_VALUE_BOOL, GN_CONFIG_NO_INDEX,
                                &v, nullptr),
              GN_OK);
    EXPECT_EQ(v, 1);
}

TEST(HostApiConfigGet, ScalarDoubleHappyPath) {
    ConfigHarness h{kSampleJson};
    double v = 0.0;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "scalar_dbl",
                                GN_CONFIG_VALUE_DOUBLE, GN_CONFIG_NO_INDEX,
                                &v, nullptr),
              GN_OK);
    EXPECT_DOUBLE_EQ(v, 0.5);
}

TEST(HostApiConfigGet, ScalarStringHappyPath) {
    ConfigHarness h{kSampleJson};
    char* str = nullptr;
    void (*free_fn)(void*) = nullptr;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "scalar_str",
                                GN_CONFIG_VALUE_STRING, GN_CONFIG_NO_INDEX,
                                static_cast<void*>(&str), &free_fn),
              GN_OK);
    ASSERT_NE(str, nullptr);
    ASSERT_NE(free_fn, nullptr);
    EXPECT_STREQ(str, "hello");
    free_fn(str);
}

TEST(HostApiConfigGet, ArraySizeHappyPath) {
    ConfigHarness h{kSampleJson};
    std::size_t n = 0;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "arr_int",
                                GN_CONFIG_VALUE_ARRAY_SIZE, GN_CONFIG_NO_INDEX,
                                &n, nullptr),
              GN_OK);
    EXPECT_EQ(n, 3u);
}

TEST(HostApiConfigGet, ArrayInt64Index) {
    ConfigHarness h{kSampleJson};
    int64_t v = 0;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "arr_int",
                                GN_CONFIG_VALUE_INT64, /*index*/ 1,
                                &v, nullptr),
              GN_OK);
    EXPECT_EQ(v, 20);
}

TEST(HostApiConfigGet, ArrayStringIndex) {
    ConfigHarness h{kSampleJson};
    char* str = nullptr;
    void (*free_fn)(void*) = nullptr;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "arr_str",
                                GN_CONFIG_VALUE_STRING, /*index*/ 0,
                                static_cast<void*>(&str), &free_fn),
              GN_OK);
    ASSERT_NE(str, nullptr);
    ASSERT_NE(free_fn, nullptr);
    EXPECT_STREQ(str, "alpha");
    free_fn(str);
}

TEST(HostApiConfigGet, RejectsNullKey) {
    ConfigHarness h{kSampleJson};
    int64_t v = 0;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, nullptr,
                                GN_CONFIG_VALUE_INT64, GN_CONFIG_NO_INDEX,
                                &v, nullptr),
              GN_ERR_NULL_ARG);
}

TEST(HostApiConfigGet, RejectsNullOutValue) {
    ConfigHarness h{kSampleJson};
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "scalar_int",
                                GN_CONFIG_VALUE_INT64, GN_CONFIG_NO_INDEX,
                                nullptr, nullptr),
              GN_ERR_NULL_ARG);
}

TEST(HostApiConfigGet, RejectsStringWithoutOutFree) {
    /// STRING reads need the destructor sink — without it the plugin
    /// would leak the malloc'd buffer.
    ConfigHarness h{kSampleJson};
    char* str = nullptr;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "scalar_str",
                                GN_CONFIG_VALUE_STRING, GN_CONFIG_NO_INDEX,
                                static_cast<void*>(&str), /*out_free*/ nullptr),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(str, nullptr);
}

TEST(HostApiConfigGet, RejectsNonStringWithOutFree) {
    /// Non-STRING reads forbid out_free — passing one signals a
    /// confused call shape that would leave free_fn dangling.
    ConfigHarness h{kSampleJson};
    int64_t v = 0;
    void (*free_fn)(void*) = nullptr;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "scalar_int",
                                GN_CONFIG_VALUE_INT64, GN_CONFIG_NO_INDEX,
                                &v, &free_fn),
              GN_ERR_NULL_ARG);
}

TEST(HostApiConfigGet, RejectsScalarTypeWithIndex) {
    /// BOOL / DOUBLE / ARRAY_SIZE never accept an index. Only
    /// INT64 / STRING fall through to the array-element path.
    ConfigHarness h{kSampleJson};
    int32_t v_b = 0;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "scalar_bool",
                                GN_CONFIG_VALUE_BOOL, /*index*/ 0,
                                &v_b, nullptr),
              GN_ERR_OUT_OF_RANGE);

    double v_d = 0.0;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "scalar_dbl",
                                GN_CONFIG_VALUE_DOUBLE, /*index*/ 0,
                                &v_d, nullptr),
              GN_ERR_OUT_OF_RANGE);
}

TEST(HostApiConfigGet, RejectsArraySizeWithIndex) {
    ConfigHarness h{kSampleJson};
    std::size_t n = 0;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "arr_int",
                                GN_CONFIG_VALUE_ARRAY_SIZE, /*index*/ 0,
                                &n, nullptr),
              GN_ERR_OUT_OF_RANGE);
}

TEST(HostApiConfigGet, TypeMismatchRejected) {
    /// The kernel parsed `scalar_int` as an integer; reading it as
    /// STRING surfaces INVALID_ENVELOPE rather than a silent zero.
    ConfigHarness h{kSampleJson};
    char* str = nullptr;
    void (*free_fn)(void*) = nullptr;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "scalar_int",
                                GN_CONFIG_VALUE_STRING, GN_CONFIG_NO_INDEX,
                                static_cast<void*>(&str), &free_fn),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(HostApiConfigGet, ArraySizeOnNonArrayRejected) {
    ConfigHarness h{kSampleJson};
    std::size_t n = 0;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "scalar_int",
                                GN_CONFIG_VALUE_ARRAY_SIZE, GN_CONFIG_NO_INDEX,
                                &n, nullptr),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(HostApiConfigGet, IndexPastEndRejected) {
    ConfigHarness h{kSampleJson};
    int64_t v = 0;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "arr_int",
                                GN_CONFIG_VALUE_INT64, /*index*/ 99,
                                &v, nullptr),
              GN_ERR_OUT_OF_RANGE);
}

TEST(HostApiConfigGet, MissingKeyReturnsNotFound) {
    ConfigHarness h{kSampleJson};
    int64_t v = 0;
    EXPECT_EQ(h.api.config_get(h.api.host_ctx, "absent.key",
                                GN_CONFIG_VALUE_INT64, GN_CONFIG_NO_INDEX,
                                &v, nullptr),
              GN_ERR_NOT_FOUND);
}
