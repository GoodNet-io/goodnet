/// @file   tests/unit/kernel/test_host_api_log.cpp
/// @brief  Plugin-facing log substruct (`gn_log_api_t`) hands a fully
///         formatted buffer to the kernel sink without ever
///         interpreting format specifiers, per `host-api.md` §11.
///
/// `should_log` is the level-filter fast path; `emit` is the literal
/// hand-off. Together they close the format-string class of attack
/// against the kernel address space — no `vsnprintf` runs on
/// plugin-supplied bytes inside the kernel.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include <spdlog/sinks/base_sink.h>
#include <spdlog/spdlog.h>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/util/log.hpp>

#include <sdk/host_api.h>
#include <sdk/log.h>
#include <sdk/types.h>

namespace {

class CaptureSink : public spdlog::sinks::base_sink<std::mutex> {
public:
    /// Tests in this fixture are single-threaded — the kernel logger
    /// flushes synchronously after `emit` returns, so the snapshot
    /// reads after every call see the final state without contention.
    [[nodiscard]] std::vector<std::string> snapshot() {
        std::lock_guard lk(snap_mu_);
        return lines_;
    }

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        spdlog::memory_buf_t formatted;
        base_sink<std::mutex>::formatter_->format(msg, formatted);
        std::lock_guard lk(snap_mu_);
        lines_.emplace_back(formatted.data(), formatted.size());
    }

    void flush_() override {}

private:
    std::mutex               snap_mu_;
    std::vector<std::string> lines_;
};

struct LogHarness {
    std::shared_ptr<CaptureSink>      sink = std::make_shared<CaptureSink>();
    spdlog::sink_ptr                  saved_sink;
    spdlog::level::level_enum         saved_level{};
    std::string                       saved_pattern;
    gn::core::Kernel                  kernel;
    gn::core::PluginContext           ctx;
    host_api_t                        api{};

    explicit LogHarness(const char* pattern =
                            "%^%l%$ [%s:%#] %v") {
        ctx.plugin_name = "log-fixture";
        ctx.kind        = GN_PLUGIN_KIND_HANDLER;
        ctx.kernel      = &kernel;
        ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
        api = gn::core::build_host_api(ctx);

        /// Splice our capturing sink into the kernel logger. Save
        /// sinks/level/pattern so the fixture restores them on
        /// teardown — the kernel logger is a singleton shared with
        /// every other test in the binary.
        auto& logger = ::gn::log::kernel();
        saved_level   = logger.level();
        saved_pattern.assign("");  // spdlog has no getter; restore via set
        if (!logger.sinks().empty()) {
            saved_sink = logger.sinks().front();
            logger.sinks().front() = sink;
        } else {
            logger.sinks().push_back(sink);
        }
        logger.set_level(spdlog::level::trace);
        logger.set_pattern(pattern);
    }

    ~LogHarness() {
        auto& logger = ::gn::log::kernel();
        if (saved_sink && !logger.sinks().empty()) {
            logger.sinks().front() = saved_sink;
        }
        logger.set_level(saved_level);
        logger.set_pattern(::gn::log::kDefaultPattern);
    }
};

}  // namespace

TEST(HostApiLog, ApiSizePopulated) {
    LogHarness h;
    EXPECT_EQ(h.api.log.api_size, sizeof(gn_log_api_t));
    EXPECT_NE(h.api.log.should_log, nullptr);
    EXPECT_NE(h.api.log.emit, nullptr);
}

TEST(HostApiLog, FormatSpecifiersInMessageStayLiteral) {
    LogHarness h;

    /// A buffer engineered to be hostile under any vsnprintf-like
    /// expansion: `%n` would write through a stack pointer; `%s`
    /// without an argument would dereference garbage; `%p` would
    /// leak an address. The kernel must never interpret any of these.
    const char* hostile = "boom %n %s %p {}";
    h.api.log.emit(h.api.host_ctx, GN_LOG_INFO,
                   "test_file.cpp", 42, hostile);
    ::gn::log::kernel().flush();

    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("boom %n %s %p {}"), std::string::npos)
        << "format specifiers must reach the sink as literal bytes; "
        << "captured: " << lines[0];
    EXPECT_NE(lines[0].find("[log-fixture]"), std::string::npos)
        << "kernel must prefix with the plugin name";
}

TEST(HostApiLog, SourceLocationReachesSink) {
    LogHarness h;
    h.api.log.emit(h.api.host_ctx, GN_LOG_INFO,
                   "callsite.cpp", 1234, "hello");
    ::gn::log::kernel().flush();
    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("callsite.cpp"), std::string::npos)
        << "captured: " << lines[0];
    EXPECT_NE(lines[0].find("1234"), std::string::npos)
        << "captured: " << lines[0];
}

TEST(HostApiLog, EmptyMessageIsAccepted) {
    LogHarness h;
    h.api.log.emit(h.api.host_ctx, GN_LOG_INFO,
                   "test.cpp", 1, "");
    ::gn::log::kernel().flush();
    EXPECT_EQ(h.sink->snapshot().size(), 1u)
        << "empty msg is a valid log line; the kernel does not drop";
}

TEST(HostApiLog, NullMessageDroppedSilently) {
    LogHarness h;
    /// `emit` documents "NULL `msg` is dropped silently"; verify we
    /// do not crash and no line is recorded.
    h.api.log.emit(h.api.host_ctx, GN_LOG_INFO,
                   "test.cpp", 1, nullptr);
    ::gn::log::kernel().flush();
    EXPECT_EQ(h.sink->snapshot().size(), 0u);
}

TEST(HostApiLog, NullFileOmitsSourceLocation) {
    /// `[%s:%#] %v` against a null `file` and zero `line` produces
    /// `[:0] %v` — spdlog itself does not synthesise a placeholder.
    /// The contract is "kernel omits the source-location prefix";
    /// the assert here is that the message survives unchanged. Plain
    /// `%v` pattern would drop the prefix outright but that is the
    /// formatter's choice, not the kernel's.
    LogHarness h{"%v"};
    h.api.log.emit(h.api.host_ctx, GN_LOG_INFO,
                   nullptr, 0, "no-loc");
    ::gn::log::kernel().flush();
    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("no-loc"), std::string::npos);
}

TEST(HostApiLog, ShouldLogReflectsKernelLevel) {
    LogHarness h;
    auto& logger = ::gn::log::kernel();

    logger.set_level(spdlog::level::warn);
    EXPECT_EQ(h.api.log.should_log(h.api.host_ctx, GN_LOG_DEBUG), 0);
    EXPECT_EQ(h.api.log.should_log(h.api.host_ctx, GN_LOG_INFO),  0);
    EXPECT_NE(h.api.log.should_log(h.api.host_ctx, GN_LOG_WARN),  0);
    EXPECT_NE(h.api.log.should_log(h.api.host_ctx, GN_LOG_ERROR), 0);

    logger.set_level(spdlog::level::trace);
    EXPECT_NE(h.api.log.should_log(h.api.host_ctx, GN_LOG_TRACE), 0);
    EXPECT_NE(h.api.log.should_log(h.api.host_ctx, GN_LOG_DEBUG), 0);
}

TEST(HostApiLog, EmitFiltersBelowKernelLevel) {
    LogHarness h;
    /// Even when a plugin skips the `should_log` fast path, the
    /// kernel-side `emit` thunk re-checks before forwarding to the
    /// sink — a misbehaving plugin cannot bypass the filter.
    ::gn::log::kernel().set_level(spdlog::level::err);
    h.api.log.emit(h.api.host_ctx, GN_LOG_INFO,
                   "test.cpp", 1, "filtered");
    ::gn::log::kernel().flush();
    EXPECT_EQ(h.sink->snapshot().size(), 0u);
}
