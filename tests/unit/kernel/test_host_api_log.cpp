/// @file   tests/unit/kernel/test_host_api_log.cpp
/// @brief  `host_api->log` slot does not interpret format specifiers
///         in the plugin-supplied buffer per `host-api.md` §11.
///
/// The kernel forwards `msg` to spdlog as a literal `{}` argument
/// — never as a format string. The pre-RC fix that swapped the
/// slot from variadic to single-buffer is what closes the
/// format-string class of attack against the kernel; this test
/// pins the resulting invariant by piping through a capturing sink
/// and asserting the bytes survived round-trip without expansion.

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
#include <sdk/types.h>

namespace {

class CaptureSink : public spdlog::sinks::base_sink<std::mutex> {
public:
    /// Tests in this fixture are single-threaded — the kernel logger
    /// flushes synchronously after `api.log` returns, so the snapshot
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
    gn::core::Kernel                  kernel;
    gn::core::PluginContext           ctx;
    host_api_t                        api{};

    LogHarness() {
        ctx.plugin_name = "log-fixture";
        ctx.kind        = GN_PLUGIN_KIND_HANDLER;
        ctx.kernel      = &kernel;
        ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
        api = gn::core::build_host_api(ctx);

        /// Splice our capturing sink into the kernel logger. Save the
        /// original sinks + level so the fixture restores them on
        /// teardown — the kernel logger is a singleton shared with
        /// every other test in the binary.
        auto& logger = ::gn::log::kernel();
        saved_level  = logger.level();
        if (!logger.sinks().empty()) {
            saved_sink = logger.sinks().front();
            logger.sinks().front() = sink;
        } else {
            logger.sinks().push_back(sink);
        }
        logger.set_level(spdlog::level::trace);
    }

    ~LogHarness() {
        auto& logger = ::gn::log::kernel();
        if (saved_sink && !logger.sinks().empty()) {
            logger.sinks().front() = saved_sink;
        }
        logger.set_level(saved_level);
    }
};

}  // namespace

TEST(HostApiLog, FormatSpecifiersInMessageStayLiteral) {
    LogHarness h;

    /// A buffer engineered to be hostile under any vsnprintf-like
    /// expansion: `%n` would write through a stack pointer; `%s`
    /// without an argument would dereference garbage; `%p` would
    /// leak an address. The kernel must never interpret any of these.
    const char* hostile = "boom %n %s %p {}";
    h.api.log(h.api.host_ctx, GN_LOG_INFO, hostile);
    ::gn::log::kernel().flush();

    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("boom %n %s %p {}"), std::string::npos)
        << "format specifiers must reach the sink as literal bytes; "
        << "captured: " << lines[0];
    EXPECT_NE(lines[0].find("[log-fixture]"), std::string::npos)
        << "kernel must prefix with the plugin name";
}

TEST(HostApiLog, EmptyMessageIsAccepted) {
    LogHarness h;
    h.api.log(h.api.host_ctx, GN_LOG_INFO, "");
    ::gn::log::kernel().flush();
    EXPECT_EQ(h.sink->snapshot().size(), 1u)
        << "empty msg is a valid log line; the kernel does not drop";
}

TEST(HostApiLog, NullMessageDroppedSilently) {
    LogHarness h;
    /// The slot's documented contract is "NULL `msg` is dropped
    /// silently"; verify we do not crash and no line is recorded.
    h.api.log(h.api.host_ctx, GN_LOG_INFO, nullptr);
    ::gn::log::kernel().flush();
    EXPECT_EQ(h.sink->snapshot().size(), 0u);
}
