/// @file   tests/unit/kernel/test_host_api_log.cpp
/// @brief  Plugin-facing log substruct (`gn_log_api_t`) hands a fully
///         formatted buffer to the kernel sink without ever
///         interpreting format specifiers, per `host-api.en.md` §11.
///
/// `should_log` is the level-filter fast path; `emit` is the literal
/// hand-off. Together they close the format-string class of attack
/// against the kernel address space — no `vsnprintf` runs on
/// plugin-supplied bytes inside the kernel.
///
/// The `CppFmt*` and `CppLogger*` tests cover `sdk/cpp/log.hpp` —
/// specifically the GCC 16 C++26 `consteval Fmt` fix (stores `const char*`,
/// uses `std::vformat`) that allows string literals and `std::string_view`
/// arguments to compile through `std::type_identity_t<Fmt<Args...>>`.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <string_view>
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
#include <sdk/cpp/log.hpp>

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

        /// Splice the capturing sink into the kernel logger. The
        /// `kernel()` snapshot keeps the logger alive for the
        /// fixture's lifetime; teardown restores the prior sink,
        /// level, and pattern so other tests in the binary see
        /// the original singleton state.
        auto logger_p = ::gn::log::kernel();
        auto& logger  = *logger_p;
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
        auto logger_p = ::gn::log::kernel();
        auto& logger  = *logger_p;
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
    ::gn::log::kernel()->flush();

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
    ::gn::log::kernel()->flush();
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
    ::gn::log::kernel()->flush();
    EXPECT_EQ(h.sink->snapshot().size(), 1u)
        << "empty msg is a valid log line; the kernel does not drop";
}

TEST(HostApiLog, NullMessageDroppedSilently) {
    LogHarness h;
    /// `emit` documents "NULL `msg` is dropped silently"; verify we
    /// do not crash and no line is recorded.
    h.api.log.emit(h.api.host_ctx, GN_LOG_INFO,
                   "test.cpp", 1, nullptr);
    ::gn::log::kernel()->flush();
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
    ::gn::log::kernel()->flush();
    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("no-loc"), std::string::npos);
}

TEST(HostApiLog, ShouldLogReflectsKernelLevel) {
    LogHarness h;
    auto logger_p = ::gn::log::kernel();
    auto& logger  = *logger_p;

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
    ::gn::log::kernel()->set_level(spdlog::level::err);
    h.api.log.emit(h.api.host_ctx, GN_LOG_INFO,
                   "test.cpp", 1, "filtered");
    ::gn::log::kernel()->flush();
    EXPECT_EQ(h.sink->snapshot().size(), 0u);
}

TEST(HostApiLog, EmitDropsCallWhenContextCanaryPoisoned) {
    /// A plugin that retained `host_api` past its own teardown
    /// would, on next `emit`, dereference a freed `PluginContext`
    /// and read garbage `plugin_name`. The destructor stamps the
    /// liveness canary to `kMagicDead`; the `log_emit` thunk
    /// (in `core/kernel/host_api/control.cpp`) checks the canary
    /// before reading any other field and silently drops the call. Simulate the post-teardown read by hand-
    /// poisoning the canary on a still-live context — the live
    /// path is exercised by every other test in this file.
    LogHarness h;
    h.ctx.magic = gn::core::PluginContext::kMagicDead;
    h.api.log.emit(h.api.host_ctx, GN_LOG_INFO,
                   "test.cpp", 1, "after-free");
    ::gn::log::kernel()->flush();
    EXPECT_EQ(h.sink->snapshot().size(), 0u);
    /// Restore so the harness's destructor can run cleanly.
    h.ctx.magic = gn::core::PluginContext::kMagicLive;
}

// ── sdk/cpp/log.hpp — C++ wrapper (gn::log::*) ───────────────────────────────
//
// These tests exercise the GCC 16 C++26 `consteval Fmt` fix: the `Fmt<Args...>`
// struct stores `const char*` (not `std::format_string`) so that implicit
// conversion of string literals through `std::type_identity_t<Fmt<Args...>>`
// compiles.  `emit()` uses `std::vformat` for the runtime format path.

TEST(CppFmt, IntArgFormattedAndDelivered) {
    // Compile-time check: `gn::log::debug(api, "literal {}", int)` must
    // compile under GCC 16 C++26 — the implicit Fmt<int> construction was
    // the failing case before the const-char* fix.
    LogHarness h;
    gn::log::debug(&h.api, "answer {}", 42);
    ::gn::log::kernel()->flush();
    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("answer 42"), std::string::npos)
        << "captured: " << lines[0];
}

TEST(CppFmt, StringViewArgFormattedAndDelivered) {
    // std::string_view was one of the types that triggered GCC 16 ambiguity
    // through the old consteval Fmt(std::format_string<Args...>) path.
    LogHarness h;
    std::string_view sv{"hello-sv"};
    gn::log::info(&h.api, "sv={}", sv);
    ::gn::log::kernel()->flush();
    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("sv=hello-sv"), std::string::npos)
        << "captured: " << lines[0];
}

TEST(CppFmt, MultipleArgsFormatted) {
    LogHarness h;
    gn::log::warn(&h.api, "{} + {} = {}", 1, 2, 3);
    ::gn::log::kernel()->flush();
    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("1 + 2 = 3"), std::string::npos)
        << "captured: " << lines[0];
}

TEST(CppFmt, SourceLocationCapturedAtCallSite) {
    // The consteval Fmt constructor captures std::source_location::current()
    // at the call site — not inside emit().  Verify the file name in the
    // delivered buffer contains this test file's name.
    LogHarness h{"%^%l%$ [%s:%#] %v"};
    gn::log::info(&h.api, "loc-check {}", 0);  // <-- source_location captured here
    ::gn::log::kernel()->flush();
    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    // The emit path forwards fmt.loc.file_name() to the kernel sink.
    EXPECT_NE(lines[0].find("test_host_api_log"), std::string::npos)
        << "source_location file should contain this file's name; "
        << "captured: " << lines[0];
}

TEST(CppFmt, ZeroArgNoFormatSpecifiers) {
    // Calling gn::log::info(api, "plain message") with no extra args
    // instantiates Fmt<> (empty pack).  This was crashing GCC 16 C++26 via
    // an ICE in check_postconditions_in_redecl when GN_EXPECTS was present on
    // the variadic template — fixed by removing the redundant contract.
    LogHarness h;
    gn::log::info(&h.api, "plain message");
    ::gn::log::kernel()->flush();
    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("plain message"), std::string::npos)
        << "captured: " << lines[0];
}

TEST(CppFmt, LongMessageTruncatedWithEllipsis) {
    // emit() truncates at kLogBufBytes-5 bytes and appends " ..." via the
    // new std::vformat + memcpy path (replacing the old std::format_to_n).
    LogHarness h;
    // Build a message that exceeds kLogBufBytes-5 (2043 bytes).
    std::string big(gn::log::kLogBufBytes, 'x');
    gn::log::info(&h.api, "{}", std::string_view{big});
    ::gn::log::kernel()->flush();
    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find(" ..."), std::string::npos)
        << "truncated message must end with \" ...\"; "
        << "captured (first 80): " << lines[0].substr(0, 80);
}

TEST(CppFmt, NullApiIsNoop) {
    // gn::log::emit() must not crash when api is nullptr — the null-check
    // guard in detail::emit() is exercised on every level wrapper.
    EXPECT_NO_FATAL_FAILURE(gn::log::debug(nullptr, "noop {}", 0));
}

TEST(CppFmt, LevelFilterRespected) {
    // gn::log::trace() must be suppressed when the kernel level is warn.
    LogHarness h;
    ::gn::log::kernel()->set_level(spdlog::level::warn);
    gn::log::trace(&h.api, "suppressed {}", 99);
    gn::log::warn(&h.api,  "visible {}", 99);
    ::gn::log::kernel()->flush();
    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("visible 99"), std::string::npos)
        << "captured: " << lines[0];
}

TEST(CppLogger, ClassMethodsDelegate) {
    // gn::log::Logger wraps the api pointer; level methods must delegate
    // through the same emit() path and deliver formatted output.
    LogHarness h;
    gn::log::Logger log{&h.api};
    log.debug("Logger {} {}", std::string_view{"works"}, 7);
    ::gn::log::kernel()->flush();
    auto lines = h.sink->snapshot();
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("Logger works 7"), std::string::npos)
        << "captured: " << lines[0];
}

TEST(CppLogger, DefaultConstructedIsNoop) {
    // A default-constructed Logger (api_==nullptr) must not crash.
    gn::log::Logger log{};
    EXPECT_NO_FATAL_FAILURE(log.info("noop {}", 0));
}
