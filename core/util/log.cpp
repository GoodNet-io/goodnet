/// @file   core/util/log.cpp
/// @brief  Singleton state + sink construction for the kernel
///         logger. The header is the public API; this file owns
///         the shared mutable state behind it.

#include <core/util/log.hpp>

#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <iterator>
#include <memory>
#include <mutex>
#include <vector>

namespace gn::log {

namespace {

namespace fs = std::filesystem;

/// Settings consumed by the custom `%Q` flag. Lives in this
/// translation unit so the formatter can read the live values
/// without a back-reference to `LogConfig` per call. Atomic for
/// the bool/int fields; `project_root_` sits behind a mutex
/// because the formatter walks it as a `string_view`.
std::atomic<int>     g_source_detail{static_cast<int>(SourceDetail::Auto)};
std::atomic<bool>    g_strip_extension{false};
std::mutex           g_root_mu;
std::string          g_project_root;

[[nodiscard]] std::string project_root_snapshot() {
    std::lock_guard lk(g_root_mu);
    return g_project_root;
}

/// `%Q` — source-location prefix that respects `SourceDetail`.
class custom_source_flag : public spdlog::custom_flag_formatter {
public:
    void format(const spdlog::details::log_msg&  msg,
                const std::tm&,
                spdlog::memory_buf_t&             dest) override
    {
        if (msg.source.empty()) return;

        std::string_view full(msg.source.filename);
        std::string_view rel = full;

        const auto root = project_root_snapshot();
        if (!root.empty()) {
            if (full.starts_with(root)) {
                rel = full.substr(root.size());
                if (!rel.empty() && (rel.front() == '/' || rel.front() == '\\')) {
                    rel.remove_prefix(1);
                }
            }
        }
        std::string_view basename = rel;
        if (auto sep = basename.find_last_of("/\\");
            sep != std::string_view::npos) {
            basename = basename.substr(sep + 1);
        }
        std::string_view name = basename;
        if (g_strip_extension.load(std::memory_order_relaxed)) {
            if (auto dot = name.find_last_of('.');
                dot != std::string_view::npos) {
                name = name.substr(0, dot);
            }
        }

        const bool verbose =
            (msg.level == spdlog::level::trace ||
             msg.level == spdlog::level::debug);

        bool show_path = false;
        bool show_line = false;
        switch (static_cast<SourceDetail>(
                    g_source_detail.load(std::memory_order_relaxed))) {
            case SourceDetail::Auto:
                show_path = verbose;
                show_line = verbose;
                break;
            case SourceDetail::FullPath:
                show_path = true;
                show_line = true;
                break;
            case SourceDetail::BasenameWithLine:
                show_path = false;
                show_line = true;
                break;
            case SourceDetail::BasenameOnly:
                show_path = false;
                show_line = false;
                break;
        }

        const std::string_view display = show_path ? rel : name;
        if (show_line) {
            fmt::format_to(std::back_inserter(dest),
                           "[{}:{}] ", display, msg.source.line);
        } else {
            fmt::format_to(std::back_inserter(dest),
                           "[{}] ", display);
        }
    }

    [[nodiscard]] std::unique_ptr<custom_flag_formatter> clone() const override {
        return std::make_unique<custom_source_flag>();
    }
};

/// Build a fresh `pattern_formatter` configured with the `%Q`
/// flag and the requested pattern.
[[nodiscard]] std::unique_ptr<spdlog::pattern_formatter>
make_formatter(std::string_view pattern) {
    auto fmt = std::make_unique<spdlog::pattern_formatter>();
    fmt->add_flag<custom_source_flag>('Q');
    fmt->set_pattern(std::string(pattern));
    return fmt;
}

[[nodiscard]] std::shared_ptr<spdlog::logger>
make_default_logger() {
    auto console = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console->set_formatter(make_formatter(kDefaultPattern));
#if defined(NDEBUG)
    /// Production stderr stays at warn-and-above by default — INFO
    /// chatter in a long-running daemon turns into noise quickly.
    /// Operators who want it back set `log.console_level = info`.
    console->set_level(spdlog::level::warn);
#endif
    auto logger = std::make_shared<spdlog::logger>("gn", console);
    logger->set_level(kDefaultLevel);
    logger->flush_on(spdlog::level::warn);
    return logger;
}

std::atomic<std::shared_ptr<spdlog::logger>>& storage() {
    static std::atomic<std::shared_ptr<spdlog::logger>> instance;
    return instance;
}
std::once_flag g_init_once;

void ensure_initialised() {
    std::call_once(g_init_once, [] {
        auto existing = spdlog::get("gn");
        if (!existing) {
            existing = make_default_logger();
            spdlog::register_logger(existing);
        }
        storage().store(std::move(existing), std::memory_order_release);
    });
}

}  // namespace

std::shared_ptr<::spdlog::logger> kernel() {
    auto p = storage().load(std::memory_order_acquire);
    if (!p) {
        ensure_initialised();
        p = storage().load(std::memory_order_acquire);
    }
    return p;
}

void init(::spdlog::level::level_enum lvl) {
    kernel()->set_level(lvl);
}

::spdlog::level::level_enum
parse_level(std::string_view name,
            ::spdlog::level::level_enum fallback) noexcept {
    if (name == "trace")                       return ::spdlog::level::trace;
    if (name == "debug")                       return ::spdlog::level::debug;
    if (name == "info")                        return ::spdlog::level::info;
    if (name == "warn" || name == "warning")   return ::spdlog::level::warn;
    if (name == "error" || name == "err")      return ::spdlog::level::err;
    if (name == "critical" || name == "fatal") return ::spdlog::level::critical;
    if (name == "off")                         return ::spdlog::level::off;
    return fallback;
}

void set_level(::spdlog::level::level_enum lvl) noexcept {
    kernel()->set_level(lvl);
}

bool init_with(const LogConfig& cfg) noexcept try {
    {
        std::lock_guard lk(g_root_mu);
        g_project_root = cfg.project_root;
    }
    g_strip_extension.store(cfg.strip_extension,
                             std::memory_order_relaxed);
    g_source_detail.store(static_cast<int>(cfg.source_detail),
                           std::memory_order_relaxed);

    std::vector<spdlog::sink_ptr> sinks;
    sinks.reserve(2);

    /// Console sink — always present. Pattern defaults to the
    /// build-aware shape unless the operator overrode it. The sink
    /// minimum level is build-aware too: Release pins WARN as the
    /// production noise filter, Debug carries everything. The
    /// operator can override via `log.console_level` to surface
    /// Release-build INFO startup markers without rebuilding.
    {
        auto console = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        const std::string_view pattern =
            cfg.console_pattern.empty() ? kDefaultPattern
                                         : std::string_view{cfg.console_pattern};
        console->set_formatter(make_formatter(pattern));
        if (!cfg.console_level.empty()) {
            console->set_level(parse_level(cfg.console_level,
#if defined(NDEBUG)
                                            spdlog::level::warn
#else
                                            spdlog::level::trace
#endif
                                            ));
        } else {
#if defined(NDEBUG)
            console->set_level(spdlog::level::warn);
#endif
        }
        sinks.push_back(std::move(console));
    }

    /// File sink — optional. Built only when the operator set a
    /// path; missing parent directories are created so the first
    /// log line never fails on a fresh deployment.
    if (!cfg.log_file.empty()) {
        const fs::path log_path = cfg.log_file;
        if (auto parent = log_path.parent_path();
            !parent.empty() && !fs::exists(parent)) {
            std::error_code ec;
            fs::create_directories(parent, ec);
        }
        auto file = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            cfg.log_file, cfg.max_size,
            static_cast<std::size_t>(cfg.max_files));
        const std::string_view pattern =
            cfg.file_pattern.empty() ? kDefaultFilePattern
                                      : std::string_view{cfg.file_pattern};
        file->set_formatter(make_formatter(pattern));
        sinks.push_back(std::move(file));
    }

    /// Build a fresh logger and atomic-swap. Concurrent callers
    /// holding a `kernel()` shared_ptr keep the prior instance
    /// alive on their own stack; the swap point itself is a
    /// release-store on `storage()`.
    auto fresh = std::make_shared<spdlog::logger>("gn",
                                                   sinks.begin(),
                                                   sinks.end());
    fresh->set_level(parse_level(cfg.level, kDefaultLevel));
    fresh->flush_on(spdlog::level::warn);

    if (spdlog::get("gn")) {
        spdlog::drop("gn");
    }
    spdlog::register_logger(fresh);

    storage().store(std::move(fresh), std::memory_order_release);
    return true;
} catch (const std::exception&) {
    return false;
} catch (...) {
    return false;
}

}  // namespace gn::log
