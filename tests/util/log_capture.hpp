/// @file   tests/util/log_capture.hpp
/// @brief  RAII guard intercepting the kernel's spdlog sink for the
///         duration of a test. Useful for "did this call emit the
///         expected warning?" assertions without polluting the
///         CTest output stream.
///
/// Usage:
///   {
///     gn::tests::LogCapture capture;
///     do_thing_that_should_warn();
///     EXPECT_THAT(capture.lines(), Contains(HasSubstr("expected")));
///   }
///
/// The capture only covers `::gn::log::kernel()`'s sinks — other
/// loggers (per-plugin module loggers, gtest's own logs) are not
/// touched. Drop the guard to restore the original sinks atomically.

#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <spdlog/sinks/base_sink.h>
#include <spdlog/spdlog.h>

#include <core/util/log.hpp>

namespace gn::tests {

class LogCapture {
public:
    LogCapture() {
        auto sink = std::make_shared<RingSink>();
        sink_ = sink;
        auto logger = ::gn::log::kernel();
        original_sinks_ = logger->sinks();
        logger->sinks().clear();
        logger->sinks().push_back(sink);
    }

    LogCapture(const LogCapture&)            = delete;
    LogCapture& operator=(const LogCapture&) = delete;

    ~LogCapture() {
        auto logger = ::gn::log::kernel();
        logger->sinks() = original_sinks_;
    }

    /// Snapshot of every log message captured so far. Thread-safe
    /// even when worker threads are still emitting; the snapshot
    /// is a copy under the sink's mutex.
    [[nodiscard]] std::vector<std::string> lines() const {
        return sink_->snapshot();
    }

private:
    class RingSink : public ::spdlog::sinks::base_sink<std::mutex> {
    public:
        std::vector<std::string> snapshot() {
            std::lock_guard<std::mutex> lk(mutex_);
            return buffer_;
        }
    protected:
        void sink_it_(const ::spdlog::details::log_msg& msg) override {
            ::spdlog::memory_buf_t formatted;
            formatter_->format(msg, formatted);
            buffer_.emplace_back(
                std::string(formatted.data(), formatted.size()));
        }
        void flush_() override {}
    private:
        std::vector<std::string> buffer_;
    };

    std::shared_ptr<RingSink>                 sink_;
    std::vector<::spdlog::sink_ptr>           original_sinks_;
};

}  // namespace gn::tests
