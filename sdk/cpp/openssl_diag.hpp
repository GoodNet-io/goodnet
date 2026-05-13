/// @file   sdk/cpp/openssl_diag.hpp
/// @brief  OpenSSL error-queue helpers + stderr-capture RAII guard.
///
/// `ERR_get_error()` returns a single error code per call; turning
/// it into a useful log line requires `ERR_error_string_n` or
/// `ERR_print_errors_fp`. Plugin sites repeated the boilerplate
/// inconsistently, sometimes dropping the queue without ever
/// looking at the contents — that masked TLS / QUIC / WSS handshake
/// failures behind `SSL_ERROR_SSL` with no payload.
///
/// `drain_err_queue()` pops every entry, formats each one through
/// `ERR_error_string_n`, and joins with newlines into one string a
/// plugin can hand to `host_api->log.emit`. The OpenSSL stderr
/// sink is intercepted via `StderrCapture` for tests that exercise
/// invalid-cert paths through OpenSSL's own `BIO_dump_indent_fp`
/// chains (mostly the WSS conformance suite).
///
/// Header-only by design — both helpers are tiny, and the SDK is a
/// header-only INTERFACE target. Including this header pulls
/// `<openssl/err.h>` so consumers must depend on the OpenSSL CMake
/// target (`PkgConfig::OpenSSL` / `OpenSSL::SSL`).

#pragma once

#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

#include <openssl/err.h>

namespace gn::sdk::openssl {

/// Pop every entry from OpenSSL's per-thread error queue and
/// concatenate them into a multi-line string. Empty queue returns
/// the empty string. Each line carries `0x<hex>:<lib>:<func>:<reason>`
/// per `ERR_error_string_n`.
[[nodiscard]] inline std::string drain_err_queue() {
    std::string out;
    char buf[256];
    while (auto code = ::ERR_get_error()) {
        ::ERR_error_string_n(code, buf, sizeof(buf));
        if (!out.empty()) out += '\n';
        out += buf;
    }
    return out;
}

/// RAII guard that redirects `stderr` into an internal pipe for the
/// guard's lifetime. Drain the captured bytes via `take()` after the
/// suspect call returns; `~StderrCapture` always restores the
/// original `stderr` fd. Useful for tests that verify OpenSSL
/// emits a specific certificate-mismatch line into stderr without
/// flooding the test runner output.
///
/// Not thread-safe across `stderr` writers — only use inside a test
/// fixture that controls every site touching `stderr`.
class StderrCapture {
public:
    StderrCapture() {
        (void)::fflush(stderr);
        original_fd_ = ::dup(STDERR_FILENO);
        int pipefd[2];
        if (::pipe(pipefd) == 0) {
            read_fd_ = pipefd[0];
            (void)::dup2(pipefd[1], STDERR_FILENO);
            ::close(pipefd[1]);
        }
    }

    StderrCapture(const StderrCapture&)            = delete;
    StderrCapture& operator=(const StderrCapture&) = delete;

    ~StderrCapture() {
        if (original_fd_ >= 0) {
            (void)::fflush(stderr);
            (void)::dup2(original_fd_, STDERR_FILENO);
            ::close(original_fd_);
        }
        if (read_fd_ >= 0) {
            ::close(read_fd_);
        }
    }

    /// Drain the captured bytes from the pipe into a string. Safe
    /// to call multiple times; second call returns empty.
    [[nodiscard]] std::string take() {
        if (read_fd_ < 0) return {};
        (void)::fflush(stderr);
        std::string out;
        char buf[1024];
        for (;;) {
            const auto n = ::read(read_fd_, buf, sizeof(buf));
            if (n <= 0) break;
            out.append(buf, static_cast<std::size_t>(n));
        }
        return out;
    }

private:
    int original_fd_ = -1;
    int read_fd_     = -1;
};

}  // namespace gn::sdk::openssl
