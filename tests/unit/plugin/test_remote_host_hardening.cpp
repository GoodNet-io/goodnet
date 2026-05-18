/// @file   tests/unit/plugin/test_remote_host_hardening.cpp
/// @brief  Assert that the subprocess fork path in `RemoteHost::spawn`
///         applies the four OS-level mitigations called out in audit
///         09-security-and-provider-switch §S-1:
///           1. `prctl(PR_SET_DUMPABLE, 0)`         — `/proc/$pid/status: Dumpable: 0`
///           2. `prctl(PR_SET_NO_NEW_PRIVS, 1)`     — `/proc/$pid/status: NoNewPrivs: 1`
///           3. `setrlimit(RLIMIT_CORE, {0,0})`     — `/proc/$pid/limits: Max core file size 0 0`
///           4. `closefrom(kWorkerSocketFd + 1)`    — `/proc/$pid/fd/` contains no fd > 3 owned by the kernel side
///
/// The test re-uses the production `RemoteHost::spawn` path against
/// the in-tree `remote_echo` worker binary; the harness mirrors the
/// stub host_api used by `test_remote_host.cpp`.

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <regex>
#include <span>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/plugin.h>

#include <core/kernel/plugin_context.hpp>
#include <core/plugin/remote_host.hpp>

namespace {

const char* worker_binary_path() {
    if (const char* env = std::getenv("GOODNET_REMOTE_ECHO_BINARY")) {
        return env;
    }
#ifdef GOODNET_REMOTE_ECHO_PATH
    return GOODNET_REMOTE_ECHO_PATH;
#else
    return "workers/remote_echo";
#endif
}

struct StubHostState {
    std::atomic<int> inbound_calls{0};
    std::atomic<int> log_calls{0};
};

gn_result_t stub_notify_inbound_bytes(void* host_ctx, gn_conn_id_t,
                                      const uint8_t*, size_t) {
    auto* s = static_cast<StubHostState*>(host_ctx);
    s->inbound_calls.fetch_add(1, std::memory_order_relaxed);
    return GN_OK;
}

void stub_log_emit(void* host_ctx, gn_log_level_t, const char*, int32_t,
                   const char*) {
    auto* s = static_cast<StubHostState*>(host_ctx);
    s->log_calls.fetch_add(1, std::memory_order_relaxed);
}

int32_t stub_is_shutdown_requested(void*) { return 0; }

host_api_t make_stub_host_api(StubHostState& s) {
    host_api_t api{};
    api.api_size = sizeof(host_api_t);
    api.host_ctx = &s;
    api.log.api_size = sizeof(gn_log_api_t);
    api.log.emit = &stub_log_emit;
    api.notify_inbound_bytes = &stub_notify_inbound_bytes;
    api.is_shutdown_requested = &stub_is_shutdown_requested;
    return api;
}

std::string slurp(const std::string& path) {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string proc_path(::pid_t pid, const std::string& leaf) {
    return "/proc/" + std::to_string(pid) + "/" + leaf;
}

}  // namespace

/// /proc/$pid/status carries the `NoNewPrivs:` line directly — it
/// must be `1` after `prctl(PR_SET_NO_NEW_PRIVS,1)` and is preserved
/// through execve.
///
/// Side note on `PR_SET_DUMPABLE,0`: that prctl ALSO runs in the
/// child branch (between fork and execve) but the Linux kernel
/// unconditionally resets `mm->dumpable` inside `setup_new_exec()`
/// based on `/proc/sys/fs/suid_dumpable`, so the post-execve worker
/// observes `dumpable == suid_dumpable` (usually 1) regardless of the
/// pre-execve prctl. The hardening still matters — it protects the
/// brief post-fork/pre-execve window where the child still holds the
/// kernel's address-space snapshot — but the effect is not directly
/// observable from `/proc/$pid` after execve. The corresponding
/// prctl call is therefore asserted by source review + code path
/// inclusion (see the audit cross-reference in remote_host.cpp).
TEST(RemoteHostHardening, StatusReportsNoNewPrivs) {
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_echo_hardening";

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                         std::span<const std::string>(),
                         ctx, make_stub_host_api(stub), diag), GN_OK)
        << diag;

    const ::pid_t pid = host.worker_pid();
    ASSERT_GT(pid, 0);

    const std::string status = slurp(proc_path(pid, "status"));
    ASSERT_FALSE(status.empty())
        << "could not read /proc/" << pid << "/status (errno="
        << errno << ")";

    std::smatch m;
    const std::regex nnp_re{R"(NoNewPrivs:\s+(\d+))"};
    ASSERT_TRUE(std::regex_search(status, m, nnp_re))
        << "no NoNewPrivs line in /proc/" << pid << "/status";
    EXPECT_EQ(m[1].str(), "1")
        << "PR_SET_NO_NEW_PRIVS,1 did not take effect";
}

/// /proc/$pid/limits carries `Max core file size <soft> <hard>` — both
/// columns must read 0 after `setrlimit(RLIMIT_CORE, {0,0})`.
TEST(RemoteHostHardening, LimitsReportZeroCoreSize) {
    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_echo_hardening";

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                         std::span<const std::string>(),
                         ctx, make_stub_host_api(stub), diag), GN_OK)
        << diag;

    const ::pid_t pid = host.worker_pid();
    ASSERT_GT(pid, 0);

    const std::string limits = slurp(proc_path(pid, "limits"));
    ASSERT_FALSE(limits.empty())
        << "could not read /proc/" << pid << "/limits (errno="
        << errno << ")";

    // Format: "Max core file size        0                    0                    bytes"
    const std::regex core_re{
        R"(Max core file size\s+(\d+)\s+(\d+))"};
    std::smatch m;
    ASSERT_TRUE(std::regex_search(limits, m, core_re))
        << "no \"Max core file size\" row in /proc/" << pid << "/limits";
    EXPECT_EQ(m[1].str(), "0") << "RLIMIT_CORE soft != 0";
    EXPECT_EQ(m[2].str(), "0") << "RLIMIT_CORE hard != 0";
}

/// `/proc/$pid/fd/` after closefrom(4): the only fds owned by the
/// kernel-side fork path are 0/1/2 (inherited stdio) and 3 (the
/// kWorkerSocketFd wire). The worker itself may open additional fds
/// after execve (it does — the SDK reads its config from fd 3, may
/// open shared libraries' debug links, etc.), but every such fd is
/// the worker's own choice. The audit-critical assertion is that
/// nothing the *parent* held above fd 3 leaked into the child.
///
/// To assert that without coupling to the worker's internal fd usage,
/// the parent opens a known-distinctive marker fd (a memfd) BEFORE
/// spawn, then verifies the worker does NOT have that fd open.
TEST(RemoteHostHardening, ClosefromDropsInheritedFdsAboveWire) {
    // Open several marker fds in the parent that the child must NOT
    // inherit. Two subtleties drive the design:
    //   • The first available fd slot is 3 (after stdin/stdout/stderr);
    //     the spawn path dup2's the worker wire socket to that exact
    //     slot, so a marker at fd 3 is unobservable (atomically
    //     replaced by dup2). The leak check therefore targets fd >= 4.
    //   • A pool of markers (rather than a single one) ensures at
    //     least one is well above the wire-socket slot regardless of
    //     what other fds gtest/dl-runtime have opened by this point.
    constexpr int kPoolSize = 8;
    std::vector<int> markers;
    markers.reserve(kPoolSize);
    for (int i = 0; i < kPoolSize; ++i) {
        const int fd = ::open("/dev/null", O_RDONLY);
        ASSERT_GE(fd, 0) << "open(/dev/null) failed: " << std::strerror(errno);
        markers.push_back(fd);
    }
    // Of the pool, only fds strictly above kWorkerSocketFd (3) are
    // leak-observable. The kernel-side spawn path WILL dup2 over
    // fd 3 if that slot was occupied, so a marker there is expected
    // to vanish. Filter for the observable subset.
    std::vector<int> observable;
    for (int fd : markers) {
        if (fd > 3) observable.push_back(fd);
    }
    ASSERT_FALSE(observable.empty())
        << "no marker fd landed above fd 3 — cannot run leak check";

    StubHostState stub;
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_echo_hardening";

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                         std::span<const std::string>(),
                         ctx, make_stub_host_api(stub), diag), GN_OK)
        << diag;
    for (int fd : markers) ::close(fd);  // parent done with markers.

    const ::pid_t pid = host.worker_pid();
    ASSERT_GT(pid, 0);

    // Read /proc/<pid>/fd/ — every entry is an fd number.
    DIR* d = ::opendir(proc_path(pid, "fd").c_str());
    ASSERT_NE(d, nullptr)
        << "could not open /proc/" << pid << "/fd (errno=" << errno << ")";

    std::set<int> child_fds;
    while (auto* ent = ::readdir(d)) {
        const std::string n = ent->d_name;
        if (n == "." || n == "..") continue;
        try {
            child_fds.insert(std::stoi(n));
        } catch (...) {
            // not an integer entry, ignore
        }
    }
    ::closedir(d);

    // No marker fd above fd 3 may have leaked into the child.
    for (int fd : observable) {
        EXPECT_EQ(child_fds.count(fd), 0u)
            << "fd " << fd << " (parent /dev/null marker) leaked into "
            << "the worker — closefrom() did not take effect";
    }
}
