# Contributing

GoodNet is a small kernel surrounded by independent plugins. The
kernel and the SDK live here; the bundled plugins live in this tree
during the pre-RC window and may move to per-plugin repositories
after `v1.0.0-rc1`.

## Where contributions land

- **Kernel and SDK changes** — pull request against `main` of this
  repository. Reviewed by the kernel maintainers; the C ABI is
  treated as a contract and every change goes through the audit
  pass below.
- **Bundled plugin changes** (`plugins/` tree) — same repository,
  same review process.
- **Out-of-tree plugin changes** — those live in their own
  repositories and follow their own conventions; the GoodNet kernel
  only cares that they implement the C ABI in `sdk/host_api.h`
  correctly.
- **Contract proposals** (`docs/contracts/*.md`) — change the
  contract first, then the code follows. A code change that
  contradicts a contract is reverted in favour of the contract.

## Setup

```bash
nix develop      # toolchain pinned through flake.nix
cmake -B build -G Ninja
cmake --build build
ctest --test-dir build
```

The `nix develop` shell carries gcc 15, libsodium, OpenSSL, asio,
spdlog, nlohmann_json, gtest, rapidcheck, clang-tidy 21. Direnv
lifts the shell automatically when the operator opts in.

## Branch model

`main` is always green: every commit on `main` builds, passes the
default test suite, ASan + UBSan, TSan, and strict clang-tidy.
Feature work lives on `feat/<topic>` branches; fixes on
`fix/<topic>`; documentation-only changes on `docs/<topic>`. Merges
into `main` are non-fast-forward (`git merge --no-ff`) so the merge
commit names the branch and the topic for `git log --first-parent`
readers.

A branch carries **one logical change**. Two unrelated improvements
land as two branches with two merges. The atomic discipline is the
review unit — a reviewer who reads only the merge commit knows what
changed.

## Commit format

```
<area>: <imperative summary, ≤72 chars/line>

Body paragraph in flat prose, ≤72 chars/line. State what the
commit adds or fixes; reference contracts as `per <name>.md §N`
rather than restating their content. Avoid history language
("changed", "previously", "fix for the wave-N audit") — describe
current behaviour or invariant. Keep the body terse: ≤150 words
for most commits.

Co-Authored-By: name <email>
```

Areas use the relevant top-level path: `core`, `sdk`, `plugins`,
`docs`, `tests`, `examples`, or a comma list when the change spans
several. Bug-fix commits prefix `fix:` instead of an area when the
fix is small and self-contained.

## Tests

Every kernel change carries a regression test. A bug-fix commit's
test must **fail on the pre-fix branch and pass on the post-fix
branch** — a green-on-both test is documentation, not a regression
guard.

The test layout:

- `tests/unit/` — compiled into one `goodnet_unit_tests` binary,
  globbed by `tests/unit/CMakeLists.txt`. Add a new test by writing
  a `test_<topic>.cpp` under the matching subdirectory; CMake picks
  it up on next configure.
- `tests/integration/` — driven through the real host_api thunks.
- `tests/abi/` — `_Static_assert` over `sizeof` and `offsetof` of
  every public ABI type. A change to `sdk/host_api.h` updates this
  file in the same commit.

Sanitiser entrypoints — required green on every PR:

```bash
nix run .#test-asan   # AddressSanitizer + UBSan
nix run .#test-tsan   # ThreadSanitizer
```

## Audit pass

After a non-trivial merge a code-critic agent reads the diff against
the parent and produces a structured report (CRIT / HIGH / MED /
LOW per-file findings). CRIT and HIGH findings land as a follow-up
branch in the same review cycle — they are not deferred to "later
polish". The audit pass is a quality gate, not an autopsy.

## Contracts first

`docs/contracts/*.md` is the spec; the code is one realisation of
it. A contract change is a public-surface change and goes through
the same review as a code change — they ride together when the
contract grows or shrinks. The reviewer reads the contract diff
first, the code diff second.

Contract style follows POSIX-man-page form:
**Producer / Effect / Returns / Payload / Concurrency / Delivery /
Ownership**. Sections describe what the implementation does, not
how it got there.

## What we don't accept

- A commit message that summarises the diff. Describe the change's
  intent and the invariant it preserves.
- A test that asserts on log content as a substitute for a
  semantic assertion.
- A "fix typo" stuck inside a feature commit. Split it.
- A merge that breaks `nix run .#test`, the sanitiser matrix, or
  strict tidy. The pre-commit hook runs tidy on changed files; do
  not bypass the hook with `--no-verify`.
- A "change for symmetry" that has no observable effect. The
  kernel earns slot count back through real wins, not aesthetic
  rebalancing.

## Pre-RC reshape window

Until the `v1.0.0-rc1` tag the C ABI in `sdk/host_api.h` is open
for reshape per `docs/contracts/abi-evolution.md` §3b. Existing
slots may be removed, renamed, or replaced; the size-prefix gating
in §3 stays useful as a forward-compatibility helper while shape
settles. Once `rc1` lands every rule in §3 (append-only, reserved-
tail-only, size-prefix gating) applies without exception.

A contributor who lands a slot reshape during the window updates
`tests/abi/test_layout.c` and the relevant contracts in the same
commit. Drift between contract and code is the fastest way to lose
the audit pass.

## Reporting a bug

Open an issue against this repository for kernel and SDK bugs;
report security issues to <security@goodnet.io> per `SECURITY.md`.
A good bug report carries the kernel commit hash, the operator's
config, the failure log, and the smallest reproduction the
reporter can build.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
