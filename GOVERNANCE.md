# Governance

GoodNet is a small kernel surrounded by independent plugins. This
document describes who decides what merges, how new maintainers are
added, and how the plugin ecosystem stays consistent without forcing
every plugin author through a single review queue.

## Roles

### BDFL (pre-rc1)

Until `v1.0.0-rc1` lands the project runs under a single
benevolent-dictator-for-life model: one maintainer makes the
final call on kernel and SDK changes. Pre-RC is a deliberate
window for shape decisions that need a single coherent voice;
multi-maintainer governance kicks in once the C ABI is frozen and
the cost of reshape becomes a coordination problem rather than a
technical one.

### Kernel maintainers (post-rc1)

After `rc1` the kernel and SDK move to a small maintainer team
(target: three to five). A maintainer is added by unanimous vote of
the existing team after a sustained track record of merged
contributions, contract authorship, and audit closures. Maintainers
review pull requests against `main`; two approvals from
non-author maintainers are required to merge a kernel change.

### Plugin authors

The bundled plugin tree (`plugins/`) is maintained by the kernel
maintainers during pre-RC and by per-plugin maintainers after rc1.
Out-of-tree plugins are authored and released independently — the
GoodNet kernel only requires the C ABI in `sdk/host_api.h` and the
`docs/contracts/` shape.

A plugin admitted into the bundled tree publishes a stable scheme
or extension namespace, ships a `default.nix` that builds the
plugin against a pinned kernel version, and follows the same
sanitiser + tidy gates as the kernel. Plugins added after rc1 land
under the kernel maintainers' review process.

### Contract authors

`docs/contracts/*.md` is the spec. Anyone may propose a contract
change; merge requires kernel-maintainer review of the *contract
delta first*, then the code that implements it. A contract author
who is not a maintainer collaborates with one through the pull
request.

## Decision process

| Question | Resolved by |
|---|---|
| Kernel C ABI shape | BDFL pre-rc1; unanimous maintainer vote after |
| Contract addition / change | maintainer review of delta + code together |
| New bundled plugin | maintainer team consensus |
| Out-of-tree plugin's behaviour | the plugin's own author and license |
| Security advisory text | `SECURITY.md` reporter + maintainers |
| Code of conduct enforcement | `CODE_OF_CONDUCT.md` channel |
| Trademark / brand use | BDFL pre-rc1; trademark-policy committee post |

A maintainer who disagrees with a pending merge raises the
objection on the pull request. If the objection survives revision,
the BDFL (pre-rc1) or majority maintainer vote (post-rc1) breaks
the tie. We do not run formal Lazy Consensus or Apache-style
majority votes for routine changes — small kernel + tight review
team makes informal consensus enough.

## Merge gates

A change merges into `main` when:

1. `cmake --build build` is green on the default toolchain.
2. `nix run .#test`, `.#test-asan`, `.#test-tsan` all green.
3. Strict `clang-tidy` is green on touched files.
4. The `CONTRIBUTING.md` commit format is followed.
5. Contract changes ride together with the code that implements
   them.
6. The required number of maintainer approvals has landed
   (1 pre-rc1, 2 post-rc1).
7. Audit pass closure — CRIT and HIGH findings either resolved in
   the same merge or in an explicit follow-up branch within the
   review cycle.

Bypassing a gate (e.g. `git merge --no-verify`) requires the BDFL
or majority maintainer agreement and a written reason in the merge
commit.

## Release cadence

| Version | Window |
|---|---|
| `v1.0.0-rc1` | C ABI freeze, public surface complete |
| `v1.0.0` | After rc1 + soak time, no rc-blocker bugs |
| `v1.x.y` | Append-only ABI evolution, plugin ecosystem grows |
| `v2.0` | Breaking changes — wire-protocol revision, post-quantum, etc. |

Rc1 is **not** a date-driven release; it lands when the public
surface is complete and the contracts have settled. Wave D / E /
F / G in `docs/ROADMAP.md` is the closure list.

## Plugin admission criteria

For a plugin to join the bundled tree (`plugins/`):

1. Implements the relevant C ABI from `sdk/` cleanly — no unsafe
   casts, no dependence on undocumented kernel internals.
2. Carries a `LICENSE` file. SDK-side dependencies follow the
   linker exception in the kernel `LICENSE`; bundled plugins
   default to MIT or Apache 2.0 for original code.
3. Ships a `CMakeLists.txt` that integrates with the top-level
   build and a `default.nix` that builds in isolation.
4. Has a unit test suite under `tests/unit/plugins/<family>/`.
5. Documents its scheme or extension namespace in
   `docs/contracts/` if it adds to the public surface.

A plugin removed from the bundled tree does not lose its history —
the per-plugin repository continues out-of-tree.

## Trademark and brand

The "GoodNet" name and logo belong to the project. Use of the
name in a way that implies endorsement of a fork or a third-party
product requires written permission from the BDFL (pre-rc1) or the
trademark-policy committee (post-rc1). Forks are permitted and
encouraged under the open-source licenses; using the GoodNet name
on a fork is not.

## Document amendments

This governance document is amended by the same process as a
contract: pull request, maintainer review, merge into `main`. A
change to the BDFL clause itself requires the BDFL's explicit
agreement (pre-rc1) or unanimous maintainer consent (post-rc1).
