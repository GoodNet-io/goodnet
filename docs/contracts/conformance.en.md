# Contract: Conformance test suite

**Status:** active · v1
**Owner:** `sdk/test/conformance/`
**Last verified:** 2026-05-06
**Stability:** v1.x; new typed-test contracts may be added without
              breaking existing instantiations.

---

## 1. Purpose

The `sdk/test/conformance/` directory exports typed-test contracts:
one header per topic that gives plugin authors a black-box invariant
suite their plugin's instance must satisfy. The kernel publishes the
header; each plugin instantiates it against its own type and runs
the suite under its own `nix run .#test`. A failure surfaces in the
plugin's own gate, not in a kernel-side cross-plugin runner.

This contract pins the header-naming convention, the
`<Plugin>Traits` specialisation pattern, the C++23 concept gate, the
`INSTANTIATE_TYPED_TEST_SUITE_P` invocation, and what counts as a
backward-compatible change to a published conformance header.

---

## 2. Header naming and location

Each typed-test contract lives at
`sdk/test/conformance/<topic>.hpp`. Files are header-only; the body
of every `TYPED_TEST_P` macro lives in the header so each plugin's
translation unit instantiates it locally.

| Aspect | Rule |
|---|---|
| Path | `sdk/test/conformance/<topic>.hpp` (no `_v1` suffix on the v1 file) |
| `<topic>` | lowercase, underscore-joined, names the invariant family — e.g. `link_teardown`, never `link` alone |
| Namespace | `gn::test::<plugin-kind>::conformance` — e.g. `gn::test::link::conformance` |
| Include guard | `#pragma once` |
| Owner-of-record | the contract document under `docs/contracts/` whose invariant the suite enforces; named in the header docstring |

A contract that needs a breaking change ships as a sibling header
`<topic>-v2.hpp` per §6 — the v1 header stays in place so existing
consumers continue to compile.

---

## 3. Traits specialisation

Every consumer specialises a single template that teaches the
fixture how to construct, configure, and dial its plugin type. For
the link family the template is
`gn::test::link::conformance::LinkTraits<L>`; analogous
`<Topic>Traits<T>` templates live in other contract namespaces.

Required members for `LinkTraits<L>`:

| Member | Signature | Effect |
|---|---|---|
| `scheme` | `static constexpr const char* scheme` | URI scheme; reproduced in every assertion message so a failure log identifies the plugin |
| `make()` | `static std::shared_ptr<L> make()` | constructs a fresh instance; the fixture builds two — server and client — per test |
| `listen_uri()` | `static std::string listen_uri()` | URI the server passes to `listen`; TCP-class transports use `:0`; IPC binds a path |
| `connect_uri(port)` | `static std::string connect_uri(std::uint16_t port)` | URI the client passes to `connect`; receives the server's bound port (zero for IPC) |
| `wire_credentials(server, client)` | `static bool wire_credentials(L&, L&)` | installs pre-shared material before `listen`; plain TCP and IPC return `true` as a no-op; TLS / Noise wire keys here |

Each member is a free static — there is no traits-base class, no
runtime traits object. The specialisation lives inside the contract
namespace; forgetting a member is a compile error at the
instantiation site, before any test runs.

---

## 4. Concept gate

Every conformance header declares a C++23 concept that the
consumer's `TypeParam` must satisfy. The fixture template is
constrained on the concept, so a plugin type that drops a required
entry point fails at template-substitution time rather than at link
time.

Link-family concept (`LinkPlugin`, declared in `link_teardown.hpp`):

| Requirement | Source |
|---|---|
| `t.listen(uri) -> gn_result_t` | `link.md` §2 |
| `t.connect(uri) -> gn_result_t` | `link.md` §2 |
| `t.shutdown() -> void` | `link.md` §9 |
| `t.set_host_api(api) -> void` | host-stub plumbing (see §5) |

The concept lives in the same header as the fixture so the gate and
body cannot drift. Optional entry points — `listen_port()` for
TCP-class plugins but not for IPC — sit behind `if constexpr
(requires { ... })` inside the test body, never on the concept
itself. Tightening the concept on an existing header is breaking;
ship `<topic>-v2.hpp` per §6.

---

## 5. INSTANTIATE_TYPED_TEST_SUITE_P

Each consumer instantiates the suite once per plugin type:

```cpp
#include <sdk/test/conformance/link_teardown.hpp>
#include <my_link/header.hpp>

namespace gn::test::link::conformance {

template <>
struct LinkTraits<::MyLink> {
    static constexpr const char* scheme = "my";
    static std::shared_ptr<::MyLink> make() { ... }
    static std::string listen_uri() { return "my://127.0.0.1:0"; }
    static std::string connect_uri(std::uint16_t p) { ... }
    static bool wire_credentials(::MyLink&, ::MyLink&) { return true; }
};

INSTANTIATE_TYPED_TEST_SUITE_P(
    MyLink,
    LinkTeardownConformance,
    ::testing::Types<::MyLink>);

}  // namespace gn::test::link::conformance
```

The `*_P` macro family (parameterised typed test) is mandatory:
`TYPED_TEST_P` bodies in a header avoid ODR violations across
instantiating translation units, and each plugin gets its own suite
name through the first macro argument. Plain `TYPED_TEST` is
forbidden — its bodies cannot live in a multiply-included header.

The first argument (`MyLink` above) is the consumer's instantiation
tag. It appears in gtest output as `MyLink/LinkTeardownConformance.<TestName>`,
identifying the failing plugin without re-reading the test source.

---

## 6. Backward-compatible changes vs breaking

Change classification for an existing conformance header:

| Change | Class | Action |
|---|---|---|
| New `TYPED_TEST_P` body using only existing traits and concept | additive | edit in place; consumers pick it up on rebuild |
| New `EXPECT_*` / `ASSERT_*` in an existing body | additive | same; failure surfaces only if the plugin violates the new check |
| New traits member (`LinkTraits::new_field`) | breaking | ship `<topic>-v2.hpp` — v1 consumers stay green |
| New concept requirement | breaking | same |
| Renamed or removed `TYPED_TEST_P` body | breaking | `REGISTER_TYPED_TEST_SUITE_P` shape changes; ship v2 |
| Removed traits member or concept requirement | additive (relaxation) | edit in place |

A v2 header sits beside v1 as
`sdk/test/conformance/<topic>-v2.hpp` with its own concept and
traits names. v1 stays unchanged until every consumer has migrated;
v1 is then removed in the next `MAJOR` SDK bump per
`abi-evolution.md` §3b. The pre-rc1 reshape window from the same
§3b applies here too: before `v1.0.0-rc1` any conformance header
may be reshaped freely; after the tag the table above governs.

---

## 7. Test outcomes

The conformance suite runs under the consumer's `nix run .#test`.
A failure represents a contract violation, not an implementation
detail — the host stub (`ConformanceHost` for the link family)
supplies the exact callback shape the kernel uses, so any divergence
the test catches reproduces in production.

Sanitiser variants are first-class:

| Target | Effect |
|---|---|
| `nix run .#test` | release build, full suite |
| `nix run .#test -- asan` | AddressSanitizer rebuild |
| `nix run .#test -- tsan` | ThreadSanitizer rebuild |
| `nix run .#test -- all` | release, asan, tsan in sequence |

Filtering — `ctest -E`, `--gtest_filter`, `grep -v` on output —
is forbidden per `recipes/test-plugin.ru.md` §7. A sanitiser-only
failure reproducible only under `tsan` belongs to the owning
plugin's gate; hiding it defeats the contract.

The kernel never runs a consumer's conformance instantiation; each
plugin owns its own gate, so the failing surface and the owning
team coincide.

---

## 8. Cross-references

- [`link.en.md`](./link.en.md) §9 — the shutdown invariant
  `LinkTeardownConformance` validates.
- [`recipes/test-plugin.ru.md`](../recipes/test-plugin.ru.md) —
  walkthrough of a fresh plugin's first conformance instantiation
  and the full-ctest no-filter rule.
- [`abi-evolution.en.md`](./abi-evolution.en.md) §3b — pre-rc1
  reshape window that conformance headers honour, and how new
  conformance contracts ride alongside SDK ABI bumps.
- [`plugin-lifetime.en.md`](./plugin-lifetime.en.md) — phases at
  which conformance fixtures may exercise a plugin instance.
