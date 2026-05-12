"""Fixtures for the livedoc pytest suite.

The `tiny_repo` fixture writes a minimal repo skeleton into a tmp
directory and monkeypatches every livedoc module's `REPO_ROOT` /
`SDK_ROOT` / `FACTS_*` constants so the extractors run against the
tmp tree without polluting the real repo. Each test gets a fresh
skeleton — fixtures are function-scoped on purpose.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent.parent / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


# Minimum host_api.h — three named slots with banner families plus
# a _reserved tail.
_HOST_API_H = '''\
#ifndef GN_HOST_API_H
#define GN_HOST_API_H

#include <stdint.h>
#include <stddef.h>

typedef int gn_result_t;
typedef uint64_t gn_conn_id_t;

typedef struct host_api_s {
    uint32_t api_size;
    void* host_ctx;

    /* ── Messaging ─────────────────────────────────────────────── */
    /** Send an envelope on an existing connection. */
    gn_result_t (*send)(void* host_ctx, gn_conn_id_t conn,
                        const uint8_t* payload, size_t payload_size);

    /** Close a connection. Safe from any thread. */
    gn_result_t (*disconnect)(void* host_ctx, gn_conn_id_t conn);

    /* ── Registry queries ──────────────────────────────────────── */
    /** Look up a connection id by remote public key. */
    gn_result_t (*find_conn_by_pk)(void* host_ctx,
                                   const uint8_t pk[32],
                                   gn_conn_id_t* out_conn);

    /* ── Reserved for future extension ─────────────────────────── */
    void* _reserved[2];
} host_api_t;

#endif
'''

_LINK_H = '''\
#ifndef GN_LINK_H
#define GN_LINK_H
#include <stdint.h>
typedef int gn_result_t;
typedef struct gn_link_vtable_s {
    uint32_t api_size;
    /* ── Lifecycle ─────────────────────────────────────────────── */
    gn_result_t (*listen)(void* self, const char* uri);
    void* _reserved[2];
} gn_link_vtable_t;
#endif
'''

_HANDLER_H = '''\
#ifndef GN_HANDLER_H
#define GN_HANDLER_H
#include <stdint.h>
typedef int gn_result_t;
typedef struct gn_handler_vtable_s {
    uint32_t api_size;
    /* ── Dispatch ──────────────────────────────────────────────── */
    gn_result_t (*on_message)(void* self, uint32_t msg_id);
    void* _reserved[2];
} gn_handler_vtable_t;
#endif
'''

_SECURITY_H = '''\
#ifndef GN_SECURITY_H
#define GN_SECURITY_H
#include <stdint.h>
typedef int gn_result_t;
typedef struct gn_security_provider_vtable_s {
    uint32_t api_size;
    /* ── Handshake ─────────────────────────────────────────────── */
    gn_result_t (*handshake_open)(void* self);
    void* _reserved[2];
} gn_security_provider_vtable_t;
#endif
'''

_EXT_LINK_H = '''\
#ifndef GN_EXT_LINK_H
#define GN_EXT_LINK_H
#include <stdint.h>
typedef int gn_result_t;
typedef struct gn_link_api_s {
    uint32_t api_size;
    /* ── Composer surface ──────────────────────────────────────── */
    gn_result_t (*composer_listen)(void* ctx, const char* uri);
    void* _reserved[2];
} gn_link_api_t;
#endif
'''

_ROADMAP_MD = '''\
# Roadmap

intro paragraph.

## Reachability

- **NAT-traversal pipeline** — first feature.
- **Kademlia-style DHT** — second feature.

---

## Non-goals

- **Kernel-level economics** — explicit out-of-scope.
'''

_ROADMAP_MAP_YAML = '''\
features:
  "NAT-traversal pipeline":
    rule:
      plugin_exists: plugins/extensions/nat-traversal
    partial_if:
      plugin_exists: plugins/handlers/heartbeat
  "Kademlia-style DHT":
    rule:
      plugin_exists: plugins/handlers/kademlia
'''


def _write_skeleton(root: Path) -> None:
    (root / "sdk").mkdir(parents=True, exist_ok=True)
    (root / "sdk" / "extensions").mkdir(parents=True, exist_ok=True)
    (root / "sdk" / "host_api.h").write_text(_HOST_API_H)
    (root / "sdk" / "link.h").write_text(_LINK_H)
    (root / "sdk" / "handler.h").write_text(_HANDLER_H)
    (root / "sdk" / "security.h").write_text(_SECURITY_H)
    (root / "sdk" / "extensions" / "link.h").write_text(_EXT_LINK_H)

    # Plugin tree — three plugins, one per kind.
    for kind, name, content in [
        ("links", "tcp", "TCP transport sample."),
        ("handlers", "heartbeat", "Heartbeat sample."),
        ("security", "null", "Null security sample."),
    ]:
        d = root / "plugins" / kind / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "README.md").write_text(f"# {kind}/{name}\n\n{content}\n")
        # Add an emit_counter call site so the catalog extractor finds
        # something deterministic.
        (d / f"{name}.cpp").write_text(
            f'#include "host_api.h"\nvoid f(host_api_t* api) {{\n'
            f'    api->emit_counter(api->host_ctx, "{kind}.{name}.hit");\n'
            f'    int64_t v;\n'
            f'    gn_config_get_int64(api, "{kind}.{name}.cap", &v);\n'
            f'}}\n'
        )
        # Per-plugin tests so the test-inventory walker has data.
        tests = d / "tests"
        tests.mkdir(exist_ok=True)
        (tests / f"test_{name}.cpp").write_text(
            f'#include <gtest/gtest.h>\n'
            f'TEST({kind.capitalize()}{name.capitalize()}Test, Basic) '
            f'{{ EXPECT_TRUE(true); }}\n'
            f'TEST_F({kind.capitalize()}Fixture, Two) '
            f'{{ EXPECT_TRUE(true); }}\n'
        )

    # Kernel tests
    kt = root / "tests" / "unit"
    kt.mkdir(parents=True, exist_ok=True)
    (kt / "test_kernel.cpp").write_text(
        '#include <gtest/gtest.h>\n'
        'TEST(Kernel, Smoke) { EXPECT_TRUE(true); }\n'
        'TEST(Kernel, Other) { EXPECT_TRUE(true); }\n'
        'TEST_F(KernelFix, Three) { EXPECT_TRUE(true); }\n'
    )

    # Roadmap + roadmap_map
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs" / "ROADMAP.en.md").write_text(_ROADMAP_MD)
    (root / "docs" / "_facts").mkdir(exist_ok=True)


@pytest.fixture
def tiny_repo(tmp_path, monkeypatch):
    """Build a minimal repo skeleton and retarget every livedoc
    module at it. Yields the tmp path."""
    _write_skeleton(tmp_path)

    # Retarget every module that hardcodes REPO_ROOT.
    from livedoc import (
        abi_extract, config_keys, inventory, metrics_catalog,
        rfc_coverage, roadmap_status,
    )

    monkeypatch.setattr(abi_extract, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(abi_extract, "SDK_ROOT", tmp_path / "sdk")
    monkeypatch.setattr(abi_extract, "FACTS_ROOT",
                        tmp_path / "docs" / "_facts")

    monkeypatch.setattr(metrics_catalog, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(metrics_catalog, "FACTS_PATH",
                        tmp_path / "docs" / "_facts"
                        / "metrics_catalog.yaml")

    monkeypatch.setattr(config_keys, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(config_keys, "FACTS_PATH",
                        tmp_path / "docs" / "_facts"
                        / "config_keys.yaml")

    monkeypatch.setattr(rfc_coverage, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(rfc_coverage, "FACTS_PATH",
                        tmp_path / "docs" / "_facts"
                        / "rfc_coverage.yaml")
    # Tests don't ship a hand-curated map; use the real one in tree.

    monkeypatch.setattr(roadmap_status, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(roadmap_status, "ROADMAP_PATH",
                        tmp_path / "docs" / "ROADMAP.en.md")
    monkeypatch.setattr(roadmap_status, "FACTS_PATH",
                        tmp_path / "docs" / "_facts"
                        / "roadmap_status.yaml")
    # Write a tmp roadmap_map.yaml the resolver can read.
    rmap = tmp_path / "tools" / "livedoc" / "roadmap_map.yaml"
    rmap.parent.mkdir(parents=True, exist_ok=True)
    rmap.write_text(_ROADMAP_MAP_YAML)
    monkeypatch.setattr(roadmap_status, "MAP_PATH", rmap)

    monkeypatch.setattr(inventory, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(inventory, "PLUGINS_ROOT", tmp_path / "plugins")

    yield tmp_path
