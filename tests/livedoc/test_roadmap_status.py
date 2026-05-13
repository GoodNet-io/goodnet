"""Unit tests for tools/livedoc/roadmap_status.py."""

from __future__ import annotations

from livedoc import roadmap_status


def test_parse_bullets_picks_only_named(tiny_repo):
    bullets = roadmap_status.parse_bullets()
    assert bullets == ["NAT-traversal pipeline", "Kademlia-style DHT"]


def test_parse_bullets_excludes_non_goals():
    text = (
        "## Goals\n"
        "- **Real feature** — yes.\n"
        "## Non-goals\n"
        "- **Out of scope** — never.\n"
    )
    assert roadmap_status.parse_bullets(text) == ["Real feature"]


def test_resolve_missing_when_no_rule_present():
    out = roadmap_status.resolve("Unmapped X", mapping={})
    assert out.status == "missing"
    assert "no rule" in out.evidence.lower()


def test_resolve_done_via_plugin_exists(tiny_repo):
    # The tiny_repo skeleton ships plugins/handlers/heartbeat/, but
    # the map asks for plugins/handlers/kademlia/ — so done iff the
    # rule is satisfied. We construct a mapping by hand here to
    # exercise the resolver directly.
    mapping = {
        "Heartbeat present": {
            "rule": {"plugin_exists": "plugins/handlers/heartbeat"},
        },
    }
    out = roadmap_status.resolve("Heartbeat present", mapping=mapping)
    assert out.status == "done"


def test_resolve_partial_via_precursor(tiny_repo):
    mapping = {
        "NAT-traversal pipeline": {
            "rule": {"plugin_exists": "plugins/extensions/nat-traversal"},
            "partial_if": {"plugin_exists": "plugins/handlers/heartbeat"},
        },
    }
    out = roadmap_status.resolve("NAT-traversal pipeline",
                                  mapping=mapping)
    # Main rule fails (path absent); partial precursor matches.
    assert out.status == "partial"


def test_resolve_missing_when_nothing_matches(tiny_repo):
    mapping = {
        "Phantom feature": {
            "rule": {"plugin_exists": "plugins/handlers/does-not-exist"},
        },
    }
    out = roadmap_status.resolve("Phantom feature", mapping=mapping)
    assert out.status == "missing"


def test_compute_writes_all_bullets(tiny_repo):
    payload = roadmap_status.compute()
    names = {f["name"] for f in payload["features"]}
    assert names == {"NAT-traversal pipeline", "Kademlia-style DHT"}


def test_any_rule_passes_when_one_matches(tiny_repo):
    mapping = {
        "X": {
            "rule": {"any": [
                {"plugin_exists": "plugins/handlers/no-such"},
                {"plugin_exists": "plugins/handlers/heartbeat"},
            ]},
        },
    }
    out = roadmap_status.resolve("X", mapping=mapping)
    assert out.status == "done"
