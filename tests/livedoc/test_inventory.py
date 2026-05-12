"""Unit tests for tools/livedoc/inventory.py (plugin walker)."""

from __future__ import annotations

from livedoc import inventory


def test_discover_links(tiny_repo):
    entries = inventory.discover_links()
    names = {e["name"] for e in entries}
    assert names == {"tcp"}
    tcp = entries[0]
    assert tcp["path"] == "plugins/links/tcp"
    # Schemes always non-empty (falls back to plugin-dir name).
    assert tcp["schemes"]


def test_discover_handlers(tiny_repo):
    entries = inventory.discover_handlers()
    names = {e["name"] for e in entries}
    assert names == {"heartbeat"}


def test_discover_security(tiny_repo):
    entries = inventory.discover_security()
    names = {e["name"] for e in entries}
    assert names == {"null"}


def test_discover_all_returns_every_kind(tiny_repo):
    inv = inventory.discover_all()
    assert set(inv) >= {"links", "handlers", "security", "extensions"}


def test_first_paragraph_skips_header(tmp_path):
    md = tmp_path / "x.md"
    md.write_text(
        "# Title\n\n## Section\n\nFirst real prose line.\n"
    )
    assert inventory._first_paragraph(md) == "First real prose line."


def test_first_paragraph_empty_when_no_prose(tmp_path):
    md = tmp_path / "x.md"
    md.write_text("# Title only\n")
    assert inventory._first_paragraph(md) == ""
