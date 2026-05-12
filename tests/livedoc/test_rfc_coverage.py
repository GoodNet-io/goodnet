"""Unit tests for tools/livedoc/rfc_coverage.py."""

from __future__ import annotations

from pathlib import Path

import yaml

from livedoc import rfc_coverage


def test_compute_reads_map_and_flags_stale(tiny_repo, monkeypatch):
    map_path = tiny_repo / "tools" / "livedoc" / "rfc_coverage.yaml"
    map_path.parent.mkdir(parents=True, exist_ok=True)
    map_path.write_text(yaml.safe_dump({
        "rfcs": [
            {"rfc": 8445, "title": "ICE", "area": "x",
             "status": "full",
             "implementation": "plugins/links/tcp"},   # exists
            {"rfc": 5766, "title": "TURN", "area": "x",
             "status": "full",
             "implementation": "plugins/links/nonexistent"},
        ],
    }))
    monkeypatch.setattr(rfc_coverage, "MAP_PATH", map_path)

    payload = rfc_coverage.compute()
    rows = payload["rfcs"]
    fresh = next(r for r in rows if r["rfc"] == 8445)
    stale = next(r for r in rows if r["rfc"] == 5766)
    assert "stale" not in (fresh.get("notes", "") or "")
    assert "stale path" in stale["notes"]


def test_compute_handles_empty_map(tiny_repo, monkeypatch):
    map_path = tiny_repo / "tools" / "livedoc" / "rfc_coverage.yaml"
    map_path.parent.mkdir(parents=True, exist_ok=True)
    map_path.write_text("rfcs: []\n")
    monkeypatch.setattr(rfc_coverage, "MAP_PATH", map_path)
    assert rfc_coverage.compute() == {"rfcs": []}


def test_write_emits_yaml(tiny_repo, monkeypatch):
    map_path = tiny_repo / "tools" / "livedoc" / "rfc_coverage.yaml"
    map_path.parent.mkdir(parents=True, exist_ok=True)
    map_path.write_text(yaml.safe_dump({"rfcs": [
        {"rfc": 9000, "title": "QUIC", "area": "x",
         "status": "partial", "implementation": ""},
    ]}))
    monkeypatch.setattr(rfc_coverage, "MAP_PATH", map_path)
    path = rfc_coverage.write()
    text = path.read_text()
    assert "rfcs:" in text and "QUIC" in text
