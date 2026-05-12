"""Unit tests for tools/livedoc/markdown_inject.py."""

from __future__ import annotations

from livedoc.markdown_inject import (
    refresh_file, regions_in, replace,
)


def test_replace_swaps_only_body():
    src = (
        "intro line\n"
        "<!-- livedoc:x -->\n"
        "stale body\n"
        "<!-- /livedoc:x -->\n"
        "trailing line\n"
    )
    out = replace(src, "x", "fresh body")
    assert "intro line" in out
    assert "trailing line" in out
    assert "stale body" not in out
    assert "fresh body" in out
    # Markers remain in place verbatim.
    assert "<!-- livedoc:x -->" in out
    assert "<!-- /livedoc:x -->" in out


def test_replace_idempotent():
    src = (
        "<!-- livedoc:foo -->\nold\n<!-- /livedoc:foo -->"
    )
    once = replace(src, "foo", "fresh")
    twice = replace(once, "foo", "fresh")
    assert once == twice


def test_replace_missing_marker_noop():
    src = "no markers here at all"
    assert replace(src, "x", "anything") == src


def test_replace_unclosed_marker_noop():
    # Open without close — current shape is conservative, no rewrite.
    src = "<!-- livedoc:x --> body with no closer"
    assert replace(src, "x", "fresh") == src


def test_replace_preserves_outside_bytes():
    src = "ALPHA\n\n<!-- livedoc:m -->\nBODY\n<!-- /livedoc:m -->\nOMEGA"
    out = replace(src, "m", "x")
    assert out.startswith("ALPHA\n\n")
    assert out.endswith("\nOMEGA")


def test_replace_only_first_occurrence_if_dupes():
    # Duplicate marker pairs in a single file: only the first
    # pair is rewritten (count=1 in re.sub).
    src = (
        "<!-- livedoc:k -->\nA\n<!-- /livedoc:k -->\n"
        "<!-- livedoc:k -->\nB\n<!-- /livedoc:k -->"
    )
    out = replace(src, "k", "x")
    # The first body got replaced; the second one stays.
    assert out.count("x") == 1
    assert "B" in out  # second pair untouched


def test_regions_in_finds_all_marker_names():
    src = (
        "<!-- livedoc:a -->\n<!-- /livedoc:a -->\n"
        "<!-- livedoc:b_2 --><!-- /livedoc:b_2 -->\n"
        "<!-- livedoc:c-d --><!-- /livedoc:c-d -->"
    )
    assert set(regions_in(src)) == {"a", "b_2", "c-d"}


def test_refresh_file_writes_only_when_changed(tmp_path):
    md = tmp_path / "x.md"
    md.write_text(
        "head\n<!-- livedoc:m -->\nold\n<!-- /livedoc:m -->\n"
    )
    # First call — must change.
    assert refresh_file(md, {"m": "new"}) is True
    body1 = md.read_text()
    assert "new" in body1
    # Second call with identical body — no change.
    assert refresh_file(md, {"m": "new"}) is False
    assert md.read_text() == body1
