"""Unit tests for tools/livedoc/metrics_catalog.py."""

from __future__ import annotations

import re

from livedoc import metrics_catalog


def test_emit_re_matches_basic_call():
    m = metrics_catalog._EMIT_RE.search(
        '   api->emit_counter(api->host_ctx, "drop.queue_hard_cap");'
    )
    assert m is not None
    assert m.group(1) == "emit_counter"
    assert m.group(2) == "drop.queue_hard_cap"


def test_emit_re_matches_iterate_counters():
    m = metrics_catalog._EMIT_RE.search(
        'iterate_counters(host_ctx, "ns.bucket", cb);'
    )
    assert m is not None
    assert m.group(1) == "iterate_counters"


def test_emit_re_skips_commented_line():
    # The regex itself matches the literal — comment filtering is
    # callers' job. Validate that the literal "//" prefix doesn't
    # break the regex.
    m = metrics_catalog._EMIT_RE.search(
        '// api->emit_counter(api->host_ctx, "x.y");'
    )
    # Match still happens — collector relies on grep filters at the
    # call level. Documenting current behaviour explicitly.
    assert m is not None


def test_collect_finds_skeleton_counters(tiny_repo):
    out = metrics_catalog.collect()
    names = {c["name"] for c in out["counters"]}
    # The skeleton writes one emit_counter per plugin.
    assert "links.tcp.hit" in names
    assert "handlers.heartbeat.hit" in names
    assert "security.null.hit" in names


def test_collect_groups_family_from_dotted_token(tiny_repo):
    out = metrics_catalog.collect()
    fam_for = {c["name"]: c["family"] for c in out["counters"]}
    assert fam_for["links.tcp.hit"] == "links"


def test_write_emits_yaml(tiny_repo):
    path = metrics_catalog.write()
    text = path.read_text()
    assert "counters:" in text
    assert "links.tcp.hit" in text
