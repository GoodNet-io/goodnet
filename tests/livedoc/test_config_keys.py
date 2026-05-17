"""Unit tests for tools/livedoc/config_keys.py."""

from __future__ import annotations

from livedoc import config_keys


def test_key_re_matches_each_helper_type():
    for helper, expected in [
        ("gn_config_get_int64", "int64"),
        ("gn_config_get_string", "string"),
        ("gn_config_get_bool", "bool"),
        ("gn_config_get_int32", "int32"),
    ]:
        line = f'    if ({helper}(api, "ice.foo", &v) == GN_OK) {{'
        m = config_keys._KEY_RE.search(line)
        assert m is not None, helper
        assert m.group(1) == expected
        assert m.group(2) == "ice.foo"


def test_collect_skeleton_keys(tiny_repo):
    out = config_keys.collect()
    names = {k["name"] for k in out["keys"]}
    assert "links.tcp.cap" in names
    assert "handlers.heartbeat.cap" in names
    assert "security.null.cap" in names


def test_collect_groups_family(tiny_repo):
    out = config_keys.collect()
    fam = {k["name"]: k["family"] for k in out["keys"]}
    assert fam["links.tcp.cap"] == "links"


def test_collect_sources_carry_file_line(tiny_repo):
    out = config_keys.collect()
    by_name = {k["name"]: k for k in out["keys"]}
    src = by_name["links.tcp.cap"]["sources"][0]
    assert src["file"].endswith("plugins/links/tcp/tcp.cpp")
    assert isinstance(src["line"], int) and src["line"] > 0


def test_write_emits_yaml(tiny_repo):
    path = config_keys.write()
    text = path.read_text()
    assert "keys:" in text
    assert "links.tcp.cap" in text


def test_write_honours_monkeypatched_facts_path(tiny_repo):
    """Defence-in-depth against the default-argument trap that
    silently corrupted `docs/_facts/host_api.yaml` (commit
    2474cd7). Pins that `config_keys.write()` resolves
    FACTS_PATH at call time so the conftest fixture reaches it."""
    expected = tiny_repo / "docs" / "_facts" / "config_keys.yaml"
    returned = config_keys.write()
    assert returned == expected, (
        f"write() must write to the monkeypatched FACTS_PATH "
        f"({expected}), got {returned}"
    )
