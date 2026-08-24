# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""L2 verify tests: semantic diff / whitelist / dry-run / baseline capture."""
import subprocess

from zthl_bashpy_migrate.verify import (capture_baseline, deep_diff, dry_run_check,
                                         loads_json, verify)


def test_loads_json_last_line():
    assert loads_json('{"a":1}\n{"b":2}\n') == {"b": 2}
    assert loads_json('{"a":1}') == {"a": 1}


def test_deep_diff_equal():
    assert deep_diff({"a": 1, "b": [1, 2]}, {"a": 1, "b": [1, 2]}) == []


def test_deep_diff_value():
    diffs = deep_diff({"a": 1, "b": {"c": 2}}, {"a": 1, "b": {"c": 3}})
    assert any(d["path"] == "$.b.c" and d["kind"] == "value_mismatch" for d in diffs)


def test_deep_diff_missing_and_extra():
    diffs = deep_diff({"a": 1}, {"a": 1, "b": 2})
    kinds = {d["kind"] for d in diffs}
    assert "extra_key" in kinds


def test_verify_whitelist_subtree():
    baseline = {"hint": {"phase": "X", "desc": "y"}}
    output = {"hint": {"phase": "X", "desc": "y"}, "checklist": [1]}
    # whitelist whole "checklist" subtree
    wl = [{"path": "$.checklist", "reason": "bash bug fixed"}]
    r = verify(baseline, output, wl)
    assert r["equivalent"] is True
    assert len(r["whitelisted"]) == 1


def test_verify_blocked_without_whitelist():
    baseline = {"a": 1}
    output = {"a": 2}
    r = verify(baseline, output, [])
    assert r["equivalent"] is False
    assert r["blocked"][0]["path"] == "$.a"


def test_dry_run_unchanged(tmp_path):
    state = tmp_path / "state.json"
    state.write_text('{"x": 1}', encoding="utf-8")
    cmd = ["python", "-c", "import sys; print('read only')"]
    r = dry_run_check(cmd, str(state))
    assert r["state_unchanged"] is True
    assert r["returncode"] == 0


def test_dry_run_detects_write(tmp_path):
    state = tmp_path / "state.json"
    state.write_text('{"x": 1}', encoding="utf-8")
    cmd = ["python", "-c", "import sys; open(sys.argv[1],'w').write('y')", str(state)]
    r = dry_run_check(cmd, str(state))
    assert r["state_unchanged"] is False


def test_capture_baseline(tmp_path):
    out = tmp_path / "baseline.json"
    r = capture_baseline(["python", "-c", "import json;print(json.dumps({'ok':True}))"],
                         str(out))
    assert r["returncode"] == 0
    assert out.read_text(encoding="utf-8").strip() == '{"ok": true}'
