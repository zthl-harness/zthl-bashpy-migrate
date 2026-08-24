# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""L1 analyze tests."""
import pytest

from zthl_bashpy_migrate.analyze import (analyze, detect_local_capture,
                                          extract_functions, migration_boundary,
                                          side_effects)


def test_extract_functions(bash_source):
    funcs = extract_functions(bash_source)
    assert set(funcs) == {"_parent", "_child", "_write_state", "cmd_main"}
    assert funcs["_parent"]["locals"] == ["shared_var"]


def test_local_capture_detected(bash_source):
    """_child references $shared_var declared local in _parent → captured."""
    issues = detect_local_capture(extract_functions(bash_source))
    hits = [i for i in issues if i["function"] == "_child"
            and i["variable"] == "shared_var"]
    assert hits, "子函数引用父函数 local 未检出"
    assert hits[0]["fix"] == "显式传参"


def test_side_effects_detected(bash_source):
    hits = side_effects(bash_source)
    labels = {h["label"] for h in hits}
    assert "file redirect write" in labels
    assert any("state.json" in h["text"] for h in hits)


def test_side_effects_stderr_redirect_excluded():
    """2026-08-23: stderr/fd 重定向（2>/dev/null、2>&1、>&2、> /dev/null）不是文件写副作用。
    原正则把 538 处 2>/dev/null 全误计为 file redirect write → 861 假阳性 ~65%。"""
    src = """f() {
  ls 2>/dev/null
  grep x 2>&1
  echo hi >&2
  cat a > /dev/null
  echo ok > out.txt
}
"""
    hits = side_effects(src)
    texts = [h["text"] for h in hits]
    assert not any(("2>/dev/null" in t) or ("2>&1" in t) or (">&2" in t)
                   or ("/dev/null" in t) for t in texts), f"stderr 重定向仍被误报: {texts}"
    assert any("out.txt" in t for t in texts), "真实文件写被误排除"
    assert len(hits) == 1, f"应仅剩 1 个真实副作用: {hits}"


def test_migration_boundary(bash_source):
    recs = migration_boundary(extract_functions(bash_source))
    by_name = {r["function"]: r["candidate"] for r in recs}
    # _write_state 有文件写 → keep-bash；_child 纯 echo → migrate
    assert by_name["_write_state"] == "keep-bash"
    assert by_name["_child"] == "migrate"


def test_analyze_report_shape(bash_source):
    report = analyze(bash_source)
    assert set(report) == {"functions", "local_captures", "side_effects",
                           "boundary_recommendations"}
    assert len(report["functions"]) == 4
