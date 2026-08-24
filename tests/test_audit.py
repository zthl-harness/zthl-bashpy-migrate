# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""L3 audit tests: dead code / write guard (bash+python) / bomb scan / LLM degrade."""
from zthl_bashpy_migrate.audit import bomb_scan, dead_code, llm_explain, write_guard_check


def test_dead_code_detected(bash_source):
    r = dead_code(bash_source, entrypoints=["cmd_main"])
    cands = {c["function"] for c in r["candidates"]}
    # _write_state 未被任何入口调用链到达（cmd_main 调用它，但调用图启发式可能不识别）
    # _child/_parent 未从 cmd_main 到达 → 候选
    assert "_parent" in cands or "_child" in cands
    assert "cmd_main" not in cands


def test_write_guard_bash_flags_missing_guard(bash_source):
    """_write_state 函数体无 dry_run 守卫 → NONE；cmd_main 有守卫 → PRESENT。"""
    r = write_guard_check(bash_source, ["_write_state", "_state_write"])
    by_fn = {i["function"]: i["guard"] for i in r["issues"]}
    assert by_fn["_write_state"] == "NONE"
    assert by_fn["cmd_main"] == "PRESENT"


def test_write_guard_python(py_source):
    """Python AST: _write_state 在 `if not dry_run:` 内 → 无 NONE。"""
    r = write_guard_check(py_source, ["_write_state", "_state_write"])
    none_issues = [i for i in r["issues"] if i.get("guard") == "NONE"]
    assert none_issues == [], f"未预期的无守卫写入: {none_issues}"


def test_write_guard_python_flags_unprotected(tmp_path):
    src = "def _write_state(p, d):\n    open(p, 'w').write('x')\n\n_write_state('/tmp/x', {})\n"
    r = write_guard_check(src, ["_write_state"])
    assert any(i.get("guard") == "NONE" for i in r["issues"])


def test_bomb_scan_flags_inline_python_and_stderr_swallow():
    """2026-08-23: 炸弹标记 — python3 内联 / stderr 吞错 / 危险命令必须显式标出。"""
    src = """f() {
  python3 -c "import json; print(1)"
  python3 - <<'EOF'
print('heredoc')
EOF
  grep x 2>/dev/null
  echo hi >&2
  echo ok > out.txt
}
"""
    r = bomb_scan(src)
    c = r["counts"]
    assert c["inline_python"] == 2, f"inline_python 应命中 2 处: {c}"
    assert c["stderr_swallow"] == 1, f"stderr_swallow 应命中 1 处: {c}"
    assert c["fd_redirect"] == 1, f"fd_redirect 应命中 1 处: {c}"
    assert c.get("dangerous_command", 0) == 0
    assert r["total"] == 4


def test_llm_degrade_without_key():
    r = llm_explain([{"item": "x"}], api_key=None)
    assert r["mode"] == "degraded"
    assert r["items"] == [{"item": "x"}]
