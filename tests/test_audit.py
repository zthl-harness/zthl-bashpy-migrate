# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""L3 audit tests: dead code / write guard (bash+python) / bomb scan / shellcheck TOP / LLM degrade."""
from zthl_bashpy_migrate.audit import (
    bomb_scan, dead_code, llm_explain, shellcheck_scan, write_guard_check,
)


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


def test_bomb_scan_case_sensitive_detected():
    """2026-08-25: 大小写敏感比较（zizmor 式检测）— 值比较（camelCase）与常量比较（ALL_CAPS）分别命中。"""
    src = """f() {
  if [ "$_allowed" = "False" ]; then echo no; fi
  [[ "$verdict" == "APPROVED" ]] && echo yes
  echo "$x" != "ok" && echo no  # 小写字面量不命中
}
"""
    r = bomb_scan(src)
    c = r["counts"]
    assert c["case_sensitive"] == 1, f"值比较应命中 1 处: {c}"
    assert c["case_sensitive_const"] == 1, f"常量比较应命中 1 处: {c}"
    # 小写字面量不命中（两类均不命中）
    for grp in (r["groups"].get("case_sensitive", []), r["groups"].get("case_sensitive_const", [])):
        assert 'x" != "ok"' not in str(grp)


def test_bomb_scan_every_finding_has_fix():
    """2026-08-25: zizmor 模式 — 每条 finding 必须带 severity + risk + fix（检测→分级→修复）。"""
    src = """f() {
  python3 -c "print(1)"
  grep x 2>/dev/null
  if [ "$a" = "False" ]; then :; fi
}
"""
    r = bomb_scan(src)
    for kind, items in r["groups"].items():
        for item in items:
            assert item["severity"], f"{kind} 缺 severity"
            assert item["risk"], f"{kind} 缺 risk"
            assert item["fix"], f"{kind} 缺 fix: {item}"


def test_shellcheck_scan_top_rules():
    """2026-08-26: shellcheck TOP 子集原生移植 — sc2164/sc2181/sc2086 命中，引号内不误报。"""
    src = """f() {
  cd "$HOME"
  if [ $? -ne 0 ]; then echo fail; fi
  echo $name
  echo "$quoted"
}
"""
    r = shellcheck_scan(src)
    c = r["counts"]
    assert c["sc2164_cd_fail"] == 1, f"cd 无错误处理应命中: {c}"
    assert c["sc2181_test_dollar"] == 1, f"$? 反模式应命中: {c}"
    assert c["sc2086_unquoted"] == 1, f"裸变量应命中: {c}"
    # 引号内 $quoted 不误报
    assert "quoted" not in str(r["groups"].get("sc2086_unquoted", []))


def test_shellcheck_sc2034_unused_and_const_exempt():
    """2026-08-26: sc2034 — 孤儿变量报，常量契约豁免（死代码教训 R5.5）。"""
    src = """_STAGE_READY="true"  # 常量契约豁免
f() {
  local orphan="x"
  echo ok
}
"""
    r = shellcheck_scan(src)
    c = r["counts"]
    assert c["sc2034_unused"] == 1, f"孤儿变量应命中: {c}"
    assert "orphan" in str(r["groups"].get("sc2034_unused", []))
    # 全大写常量 _STAGE_READY 豁免（case 分支/constants 契约不是死代码）
    assert "_STAGE_READY" not in str(r["groups"].get("sc2034_unused", []))


def test_shellcheck_scan_skips_python_inline():
    """2026-08-26: python 内联/heredoc 内容不按 bash 扫（归 bomb_scan.inline_python）。"""
    src = """f() {
  python3 - <<'PYEOF'
u=d.get('updated','')
PYEOF
  echo $name
}
"""
    r = shellcheck_scan(src)
    # heredoc python 内容不报 sc2034；bash 行 echo $name 仍报 sc2086
    assert "u=d.get" not in str(r["groups"].get("sc2034_unused", []))
    assert r["counts"]["sc2086_unquoted"] == 1, f"bash 裸变量应命中: {r['counts']}"


def test_llm_degrade_without_key():
    r = llm_explain([{"item": "x"}], api_key=None)
    assert r["mode"] == "degraded"
    assert r["items"] == [{"item": "x"}]
