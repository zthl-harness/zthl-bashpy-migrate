# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""v0.3.1 四条新规则回归：SC2155 / SC2046 / E722 / F841。"""
from zthl_bashpy_migrate.audit import python_lint, shellcheck_scan


def _kinds(src, strict=False):
    return shellcheck_scan(src, strict=strict)["counts"]


def test_sc2155_declaration_with_assignment():
    src = "f() {\n  local out=$(cmd)\n  local ok\n  ok=$(cmd)\n}\n"
    c = _kinds(src)
    assert c.get("sc2155_local_assign", 0) == 1     # 只报 local out=$(cmd)


def test_sc2046_strict_only():
    """SC2046 是分级建议（实测多为刻意的 for 分词）⟹ 仅在 --strict 下启用。"""
    src = 'f() {\n  echo $(ls)\n  x=$(ls)\n  echo "$(ls)"\n  [[ $(x) == y ]]\n}\n'
    assert _kinds(src).get("sc2046_unquoted_subst", 0) == 0
    assert _kinds(src, strict=True).get("sc2046_unquoted_subst", 0) == 1   # 只有 echo $(ls)


def test_e722_bare_except():
    src = "try:\n    pass\nexcept:\n    pass\nexcept ValueError:\n    pass\n"
    r = python_lint(src)
    assert r["counts"]["e722"] == 1
    assert r["e722_bare_except"][0]["line"] == 3


def test_f841_unused_local():
    src = ("def f(a):\n    b = 1\n    used = 2\n    _ignored = 3\n"
           "    return used + a\n")
    r = python_lint(src)
    names = {i["name"] for i in r["f841_unused_local"]}
    assert names == {"b"}


def test_f841_nested_scope_isolated():
    src = ("def outer():\n    x = 1\n    def inner():\n        y = 2\n"
           "        return y\n    return x\n")
    r = python_lint(src)
    assert r["counts"]["f841"] == 0
