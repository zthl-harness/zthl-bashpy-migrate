# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""内联载荷清单（inventory）与两处精度修复的回归测试（2026-11-04）。

背景：`audit --bomb` 只做行级告警（注释误报、同载荷不合并、无体量），
拆解排序需要可排序清单 ⟹ 新增 `scan_inline`，并把两处注释假阳性修掉。
"""
from zthl_bashpy_migrate.analyze import analyze, side_effects
from zthl_bashpy_migrate.audit import bomb_scan
from zthl_bashpy_migrate.inventory import scan_inline

SRC = """f1() {
  v=$(python3 -c 'print(1)')
  python3 -c 'import json'
  python3 -c "$v"
  # python3 -c 'commented'
  python3 -c "
print(1)
"
}
python3 <<'PY'
print(2)
PY
"""


def test_categories():
    r = scan_inline(SRC)
    assert r["by_cat"]["payload"] == 3      # 单行 + 多行 + heredoc
    assert r["by_cat"]["import_probe"] == 1
    assert r["by_cat"]["wrapper"] == 1
    assert r["by_cat"]["comment"] == 1
    assert r["total"] == 6
    assert r["payload_bytes"] > 0


def test_function_attribution_and_kinds():
    r = analyze(SRC)["inline_inventory"]
    funcs = {(it["cat"], it["kind"]): it["func"] for it in r["items"]}
    assert funcs[("payload", "single")] == "f1"
    assert funcs[("payload", "multi")] == "f1"
    assert funcs[("payload", "heredoc")] == "<top-level>"


def test_identity_ignores_line_and_indent():
    """身份 = 载荷文本（折叠空白），与行号/缩进/引号形态无关。"""
    a = scan_inline("f() {\n  python3 -c 'print(1)'\n}\n")
    b = scan_inline("g() {\n\n\npython3 -c \"print(1)\"\n}\n")
    sa = [i["sha"] for i in a["items"] if i["cat"] == "payload"][0]
    sb = [i["sha"] for i in b["items"] if i["cat"] == "payload"][0]
    assert sa == sb
    c = scan_inline("f() {\n  python3 -c 'print(2)'\n}\n")
    assert [i["sha"] for i in c["items"] if i["cat"] == "payload"][0] != sa


def test_analyze_includes_inventory():
    r = analyze(SRC)
    assert "inline_inventory" in r and r["inline_inventory"]["total"] == 6
    rng = r["functions"]["f1"]["line_range"]
    assert rng[0] < rng[1] and rng[0] >= 1


def test_side_effects_skip_comments():
    src = "# 说明：> out.txt 不是副作用\nf() {\n  echo hi > out.txt\n}\n"
    hits = side_effects(src)
    assert len(hits) == 1 and hits[0]["line"] == 3


def test_bomb_scan_skip_comments():
    src = "# python3 -c 'commented'\nf() {\n  python3 -c 'print(1)'\n}\n"
    r = bomb_scan(src)
    assert r["counts"].get("inline_python", 0) == 1
