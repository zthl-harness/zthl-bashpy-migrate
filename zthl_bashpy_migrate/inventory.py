# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""inventory.py — 内联 Python 载荷清点（L1.5，2026-11-04）。

为什么单列：`audit --bomb` 的 `inline_python` 是**行级告警**（够用但不精确：
注释行会命中、同名载荷不合并、无体量信息）。拆解炸弹需要的是**可排序的清单**：
哪一块最大、属于哪个函数、是真实载荷还是 import 探测/壳。

四类判据（可机检，与 gatekeeper 侧 `gk_bomb_inventory.py` 同口径但**独立实现**）：

| cat | 判据 |
|:--|:--|
| `comment` | 该行 lstrip 后以 `#` 开头（不可执行；保留记录以便解释命中，但不计入可拆目标） |
| `wrapper` | `-c` 后紧跟 `$`（代码在变量/命令替换里，改本处无效） |
| `import_probe` | 单引号体内**仅有** `import X` / `from X import Y`（能力探测，改造收益为零） |
| `payload` | 其余（单行 / 多行 `-c "` / heredoc）——**唯一的拆解目标** |

身份 = `sha1(归一化载荷)[:12]`，**不含行号** ⟹ 代码搬家不算新增。
"""
import hashlib
import re
from typing import Dict, List, Optional

_C_RE = re.compile(r"python3?\s+-c")
_H_RE = re.compile(r"python3?\s+(?:-\s[^<]*?)?<<\s*'?([A-Za-z_][A-Za-z0-9_]*)'?")
_WRAP_RE = re.compile(r"""python3?\s+-c\s+["']?\$""")
_SQ_RE = re.compile(r"""python3?\s+-c\s+'([^']*)'""")
_IMPORT_ONLY_RE = re.compile(
    r"^(?:import\s+[\w.]+(?:\s*,\s*[\w.]+)*|from\s+[\w.]+\s+import\s+[\w.,\s*]+)$")


def _sha(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:12]


def _norm(s: str) -> str:
    """折叠空白 + 去首尾：纯缩进变动不产生新身份。"""
    return re.sub(r"\s+", " ", s).strip()


def _func_at(line_no: int, funcs: Optional[Dict[str, Dict[str, object]]]) -> str:
    """按 `line_range` 归属函数；无命中归 `<top-level>`。"""
    best = "<top-level>"
    for name, meta in (funcs or {}).items():
        rng = meta.get("line_range") or []
        if len(rng) == 2 and rng[0] <= line_no <= rng[1]:
            if len(rng) == 2:
                best = name
    return best


def _collect_dq(lines: List[str], i: int, after: int) -> tuple:
    """从 `-c` 之后收集多行双引号载荷，返回 (body, 结束行下标)。

    只认**未转义**的闭引号；换行按 `\\n` 连接（身份归一化会折叠空白）。
    """
    s = lines[i]
    k = after
    while k < len(s) and s[k] in " \t":
        k += 1
    if k < len(s) and s[k] == '"':
        k += 1
    buf: List[str] = []
    j = i
    cur = s[k:]
    while True:
        esc = False
        cut = None
        for pos, ch in enumerate(cur):
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                cut = pos
                break
        if cut is not None:
            buf.append(cur[:cut])
            return "\n".join(buf), j
        buf.append(cur)
        j += 1
        if j >= len(lines):
            return "\n".join(buf), len(lines) - 1
        cur = lines[j]


def _collect_heredoc(lines: List[str], i: int, tag: str) -> tuple:
    buf = []
    j = i + 1
    while j < len(lines) and lines[j].strip() != tag:
        buf.append(lines[j])
        j += 1
    return "\n".join(buf), j


def scan_inline(source: str,
                funcs: Optional[Dict[str, Dict[str, object]]] = None) -> Dict[str, object]:
    """清单化内联 python 载荷（只读、确定性）。"""
    lines = source.splitlines()
    items: List[Dict[str, object]] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        mh = _H_RE.search(ln)
        if mh:
            body, end = _collect_heredoc(lines, i, mh.group(1))
            items.append({"line": i + 1, "func": _func_at(i + 1, funcs),
                          "cat": "payload", "kind": "heredoc",
                          "sha": _sha(_norm(body)), "size": len(body),
                          "text": ln.strip()[:120]})
            i = end + 1
            continue
        if _C_RE.search(ln):
            func = _func_at(i + 1, funcs)
            if ln.lstrip().startswith("#"):
                items.append({"line": i + 1, "func": func, "cat": "comment",
                              "kind": "comment", "sha": _sha(_norm(ln)),
                              "size": len(ln), "text": ln.strip()[:120]})
            elif _WRAP_RE.search(ln):
                items.append({"line": i + 1, "func": func, "cat": "wrapper",
                              "kind": "wrapper", "sha": _sha(_norm(ln)),
                              "size": len(ln), "text": ln.strip()[:120]})
            else:
                msq = _SQ_RE.search(ln)
                if msq:
                    body = msq.group(1)
                    cat = ("import_probe" if _IMPORT_ONLY_RE.match(body.strip())
                           else "payload")
                    items.append({"line": i + 1, "func": func, "cat": cat,
                                  "kind": "single", "sha": _sha(_norm(body)),
                                  "size": len(body), "text": ln.strip()[:120]})
                else:
                    body, end = _collect_dq(lines, i, _C_RE.search(ln).end())
                    items.append({"line": i + 1, "func": func, "cat": "payload",
                                  "kind": "multi", "sha": _sha(_norm(body)),
                                  "size": len(body), "text": ln.strip()[:120]})
                    i = end
        i += 1

    by_cat: Dict[str, int] = {}
    by_kind: Dict[str, int] = {}
    for it in items:
        by_cat[it["cat"]] = by_cat.get(it["cat"], 0) + 1
        by_kind[it["kind"]] = by_kind.get(it["kind"], 0) + 1
    return {"total": len(items), "by_cat": by_cat, "by_kind": by_kind,
            "payload_bytes": sum(it["size"] for it in items if it["cat"] == "payload"),
            "items": items}
