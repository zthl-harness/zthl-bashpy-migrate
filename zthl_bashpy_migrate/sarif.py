# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""sarif.py — audit 报告 → SARIF 2.1.0（2026-11-04）。

为什么要有：审计结果此前只有自定义 JSON，接不进 GitHub code scanning、GitLab SAST、
VS Code SARIF Viewer 等以 SARIF 为共同最小公分母的平台。

设计约束（确定性优先，对齐 L2 verify 口径）：
- **无时间戳、无随机量** ⟹ 同一输入逐字相同输出，可直接进棘轮基线。
- **排序固定**：rules 按 ruleId 字典序；results 按 (line, column, ruleId, message)，
  无行号的 finding 排最后。
- **分级映射固定**：CRITICAL/HIGH → error，MEDIUM → warning，LOW/未标注 → note。
- **行级不可得**（函数级/模块级 finding）→ 省略 region，不伪造行号。
- `inline_inventory` 是**证据清单**不是告警，不转 results（避免把 96 条 payload 当缺陷噪声）。
"""
from typing import Dict, Iterable, List, Optional

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/zthl-harness/zthl-bashpy-migrate"
_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
_SEV_RANK = {"note": 0, "warning": 1, "error": 2}
_TAGS = ["bashpy-migrate", "migration"]


def _level(severity) -> str:
    """severity → SARIF level；未标注一律降为 note（不夸大）。"""
    return _LEVEL.get(str(severity or "").upper(), "note")


def _uri(path) -> str:
    """Windows 绝对路径 → file:/// URI；其余转正斜杠（GitHub 接受相对路径）。"""
    p = str(path or "").replace("\\", "/")
    if len(p) >= 2 and p[1] == ":" and p[0].isalpha():   # C:/...
        return "file:///" + p
    if p.startswith("//"):                               # UNC
        return "file://" + p
    return p


def _props(item: dict) -> dict:
    """保留可审计上下文（严重度/风险/修法/源码片段），丢弃错误标记。"""
    return {k: item[k] for k in ("severity", "risk", "fix", "text", "name",
                                 "func", "call", "function", "guard")
            if item.get(k) not in (None, "", [], {})}


def _fingerprint(rule_id: str, uri: str, message: str, line: Optional[int]) -> str:
    """稳定指纹（跨运行不变）：只依赖规则/文件/行号/消息，不含时间与绝对随机量。"""
    import hashlib
    raw = "%s|%s|%s|%s" % (rule_id, uri, line if line else "", message)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _groups(report: dict, section: str) -> Iterable[dict]:
    """bomb_scan / shellcheck_scan 的 groups 结构 → findings。"""
    sec = report.get(section) or {}
    for rule, items in sorted((sec.get("groups") or {}).items()):
        for it in items or []:
            yield {"rule": rule, "level": _level(it.get("severity")),
                   "message": it.get("risk") or rule,
                   "line": it.get("line"), "col": it.get("col"),
                   "props": _props(it)}


def _write_guard(report: dict) -> Iterable[dict]:
    sec = report.get("write_guard") or {}
    for it in sec.get("issues", []) or []:
        if it.get("error"):
            yield {"rule": "write_guard", "level": "error",
                   "message": str(it["error"]), "line": None, "col": None, "props": {}}
            continue
        guard = it.get("guard")
        yield {"rule": "write_guard",
               "level": "warning" if guard == "NONE" else "note",
               "message": it.get("risk") or "write path guard needs review",
               "line": it.get("line"), "col": None, "props": _props(it)}


def _python_lint(report: dict) -> Iterable[dict]:
    sec = report.get("python_lint") or {}
    if sec.get("error"):
        yield {"rule": "python_lint", "level": "error", "message": str(sec["error"]),
               "line": None, "col": None, "props": {}}
        return
    for it in sec.get("e722_bare_except", []) or []:
        yield {"rule": "e722_bare_except", "level": "warning",
               "message": "裸 except（E722）：连 KeyboardInterrupt/SystemExit 一起吞",
               "line": it.get("line"), "col": None, "props": _props(it)}
    for it in sec.get("f841_unused_local", []) or []:
        yield {"rule": "f841_unused_local", "level": "note",
               "message": "局部变量 '%s' 赋值后未使用（F841）" % it.get("name"),
               "line": it.get("line"), "col": None, "props": _props(it)}


def _python_deadcode(report: dict) -> Iterable[dict]:
    sec = report.get("python_module_deadcode") or {}
    if sec.get("error"):
        yield {"rule": "py_deadcode", "level": "error", "message": str(sec["error"]),
               "line": None, "col": None, "props": {}}
        return
    for it in sec.get("unused_imports", []) or []:
        yield {"rule": "py_unused_import", "level": "note",
               "message": "未使用 import '%s'" % it.get("name"),
               "line": it.get("line"), "col": None, "props": _props(it)}
    for it in sec.get("unused_functions", []) or []:
        yield {"rule": "py_unused_function", "level": "note",
               "message": "模块级函数 '%s' 无调用点" % it.get("name"),
               "line": it.get("line"), "col": None, "props": _props(it)}


def _dead_code(report: dict) -> Iterable[dict]:
    sec = report.get("dead_code") or {}
    for it in sec.get("candidates", []) or []:
        yield {"rule": "dead_code", "level": "note",
               "message": "函数 '%s' 从入口不可达（refs=%s）" % (it.get("function"), it.get("refs")),
               "line": None, "col": None, "props": {}}


_COLLECTORS = (
    lambda r: _groups(r, "bomb_scan"),
    lambda r: _groups(r, "shellcheck_scan"),
    _write_guard,
    _python_lint,
    _python_deadcode,
    _dead_code,
)


def to_sarif(report: dict, artifact: str, tool_version: str = "") -> dict:
    """audit 报告 → SARIF 2.1.0 文档（确定性：同输入逐字相同）。"""
    findings: List[dict] = []
    for collect in _COLLECTORS:
        findings.extend(list(collect(report or {})))

    uri = _uri(artifact)
    # 去重：同规则/行/列/消息只留一条（bomb 与 shellcheck 分组独立，不会互相吞）
    seen = set()
    uniq: List[dict] = []
    for f in findings:
        key = (f["rule"], f["line"], f["col"], f["message"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    # 固定排序：有行号按行升序在前，无行号在后
    uniq.sort(key=lambda f: (f["line"] is None, f["line"] or 0, f["col"] or 0,
                             f["rule"], f["message"]))

    rule_ids = sorted({f["rule"] for f in uniq})
    rules: List[dict] = []
    index: Dict[str, int] = {}
    for rid in rule_ids:
        occ = [f for f in uniq if f["rule"] == rid]
        worst = max(occ, key=lambda f: _SEV_RANK.get(f["level"], 0))
        props = worst.get("props") or {}
        rules.append({
            "id": rid,
            "shortDescription": {"text": str(worst["message"])[:160]},
            "help": {"text": str(props.get("fix") or props.get("risk") or worst["message"])},
            "defaultConfiguration": {"level": worst["level"]},
            "properties": {"tags": list(_TAGS)},
        })
        index[rid] = len(rules) - 1

    results: List[dict] = []
    for f in uniq:
        loc = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        if f.get("line"):
            region = {"startLine": int(f["line"])}
            if f.get("col"):
                region["startColumn"] = int(f["col"])
            loc["physicalLocation"]["region"] = region
        result_props = dict(f.get("props") or {})
        result_props["rule"] = f["rule"]
        results.append({
            "ruleId": f["rule"],
            "ruleIndex": index[f["rule"]],
            "level": f["level"],
            "message": {"text": str(f["message"])},
            "locations": [loc],
            "partialFingerprints": {
                "bashpy/v1": _fingerprint(f["rule"], uri, str(f["message"]), f.get("line")),
            },
            "properties": result_props,
        })

    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "bashpy-migrate",
                "version": str(tool_version or "0"),
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }},
            "columnKind": "unicodeCodePoints",
            "invocations": [{"executionSuccessful": True}],
            "results": results,
            "properties": {"artifact": uri, "deterministic": True},
        }],
    }
