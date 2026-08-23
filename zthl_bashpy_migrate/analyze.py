"""analyze.py — L1: bash function structure, dependency graph, side effects.

Deterministic, 0 API. Heuristics are conservative: they flag *candidates* for
human/LLM triage rather than making hard claims.

Lesson mapping (gatekeeper Phase 7, 2026-08-23):
  - "子函数引用父函数 local = 静默空值" → local_captures detection
  - "环境副作用留 bash / 纯判定转 Python" → boundary_recommendations
"""
import json
import re
from typing import Dict, List, Optional

_FUNC_RE = re.compile(r"^(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", re.M)
_LOCAL_RE = re.compile(r"\blocal\s+([A-Za-z_][A-Za-z0-9_]*)")
_VAR_REF_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
_CALL_RE = re.compile(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*$", re.M)

# 副作用命令（写文件 / 改状态 / 网络）→ 建议留 bash 环境层
_SIDE_EFFECT_PATTERNS = [
    (r">>\s*\S|>\s*\S+[^|]", "file redirect write"),
    (r"\b(mv|rm|cp|touch|mkdir|rmdir|ln|dd)\b", "fs mutation"),
    (r"\bgit\s+(add|commit|push|reset|checkout|restore|branch|merge|rebase|clean)", "git write"),
    (r"\b(curl|wget|git\s+clone|git\s+fetch)\b", "network"),
    (r"json\.dump\s*\(|open\([^)]*['\"]w['\"]\)", "state file write"),
    (r"python3?\s+-c\s+[\"']", "inline python (candidate to migrate)"),
]
# 2026-08-23: stderr/fd 重定向（2>/dev/null、2>&1、>&2、1>&2、> /dev/null）不是文件写副作用。
# 原 `file redirect write` 正则 `>\s*\S` 把 gatekeeper-cli.sh 的 538 处 2>/dev/null + 27 处 2>&1
# 全部误计为"文件写"，861 副作用里 ~565 个是假阳性（假阳性率 ~65%）。命中此形态的行使不算副作用。
_FD_REDIRECT_RE = re.compile(r"[12]?\s*>\s*(?:&[0-9]*|/dev/)|\>\s*&\s*[0-9]")
# 纯判定命令 → 建议转 Python（无外部副作用）
_PURE_READ_PATTERNS = [
    (r"json_val\s", "state read"),
    (r"json\.load\s*\(|open\([^)]*['\"]r['\"]\)", "state read"),
    (r"echo\s+['\"]?\{", "json emit"),
]


def extract_functions(source: str) -> Dict[str, Dict[str, object]]:
    """Extract bash functions with body ranges and declared locals.

    Body detection: from the opening brace of `name() {` to the matching
    closing brace at the same top-level depth (conservative brace counter).
    """
    matches = list(_FUNC_RE.finditer(source))
    funcs: Dict[str, Dict[str, object]] = {}
    for i, m in enumerate(matches):
        name = m.group(1)
        start = m.end()  # after `{`
        depth = 1
        end = None
        pos = start
        while pos < len(source):
            c = source[pos]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = pos
                    break
            pos += 1
        if end is None:
            end = len(source)
        body = source[start:end]
        locals_decl = [x.group(1) for x in _LOCAL_RE.finditer(body)]
        funcs[name] = {
            "range": [m.start(), end],
            "locals": locals_decl,
            "calls": _calls_in(body),
            "body": body,
        }
    return funcs


def _calls_in(body: str) -> List[str]:
    """Heuristic: names at end-of-line / after `;` / in $() that look like calls."""
    names = set(_VAR_REF_RE.sub("", body))
    calls = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # strip leading control words
        line = re.sub(r"^(local|export|if|then|else|elif|fi|case|esac|for|while|do|done|return|break|continue)\b", "", line)
        m = _CALL_RE.search(line.rstrip("; "))
        if m and m.group(1) not in ("echo", "printf", "set", "unset", "cd"):
            calls.append(m.group(1))
    return sorted(set(calls))


def detect_local_capture(funcs: Dict[str, Dict[str, object]]) -> List[Dict[str, str]]:
    """Flag functions that reference a variable which is a *parent* function's
    local — in bash this silently resolves to empty (the Phase 7 lesson).
    Conservative: checks variable refs in a function against other functions'
    declared locals, when the ref is not itself declared local."""
    all_locals = {name: set(meta["locals"]) for name, meta in funcs.items()}
    issues = []
    for name, meta in funcs.items():
        body = meta.get("body", "")
        refs = set(_VAR_REF_RE.findall(body))
        own = set(meta["locals"])
        for other, locs in all_locals.items():
            if other == name:
                continue
            captured = (refs & locs) - own
            for v in sorted(captured):
                issues.append({
                    "function": name,
                    "variable": v,
                    "declared_in": other,
                    "risk": "子函数引用父函数/兄弟函数 local — bash 静默空值",
                    "fix": "显式传参",
                })
    return issues


def side_effects(source: str) -> List[Dict[str, str]]:
    """Flag lines matching side-effect patterns (candidate: keep in bash env).

    2026-08-23: stderr/fd 重定向（2>/dev/null、2>&1、>&2 等）不算文件写副作用，
    在 `file redirect write` 命中时二次校验 _FD_REDIRECT_RE 排除，消除假阳性。
    """
    hits = []
    for i, line in enumerate(source.splitlines(), 1):
        for pat, label in _SIDE_EFFECT_PATTERNS:
            if not re.search(pat, line):
                continue
            if label == "file redirect write" and _FD_REDIRECT_RE.search(line):
                break  # stderr/fd 重定向 → 非文件写，跳过本行
            hits.append({"line": i, "label": label, "text": line.strip()[:120]})
            break
    return hits


def migration_boundary(funcs: Dict[str, Dict[str, object]]) -> List[Dict[str, str]]:
    """Suggest which functions are pure-decision (migrate to Python) vs
    env-side-effect (keep in bash). Pure = no side-effect calls & no git/network."""
    recs = []
    for name in funcs:
        recs.append({
            "function": name,
            "candidate": "migrate" if _is_pure(name, funcs) else "keep-bash",
        })
    return recs


def _is_pure(name: str, funcs: Dict[str, Dict[str, object]]) -> bool:
    body = funcs[name].get("body", "")
    for pat, _ in _SIDE_EFFECT_PATTERNS:
        if re.search(pat, body):
            return False
    return True


def analyze(source: str) -> Dict[str, object]:
    """Full L1 analysis → JSON report."""
    funcs = extract_functions(source)
    return {
        "functions": funcs,
        "local_captures": detect_local_capture(funcs),
        "side_effects": side_effects(source),
        "boundary_recommendations": migration_boundary(funcs),
    }
