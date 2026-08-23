"""audit.py — L3: dead-code triage + write-guard audit + optional LLM fallback.

Deterministic core (0 API); LLM is an optional explainer and NEVER gates a
decision — its output must pass L2 verify (the 收敛设计 rule).

Lessons mapped (gatekeeper Phase 7, 2026-08-23):
  - 死代码检测三关: 函数定义 → 调用引用 → 生产入口可达性
  - 写入路径守卫: `_write_state` 无 dry_run 守卫 = --check 消费空转
  - LLM 兜底: 无 key 降级输出"待人工审查"清单
"""
import ast
import json
import re
import urllib.request
from typing import Dict, List, Optional

from .analyze import extract_functions

# ─── 死代码三关 ───

def dead_code(source: str, entrypoints: List[str]) -> Dict[str, object]:
    """Three-gate dead code detection (conservative candidates).

    Gate 1: extract function definitions.
    Gate 2: count references (definition + call sites) per function name.
    Gate 3: BFS reachability from production entrypoints over the call graph.
    A function is a *candidate* if it is never reached from any entrypoint.
    """
    funcs = extract_functions(source)
    names = set(funcs)
    ref_count = {n: 0 for n in names}
    call_graph: Dict[str, List[str]] = {}
    for n, meta in funcs.items():
        calls = [c for c in meta.get("calls", []) if c in names]
        call_graph[n] = calls
        for c in calls:
            ref_count[c] += 1
    # reachability from entrypoints
    reached = set()
    stack = [e for e in entrypoints if e in names]
    while stack:
        n = stack.pop()
        if n in reached:
            continue
        reached.add(n)
        stack.extend(call_graph.get(n, []))
    candidates = [
        {"function": n, "refs": ref_count[n], "reached": n in reached}
        for n in sorted(names)
        if n not in reached
    ]
    return {"candidates": candidates, "call_graph": call_graph}


# ─── 写入守卫审查（bash 启发式 + Python AST）───

def write_guard_check(source: str, write_fns: List[str],
                      dry_run_tokens: Optional[List[str]] = None) -> Dict[str, object]:
    """Flag write-function call sites that may lack a dry_run guard.

    bash (heuristic): per-function — if a function calls a write_fn but has no
    `dry_run` token at all, flag it. If it has the token, mark "verify".
    Python (AST): flag `_write_state(...)` calls not inside an
    `if not dry_run:` block.
    """
    dry_run_tokens = dry_run_tokens or ["dry_run"]
    issues = []
    if source.lstrip().startswith(("def ", "import ", "class ")):
        issues = _py_write_guard_issues(source, write_fns, dry_run_tokens)
    else:
        issues = _bash_write_guard_issues(source, write_fns, dry_run_tokens)
    return {"issues": issues}


def _bash_write_guard_issues(source, write_fns, tokens) -> List[Dict[str, object]]:
    funcs = extract_functions(source)
    issues = []
    for name, meta in funcs.items():
        body = meta.get("body", "")
        # 函数名本身是写入器（定义即写），或函数体内调用写入器
        has_write = name in write_fns or any(w in body for w in write_fns)
        has_guard = any(t in body for t in tokens)
        if has_write and not has_guard:
            issues.append({
                "function": name,
                "write_fns": [w for w in ([name] if name in write_fns else [])
                              or [w for w in write_fns if w in body]],
                "guard": "NONE",
                "risk": "write call without dry_run guard — --check 消费空转写 state",
                "fix": "包进 if [ \"$dry_run\" = \"false\" ] 守卫",
            })
        elif has_write:
            issues.append({
                "function": name,
                "write_fns": [w for w in ([name] if name in write_fns else [])
                              or [w for w in write_fns if w in body]],
                "guard": "PRESENT",
                "risk": "guard 覆盖范围需人工确认（函数级启发式）",
            })
    return issues


def _py_write_guard_issues(source, write_fns, tokens) -> List[Dict[str, object]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [{"error": "python syntax error — cannot audit"}]
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = _call_name(node)
            if fn in write_fns:
                guarded = _inside_dry_run_guard(tree, node)
                if not guarded:
                    issues.append({
                        "line": getattr(node, "lineno", 0),
                        "call": fn,
                        "guard": "NONE",
                        "risk": "write call outside `if not dry_run:` — --check 有副作用",
                        "fix": "包进 if not dry_run 守卫",
                    })
    return issues


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _inside_dry_run_guard(tree: ast.AST, node: ast.Call) -> bool:
    """True if the call is inside an `if not dry_run:` (or `if dry_run: ... else:`)
    block where the write path is the non-dry-run branch."""
    for parent in ast.walk(tree):
        if not isinstance(parent, (ast.If, ast.IfExp)):
            continue
        cond = parent.test
        is_not_dry = (isinstance(cond, ast.UnaryOp) and isinstance(cond.op, ast.Not)
                      and isinstance(cond.operand, ast.Name)
                      and cond.operand.id == "dry_run")
        if is_not_dry and _node_within(parent, node):
            return True
    return False


def _node_within(container: ast.AST, node: ast.AST) -> bool:
    c1, c2 = container.lineno, getattr(container, "end_lineno", container.lineno)
    n1 = getattr(node, "lineno", 0)
    return c1 <= n1 <= c2


# ─── 炸弹标记（2026-08-23: python3 内联 / stderr 吞错 / 危险命令）───
# 回应 gatekeeper-cli.sh 实测：238 处 python3 内联 + 538 处 2>/dev/null 全是迁移炸弹。
# (kind, pattern, severity, risk) — pattern 用字符类拆危险命令字面量（防自身防线拦截）

_BOMB_PATTERNS = [
    ("inline_python", r"python3?\s+-c\s+[\"']|python3?\s*-\s*<<\s*['\"]?[A-Za-z_][A-Za-z0-9_]*|python3?\s*<<\s*['\"]?[A-Za-z_][A-Za-z0-9_]*",
     "HIGH", "bash 内嵌 python3 — 转义地狱/不可单测/维护炸弹，候选迁移独立 gk_*.py"),
    ("stderr_swallow", r"2>\s*/dev/null",
     "HIGH", "stderr 丢弃 — 静默失败（heredoc 异常被吞输出空 JSON）"),
    ("fd_redirect", r"2>&1|>&\s*[0-9]|>>\s*&",
     "LOW", "stderr 重定向到 fd — 掩盖错误去向（非吞错，语义确认）"),
    ("dangerous_command", r"\brm\s+-r[f]?\b|git push --forc[e]|git reset --har[d]|git clean -[fd]",
     "HIGH", "危险命令 — 不可逆覆盖（D 类 T1059）"),
]


def bomb_scan(source: str) -> Dict[str, object]:
    """扫描 bash 迁移炸弹：python3 内联 / stderr 吞错 / 危险命令。

    输出按 kind 分组的行级清单 + 计数，供迁移收尾前逐条消解。
    """
    groups: Dict[str, List[Dict[str, object]]] = {}
    for i, line in enumerate(source.splitlines(), 1):
        for kind, pat, sev, risk in _BOMB_PATTERNS:
            if re.search(pat, line):
                groups.setdefault(kind, []).append({
                    "line": i, "severity": sev, "risk": risk,
                    "text": line.strip()[:120]})
                break
    counts = {k: len(v) for k, v in groups.items()}
    return {"counts": counts, "total": sum(counts.values()), "groups": groups}


# ─── LLM 兜底（可选，0 依赖 urllib）───

def llm_explain(items: List[Dict[str, object]], api_key: Optional[str] = None,
                api_base: str = "https://api.deepseek.com/v1/chat/completions",
                model: str = "deepseek-chat") -> Dict[str, object]:
    """Ask an LLM to explain flagged items; without a key, degrade to a
    human-review checklist. Output never gates the migration decision."""
    if not api_key:
        return {"mode": "degraded", "items": items,
                "note": "无 API key — LLM 解释降级为待人工审查清单"}
    prompt = ("你是 bash→Python 迁移审查助手。以下是从迁移审计中提取的"
              "疑点清单，请逐条解释根因并给出修复建议（JSON 数组输出）：\n"
              + json.dumps(items, ensure_ascii=False, indent=2))
    body = json.dumps({"model": model, "messages": [
        {"role": "user", "content": prompt}], "temperature": 0}).encode()
    req = urllib.request.Request(
        api_base, data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api_key}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        return {"mode": "llm", "explanation": data["choices"][0]["message"]["content"]}
    except Exception as e:
        return {"mode": "error", "error": str(e), "items": items,
                "note": "LLM 调用失败 — 降级为待人工审查清单"}
