# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

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
# (kind, pattern, severity, risk, fix) — pattern 用字符类拆危险命令字面量（防自身防线拦截）
# fix = zizmor 式修复建议（2026-08-25: 检测 + 分级 + 修复方法三件套）

_BOMB_PATTERNS = [
    ("inline_python", r"python3?\s+-c\s+[\"']|python3?\s*-\s*<<\s*['\"]?[A-Za-z_][A-Za-z0-9_]*|python3?\s*<<\s*['\"]?[A-Za-z_][A-Za-z0-9_]*",
     "HIGH", "bash 内嵌 python3 — 转义地狱/不可单测/维护炸弹，候选迁移独立 gk_*.py",
     "迁移为独立 scripts/gk_*.py（复用 17 脚本模式：函数化 + 带测试 + self-check 门禁）"),
    ("stderr_swallow", r"2>\s*/dev/null",
     "HIGH", "stderr 丢弃 — 静默失败（heredoc 异常被吞输出空 JSON）",
     "关键路径改 2>>\"$GK_DBG_LOG\" 保留错误线索；非关键路径保留但需显式 || echo 兜底"),
    ("fd_redirect", r"2>&1|>&\s*[0-9]|>>\s*&",
     "LOW", "stderr 重定向到 fd — 掩盖错误去向（非吞错，语义确认）",
     "语义确认即可；若掩盖错误去向，改显式落日志（2>>\"$GK_DBG_LOG\"）"),
    ("dangerous_command", r"\brm\s+-r[f]?\b|git push --forc[e]|git reset --har[d]|git clean -[fd]",
     "HIGH", "危险命令 — 不可逆覆盖（D 类 T1059）",
     "改用 --force-with-lease / 加 $_tmp 变量形态豁免 + 人工确认（对齐 Gate R0.2 修复建议）"),
    # 2026-08-25: 大小写敏感字符串比较（业界语法最佳实践，shellcheck 对齐），拆两类：
    #   1. case_sensitive       — camelCase 字面量（True/False/None）＝ 生成方值耦合（python bool repr）
    #   2. case_sensitive_const — ALL_CAPS 字面量（APPROVED/环境变量名）＝ 常量/名称，大小写是语义一部分
    # 两类修复方法不同：值耦合适合 ${var,,} 归一化；名称/常量归一化会破坏比较。
    ("case_sensitive",
     r"\"?\$[A-Za-z_][A-Za-z0-9_]*\"?\s*(?:==|=|!=)\s*\"[A-Z][a-z][A-Za-z0-9_]*\"",
     "LOW", "大小写敏感值比较 — 与生成方字面量强耦合（如 = \"False\" 依赖 python bool repr 大写，上游改小写即静默失效）",
     "用 [[ \"${var,,}\" = \"literal\" ]] 归一化比较（bash4+），或 case \"$var\" in [Ff]alse) 分支；"
     "建议生成方统一小写输出（bool 用 0/1 或 true/false）"),
    ("case_sensitive_const",
     r"\"?\$[A-Za-z_][A-Za-z0-9_]*\"?\s*(?:==|=|!=)\s*\"[A-Z][A-Z0-9_]*\"",
     "LOW", "常量/环境变量名大小写比较 — 名称区分大小写，对名称做 ${var,,} 归一化会破坏匹配",
     "先确认比较对象是环境变量名（保留精确匹配）还是生成方值（用 [[ \"${var,,}\" = ... ]] 归一化）；"
     "名称集合用 case \"$var\" in DEEPSEEK_API_KEY|OPENAI_API_KEY) 显式列出合法分支"),
]


def bomb_scan(source: str) -> Dict[str, object]:
    """扫描 bash 迁移炸弹：python3 内联 / stderr 吞错 / 危险命令 / 大小写敏感比较。

    输出按 kind 分组的行级清单 + 计数，供迁移收尾前逐条消解。
    每条 finding 带 severity + risk + **fix**（zizmor 式：检测 → 分级 → 修复方法）。
    """
    groups: Dict[str, List[Dict[str, object]]] = {}
    for i, line in enumerate(source.splitlines(), 1):
        for kind, pat, sev, risk, fix in _BOMB_PATTERNS:
            if re.search(pat, line):
                groups.setdefault(kind, []).append({
                    "line": i, "severity": sev, "risk": risk, "fix": fix,
                    "text": line.strip()[:120]})
                break
    counts = {k: len(v) for k, v in groups.items()}
    return {"counts": counts, "total": sum(counts.values()), "groups": groups}


# ─── shellcheck TOP 规则原生移植（2026-08-26，zizmor 式自包含）───
# 对齐 gatekeeper L3.5 dead_code_gate1 + l5_blind_spot 的确定性实现：
# 替代外部 shellcheck binary 依赖（外部 shellcheck 降级为可选增强，未装不参与门禁）。
# 子集 = 迁移场景 TOP 4：sc2164（cd 失败无处理）/ sc2181（$? 反模式）/
#         sc2086（裸变量展开）/ sc2034（未使用变量，常量契约豁免）。
# (kind, pattern, severity, risk, fix) — 单行级可确定性判定的规则走正则表；
# 需要引号状态/全文件作用域的（sc2086/sc2034）走专用函数。

_SC_SINGLE_RULES = [
    ("sc2164_cd_fail", r"^\s*cd\s+\S+\s*$",
     "LOW", "SC2164 — cd 失败无错误处理，后续命令在错误目录执行",
     "cd \"$dir\" || { echo \"cd failed: $dir\" >&2; return 1; }"),
    ("sc2181_test_dollar", r"\[[^]]*\$\?[^]]*\]",
     "LOW", "SC2181 — 用 $? 反模式测试命令结果（掩盖真实退出码来源，易受中间命令干扰）",
     "直接 if cmd; then 判断，或 command || handle_failure；勿写 if [ $? -ne 0 ]"),
]

# sc2034 豁免：全大写/下划线开头 = 常量/契约；META_ 前缀 = 文档契约（死代码教训 R5.5：
# case 分支变量与 constants 区是初始化默认值/输出契约，不是死代码，禁止报）
_SC_2034_EXEMPT = re.compile(r"^(?:[A-Z_][A-Z0-9_]*|META_[a-zA-Z0-9_]*)$")
_SC_2034_DEF = re.compile(
    r"^\s*(?:local\s+|readonly\s+|declare\s+-[a-zA-Z]*\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*=")


def _skip_cmd_subst(line: str, j: int, n: int) -> int:
    """跳过 `$(` 命令替换直到匹配 `)`（独立引号上下文，嵌套 `$(` 计数）。
    命令替换内的引号不影响外层引号状态（`"$(basename "$b")"` 的内层 `"` 不得关闭外层）。"""
    depth = 1
    s = d = False
    j += 2  # 跳过 $(
    while j < n:
        c = line[j]
        if c == "'" and not d:
            s = not s
        elif c == '"' and not s:
            d = not d
        elif c == "\\" and not s:
            j += 1
        elif not s and not d:
            if c == "(" and j > 0 and line[j - 1] == "$":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return j + 1
        j += 1
    return n


def _sc2086_unquoted_issues(lines: List[str]) -> List[Dict[str, object]]:
    """SC2086 — 裸变量展开。行级引号状态扫描：`$var` 不在引号内/花括号/命令替换内 → 命中。
    `$@`/`$1`/`$((...))` 天然不匹配（`[A-Za-z_]` 不接 `(`/数字）。
    保守：花括号 `${var}` 场景漏报（避免 `${var,,}` 误报，大小写另有 case_sensitive 规则）。"""
    issues = []
    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        j, n = 0, len(line)
        in_s = in_d = False
        while j < n:
            c = line[j]
            if c == "'" and not in_d:
                in_s = not in_s
                j += 1
                continue
            if c == '"' and not in_s:
                in_d = not in_d
                j += 1
                continue
            if c == "\\":  # 转义（含 \$, \", \'）跳过下一字符
                j += 2
                continue
            if c == "$":
                nxt = line[j + 1] if j + 1 < n else ""
                if nxt == "(" and not in_s:
                    # $(...) 命令替换 — 独立引号上下文整体跳过（双引号内的 $() 同样跳过）
                    j = _skip_cmd_subst(line, j, n)
                    continue
                if not in_s and not in_d:
                    if nxt == "{":  # ${...} 参数展开 — 保守跳过整块
                        close = line.find("}", j + 2)
                        j = (close + 1) if close != -1 else n
                        continue
                    m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", line[j + 1:])
                    if m:
                        issues.append({"line": i, "col": j + 1, "var": m.group(0),
                                       "text": line.strip()[:120],
                                       "fix": "加双引号 \"${var}\"，或确认词分割是有意为之"})
                        j += 1 + len(m.group(0))
                        continue
            j += 1
    return issues


def _sc2034_unused_issues(lines: List[str]) -> List[Dict[str, object]]:
    """SC2034 — 未使用变量（保守版）。只报小写/驼峰赋值名且过滤后行内引用 ≤ 定义次数。
    全大写常量/export/readonly 豁免（外部契约）。"""
    text = "\n".join(lines)
    defs = []  # [(line_no, name)]
    for i, line in enumerate(lines, 1):
        s = line.lstrip()
        if s.startswith("#"):
            continue
        m = _SC_2034_DEF.match(s)
        if not m:
            continue
        name = m.group(1)
        if _SC_2034_EXEMPT.match(name):
            continue
        if "export" in s or "readonly" in s:
            continue
        defs.append((i, name))
    issues = []
    for i, name in defs:
        pat = re.compile(r"\$\{" + re.escape(name) + r"\}|\$" + re.escape(name)
                         + r"\b|\b" + re.escape(name) + r"\s*=")
        refs = len(pat.findall(text))
        if refs <= sum(1 for _, n in defs if n == name):
            issues.append({"line": i, "var": name, "text": lines[i - 1].strip()[:120],
                           "fix": "删除该变量，或显式声明其为输出契约（如 export/返回值使用）"})
    return issues


def _python_inline_skip(lines: List[str]) -> set:
    """收集 python 内联行号集合（python3 -c 行 + heredoc 内容区间）。

    bash 语法检测应跳过 python 内容（shellcheck 同理不扫 heredoc/内联 python
    —— 这是 python 迁移炸弹，归 bomb_scan.inline_python 管，不属于 shellcheck 语义）。
    覆盖：单行 `python3 -c '...'` / 多行 `python3 -c "` 跨行字符串 / `<<TAG` heredoc 内容。
    """
    skip = set()
    in_heredoc = False
    heredoc_tag = ""
    in_py_c = False
    py_c_quote = ""
    for i, line in enumerate(lines, 1):
        if in_heredoc:
            skip.add(i)
            if line.strip() == heredoc_tag:
                in_heredoc = False
            continue
        if in_py_c:
            skip.add(i)
            # 闭合：行内含未转义 quote 且位于收尾位置（行尾 / ) | > ; && || 后）
            j = 0
            while j < len(line):
                if line[j] == "\\":
                    j += 2
                    continue
                if line[j] == py_c_quote:
                    rest = line[j + 1:].strip()
                    if not rest or rest.startswith((")", "|", ">", "2>", ";", "&&", "||")):
                        in_py_c = False
                        break
                j += 1
            continue
        if re.search(r"python3?\s+-c\s+[\"']", line):
            skip.add(i)
            m = re.search(r"python3?\s+-c\s+([\"'])", line)
            if m:
                q = m.group(1)
                if q not in line[m.end():]:  # 引号未同行闭合 → 多行 -c 字符串
                    in_py_c = True
                    py_c_quote = q
            continue
        if re.search(r"python3?\s*-\s*<<\s*['\"]?[A-Za-z_][A-Za-z0-9_]*|python3?\s*<<\s*['\"]?[A-Za-z_][A-Za-z0-9_]*", line):
            skip.add(i)
            m = re.search(r"<<\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
            if m:
                heredoc_tag = m.group(1)
                in_heredoc = True
    return skip


def shellcheck_scan(source: str) -> Dict[str, object]:
    """shellcheck TOP 规则原生移植（检测 → 分级 → fix 三件套）。

    输出按 kind 分组的行级清单 + 计数，供 dead_code_gate1 / l5_blind_spot
    确定性消费。每条 finding 带 severity + risk + fix（zizmor 模式）。
    python 内联/heredoc 内容跳过（归 bomb_scan.inline_python 管，shellcheck 语义不扫）。
    """
    lines = source.splitlines()
    skip = _python_inline_skip(lines)
    filtered = [ln for k, ln in enumerate(lines, 1) if k not in skip]
    groups: Dict[str, List[Dict[str, object]]] = {}
    for i, line in enumerate(lines, 1):
        if i in skip or line.lstrip().startswith("#"):
            continue
        for kind, pat, sev, risk, fix in _SC_SINGLE_RULES:
            if re.search(pat, line):
                groups.setdefault(kind, []).append({
                    "line": i, "severity": sev, "risk": risk, "fix": fix,
                    "text": line.strip()[:120]})
    for item in _sc2086_unquoted_issues(filtered):
        groups.setdefault("sc2086_unquoted", []).append(
            {"severity": "LOW", "risk": "SC2086 — 裸变量展开（未引号）→ 词分割/通配符展开意外",
             **item, "line": _offset_line(skip, item["line"])})
    for item in _sc2034_unused_issues(filtered):
        groups.setdefault("sc2034_unused", []).append(
            {"severity": "LOW", "risk": "SC2034 — 未使用变量（潜在绕过面/死代码）", **item,
             "line": _offset_line(skip, item["line"])})
    counts = {k: len(v) for k, v in groups.items()}
    return {"counts": counts, "total": sum(counts.values()), "groups": groups}


def _offset_line(skip: set, relative_line: int) -> int:
    """把过滤后行号映射回原文件行号（跳过集合按升序）。"""
    orig = 0
    count = 0
    while count < relative_line:
        orig += 1
        if orig not in skip:
            count += 1
    return orig


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
