# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""cli.py — bashpy-migrate command line entry.

Subcommands:
  analyze   L1: bash 函数依赖图 / 副作用清单 / 迁移边界建议
  verify    L2: 语义等价（baseline 固化快照 / output 对比 / dry-run 零副作用）
  audit     L3: 死代码三关 + 写入守卫审查 + LLM 兜底（可选）
"""
import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .analyze import analyze as l1_analyze
from .audit import (bomb_scan, dead_code, llm_explain, python_module_deadcode,
                    shellcheck_scan, write_guard_check)
from .verify import (capture_baseline, dry_run_check, loads_json, verify)


def _emit(obj: dict) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def _cmd_analyze(args) -> int:
    with open(args.script, encoding="utf-8", errors="replace") as f:
        src = f.read()
    report = l1_analyze(src)
    _emit(report)
    return 0


def _cmd_verify(args) -> int:
    if args.baseline_capture:
        result = capture_baseline(_split_cmd(args.cmd), args.out)
        _emit(result)
        return 0
    if args.dry_run:
        result = dry_run_check(_split_cmd(args.cmd), args.state)
        _emit(result)
        return 0 if result["state_unchanged"] else 1
    # semantic equivalence: baseline vs output
    with open(args.baseline, encoding="utf-8", errors="replace") as f:
        baseline = loads_json(f.read())
    with open(args.output, encoding="utf-8", errors="replace") as f:
        output = loads_json(f.read())
    whitelist = None
    if args.whitelist:
        from .verify import load_whitelist
        whitelist = load_whitelist(args.whitelist)
    result = verify(baseline, output, whitelist)
    _emit(result)
    return 0 if result["equivalent"] else 1


def _cmd_audit(args) -> int:
    with open(args.script, encoding="utf-8", errors="replace") as f:
        src = f.read()
    report: dict = {}
    if args.dead_code:
        entries = [e.strip() for e in args.entry.split(",") if e.strip()]
        report["dead_code"] = dead_code(src, entries)
    if args.write_fns:
        fns = [e.strip() for e in args.write_fns.split(",") if e.strip()]
        report["write_guard"] = write_guard_check(src, fns)
    if args.bomb:
        report["bomb_scan"] = bomb_scan(src)
    if args.shellcheck:
        report["shellcheck_scan"] = shellcheck_scan(src)
    if args.py_deadcode:
        report["python_module_deadcode"] = python_module_deadcode(src)
    if args.explain and report:
        items: List[dict] = []
        for sec in report.values():
            if not isinstance(sec, dict):
                continue
            items.extend(sec.get("candidates", sec.get("issues", [])))
            for group in (sec.get("groups") or {}).values():
                items.extend(group)
        report["llm"] = llm_explain(items, args.api_key)
    _emit(report)
    return 0


def _split_cmd(cmd: str) -> List[str]:
    """Split a shell-ish command string into argv (shlex, no shell=True)."""
    import shlex
    return shlex.split(cmd)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bashpy-migrate",
        description="Deterministic bash → Python migration verification engine")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="L1: bash 函数结构/副作用/迁移边界")
    a.add_argument("--script", required=True, help="bash script path")
    a.set_defaults(func=_cmd_analyze)

    v = sub.add_parser("verify", help="L2: 语义等价 / 固化快照 / dry-run 零副作用")
    v.add_argument("--baseline-capture", action="store_true",
                   help="固化 bash 版快照: verify baseline --cmd ... --out ...")
    v.add_argument("--cmd", help="命令串（baseline-capture / dry-run 用）")
    v.add_argument("--out", help="基线输出文件")
    v.add_argument("--baseline", help="固化基线 JSON 文件")
    v.add_argument("--output", help="Python 版输出 JSON 文件")
    v.add_argument("--whitelist", help="契约改进白名单 JSON")
    v.add_argument("--dry-run", action="store_true",
                   help="dry_run 零副作用检查: verify --dry-run --cmd ... --state ...")
    v.add_argument("--state", help="state 文件（dry-run 检查前后 hash 对比）")
    v.set_defaults(func=_cmd_verify)

    au = sub.add_parser(
        "audit",
        help="L3: 死代码三关 + 写入守卫 + 炸弹标记 + shellcheck TOP 子集 + Python 模块级死代码 + LLM 兜底")
    au.add_argument("--script", required=True, help="bash 或 Python 源码路径")
    au.add_argument("--dead-code", action="store_true", help="跑死代码三关")
    au.add_argument("--entry", default="main", help="生产入口函数（逗号分隔）")
    au.add_argument("--write-fns", default="_state_write,_write_state",
                    help="写入函数名（逗号分隔）")
    au.add_argument("--bomb", action="store_true",
                    help="炸弹标记扫描（python3 内联 / stderr 吞错 / 危险命令）")
    au.add_argument("--shellcheck", action="store_true",
                    help="shellcheck TOP 子集扫描（sc2086/sc2164/sc2181/sc2034，零依赖确定性移植）")
    au.add_argument("--py-deadcode", action="store_true",
                    help="Python 模块级死代码扫描（AST 未使用 import/函数）")
    au.add_argument("--explain", action="store_true", help="LLM 解释（可选）")
    au.add_argument("--api-key", default=None, help="LLM API key（缺省降级人工审查）")
    au.set_defaults(func=_cmd_audit)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
