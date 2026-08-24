# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""verify.py — L2: semantic-equivalence verification (deterministic, 0 API).

Core idea (Phase 7f 收敛设计, 2026-08-23):
  - Migrations happen while BOTH bash and Python versions exist.
  - Freeze the bash output as a *snapshot baseline* before replacement,
    then continuously verify the Python output against it.
  - Contract-improvement whitelist: bash bugs fixed in the port (e.g. the
    duplicated-key `doc_changes` bug) are registered, not flagged as diffs.

Lessons mapped:
  - bash 字符串拼接 JSON 产生非法输出 → 语义等价 = json.loads 递归比较（非字符串 diff）
  - dry_run 零副作用契约 → --check 前后 state hash 比对
"""
import hashlib
import json
import subprocess
from typing import Dict, List, Optional


# ─── JSON 语义等价 diff ───

def loads_json(text: str) -> object:
    """Parse JSON text (tolerant: strip trailing garbage lines)."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # some CLIs print multiple JSON lines; keep the LAST parseable line
        for line in reversed(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
        raise


def deep_diff(a: object, b: object, path: str = "$") -> List[Dict[str, object]]:
    """Recursive semantic diff. Returns [] when semantically equivalent."""
    diffs: List[Dict[str, object]] = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in a.keys() - b.keys():
            diffs.append({"path": f"{path}.{k}", "kind": "missing_key",
                          "expected": a[k], "actual": None})
        for k in b.keys() - a.keys():
            diffs.append({"path": f"{path}.{k}", "kind": "extra_key",
                          "expected": None, "actual": b[k]})
        for k in a.keys() & b.keys():
            diffs.extend(deep_diff(a[k], b[k], f"{path}.{k}"))
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            diffs.append({"path": path, "kind": "length_mismatch",
                          "expected": len(a), "actual": len(b)})
        for i, (x, y) in enumerate(zip(a, b)):
            diffs.extend(deep_diff(x, y, f"{path}[{i}]"))
    elif type(a) is not type(b):
        diffs.append({"path": path, "kind": "type_mismatch",
                      "expected": a, "actual": b})
    else:
        if a != b:
            diffs.append({"path": path, "kind": "value_mismatch",
                          "expected": a, "actual": b})
    return diffs


# ─── 契约改进白名单 ───

def load_whitelist(path: str) -> List[Dict[str, str]]:
    """Whitelist config: {"diffs": [{"path": "...", "reason": "..."}, ...]}."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("diffs", []) if isinstance(data, dict) else []
    except (OSError, json.JSONDecodeError):
        return []


def verify(baseline: object, output: object,
           whitelist: Optional[List[Dict[str, str]]] = None) -> Dict[str, object]:
    """Compare output against baseline; separate whitelisted from blocked diffs.

    Whitelist entries match by diff `path` (exact) or by glob-ish prefix
    (trailing `*`). A whitelisted path is *removed* from consideration, so a
    single whitelist entry can cover an entire subtree.
    """
    diffs = deep_diff(baseline, output)
    whitelist = whitelist or []
    blocked: List[Dict[str, object]] = []
    whitelisted: List[Dict[str, object]] = []
    for d in diffs:
        p = str(d.get("path", ""))
        hit = None
        for w in whitelist:
            wp = w.get("path", "")
            if wp.endswith("*") and p.startswith(wp[:-1]):
                hit = w
                break
            if wp == p:
                hit = w
                break
        if hit:
            d = dict(d)
            d["whitelist_reason"] = hit.get("reason", "")
            whitelisted.append(d)
        else:
            blocked.append(d)
    return {
        "equivalent": not blocked,
        "diff_count": len(diffs),
        "blocked": blocked,
        "whitelisted": whitelisted,
    }


# ─── dry_run 零副作用检查 ───

def file_sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


def dry_run_check(run_cmd: List[str], state_file: str,
                  timeout: int = 60) -> Dict[str, object]:
    """Run `run_cmd` (e.g. `bash ... advance STAGE_1 --check`) and assert the
    state file is unchanged — the zero-side-effect contract for --check."""
    before = file_sha256(state_file)
    p = subprocess.run(run_cmd, capture_output=True, text=True, timeout=timeout)
    after = file_sha256(state_file)
    return {
        "returncode": p.returncode,
        "state_unchanged": before == after,
        "sha_before": before,
        "sha_after": after,
        "stdout_tail": p.stdout.strip().splitlines()[-1:] if p.stdout else [],
        "stderr_tail": p.stderr.strip().splitlines()[-3:] if p.stderr else [],
    }


# ─── 固化快照 ───

def capture_baseline(run_cmd: List[str], out_file: str,
                     timeout: int = 60) -> Dict[str, object]:
    """Run the bash-side command and freeze its output as a snapshot baseline."""
    p = subprocess.run(run_cmd, capture_output=True, text=True, timeout=timeout)
    with open(out_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(p.stdout)
    return {
        "returncode": p.returncode,
        "baseline_file": out_file,
        "bytes": len(p.stdout),
        "stderr_tail": p.stderr.strip().splitlines()[-3:] if p.stderr else [],
    }
