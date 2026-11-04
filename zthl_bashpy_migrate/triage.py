# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""triage.py — 分诊模型（advisory only，2026-11-04）。

定位（用户裁定「实现分诊模型（advisory）」）：
  **只影响"先看哪条"，不影响任何判定**。确定性核心（dead_code / write_guard /
  shellcheck / bomb_scan / py_lint）出的是**唯一判据**；模型输出只是排序与分组建议，
  永不改 verdict、永不改 exit code、永不让 audit 变红。

四道边界（缺一不可）：
  ① **不改判**：返回结构里 `advisory_only: True`；调用方只能用它排序。
  ② **schema 强校验**：`verdict ∈ {FIX,REVIEW,IGNORE}`、`confidence ∈ [0,1]`、
     `reason` 非空字符串、`index` 在范围内 —— 任一不合规即丢弃（记 `dropped`），
     不做"猜它想说啥"的修补。
  ③ **预算**：`max_items`（截断输入并报告 `truncated`）、`max_tokens`、`timeout_s`、
     重试上限 1 次。超预算即降级，不无限重试。
  ④ **失败降级**：无 key / 网络失败 / 非 JSON / 全丢光 ⟹ `mode ∈ {degraded, error}`，
     返回**原顺序**清单，绝不抛异常。

可复现：`temperature=0` + `PROMPT_VERSION` + 模型名三者进入缓存键；命中缓存直接返回，
同一输入不重复计费（`BASHPY_TRIAGE_CACHE=0` 可关闭，`BASHPY_TRIAGE_CACHE_DIR` 可改路径）。
"""
import hashlib
import json
import os
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROMPT_VERSION = "triage/v1"
VERDICTS = ("FIX", "REVIEW", "IGNORE")
_PRIORITY = {"FIX": 0, "REVIEW": 1, "IGNORE": 2}
DEFAULT_BASE = "https://api.deepseek.com/v1/chat/completions"
DEFAULT_MODEL = "deepseek-chat"
DEFAULT_MAX_ITEMS = 50
DEFAULT_MAX_TOKENS = 512
DEFAULT_TIMEOUT = 20
MAX_RETRIES = 1


# ── 预算 / 缓存 ────────────────────────────────────────────────────────────
def _cache_dir() -> Path:
    return Path(os.environ.get("BASHPY_TRIAGE_CACHE_DIR",
                              str(Path.home() / ".cache" / "bashpy-triage")))


def cache_key(items: List[dict], model: str) -> str:
    """缓存键 = prompt 版本 + 模型 + 归一后的 items（顺序敏感）。"""
    raw = json.dumps({"v": PROMPT_VERSION, "model": model, "items": items},
                     ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _cache_get(key: str) -> Optional[dict]:
    if os.environ.get("BASHPY_TRIAGE_CACHE", "1") == "0":
        return None
    try:
        p = _cache_dir() / (key + ".json")
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001 — 缓存损坏不得影响主流程
        return None
    return None


def _cache_put(key: str, value: dict) -> None:
    if os.environ.get("BASHPY_TRIAGE_CACHE", "1") == "0":
        return
    try:
        d = _cache_dir()
        d.mkdir(parents=True, exist_ok=True)
        (d / (key + ".json")).write_text(json.dumps(value, ensure_ascii=False),
                                        encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass


# ── 网络（模块级 = 测试注入点）─────────────────────────────────────────────
def _request(url: str, body: bytes, timeout: int) -> dict:
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + os.environ.get("_BASHPY_TRIAGE_KEY", "")})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ── prompt / 解析 ──────────────────────────────────────────────────────────
def build_prompt(items: List[dict]) -> str:
    return (
        "你是 bash→Python 迁移审计的**分诊助手**。下面是从确定性审计里提取的疑点清单。\n"
        "任务：给每条一个处置建议，只用于排序，**不要**改变任何既有判定。\n"
        "只输出 JSON 数组，不要解释文字。每个元素字段固定：\n"
        '  {"index": <输入下标>, "verdict": "FIX"|"REVIEW"|"IGNORE", '
        '"confidence": <0..1>, "reason": "<不超过 60 字>"}\n'
        "verdict 含义：FIX=确定要改；REVIEW=需人工判断；IGNORE=可忽略（误报/无害）。\n"
        "清单：\n" + json.dumps(items, ensure_ascii=False, indent=2)
    )


def _strip_fence(text: str) -> str:
    t = (text or "").strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        t = "\n".join(lines).strip()
    return t


def validate(raw, n_items: int) -> Tuple[List[dict], int]:
    """schema 强校验 → (合规项, 丢弃数)。不合规一律丢，不修补。"""
    if not isinstance(raw, list):
        return [], -1                      # -1 = 整体不可解析（调用方按降级处理）
    good, dropped = [], 0
    for it in raw:
        if not isinstance(it, dict):
            dropped += 1
            continue
        idx = it.get("index")
        verdict = str(it.get("verdict") or "").upper()
        conf = it.get("confidence")
        reason = it.get("reason")
        if (not isinstance(idx, int) or isinstance(idx, bool) or not (0 <= idx < n_items)
                or verdict not in VERDICTS
                or not isinstance(conf, (int, float)) or isinstance(conf, bool)
                or not (0.0 <= float(conf) <= 1.0)
                or not isinstance(reason, str) or not reason.strip()):
            dropped += 1
            continue
        good.append({"index": idx, "verdict": verdict,
                     "confidence": float(conf), "reason": reason.strip()})
    # 同 index 多次出现：保留置信度最高的一条（确定性）
    best: Dict[int, dict] = {}
    for g in good:
        cur = best.get(g["index"])
        if cur is None or g["confidence"] > cur["confidence"]:
            best[g["index"]] = g
    dropped += len(good) - len(best)
    return sorted(best.values(), key=lambda g: g["index"]), dropped


# ── 主入口 ────────────────────────────────────────────────────────────────
def triage(items: List[dict], api_key: Optional[str] = None,
           api_base: str = DEFAULT_BASE, model: str = DEFAULT_MODEL,
           max_items: int = DEFAULT_MAX_ITEMS, max_tokens: int = DEFAULT_MAX_TOKENS,
           timeout: int = DEFAULT_TIMEOUT) -> dict:
    """分诊（advisory）。**永不抛异常**，失败一律降级为原顺序清单。"""
    items = [it for it in (items or []) if isinstance(it, dict)]
    head = items[:max_items]
    truncated = len(items) - len(head)
    budget = {"max_items": max_items, "max_tokens": max_tokens,
              "timeout_s": timeout, "retries": MAX_RETRIES}
    base = {"advisory_only": True, "model": model, "prompt_version": PROMPT_VERSION,
            "budget": budget, "truncated": truncated,
            "note": "advisory only：只用于排序，不参与任何判定 / exit code"}

    if not head:
        return dict(base, mode="degraded", dropped=0, items=[],
                    note="空清单 —— 无分诊输入")
    if not api_key:
        return dict(base, mode="degraded", dropped=0,
                    items=_unjudged(head, "无 API key"),
                    note="无 API key — 分诊降级为原顺序清单（判定不受影响）")

    key = cache_key(head, model)
    cached = _cache_get(key)
    if cached is not None:
        return dict(base, mode="triage", cache="hit",
                    dropped=cached.get("dropped", 0), items=cached.get("items", []))

    body = json.dumps({"model": model, "temperature": 0,
                       "max_tokens": max_tokens,
                       "messages": [{"role": "user", "content": build_prompt(head)}]}).encode()
    os.environ["_BASHPY_TRIAGE_KEY"] = api_key        # 仅进程内，避免进日志/参数
    last_err = ""
    try:
        for attempt in range(MAX_RETRIES + 1):
            try:
                data = _request(api_base, body, timeout)
                text = data["choices"][0]["message"]["content"]
                good, dropped = validate(json.loads(_strip_fence(text)), len(head))
                if dropped < 0:
                    last_err = "模型输出不是 JSON 数组"
                    continue
                if not good:
                    last_err = "模型输出无一条通过 schema 校验"
                    continue
                ordered = _order(head, good)
                _cache_put(key, {"items": ordered, "dropped": dropped})
                return dict(base, mode="triage", cache="miss",
                            dropped=dropped, items=ordered)
            except Exception as e:  # noqa: BLE001 — 单次失败不终止，按重试预算
                last_err = "%s: %s" % (type(e).__name__, e)
        return dict(base, mode="error", dropped=0,
                    items=_unjudged(head, "分诊失败"),
                    error=last_err)
    finally:
        os.environ.pop("_BASHPY_TRIAGE_KEY", None)


def _unjudged(head: List[dict], reason: str) -> List[dict]:
    """降级清单：与分诊成功路径**同构**（省得调用方写两套分支）。"""
    return [{"index": i, "verdict": "UNADJUDICATED", "confidence": 0.0,
             "reason": reason, "item": it} for i, it in enumerate(head)]


def _order(head: List[dict], good: List[dict]) -> List[dict]:
    """按 verdict 优先级 + 置信度降序排；**未被模型提及的条目保持原相对顺序排在末尾**。"""
    by_idx = {g["index"]: g for g in good}
    ranked = sorted(good, key=lambda g: (_PRIORITY[g["verdict"]], -g["confidence"], g["index"]))
    out = [{"index": g["index"], "verdict": g["verdict"],
            "confidence": g["confidence"], "reason": g["reason"],
            "item": head[g["index"]]} for g in ranked]
    for i, it in enumerate(head):
        if i not in by_idx:
            out.append({"index": i, "verdict": "UNADJUDICATED",
                        "confidence": 0.0, "reason": "模型未给出建议", "item": it})
    return out
