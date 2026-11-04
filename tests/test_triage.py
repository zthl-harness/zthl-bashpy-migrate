# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
"""triage 测试 — 分诊模型（advisory）的边界：不改判 / schema 强校验 / 预算 / 降级。

零网络：只 patch 模块边界 `triage._request`（R1 纪律）。
"""
import json

import pytest

from zthl_bashpy_migrate import triage as T


ITEMS = [{"item": "SC2086 @L12"}, {"item": "dead code: foo"}, {"item": "bomb @L44"}]


@pytest.fixture(autouse=True)
def _cache(tmp_path, monkeypatch):
    monkeypatch.setenv("BASHPY_TRIAGE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("BASHPY_TRIAGE_CACHE", raising=False)


def _resp(payload) -> dict:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return {"choices": [{"message": {"content": text}}]}


class TestDegrade:
    def test_no_key_returns_original_order(self):
        r = T.triage(ITEMS, api_key=None)
        assert r["mode"] == "degraded"
        assert r["advisory_only"] is True
        assert [x["index"] for x in r["items"]] == [0, 1, 2]
        assert all(x["verdict"] == "UNADJUDICATED" for x in r["items"])

    def test_empty_input(self):
        r = T.triage([], api_key="k")
        assert r["mode"] == "degraded" and r["items"] == []

    def test_network_failure_never_raises(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("net down")
        monkeypatch.setattr(T, "_request", boom)
        r = T.triage(ITEMS, api_key="k")
        assert r["mode"] == "error"
        assert [x["index"] for x in r["items"]] == [0, 1, 2]
        assert "net down" in r["error"]

    def test_all_invalid_payload_is_error(self, monkeypatch):
        monkeypatch.setattr(T, "_request", lambda *a, **k: _resp([{"index": 0, "verdict": "???"}]))
        r = T.triage(ITEMS, api_key="k")
        assert r["mode"] == "error"


class TestSchema:
    def test_valid_payload_is_ordered_fix_first(self, monkeypatch):
        monkeypatch.setattr(T, "_request", lambda *a, **k: _resp([
            {"index": 2, "verdict": "IGNORE", "confidence": 0.9, "reason": "误报"},
            {"index": 1, "verdict": "FIX", "confidence": 0.8, "reason": "真死代码"},
            {"index": 0, "verdict": "REVIEW", "confidence": 0.6, "reason": "需判断"},
        ]))
        r = T.triage(ITEMS, api_key="k")
        assert r["mode"] == "triage" and r["dropped"] == 0
        assert [x["verdict"] for x in r["items"]] == ["FIX", "REVIEW", "IGNORE"]

    def test_invalid_entries_dropped_not_guessed(self, monkeypatch):
        monkeypatch.setattr(T, "_request", lambda *a, **k: _resp([
            {"index": 0, "verdict": "FIX", "confidence": 1.7, "reason": "越界置信度"},
            {"index": 99, "verdict": "FIX", "confidence": 0.5, "reason": "越界下标"},
            {"index": 1, "verdict": "FIX", "confidence": 0.5, "reason": ""},
            {"index": 2, "verdict": "IGNORE", "confidence": 0.4, "reason": "无害"},
        ]))
        r = T.triage(ITEMS, api_key="k")
        assert r["mode"] == "triage"
        assert r["dropped"] == 3
        assert [x["index"] for x in r["items"] if x["verdict"] != "UNADJUDICATED"] == [2]

    def test_unmentioned_items_appended_as_unadjudicated(self, monkeypatch):
        monkeypatch.setattr(T, "_request", lambda *a, **k: _resp([
            {"index": 0, "verdict": "FIX", "confidence": 0.9, "reason": "x"},
        ]))
        r = T.triage(ITEMS, api_key="k")
        kinds = [x["verdict"] for x in r["items"]]
        assert kinds == ["FIX", "UNADJUDICATED", "UNADJUDICATED"]

    def test_fence_is_stripped(self, monkeypatch):
        body = "```json\n" + json.dumps([
            {"index": 0, "verdict": "FIX", "confidence": 0.9, "reason": "x"}]) + "\n```"
        monkeypatch.setattr(T, "_request", lambda *a, **k: _resp(body))
        assert T.triage(ITEMS, api_key="k")["mode"] == "triage"

    def test_duplicate_index_keeps_highest_confidence(self):
        good, dropped = T.validate([
            {"index": 0, "verdict": "FIX", "confidence": 0.2, "reason": "a"},
            {"index": 0, "verdict": "IGNORE", "confidence": 0.9, "reason": "b"},
        ], 1)
        assert len(good) == 1 and good[0]["verdict"] == "IGNORE" and dropped == 1


class TestBudgetAndRetry:
    def test_truncates_to_max_items(self, monkeypatch):
        monkeypatch.setattr(T, "_request", lambda *a, **k: _resp([
            {"index": 0, "verdict": "FIX", "confidence": 0.9, "reason": "x"}]))
        r = T.triage(ITEMS, api_key="k", max_items=1)
        assert r["truncated"] == 2
        assert len(r["items"]) == 1

    def test_one_retry_then_success(self, monkeypatch):
        calls = {"n": 0}

        def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("transient")
            return _resp([{"index": 0, "verdict": "FIX", "confidence": 0.9, "reason": "x"}])
        monkeypatch.setattr(T, "_request", flaky)
        r = T.triage(ITEMS, api_key="k")
        assert r["mode"] == "triage" and calls["n"] == 2

    def test_budget_reported(self, monkeypatch):
        monkeypatch.setattr(T, "_request", lambda *a, **k: _resp([
            {"index": 0, "verdict": "FIX", "confidence": 0.9, "reason": "x"}]))
        r = T.triage(ITEMS, api_key="k", max_items=10, max_tokens=128, timeout=7)
        assert r["budget"] == {"max_items": 10, "max_tokens": 128,
                               "timeout_s": 7, "retries": T.MAX_RETRIES}


class TestCache:
    def test_second_call_hits_cache(self, monkeypatch):
        monkeypatch.setattr(T, "_request", lambda *a, **k: _resp([
            {"index": 0, "verdict": "FIX", "confidence": 0.9, "reason": "x"}]))
        assert T.triage(ITEMS, api_key="k")["cache"] == "miss"

        def boom(*a, **k):
            raise AssertionError("不应再发请求（应命中缓存）")
        monkeypatch.setattr(T, "_request", boom)
        r = T.triage(ITEMS, api_key="k")
        assert r["mode"] == "triage" and r["cache"] == "hit"

    def test_cache_can_be_disabled(self, monkeypatch):
        monkeypatch.setenv("BASHPY_TRIAGE_CACHE", "0")
        monkeypatch.setattr(T, "_request", lambda *a, **k: _resp([
            {"index": 0, "verdict": "FIX", "confidence": 0.9, "reason": "x"}]))
        assert T.triage(ITEMS, api_key="k")["cache"] == "miss"
        assert T.triage(ITEMS, api_key="k")["cache"] == "miss"


class TestCliWiring:
    def test_triage_flag_added(self):
        from zthl_bashpy_migrate.cli import build_parser
        ns = build_parser().parse_args(["audit", "--script", "x.sh", "--triage"])
        assert ns.triage is True

    def test_advisory_never_changes_exit_code(self, monkeypatch, tmp_path, capsys):
        """分诊失败也不得让 audit 变红（这是 advisory 的定义）。"""
        from zthl_bashpy_migrate import cli
        src = tmp_path / "x.sh"
        src.write_text("#!/bin/bash\nrm -rf /tmp/zzz\n", encoding="utf-8")
        monkeypatch.setattr(T, "_request", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
        rc = cli.main(["audit", "--script", str(src), "--bomb", "--triage", "--api-key", "k"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["triage"]["advisory_only"] is True
        assert out["triage"]["mode"] in ("degraded", "error")
