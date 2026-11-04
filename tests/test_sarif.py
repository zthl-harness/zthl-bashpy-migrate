# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""SARIF 2.1.0 输出回归（2026-11-04）。

判据：① 结构合法（schema/version/driver/results）；② 分级映射固定；
③ 确定性（同输入逐字相同、排序固定）；④ 只读消费 audit 报告，不改既有 JSON 契约。
"""
import json

from zthl_bashpy_migrate.cli import main
from zthl_bashpy_migrate.sarif import SCHEMA, VERSION, to_sarif


def _report(**sections):
    return dict(sections)


def _rules(doc):
    return [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]


def _results(doc):
    return doc["runs"][0]["results"]


class TestStructure:
    def test_schema_and_driver(self):
        doc = to_sarif(_report(), "a.sh", "0.3.1")
        assert doc["$schema"] == SCHEMA
        assert doc["version"] == VERSION
        drv = doc["runs"][0]["tool"]["driver"]
        assert drv["name"] == "bashpy-migrate"
        assert drv["version"] == "0.3.1"
        assert doc["runs"][0]["columnKind"] == "unicodeCodePoints"

    def test_empty_report_has_no_results(self):
        doc = to_sarif(_report(), "a.sh")
        assert _results(doc) == []
        assert _rules(doc) == []

    def test_windows_path_becomes_file_uri(self):
        doc = to_sarif(_report(bomb_scan={"groups": {"inline_python": [
            {"line": 1, "severity": "LOW", "risk": "r"}]}}), r"C:\tmp\x.sh")
        assert doc["runs"][0]["properties"]["artifact"] == "file:///C:/tmp/x.sh"
        uri = _results(doc)[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "file:///C:/tmp/x.sh"


class TestLevelMapping:
    def test_high_to_error_medium_warning_low_note(self):
        doc = to_sarif(_report(bomb_scan={"groups": {
            "inline_python": [{"line": 3, "severity": "HIGH", "risk": "r", "fix": "f"}],
            "stderr_swallow": [{"line": 5, "severity": "MEDIUM", "risk": "r", "fix": "f"}],
            "dangerous_cmd": [{"line": 7, "severity": "LOW", "risk": "r", "fix": "f"}],
        }}), "a.sh")
        levels = {r["ruleId"]: r["level"] for r in _results(doc)}
        assert levels == {"inline_python": "error", "stderr_swallow": "warning",
                          "dangerous_cmd": "note"}

    def test_unlabelled_severity_is_note(self):
        doc = to_sarif(_report(shellcheck_scan={"groups": {
            "sc2164_cd_fail": [{"line": 1, "risk": "r"}]}}), "a.sh")
        assert _results(doc)[0]["level"] == "note"

    def test_error_sections_become_error(self):
        doc = to_sarif(_report(python_lint={"error": "python syntax error"},
                               write_guard={"issues": [{"error": "bad"}]}), "a.py")
        assert {r["level"] for r in _results(doc)} == {"error"}
        assert {r["ruleId"] for r in _results(doc)} == {"python_lint", "write_guard"}


class TestLocations:
    def test_line_and_column_region(self):
        doc = to_sarif(_report(shellcheck_scan={"groups": {
            "sc2086_unquoted": [{"line": 9, "col": 14, "severity": "LOW",
                                 "risk": "r", "fix": "quote it"}]}}), "a.sh")
        region = _results(doc)[0]["locations"][0]["physicalLocation"]["region"]
        assert region == {"startLine": 9, "startColumn": 14}

    def test_no_line_omits_region(self):
        doc = to_sarif(_report(dead_code={"candidates": [
            {"function": "orphan", "refs": 0, "reached": False}]}), "a.sh")
        pl = _results(doc)[0]["locations"][0]["physicalLocation"]
        assert "region" not in pl

    def test_rule_metadata_carries_fix(self):
        doc = to_sarif(_report(bomb_scan={"groups": {
            "inline_python": [{"line": 1, "severity": "HIGH", "risk": "风险",
                               "fix": "拆成文件"}]}}), "a.sh")
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["id"] == "inline_python"
        assert rule["help"]["text"] == "拆成文件"
        assert rule["defaultConfiguration"]["level"] == "error"
        assert "bashpy-migrate" in rule["properties"]["tags"]


class TestFindingsSources:
    def test_python_lint_mapping(self):
        doc = to_sarif(_report(python_lint={
            "e722_bare_except": [{"line": 2, "fix": "except Exception"}],
            "f841_unused_local": [{"line": 4, "name": "tmp", "func": "f", "fix": "删"}],
            "counts": {"e722": 1, "f841": 1}, "total": 2}), "a.py")
        got = {(r["ruleId"], r["level"], r["locations"][0]["physicalLocation"]["region"]["startLine"])
               for r in _results(doc)}
        assert got == {("e722_bare_except", "warning", 2), ("f841_unused_local", "note", 4)}

    def test_write_guard_none_vs_present(self):
        doc = to_sarif(_report(write_guard={"issues": [
            {"function": "f", "guard": "NONE", "risk": "无守卫"},
            {"function": "g", "guard": "PRESENT", "risk": "需确认"},
        ]}), "a.sh")
        levels = [(r["level"], r["properties"]["function"]) for r in _results(doc)]
        assert ("warning", "f") in levels and ("note", "g") in levels

    def test_python_deadcode_and_dead_code(self):
        doc = to_sarif(_report(
            python_module_deadcode={"unused_imports": [{"name": "os", "line": 1}],
                                    "unused_functions": [{"name": "f", "line": 9}], "total": 2},
            dead_code={"candidates": [{"function": "orphan", "refs": 0}]}), "a.py")
        assert set(_rules(doc)) == {"py_unused_import", "py_unused_function", "dead_code"}

    def test_inline_inventory_not_reported_as_findings(self):
        """证据清单不进 results（避免 96 条 payload 变噪声）。"""
        doc = to_sarif(_report(inline_inventory={"total": 3, "items": [
            {"line": 1, "cat": "payload", "sha": "x"}]}), "a.sh")
        assert _results(doc) == []


class TestDeterminism:
    def test_same_input_same_output(self):
        rep = _report(bomb_scan={"groups": {
            "inline_python": [{"line": 2, "severity": "HIGH", "risk": "r", "fix": "f"},
                              {"line": 1, "severity": "MEDIUM", "risk": "r2", "fix": "f2"}]}})
        a = json.dumps(to_sarif(rep, "a.sh", "0.3.1"), ensure_ascii=False, sort_keys=True)
        b = json.dumps(to_sarif(rep, "a.sh", "0.3.1"), ensure_ascii=False, sort_keys=True)
        assert a == b

    def test_results_sorted_by_line_then_rule(self):
        doc = to_sarif(_report(
            bomb_scan={"groups": {"inline_python": [{"line": 9, "severity": "HIGH"}]}},
            shellcheck_scan={"groups": {"sc2164_cd_fail": [{"line": 2, "severity": "LOW"}]}},
            dead_code={"candidates": [{"function": "orphan", "refs": 0}]}), "a.sh")
        lines = [r["locations"][0]["physicalLocation"].get("region", {}).get("startLine")
                 for r in _results(doc)]
        assert lines == [2, 9, None]

    def test_rules_sorted_by_id(self):
        doc = to_sarif(_report(
            bomb_scan={"groups": {"z_rule": [{"line": 1, "severity": "LOW"}],
                                  "a_rule": [{"line": 2, "severity": "LOW"}]}}), "a.sh")
        assert _rules(doc) == ["a_rule", "z_rule"]

    def test_duplicate_findings_deduped(self):
        item = {"line": 1, "severity": "LOW", "risk": "same", "fix": "f"}
        doc = to_sarif(_report(bomb_scan={"groups": {"inline_python": [item, dict(item)]}}), "a.sh")
        assert len(_results(doc)) == 1

    def test_fingerprint_stable_and_rule_sensitive(self):
        rep = _report(bomb_scan={"groups": {
            "inline_python": [{"line": 1, "severity": "LOW", "risk": "r"}]}})
        f1 = _results(to_sarif(rep, "a.sh"))[0]["partialFingerprints"]["bashpy/v1"]
        f2 = _results(to_sarif(rep, "a.sh"))[0]["partialFingerprints"]["bashpy/v1"]
        other = _results(to_sarif(_report(bomb_scan={"groups": {
            "stderr_swallow": [{"line": 1, "severity": "LOW", "risk": "r"}]}}), "a.sh")
        )[0]["partialFingerprints"]["bashpy/v1"]
        assert f1 == f2 and f1 != other


class TestCli:
    def test_audit_format_sarif_end_to_end(self, tmp_path, capsys):
        script = tmp_path / "x.sh"
        script.write_text(
            "f() {\n"
            "  local out=$(cmd)\n"
            "  python3 -c \"print(1)\"\n"
            "  cd /tmp\n"
            "}\n", encoding="utf-8")
        code = main(["audit", "--script", str(script), "--bomb", "--shellcheck",
                     "--py-lint", "--format", "sarif"])
        assert code == 0
        doc = json.loads(capsys.readouterr().out)
        rules = set(_rules(doc))
        assert {"inline_python", "sc2155_local_assign", "sc2164_cd_fail"} <= rules
        assert all(r["ruleId"] in rules for r in _results(doc))
        # artifact 是 file URI，且行号指向原文件
        assert doc["runs"][0]["properties"]["artifact"].startswith("file:///")
        assert any(r["locations"][0]["physicalLocation"].get("region", {}).get("startLine") == 2
                   for r in _results(doc))

    def test_default_format_stays_json(self, tmp_path, capsys):
        script = tmp_path / "x.sh"
        script.write_text("echo hi\n", encoding="utf-8")
        assert main(["audit", "--script", str(script), "--bomb"]) == 0
        doc = json.loads(capsys.readouterr().out)
        assert "bomb_scan" in doc and "$schema" not in doc
