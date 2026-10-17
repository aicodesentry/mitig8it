"""The pieces of a scan whose output used to depend on arrival order or on a clock.

`docs/validation/determinism-and-recall-gate-2026-10.md` lists every source of run-to-run
variation found in a scan over identical input. These tests pin the ones that are fixed in the
service itself: supporting detections are sorted, the final finding order has no ties left for
arrival order to break, tier 2's output is in file order whatever order the scanner printed it,
the two tiers' limitations are joined in a fixed order, and the scanner's two timeouts can be
lifted for a measurement. The end-to-end check, two runs over one fixture set compared byte for
byte, is `test_determinism_end_to_end.py`.
"""
from __future__ import annotations

import os
from unittest import mock

import pytest

import main
import opengrep_runner
from finding_quality import cluster_findings


def _finding(rule_id: str, line: int = 10, *, internal_type: str = "sql_injection", **extra) -> dict:
    finding = {
        "rule_id": rule_id,
        "internal_type": internal_type,
        "file_path": "src/app.py",
        "line_start": line,
        "line_end": line,
        "severity": "high",
        "confidence": 0.8,
        "code_snippet": f"query(x)  # {line}",
        "evidence": f"Matched `{rule_id}`.",
        "fingerprint": f"fp-{rule_id}-{line}",
        "taxonomy_mappings": {"cwe": ["CWE-89"], "owasp": [], "attack": [], "capec": []},
        "taxonomy_versions": {"cwe": "4.18", "attack": None, "capec": None, "owasp": None},
    }
    finding.update(extra)
    return finding


class TestSupportingDetectionsAreSorted:
    """The trial saw `auth.weak_password_hash` leave a supporting list between two runs."""

    def test_the_list_is_the_same_whatever_order_the_cluster_arrived_in(self):
        primary = _finding("opengrep.cwe-89.sql", severity="critical")
        a = _finding("sql.injection.raw_query")
        b = _finding("auth.weak_password_hash")
        c = _finding("db.query.concat")

        one = cluster_findings([primary, a, b, c])
        other = cluster_findings([primary, c, b, a])

        assert len(one) == len(other) == 1
        assert one[0]["evidence"] == other[0]["evidence"]
        assert one[0]["merged_rule_ids"] == other[0]["merged_rule_ids"]
        assert "Supporting detections: auth.weak_password_hash, db.query.concat, sql.injection.raw_query." in one[0]["evidence"]

    def test_the_survivor_stays_first_in_merged_rule_ids(self):
        primary = _finding("opengrep.cwe-89.sql", severity="critical")
        merged = cluster_findings([primary, _finding("z.rule"), _finding("a.rule")])[0]
        assert merged["merged_rule_ids"] == ["opengrep.cwe-89.sql", "a.rule", "z.rule"]
        assert merged["evidence_details"]["extra"]["merged_rule_ids"] == merged["merged_rule_ids"]


class TestFinalOrderHasNoTies:
    def test_equal_severity_findings_on_one_line_come_back_in_one_order(self):
        # Different internal types, so they do not cluster; same severity, confidence, file
        # and line, so before the tie-breakers their order was the order they arrived in.
        x = _finding("opengrep.x", internal_type="command_injection")
        y = _finding("opengrep.y", internal_type="path_traversal")
        z = _finding("opengrep.z", internal_type="open_redirect")

        first = [f["rule_id"] for f in cluster_findings([z, x, y])]
        second = [f["rule_id"] for f in cluster_findings([y, z, x])]

        assert first == second == ["opengrep.x", "opengrep.y", "opengrep.z"]


class TestTierTwoOutputIsInFileOrder:
    def test_findings_and_limitations_are_sorted_whatever_the_scanner_printed(self, monkeypatch):
        """`_scan_batch` is replaced by a scanner that answers in reverse file order."""
        reversed_findings = [
            _finding("opengrep.b", line=5, file_path="z.py"),
            _finding("opengrep.a", line=5, file_path="z.py"),
            _finding("opengrep.a", line=9, file_path="a.py"),
        ]
        reversed_limitations = [
            {"path": "z.py", "kind": "partial_parse", "type": "Syntax error", "message": "", "line": 3},
            {"path": "a.py", "kind": "not_analyzed", "type": "Timeout", "message": "", "line": None},
        ]
        monkeypatch.setattr(
            opengrep_runner, "_scan_batch", lambda batch: (list(reversed_findings), list(reversed_limitations))
        )
        files = [
            {"path": "z.py", "content": "x = 1\n", "patch": ""},
            {"path": "a.py", "content": "x = 1\n", "patch": ""},
        ]
        findings, limitations = opengrep_runner.run_opengrep_with_limitations(files)

        assert [(f["file_path"], f["line_start"], f["rule_id"]) for f in findings] == [
            ("a.py", 9, "opengrep.a"),
            ("z.py", 5, "opengrep.a"),
            ("z.py", 5, "opengrep.b"),
        ]
        assert [item["path"] for item in limitations] == ["a.py", "z.py"]


class TestTheTwoTiersLimitationsAreJoinedInOrder:
    def test_tier_one_limitations_come_before_tier_two_whichever_thread_finished_first(self, monkeypatch):
        def slow_tier1(files, limitations=None):
            import time

            time.sleep(0.05)
            limitations.append({"kind": "budget", "path": "", "message": "tier 1"})
            return []

        def fast_tier2(files):
            return [], [{"kind": "partial_parse", "path": "a.py", "type": "Syntax error", "message": "tier 2", "line": 1}]

        monkeypatch.setattr(main, "pattern_findings", slow_tier1)
        monkeypatch.setattr(main, "run_opengrep_with_limitations", fast_tier2)
        payload = main.AnalyzePRRequest(
            repository_full_name="o/r",
            pull_request_number=1,
            commit_sha="a" * 40,
            files=[main.ChangedFile(path="a.py", patch="@@ -1,1 +1,1 @@\n+x = 1\n", content="x = 1\n")],
        )
        result = main.analyze_pull_request_payload(payload)
        assert [item["message"] for item in result["analysis_limitations"]] == ["tier 1", "tier 2"]


class TestScannerTimeoutsReadTheEnvironment:
    def test_defaults_are_the_production_values(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENGREP_RULE_TIMEOUT_SECONDS", None)
            os.environ.pop("OPENGREP_PROCESS_TIMEOUT_SECONDS", None)
            assert opengrep_runner.rule_timeout_seconds() == 30
            assert opengrep_runner.process_timeout_seconds() == 120

    @pytest.mark.parametrize("raw", ["0", "-5", "soon", ""])
    def test_a_value_that_is_not_a_positive_integer_keeps_the_default(self, raw):
        with mock.patch.dict(os.environ, {"OPENGREP_RULE_TIMEOUT_SECONDS": raw}):
            assert opengrep_runner.rule_timeout_seconds() == 30

    def test_a_measurement_can_lift_both(self):
        with mock.patch.dict(
            os.environ,
            {"OPENGREP_RULE_TIMEOUT_SECONDS": "86400", "OPENGREP_PROCESS_TIMEOUT_SECONDS": "86400"},
        ):
            assert opengrep_runner.rule_timeout_seconds() == 86400
            assert opengrep_runner.process_timeout_seconds() == 86400

    def test_the_scanner_is_invoked_with_the_configured_rule_timeout(self, monkeypatch):
        seen: dict = {}

        class Completed:
            returncode = 0
            stdout = '{"results": [], "errors": []}'
            stderr = ""

        def fake_run(command, **kwargs):
            seen["command"] = command
            seen["timeout"] = kwargs.get("timeout")
            return Completed()

        monkeypatch.setattr(opengrep_runner.subprocess, "run", fake_run)
        with mock.patch.dict(
            os.environ,
            {"OPENGREP_RULE_TIMEOUT_SECONDS": "7", "OPENGREP_PROCESS_TIMEOUT_SECONDS": "11"},
        ):
            opengrep_runner._run_semgrep("/tmp/nowhere")
        assert seen["timeout"] == 11
        assert seen["command"][seen["command"].index("--timeout") + 1] == "7"
