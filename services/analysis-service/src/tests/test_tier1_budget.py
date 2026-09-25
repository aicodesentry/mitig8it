"""Tier 1 stops on a budget instead of blowing the orchestrator's deadline.

The replay measured 50 s for 200 files of 75 kB, inside every cap the pipeline enforces,
against a 30 s budget in `prAnalysisOrchestrator.js`. Tier 1 now keeps the findings it has
and reports the rest as a limitation.
"""

import re
import time

import pytest

from main import (
    AnalyzePRRequest,
    DEFAULT_TIER1_BUDGET_SECONDS,
    DEFAULT_TIER1_FILE_BUDGET_SECONDS,
    ChangedFile,
    analyze_tier1_payload,
    pattern_findings,
    tier1_budget_seconds,
    tier1_file_budget_seconds,
)
from security_rules import SecurityRule


class SlowPattern:
    """A rule pattern that costs real time and never matches."""

    def __init__(self, seconds):
        self.seconds = seconds
        self.pattern = "slow"

    def search(self, text):
        time.sleep(self.seconds)
        return None


def _rule(pattern, rule_id="slow.rule"):
    return SecurityRule(
        rule_id=rule_id,
        title="Slow rule",
        category="synthetic",
        cwe_id="CWE-1",
        owasp_category="A01:2021",
        severity="medium",
        confidence=0.5,
        exploitability="low",
        pattern=pattern,
        description="",
        remediation="",
    )


def _files(count):
    return [
        ChangedFile(path=f"src/file{index}.ts", patch="@@ -1,1 +1,1 @@\n+const x = 1;\n")
        for index in range(count)
    ]


class TestBudgetConfiguration:
    def test_defaults(self, monkeypatch):
        monkeypatch.delenv("TIER1_BUDGET_SECONDS", raising=False)
        monkeypatch.delenv("TIER1_FILE_BUDGET_SECONDS", raising=False)
        assert tier1_budget_seconds() == DEFAULT_TIER1_BUDGET_SECONDS == 20.0
        assert tier1_file_budget_seconds() == DEFAULT_TIER1_FILE_BUDGET_SECONDS

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("TIER1_BUDGET_SECONDS", "3.5")
        assert tier1_budget_seconds() == 3.5

    @pytest.mark.parametrize("value", ["", "   ", "nonsense", "0", "-4"])
    def test_an_unusable_value_falls_back_to_the_default(self, monkeypatch, value):
        monkeypatch.setenv("TIER1_BUDGET_SECONDS", value)
        assert tier1_budget_seconds() == DEFAULT_TIER1_BUDGET_SECONDS


class TestTotalBudget:
    def test_the_pass_stops_and_records_what_it_did_not_reach(self, monkeypatch):
        monkeypatch.setattr("main.SECURITY_RULES", [_rule(SlowPattern(0.15))])
        monkeypatch.setenv("TIER1_BUDGET_SECONDS", "0.4")
        monkeypatch.setenv("TIER1_FILE_BUDGET_SECONDS", "10")

        limitations = []
        started = time.monotonic()
        pattern_findings(_files(20), limitations)
        elapsed = time.monotonic() - started

        assert elapsed < 5, "the budget must stop the pass, not merely annotate it"
        assert len(limitations) == 1
        assert limitations[0]["kind"] == "budget"
        assert re.fullmatch(
            r"Tier 1 stopped after \d+ of 20 files \(0\.4 s budget\)",
            limitations[0]["message"],
        ), limitations[0]["message"]

    def test_findings_made_before_the_budget_are_kept(self, monkeypatch):
        real_rule = _rule(re.compile(r"eval\("), rule_id="code.injection.eval")
        monkeypatch.setattr("main.SECURITY_RULES", [real_rule, _rule(SlowPattern(0.2))])
        monkeypatch.setenv("TIER1_BUDGET_SECONDS", "0.5")
        monkeypatch.setenv("TIER1_FILE_BUDGET_SECONDS", "10")

        files = [ChangedFile(path="src/a.ts", patch="@@ -1,1 +1,1 @@\n+const v = eval(payload);\n")]
        files.extend(_files(10))

        limitations = []
        findings = pattern_findings(files, limitations)

        assert [f["rule_id"] for f in findings][:1] == ["code.injection.eval"]
        assert limitations and limitations[0]["kind"] == "budget"

    def test_no_limitation_when_the_pass_finishes(self, monkeypatch):
        monkeypatch.setenv("TIER1_BUDGET_SECONDS", "20")
        limitations = []
        pattern_findings(_files(3), limitations)
        assert limitations == []


class TestPerFileCap:
    def test_a_single_slow_file_stops_without_stopping_the_pass(self, monkeypatch):
        monkeypatch.setattr("main.SECURITY_RULES", [_rule(SlowPattern(0.1), f"slow.{i}") for i in range(20)])
        monkeypatch.setenv("TIER1_BUDGET_SECONDS", "30")
        monkeypatch.setenv("TIER1_FILE_BUDGET_SECONDS", "0.3")

        limitations = []
        started = time.monotonic()
        pattern_findings(_files(2), limitations)
        elapsed = time.monotonic() - started

        assert elapsed < 3
        assert len(limitations) == 2, "one per file, and the second file was still scanned"
        for limitation in limitations:
            assert limitation["kind"] == "budget"
            assert "per-file cap" in limitation["message"]
        assert {limitation["path"] for limitation in limitations} == {"src/file0.ts", "src/file1.ts"}


class TestLimitationsInThePayload:
    def test_the_tier1_response_carries_the_limitation(self, monkeypatch):
        monkeypatch.setattr("main.SECURITY_RULES", [_rule(SlowPattern(0.15))])
        monkeypatch.setenv("TIER1_BUDGET_SECONDS", "0.3")

        payload = AnalyzePRRequest(
            repository_full_name="acme/app",
            pull_request_number=1,
            commit_sha="a" * 40,
            files=[{"path": f"src/f{i}.ts", "patch": "@@ -1,1 +1,1 @@\n+const x = 1;\n"} for i in range(10)],
        )
        result = analyze_tier1_payload(payload)

        assert result["analysis_limitations"]
        assert result["analysis_limitations"][0]["kind"] == "budget"

    def test_an_ordinary_response_carries_an_empty_list(self):
        payload = AnalyzePRRequest(
            repository_full_name="acme/app",
            pull_request_number=1,
            commit_sha="a" * 40,
            files=[{"path": "src/a.ts", "patch": "@@ -1,1 +1,1 @@\n+const x = 1;\n"}],
        )
        assert analyze_tier1_payload(payload)["analysis_limitations"] == []
