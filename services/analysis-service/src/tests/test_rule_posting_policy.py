"""The posting policy is applied once, and a quarantined finding never leaves the service.

The point of one filter is that no caller has to know the policy. A quarantined finding is
not posted to GitHub, not counted in the check summary and not handed to remediation,
because it is not in the response at all. It is still counted, so the replay and the
metrics can keep measuring the rule that produced it.

Both tiers declare into the same set. Tier 1 declares it on the rule
(`posting=POSTING_QUARANTINE`); tier 2 declares it per rule in its YAML metadata
(`posting: quarantine`). `main.QUARANTINED_RULE_IDS` is the union, and
`partition_by_posting_policy` is the one filter that reads it.
"""
from __future__ import annotations

import pytest

import main
from main import (
    AnalyzePRRequest,
    QUARANTINED_RULE_IDS,
    analyze_pull_request_payload,
    analyze_tier1_payload,
    analyze_tier2_payload,
    partition_by_posting_policy,
    quarantined_counts_by_rule,
)
from security_rules import POSTING_QUARANTINE, SECURITY_RULES


def _finding(rule_id: str, line: int = 1) -> dict:
    return {
        "rule_id": rule_id,
        "internal_type": "sql_injection",
        "title": "t",
        "description": "d",
        "category": "SQL injection",
        "cwe_id": "CWE-89",
        "severity": "high",
        "confidence": 0.9,
        "file_path": "src/app.js",
        "line_start": line,
        "line_end": line,
        "code_snippet": "db.query(x)",
        "fingerprint": f"{rule_id}-{line}",
    }


@pytest.fixture
def quarantine(monkeypatch):
    monkeypatch.setattr(main, "QUARANTINED_RULE_IDS", frozenset({"opengrep.noisy.rule"}))


class TestQuarantineSet:
    def test_every_quarantined_tier1_rule_is_in_the_set(self):
        tier1 = {rule.rule_id for rule in SECURITY_RULES if rule.posting == POSTING_QUARANTINE}
        assert tier1
        assert tier1 <= QUARANTINED_RULE_IDS

    def test_every_quarantined_tier2_rule_is_in_the_set(self):
        from opengrep_runner import quarantined_rule_ids

        tier2 = frozenset(quarantined_rule_ids())
        assert tier2
        assert tier2 <= QUARANTINED_RULE_IDS

    def test_the_set_is_exactly_the_union_of_the_two_tiers(self):
        from opengrep_runner import quarantined_rule_ids

        tier1 = {rule.rule_id for rule in SECURITY_RULES if rule.posting == POSTING_QUARANTINE}
        assert QUARANTINED_RULE_IDS == frozenset(tier1 | set(quarantined_rule_ids()))

    def test_at_least_one_rule_is_quarantined_so_the_path_is_exercised(self):
        assert QUARANTINED_RULE_IDS


class TestPartition:
    def test_quarantined_findings_are_separated_and_counted(self):
        findings = [
            {"rule_id": "null.pointer.deref", "file_path": "a.ts"},
            {"rule_id": "null.pointer.deref", "file_path": "b.ts"},
            {"rule_id": "sql.injection.raw_query", "file_path": "c.py"},
        ]
        postable, quarantined = partition_by_posting_policy(findings)
        assert [f["rule_id"] for f in postable] == ["sql.injection.raw_query"]
        assert quarantined_counts_by_rule(quarantined) == {"null.pointer.deref": 2}

    def test_a_quarantined_rule_is_removed_and_a_posting_rule_is_kept(self, quarantine):
        postable, quarantined = partition_by_posting_policy(
            [_finding("opengrep.noisy.rule"), _finding("opengrep.good.rule", 2)]
        )
        assert [f["rule_id"] for f in postable] == ["opengrep.good.rule"]
        assert [f["rule_id"] for f in quarantined] == ["opengrep.noisy.rule"]

    def test_the_filter_is_by_rule_not_by_tier(self, monkeypatch):
        """Tier 1 rule ids go through the same set, which is what makes it one policy."""
        monkeypatch.setattr(
            main, "QUARANTINED_RULE_IDS", frozenset({"opengrep.noisy.rule", "authz.missing_function_level"})
        )
        postable, quarantined = partition_by_posting_policy(
            [_finding("authz.missing_function_level"), _finding("null.pointer.deref", 2)]
        )
        assert [f["rule_id"] for f in postable] == ["null.pointer.deref"]
        assert [f["rule_id"] for f in quarantined] == ["authz.missing_function_level"]

    def test_an_empty_list_is_handled(self):
        assert partition_by_posting_policy([]) == ([], [])

    def test_a_finding_without_a_rule_id_is_still_posted(self):
        postable, quarantined = partition_by_posting_policy([{"file_path": "a.ts"}])
        assert len(postable) == 1 and quarantined == []

    def test_counts_are_grouped_by_rule(self):
        counts = quarantined_counts_by_rule(
            [_finding("a"), _finding("a", 2), _finding("b", 3)]
        )
        assert counts == {"a": 2, "b": 1}


def _tier1(path, lines):
    payload = AnalyzePRRequest(
        repository_full_name="acme/app",
        pull_request_number=1,
        commit_sha="a" * 40,
        files=[{"path": path, "patch": "@@ -1,1 +1,1 @@\n" + "".join(f"+{line}\n" for line in lines)}],
    )
    return analyze_tier1_payload(payload)


class TestPipelineFilter:
    def test_a_quarantined_rule_produces_no_posted_finding(self):
        result = _tier1("src/pool.ts", ["connection.removeAllListeners('error').on('error', handler);"])
        assert [f["rule_id"] for f in result["findings"]] == []

    def test_a_quarantined_rule_still_runs_and_is_counted(self):
        result = _tier1("src/pool.ts", ["connection.removeAllListeners('error').on('error', handler);"])
        assert result["quarantined_findings"].get("null.pointer.deref", 0) >= 1

    def test_a_posting_rule_is_unaffected(self):
        result = _tier1("src/db.py", ['cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'])
        assert "sql.injection.raw_query" in [f["rule_id"] for f in result["findings"]]

    def test_a_clean_file_reports_no_quarantined_counts(self):
        result = _tier1("src/clean.ts", ["const total = 1 + 2;"])
        assert result["findings"] == []
        assert result["quarantined_findings"] == {}

    def test_the_combined_endpoint_applies_the_same_filter(self):
        payload = AnalyzePRRequest(
            repository_full_name="acme/app",
            pull_request_number=1,
            commit_sha="a" * 40,
            files=[{"path": "src/pool.ts", "patch": "@@ -1,1 +1,1 @@\n+stream.destroy();\n"}],
        )
        try:
            result = analyze_pull_request_payload(payload)
        except RuntimeError:
            pytest.skip("tier 2 scanner is unavailable in this environment")
        assert "authz.missing_function_level" not in [f["rule_id"] for f in result["findings"]]
        assert result["quarantined_findings"].get("authz.missing_function_level", 0) >= 1


class TestEndpointsReportTheWithheld:
    def _payload(self) -> AnalyzePRRequest:
        return AnalyzePRRequest(
            repository_full_name="acme/app",
            pull_request_number=1,
            commit_sha="deadbeef",
            files=[],
        )

    def test_tier1_reports_a_quarantined_count_key(self):
        result = analyze_tier1_payload(self._payload())
        assert result["quarantined_findings"] == {}

    def test_tier2_reports_a_quarantined_count_key(self, monkeypatch):
        monkeypatch.setattr(main, "run_opengrep_with_limitations", lambda files: ([], []))
        result = analyze_tier2_payload(self._payload())
        assert result["quarantined_findings"] == {}

    def test_a_quarantined_tier2_finding_does_not_reach_the_response(self, monkeypatch):
        monkeypatch.setattr(main, "QUARANTINED_RULE_IDS", frozenset({"opengrep.noisy.rule"}))
        monkeypatch.setattr(
            main,
            "run_opengrep_with_limitations",
            lambda files: ([_finding("opengrep.noisy.rule"), _finding("opengrep.good.rule", 2)], []),
        )
        result = analyze_tier2_payload(self._payload())
        assert [f["rule_id"] for f in result["findings"]] == ["opengrep.good.rule"]
        assert result["quarantined_findings"] == {"opengrep.noisy.rule": 1}


class TestLoadedPolicy:
    def test_the_service_starts_with_the_policy_both_tiers_declare(self):
        from opengrep_runner import quarantined_rule_ids
        from security_rules import POSTING_QUARANTINE, SECURITY_RULES

        tier1 = {rule.rule_id for rule in SECURITY_RULES if rule.posting == POSTING_QUARANTINE}
        assert main.QUARANTINED_RULE_IDS == frozenset(quarantined_rule_ids()) | tier1

    def test_at_least_one_rule_is_quarantined_so_the_path_is_exercised(self):
        assert main.QUARANTINED_RULE_IDS

    def test_both_tiers_contribute_to_the_one_set(self):
        """One filter, two sources. If either source stops feeding it, a rule that was
        measured and found wrong quietly starts posting again."""
        assert any(rule_id.startswith("opengrep.") for rule_id in main.QUARANTINED_RULE_IDS)
        assert any(not rule_id.startswith("opengrep.") for rule_id in main.QUARANTINED_RULE_IDS)


class TestTier1PostingPolicy:
    """A tier 1 rule declares its posting state next to the pattern whose precision was
    measured, exactly as a tier 2 rule does in its YAML metadata."""

    def test_a_quarantined_tier1_rule_carries_its_evidence(self):
        from security_rules import POSTING_QUARANTINE, PRECISION_MEASURED, SECURITY_RULES

        quarantined = [rule for rule in SECURITY_RULES if rule.posting == POSTING_QUARANTINE]
        assert quarantined, "the tier 1 quarantine path is not exercised by any rule"
        for rule in quarantined:
            assert rule.precision == PRECISION_MEASURED, (
                f"{rule.rule_id} is quarantined without a measurement; the quarantine is for "
                "rules measured and found wrong, not for rules nobody has looked at"
            )
            assert rule.precision_evidence.strip(), (
                f"{rule.rule_id} is quarantined with no evidence, so nothing says what would "
                "let someone re-enable it"
            )

    def test_an_unmeasured_tier1_rule_still_posts(self):
        from security_rules import POSTING_POST, PRECISION_UNMEASURED, SECURITY_RULES

        for rule in SECURITY_RULES:
            if rule.precision == PRECISION_UNMEASURED:
                assert rule.posting == POSTING_POST, rule.rule_id

    def test_a_quarantined_tier1_finding_does_not_reach_the_response(self, monkeypatch):
        from security_rules import POSTING_QUARANTINE, SECURITY_RULES

        rule_id = next(
            rule.rule_id for rule in SECURITY_RULES if rule.posting == POSTING_QUARANTINE
        )
        monkeypatch.setattr(main, "pattern_findings", lambda files, limitations=None: [_finding(rule_id)])
        result = analyze_tier1_payload(
            AnalyzePRRequest(
                repository_full_name="acme/app", pull_request_number=1,
                commit_sha="deadbeef", files=[],
            )
        )
        assert result["findings"] == []
        assert result["quarantined_findings"] == {rule_id: 1}
