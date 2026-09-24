"""The posting filter in the tier 1 pipeline.

Quarantined rules still run and are still counted. They simply do not arrive at the
api-service, so nothing downstream needs to know the policy exists.
"""

import pytest

from main import (
    AnalyzePRRequest,
    QUARANTINED_RULE_IDS,
    analyze_pull_request_payload,
    analyze_tier1_payload,
    partition_by_posting_policy,
    quarantined_counts_by_rule,
)
from security_rules import POSTING_QUARANTINE, SECURITY_RULES


class TestQuarantineSet:
    def test_the_pipeline_reads_the_set_off_the_rules(self):
        assert QUARANTINED_RULE_IDS == {
            rule.rule_id for rule in SECURITY_RULES if rule.posting == POSTING_QUARANTINE
        }
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

    def test_an_empty_list_is_handled(self):
        assert partition_by_posting_policy([]) == ([], [])

    def test_a_finding_without_a_rule_id_is_still_posted(self):
        postable, quarantined = partition_by_posting_policy([{"file_path": "a.ts"}])
        assert len(postable) == 1 and quarantined == []


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
