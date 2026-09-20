import pytest

from test_code_scope import (
    classify_finding,
    classify_findings,
    count_test_code_files,
    is_analyzable_path,
    is_excluded_path,
    is_runtime_scannable_path,
    is_test_code_path,
)


class TestPathClassification:
    def test_test_paths_are_flagged(self):
        assert is_test_code_path("services/analysis-service/src/tests/test_llm_triage.py") is True
        assert is_test_code_path("services/api-service/tests/orchestrator.test.js") is True
        assert is_test_code_path("frontend/src/pages/__tests__/RepositoriesPage.test.jsx") is True
        assert is_test_code_path("test_vuln.go") is True
        assert is_test_code_path("nested/fixtures/test_vuln.ts") is True
        assert is_test_code_path("widget.spec.tsx") is True

    def test_runtime_paths_are_not_flagged(self):
        assert is_test_code_path("services/api-service/src/routes/auth.js") is False
        assert is_test_code_path("services/orders.js") is False
        assert is_test_code_path("main.py") is False

    def test_test_paths_stay_analyzable(self):
        assert is_analyzable_path("services/api-service/tests/orchestrator.test.js") is True
        assert is_analyzable_path("test_vuln.go") is True

    def test_rule_assets_are_excluded_entirely(self):
        assert is_excluded_path("services/analysis-service/src/opengrep_rules/javascript.yml") is True
        assert is_analyzable_path("services/analysis-service/src/opengrep_rules/javascript.yml") is False
        assert is_runtime_scannable_path("services/analysis-service/src/opengrep_rules/javascript.yml") is False

    def test_empty_path_is_not_analyzable(self):
        assert is_analyzable_path("") is False
        assert is_test_code_path("") is False

    def test_counts_distinct_test_files(self):
        paths = [
            "test_vuln.go",
            "test_vuln.go",
            "services/api-service/tests/a.test.js",
            "services/orders.js",
        ]
        assert count_test_code_files(paths) == 2


class TestFindingClassification:
    def test_test_finding_becomes_informational(self):
        finding = classify_finding({
            "file_path": "test_vuln.go",
            "severity": "critical",
            "evidence_details": {"analysis_scope": "ast-pattern"},
        })

        assert finding["in_test_code"] is True
        assert finding["severity"] == "info"
        assert finding["original_severity"] == "critical"
        assert finding["evidence_details"]["extra"]["in_test_code"] is True
        assert finding["evidence_details"]["extra"]["original_severity"] == "critical"
        # Untouched evidence survives.
        assert finding["evidence_details"]["analysis_scope"] == "ast-pattern"

    def test_runtime_finding_keeps_its_severity(self):
        finding = classify_finding({"file_path": "services/orders.js", "severity": "critical"})

        assert finding["in_test_code"] is False
        assert finding["severity"] == "critical"
        assert "original_severity" not in finding
        assert "evidence_details" not in finding

    def test_classification_is_idempotent_after_a_transport_round_trip(self):
        finding = classify_finding({"file_path": "test_vuln.go", "severity": "high"})
        # Top-level markers are in-process only; the transport keeps extra.
        round_tripped = {
            "file_path": finding["file_path"],
            "severity": finding["severity"],
            "evidence_details": {"extra": dict(finding["evidence_details"]["extra"])},
        }

        # An LLM triage pass raises the severity; classification restores info.
        round_tripped["severity"] = "critical"
        reclassified = classify_finding(round_tripped)

        assert reclassified["severity"] == "info"
        assert reclassified["original_severity"] == "high"

    def test_classify_findings_maps_every_finding(self):
        findings = classify_findings([
            {"file_path": "test_a.py", "severity": "high"},
            {"file_path": "app.py", "severity": "high"},
        ])

        assert [f["severity"] for f in findings] == ["info", "high"]
        assert [f["in_test_code"] for f in findings] == [True, False]

    @pytest.mark.parametrize("value", [None, "not-a-dict", 7])
    def test_non_dict_findings_pass_through(self, value):
        assert classify_finding(value) == value
