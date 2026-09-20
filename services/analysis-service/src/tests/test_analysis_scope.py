from main import (
    AnalyzePRRequest,
    TriageRequest,
    analyze_tier1_payload,
    is_runtime_scannable_path,
    triage_findings_payload,
)


class TestAnalysisScope:
    def test_runtime_files_remain_scannable(self):
        assert is_runtime_scannable_path("services/api-service/src/routes/auth.js") is True
        assert is_runtime_scannable_path("frontend/src/pages/HomePage.jsx") is True

    def test_test_and_rule_files_are_excluded(self):
        assert is_runtime_scannable_path("services/analysis-service/src/tests/test_llm_triage.py") is False
        assert is_runtime_scannable_path("services/api-service/tests/orchestrator.test.js") is False
        assert is_runtime_scannable_path("frontend/src/pages/__tests__/RepositoriesPage.test.jsx") is False
        assert is_runtime_scannable_path("test_vuln.js") is False
        assert is_runtime_scannable_path("nested/fixtures/test_vuln.ts") is False
        assert is_runtime_scannable_path("services/analysis-service/src/opengrep_rules/javascript.yml") is False


class TestTierPayloadsReportTestCode:
    def test_tier1_reports_test_file_findings_as_informational(self):
        payload = AnalyzePRRequest(
            repository_full_name="acme/app",
            pull_request_number=1,
            commit_sha="a" * 40,
            files=[
                {"path": "test_security.py", "patch": '+password = "hardcoded-secret-value"\n'},
                {"path": "services/analysis-service/src/opengrep_rules/python.yml", "patch": "+rules:\n"},
            ],
        )

        result = analyze_tier1_payload(payload)

        assert result["test_files_analyzed"] == 1
        test_findings = [f for f in result["findings"] if f["file_path"] == "test_security.py"]
        assert test_findings, "test-code findings must be reported"
        assert all(f["severity"] == "info" for f in test_findings)
        assert all(f["in_test_code"] is True for f in test_findings)
        assert all(f["original_severity"] != "info" for f in test_findings)
        assert not [f for f in result["findings"] if "opengrep_rules/" in f["file_path"]]

    def test_tier3_keeps_test_findings_informational(self):
        payload = TriageRequest(
            repository_full_name="acme/app",
            pull_request_number=1,
            commit_sha="a" * 40,
            findings=[{
                "rule_id": "hardcoded_secret",
                "file_path": "test_security.py",
                "severity": "critical",
                "confidence": 0.9,
                "category": "secrets",
                "line_start": 1,
                "code_snippet": "password = 'x'",
            }],
        )

        result = triage_findings_payload(payload)

        assert [f["severity"] for f in result["findings"]] == ["info"]
        assert result["findings"][0]["original_severity"] == "critical"
