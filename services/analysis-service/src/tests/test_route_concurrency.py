"""The analysis routes must not stall the event loop.

The handlers run a semgrep subprocess with a two-minute timeout and blocking LLM
HTTP calls. Declared `async def`, they ran on uvicorn's single event loop and one
slow request blocked every other request, including /health, which Cloud Run
uses to decide whether the instance is alive.
"""
import threading
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import main
from main import AnalyzePRRequest, analyze_pull_request_payload, app, run_tiers_concurrently

SECRET = "test-internal-secret"
HEADERS = {"x-internal-secret": SECRET}
PAYLOAD = {
    "repository_full_name": "owner/repo",
    "pull_request_number": 1,
    "commit_sha": "abc123",
    "files": [{"path": "app.py", "patch": "+eval(user_input)"}],
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("ANALYSIS_SERVICE_INTERNAL_SECRET", SECRET)
    # The context manager form shares one event loop across every request, which is
    # the shape uvicorn gives the app. Without it each request gets a loop of its own
    # and this test could not observe a blocked loop.
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize("route", ["/analyze/pr", "/analyze/pr/tier2"])
def test_slow_analysis_does_not_block_health(client, route):
    def slow_opengrep(files):
        time.sleep(1.0)
        return [], []

    outcome = {}

    def analyze():
        outcome["response"] = client.post(route, json=PAYLOAD, headers=HEADERS)

    with patch("main.run_opengrep_with_limitations", side_effect=slow_opengrep):
        worker = threading.Thread(target=analyze)
        worker.start()
        time.sleep(0.2)  # the analysis request is now inside the blocking call
        started = time.perf_counter()
        health = client.get("/health")
        health_latency = time.perf_counter() - started
        worker.join()

    assert health.status_code == 200
    assert health_latency < 0.5, f"/health waited {health_latency:.2f}s behind a running analysis"
    assert outcome["response"].status_code == 200


def test_slow_triage_does_not_block_health(client):
    def slow_triage(findings, file_patches, repo_profile):
        time.sleep(1.0)
        return findings

    payload = {
        "repository_full_name": "owner/repo",
        "pull_request_number": 1,
        "commit_sha": "abc123",
        "findings": [{"rule_id": "x", "file_path": "app.py", "line_start": 1, "severity": "high", "category": "c"}],
        "file_patches": {},
        "repo_profile": {},
    }
    outcome = {}

    def triage():
        outcome["response"] = client.post("/analyze/pr/tier3", json=payload, headers=HEADERS)

    with patch("main.triage_findings", side_effect=slow_triage):
        worker = threading.Thread(target=triage)
        worker.start()
        time.sleep(0.2)
        started = time.perf_counter()
        health = client.get("/health")
        health_latency = time.perf_counter() - started
        worker.join()

    assert health.status_code == 200
    assert health_latency < 0.5
    assert outcome["response"].status_code == 200


def _request(patch_text="+eval(user_input)"):
    return AnalyzePRRequest(
        repository_full_name="owner/repo",
        pull_request_number=1,
        commit_sha="abc123",
        files=[{"path": "app.py", "patch": patch_text}],
    )


def _opengrep_finding(template):
    finding = dict(template)
    finding.update(rule_id="opengrep.fake", fingerprint="opengrep-fp", line_start=99, code_snippet="fake()")
    return finding


@pytest.mark.parametrize("opengrep_delay", [0.0, 0.3])
def test_combined_route_merges_tier_findings_in_tier_order(opengrep_delay):
    """Tier 1 findings precede tier 2 findings whichever tier finishes first."""
    request = _request()
    tier1_ids = [f["rule_id"] for f in main.pattern_findings(list(request.files))]
    assert tier1_ids == ["code.injection.eval"]
    template = main.pattern_findings(list(request.files))[0]

    def opengrep(files):
        time.sleep(opengrep_delay)
        return [_opengrep_finding(template)], []

    with patch("main.run_opengrep_with_limitations", side_effect=opengrep):
        result = analyze_pull_request_payload(request)

    assert [f["rule_id"] for f in result["findings"]] == ["code.injection.eval", "opengrep.fake"]


def test_tier_order_is_fixed_when_tier1_finishes_last():
    def tier1():
        time.sleep(0.2)
        return [{"rule_id": "tier1"}]

    def tier2():
        return [{"rule_id": "tier2"}]

    assert [f["rule_id"] for f in run_tiers_concurrently(tier1, tier2)] == ["tier1", "tier2"]


def test_combined_route_fails_closed_when_opengrep_fails_after_tier1_succeeds():
    request = _request()
    with patch("main.run_opengrep_with_limitations", side_effect=RuntimeError("detector unavailable")):
        with pytest.raises(RuntimeError, match="Required OpenGrep analysis failed"):
            analyze_pull_request_payload(request)
