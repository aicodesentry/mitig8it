"""Two scans of the same pull request answer with the same bytes.

The request is every positive case of `benchmarks/tier2-precision/cases.json` and every true
positive of `benchmarks/tier1-precision/cases.json`, each as a new file, so it spans both tiers
and well over thirty files. It is analysed twice through `analyze_pull_request_payload`, once
with tier 1 held back so tier 2 finishes first and once the other way round, and the two
responses are compared as serialized JSON with key order intact. A response carries no
timestamp today; `_without_timestamps` removes any key that looks like one so that a future
timestamp does not turn this into a test of the clock.

Both tiers' time limits are lifted for the run, which is what a measurement does
(`scripts/replay/replay.py --no-tier1-budget --no-scanner-timeouts`): with them in place, what a
budget removes depends on how busy the machine is, and that is a known, surfaced source of
variation rather than one this test is looking for. The test asserts that no budget or timeout
limitation was recorded, so a run that hit one fails loudly instead of comparing two truncated
answers.

Skipped where the scanner is not installed; the CI analysis job installs it from the pinned
requirements.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

import main
from finding_quality import detector_kind
from opengrep_runner import scanner_available

REPO_ROOT = Path(__file__).resolve().parents[4]
TIER1_CASES = REPO_ROOT / "benchmarks" / "tier1-precision" / "cases.json"
TIER2_CASES = REPO_ROOT / "benchmarks" / "tier2-precision" / "cases.json"

LIFTED = "86400"
TIMESTAMP_KEYS = {"timestamp", "created_at", "updated_at", "analyzed_at", "started_at", "finished_at", "duration_ms"}

pytestmark = pytest.mark.skipif(not scanner_available(), reason="the scanner is not installed here")


def _added_file_patch(text: str) -> str:
    lines = text.splitlines()
    return f"@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{line}\n" for line in lines)


def _files() -> List[Dict[str, Any]]:
    files: List[Dict[str, Any]] = []
    tier2 = json.loads(TIER2_CASES.read_text(encoding="utf-8"))["cases"]
    for case in sorted(tier2, key=lambda item: item["id"]):
        if case["expect"] != "finding":
            continue
        files.append({"path": f"tier2/{case['path']}", "code": case["code"]})
    tier1 = json.loads(TIER1_CASES.read_text(encoding="utf-8"))["true_positives"]
    for case in sorted(tier1, key=lambda item: item["id"]):
        files.append({"path": f"tier1/{case['id']}/{case['path']}", "code": "\n".join(case["snippet"]) + "\n"})
    return files


def _request() -> main.AnalyzePRRequest:
    changed = []
    for entry in _files():
        code = entry["code"]
        changed.append(
            main.ChangedFile(
                path=entry["path"],
                patch=_added_file_patch(code),
                content=code,
                additions=len(code.splitlines()),
                status="added",
                reviewable_line_spans=[{"start": 1, "end": max(1, len(code.splitlines()))}],
            )
        )
    return main.AnalyzePRRequest(
        repository_full_name="determinism/fixture",
        pull_request_number=1,
        commit_sha="d" * 40,
        files=changed,
    )


def _without_timestamps(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _without_timestamps(item) for key, item in value.items() if key not in TIMESTAMP_KEYS}
    if isinstance(value, list):
        return [_without_timestamps(item) for item in value]
    return value


def _serialized(result: Dict[str, Any]) -> str:
    # No sort_keys: the order the service builds its dictionaries in is part of what is compared.
    return json.dumps(_without_timestamps(result), ensure_ascii=False, indent=1)


def _delayed(function, seconds: float):
    def wrapper(*args, **kwargs):
        time.sleep(seconds)
        return function(*args, **kwargs)

    return wrapper


@pytest.fixture(scope="module")
def two_scans():
    """The same request analysed twice, each tier finishing first once. Shared by both tests."""
    with pytest.MonkeyPatch.context() as patch:
        for name in (
            "TIER1_BUDGET_SECONDS",
            "TIER1_FILE_BUDGET_SECONDS",
            "OPENGREP_RULE_TIMEOUT_SECONDS",
            "OPENGREP_PROCESS_TIMEOUT_SECONDS",
        ):
            patch.setenv(name, LIFTED)
        patch.setenv("LLM_TRIAGE_ENABLED", "false")
        request = _request()
        original_tier1 = main.pattern_findings
        original_tier2 = main.run_opengrep_with_limitations

        # Tier 2 finishes first: tier 1 waits before it starts.
        patch.setattr(main, "pattern_findings", _delayed(original_tier1, 0.5))
        first = main.analyze_pull_request_payload(request)

        # Tier 1 finishes first: tier 2 waits before it starts.
        patch.setattr(main, "pattern_findings", original_tier1)
        patch.setattr(main, "run_opengrep_with_limitations", _delayed(original_tier2, 0.5))
        second = main.analyze_pull_request_payload(request)
    return request, first, second


def test_two_scans_of_one_request_are_byte_identical(two_scans):
    request, first, second = two_scans
    assert len(request.files) >= 30

    kinds = {detector_kind(finding) for finding in first["findings"]}
    assert {"deterministic", "opengrep"} <= kinds, f"the fixture must exercise both tiers, got {kinds}"
    assert len(first["findings"]) >= 30

    ceilings = [
        item
        for item in first["analysis_limitations"] + second["analysis_limitations"]
        if item.get("kind") != "partial_parse"
    ]
    assert ceilings == [], f"a time or resource ceiling was reached, so this is not a measurement: {ceilings}"

    one, other = _serialized(first), _serialized(second)
    if one != other:
        # A readable failure: the first differing finding rather than two large strings.
        for index, (a, b) in enumerate(zip(first["findings"], second["findings"])):
            assert a == b, f"finding {index} differs between the two scans"
    assert one == other


def test_supporting_detections_are_sorted_in_a_real_scan(two_scans):
    """Every merged finding lists its supporting rules in sorted order, survivor first."""
    _, result, _ = two_scans
    merged = [finding for finding in result["findings"] if len(finding.get("merged_rule_ids") or []) > 1]
    assert merged, "the fixture must produce at least one merged finding"
    for finding in merged:
        survivor, *rest = finding["merged_rule_ids"]
        assert survivor == finding["rule_id"]
        assert rest == sorted(rest)
