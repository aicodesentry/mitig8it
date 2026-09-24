"""Calling the analysis service in process, with no server and no network hop.

In production the api-service posts to a FastAPI instance over HTTP. Inside the action there is
no second process to post to, so the same function the HTTP route calls is imported and called
directly. The scanning code, the rule files and the tier behaviour are the service's, unchanged;
only the transport is gone.

The module lives on `sys.path` as a flat set of modules, the way its own Dockerfile runs it
(`uvicorn main:app --app-dir src`), so the import is a path insertion rather than a package
import. `main` is imported exactly once per process: it registers Prometheus collectors at module
scope and a second import under another name raises on duplicate timeseries.
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Sequence

ANALYSIS_SRC_ENV = "MITIG8IT_ANALYSIS_SRC"
DEFAULT_ANALYSIS_SRC = "/opt/mitig8it/services/analysis-service/src"


def analysis_src() -> Path:
    """Where the analysis service's modules live in this container."""
    configured = os.environ.get(ANALYSIS_SRC_ENV)
    if configured:
        return Path(configured)
    packaged = Path(DEFAULT_ANALYSIS_SRC)
    if packaged.is_dir():
        return packaged
    # Running from a checkout rather than the image, which is how the unit tests run.
    return Path(__file__).resolve().parents[2] / "services/analysis-service/src"


@lru_cache(maxsize=1)
def _analysis_main():
    source = analysis_src()
    if not (source / "main.py").is_file():
        raise RuntimeError(f"the analysis service was not found at {source}")
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    import main  # noqa: PLC0415  (deliberately deferred: the path must be set first)

    return main


def model_triage_enabled() -> bool:
    """Whether tier 3 will call a model.

    The analysis service treats triage as on unless told otherwise, so the action turns it off
    explicitly whenever the workflow supplied no key. Nothing then leaves the runner.
    """
    disabled = {"0", "false", "no", "off"}
    return os.environ.get("LLM_TRIAGE_ENABLED", "true").strip().lower() not in disabled


def analyze(
    repository_full_name: str,
    pull_request_number: int,
    commit_sha: str,
    files: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Run the review tiers over the changed files and return the findings.

    Tier 2 fails the call closed: a scanner that did not run must never be reported as a scanner
    that found nothing, so an exception here ends the run without publishing a clean result.
    """
    main = _analysis_main()
    request = main.AnalyzePRRequest(
        repository_full_name=repository_full_name,
        pull_request_number=pull_request_number,
        commit_sha=commit_sha,
        files=list(files),
    )
    result = main.analyze_pull_request_payload(request)
    findings = result.get("findings")
    if not isinstance(findings, list):
        raise RuntimeError("Incomplete analysis response: findings missing")
    return findings


def is_informational(finding: Dict[str, Any]) -> bool:
    """True for a finding the review reports but never blocks on.

    Test code is scanned and reported, because a vulnerable helper is still worth seeing, but its
    severity is forced to `info` upstream and it does not count towards the check conclusion.
    """
    if str(finding.get("severity") or "").lower() == "info":
        return True
    extra = (finding.get("evidence_details") or {}).get("extra") or {}
    return bool(extra.get("in_test_code")) or bool(finding.get("in_test_code"))


def severity_counts(findings: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    """Runtime findings by severity. Informational findings are counted separately."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        if is_informational(finding):
            counts["info"] += 1
            continue
        severity = str(finding.get("severity") or "").lower()
        if severity in counts:
            counts[severity] += 1
    return counts
