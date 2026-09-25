"""Shared sandbox execution helpers: scanner report parsing, outcome rules, evidence assembly.

Both the production Kubernetes driver and the development-only local driver use these so a
single definition of "what a check result means" applies to every verification level.
"""
from __future__ import annotations

import json
import os
from typing import Any

MAX_SCANNER_FINDINGS = 500
MAX_FINGERPRINT_CHARS = 200
SCANNER_REPORT_KEY = "mitig8it_scanner_findings"
# A failed check keeps the end of its output, so the agent's `inspect_failure` can see why a
# generated test crashed (an undefined helper, a module it could not load) instead of only an
# exit code. Bounded, and only for failures: passing output is never evidence of anything.
MAX_OUTPUT_TAIL_CHARS = 800


def output_tail(output: str, exit_code: int | None) -> str | None:
    """The last `MAX_OUTPUT_TAIL_CHARS` characters of a failed check's output, else None."""
    if exit_code is None or exit_code == 0:
        return None
    text = output.strip()
    return text[-MAX_OUTPUT_TAIL_CHARS:] if text else ""


def parse_scanner_findings(output: str) -> list[str] | None:
    """Parses the structured scanner report line defined in contracts/repair-v1.md.

    A `scanner` check must print one JSON object line containing
    `{"mitig8it_scanner_findings": ["<fingerprint>", ...]}`. Repository text that does not
    match the contract is not a report: this returns None so the verifier stays honest about
    not having comparable findings rather than assuming there were none.
    """
    found: list[str] | None = None
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{") or SCANNER_REPORT_KEY not in line:
            continue
        try:
            document = json.loads(line)
        except ValueError:
            continue
        if not isinstance(document, dict):
            continue
        fingerprints = document.get(SCANNER_REPORT_KEY)
        if not isinstance(fingerprints, list) or len(fingerprints) > MAX_SCANNER_FINDINGS:
            continue
        if any(not isinstance(item, str) or not item or len(item) > MAX_FINGERPRINT_CHARS for item in fingerprints):
            continue
        found = sorted(set(fingerprints))
    return found


def aggregate_outcome(records: list[dict[str, Any]]) -> str:
    """Deterministic outcome from baseline/candidate check pairs; never optimistic."""
    outcome = "passed"
    for record in records:
        baseline, candidate = record.get("baseline") or {}, record.get("candidate") or {}
        if not baseline.get("completed") or not candidate.get("completed"):
            outcome = "inconclusive"
        elif candidate.get("status") != "passed":
            return "failed"
        elif record["kind"] in {"existing_test", "typecheck", "build", "behavior"} and baseline.get("status") != "passed":
            outcome = "inconclusive"
        elif record["kind"] == "exploit" and baseline.get("status") != "failed":
            return "failed"
    return outcome


def build_evidence(payload: dict[str, Any], result: dict[str, Any], runner: dict[str, Any], verification_level: str) -> dict[str, Any]:
    repository = payload["repository"]
    return {
        "schema_version": "v1",
        "execution_id": payload["execution_id"],
        "request_digest": payload["request_digest"],
        "request_nonce": payload["request_nonce"],
        "outcome": result["outcome"],
        "reason_code": result.get("reason_code"),
        "verification_level": verification_level,
        "original_tree_digest": repository["original_tree_digest"],
        "candidate_tree_digest": repository["candidate_tree_digest"],
        "head_tree_oid": repository["head_tree_oid"],
        "verified_tree_oid": repository["verified_tree_oid"],
        "runner": {"broker_id": os.getenv("SANDBOX_BROKER_ID", "unconfigured"), **runner},
        "checks": result.get("checks", []),
        "coverage_gaps": result.get("coverage_gaps", []),
        # Present on every run, so a reader never has to tell "installed nothing" apart from
        # "came from a driver that does not know about installing". `dependencies_installed`
        # false with no reason code is the ordinary dependency-free run.
        "dependencies": result.get("dependencies") or {"dependencies_installed": False},
    }
