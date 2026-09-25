"""One pull request, one child process.

The parent hands this process a prepared payload and kills it if it overruns the
per-PR wall clock, so a hang or a hard crash in a service costs one pull request
instead of the whole replay. Every stage result, limitation and traceback is written
to the output file as JSON.
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
ANALYSIS_SRC = REPO_ROOT / "services" / "analysis-service" / "src"
REMEDIATION_ROOT = REPO_ROOT / "services" / "remediation-service"

# The replay never calls a model: triage is switched off through the service's own flag.
os.environ.setdefault("LLM_TRIAGE_ENABLED", "false")

for entry in (str(ANALYSIS_SRC), str(REMEDIATION_ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)


def _stage(name: str, fn) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        value = fn()
        return {"stage": name, "ok": True, "value": value, "duration_ms": int((time.perf_counter() - started) * 1000)}
    except BaseException as exc:  # noqa: BLE001 - a replay records every failure shape.
        return {
            "stage": name,
            "ok": False,
            "error_type": type(exc).__name__,
            "error": str(exc)[:1000],
            "traceback": traceback.format_exc()[-4000:],
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }


# --- analysis -------------------------------------------------------------------------------


def run_analysis(payload: dict[str, Any]) -> dict[str, Any]:
    import main as analysis_main  # noqa: PLC0415 - imported inside the child process only.

    if os.environ.get("REPLAY_INCLUDE_QUARANTINED") == "1":
        # A quarantined rule is withheld from a reviewer, not from a measurement. The
        # service drops its findings before returning, so a corpus run that is trying to
        # decide whether a quarantined rule has earned its way back would never see them.
        # The policy is emptied here, in the harness, and `score.py` re-applies it from the
        # rule files, so quarantined findings are reported separately rather than mixed in.
        analysis_main.QUARANTINED_RULE_IDS = frozenset()

    tier1_request = analysis_main.AnalyzePRRequest(
        repository_full_name=payload["repo"],
        pull_request_number=payload["number"],
        commit_sha=payload["head_sha"],
        files=[
            analysis_main.ChangedFile(
                path=item["path"],
                patch=item["patch"],
                additions=item.get("additions", 0),
                deletions=item.get("deletions", 0),
                status=item.get("status", "modified"),
            )
            for item in payload["files"]
        ],
    )
    tier2_request = analysis_main.AnalyzePRRequest(
        repository_full_name=payload["repo"],
        pull_request_number=payload["number"],
        commit_sha=payload["head_sha"],
        files=[
            analysis_main.ChangedFile(
                path=item["path"],
                patch=item["patch"],
                content=item.get("content", ""),
                additions=item.get("additions", 0),
                deletions=item.get("deletions", 0),
                status=item.get("status", "modified"),
                reviewable_line_spans=item.get("reviewable_line_spans", []),
            )
            for item in payload["files"]
        ],
    )

    tier1 = _stage("tier1", lambda: analysis_main.analyze_tier1_payload(tier1_request))
    tier2 = _stage("tier2", lambda: analysis_main.analyze_tier2_payload(tier2_request))

    findings: list[dict[str, Any]] = []
    for result in (tier1, tier2):
        if result["ok"]:
            findings.extend(result["value"]["findings"])

    return {
        "tier1": _strip(tier1),
        "tier2": _strip(tier2),
        "findings": findings,
        "tier3": {"stage": "tier3", "ok": None, "skipped": "no_model_key_llm_triage_disabled"},
    }


def _strip(result: dict[str, Any]) -> dict[str, Any]:
    """The stage record without the findings body, which is reported once at the top level."""
    trimmed = dict(result)
    value = trimmed.pop("value", None)
    if isinstance(value, dict):
        trimmed["finding_count"] = len(value.get("findings", []))
        trimmed["files_analyzed"] = value.get("files_analyzed")
        trimmed["test_files_analyzed"] = value.get("test_files_analyzed")
    return trimmed


# --- remediation ----------------------------------------------------------------------------

SNAPSHOT_BYTE_BUDGET = 4_000_000


class _AgentNeeded(Exception):
    pass


def _refusing_provider(modules: dict[str, Any], counter: dict[str, int]):
    action = modules["ProviderAction"]

    class RefusingProvider:
        """Stands in for the model. Every call is one repair the template path could not make."""

        async def next_action(self, messages, tools):
            counter["agent_calls"] += 1
            return action(
                "abstain",
                {
                    "reason_code": "replay_model_path_disabled",
                    "explanation": "The replay runs the deterministic template path only.",
                },
                input_tokens=0,
                output_tokens=0,
            )

    return RefusingProvider()


def load_remediation_modules() -> dict[str, Any]:
    from src.agent import ProviderAction, RepairAgent  # noqa: PLC0415
    from src.digests import git_blob_sha1  # noqa: PLC0415
    from src.engine import RepairEngine  # noqa: PLC0415
    from src.families import family_supported, language_of_path, rule_family  # noqa: PLC0415
    from src.git_tree import compute_tree_oid  # noqa: PLC0415
    from src.models import FindingSnapshot, GitTreeEntry, RepairRequest  # noqa: PLC0415
    from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver  # noqa: PLC0415
    from src.verification import Verifier  # noqa: PLC0415

    return {
        "ProviderAction": ProviderAction,
        "RepairAgent": RepairAgent,
        "RepairEngine": RepairEngine,
        "FindingSnapshot": FindingSnapshot,
        "GitTreeEntry": GitTreeEntry,
        "RepairRequest": RepairRequest,
        "InProcessSandboxBroker": InProcessSandboxBroker,
        "LocalSubprocessDriver": LocalSubprocessDriver,
        "Verifier": Verifier,
        "compute_tree_oid": compute_tree_oid,
        "git_blob_sha1": git_blob_sha1,
        "family_supported": family_supported,
        "language_of_path": language_of_path,
        "rule_family": rule_family,
    }


def _snapshot_files(modules: dict[str, Any], payload: dict[str, Any], required_path: str) -> list[dict[str, str]]:
    """The affected file first, then the rest of the fetched head content within a byte budget."""
    by_path = {item["path"]: item.get("content", "") for item in payload["files"] if item.get("content")}
    if required_path not in by_path:
        return []
    ordered = [required_path] + sorted(path for path in by_path if path != required_path)
    files: list[dict[str, str]] = []
    total = 0
    for path in ordered:
        content = by_path[path]
        size = len(content.encode("utf-8"))
        if files and total + size > SNAPSHOT_BYTE_BUDGET:
            continue
        files.append({"path": path, "content": content, "sha": modules["git_blob_sha1"](content.encode("utf-8"))})
        total += size
    return files


def _finding_snapshot_payload(finding: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "id": f"replay-{index}",
        "snapshot_id": f"replay-{index}",
        "rule_id": str(finding.get("rule_id") or "")[:200],
        "cwe_id": str(finding.get("cwe_id") or "")[:40],
        "category": str(finding.get("category") or "")[:120],
        "title": str(finding.get("title") or "")[:500],
        "message": str(finding.get("description") or "")[:4000],
        "file_path": finding.get("file_path"),
        "line_start": max(1, int(finding.get("line_start") or 1)),
        "line_end": max(1, int(finding.get("line_end") or finding.get("line_start") or 1)),
    }


def run_remediation(payload: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    import asyncio  # noqa: PLC0415

    modules = load_remediation_modules()
    by_path = {item["path"]: item.get("content", "") for item in payload["files"] if item.get("content")}

    attempted: list[dict[str, Any]] = []
    supported_count = 0
    candidates = 0
    verified = 0
    agent_needed = 0
    limitations: list[str] = []
    exceptions: list[dict[str, Any]] = []

    for index, finding in enumerate(findings):
        path = finding.get("file_path") or ""
        shim = _FindingShim(finding)
        family = modules["rule_family"](shim)
        language = modules["language_of_path"](path)
        if not modules["family_supported"](family, language):
            continue
        supported_count += 1

        if path not in by_path:
            limitations.append("remediation_skipped:head_content_unavailable")
            attempted.append({"finding": finding.get("rule_id"), "path": path, "family": family,
                              "outcome": "skipped", "reason": "head_content_unavailable"})
            continue

        started = time.perf_counter()
        counter = {"agent_calls": 0}
        try:
            outcome = _repair_one(modules, payload, finding, index, family, counter)
        except BaseException as exc:  # noqa: BLE001
            exceptions.append({
                "where": "remediation",
                "path": path,
                "rule_id": finding.get("rule_id"),
                "error_type": type(exc).__name__,
                "error": str(exc)[:1000],
                "traceback": traceback.format_exc()[-4000:],
            })
            continue
        outcome["duration_ms"] = int((time.perf_counter() - started) * 1000)
        outcome["family"] = family
        outcome["path"] = path
        outcome["rule_id"] = finding.get("rule_id")
        if counter["agent_calls"]:
            agent_needed += 1
            outcome["agent_needed"] = True
        if outcome.get("candidate_count"):
            candidates += 1
        if outcome.get("verification_passed"):
            verified += 1
        limitations.extend(outcome.get("limitations", []))
        attempted.append(outcome)

    return {
        "supported_family_findings": supported_count,
        "attempted": attempted,
        "candidates_produced": candidates,
        "verified": verified,
        "agent_needed": agent_needed,
        "limitations": limitations,
        "exceptions": exceptions,
    }


class _FindingShim:
    """`rule_family` reads five attributes off a finding; the analysis dict carries them by key."""

    def __init__(self, finding: dict[str, Any]):
        self.rule_id = finding.get("rule_id") or ""
        self.cwe_id = finding.get("cwe_id") or ""
        self.category = finding.get("category") or ""
        self.title = finding.get("title") or ""
        self.message = finding.get("description") or ""


def _repair_one(
    modules: dict[str, Any],
    payload: dict[str, Any],
    finding: dict[str, Any],
    index: int,
    family: str,
    counter: dict[str, int],
) -> dict[str, Any]:
    import asyncio  # noqa: PLC0415

    path = finding["file_path"]
    files = _snapshot_files(modules, payload, path)
    if not files:
        return {"outcome": "skipped", "reason": "head_content_unavailable"}

    entries = [modules["GitTreeEntry"](path=item["path"], mode="100644", type="blob", sha=item["sha"]) for item in files]
    tree_oid = modules["compute_tree_oid"](entries)

    request = modules["RepairRequest"].model_validate({
        "schema_version": "v1",
        "job_id": f"replay-{payload['repo'].replace('/', '-')}-{payload['number']}-{index}",
        "tenant_id": "replay",
        "repository_id": payload["repo"],
        "head_sha": payload["head_sha"],
        "base_sha": payload["base_sha"],
        "head_tree_oid": tree_oid,
        "tree_entries": [entry.model_dump() for entry in entries],
        "tree_truncated": False,
        "findings": [_finding_snapshot_payload(finding, index)],
        "files": files,
        "profile": {"source": "real_repo_replay"},
        "policy": {
            "policy_version": "replay-template-only-v1",
            "input_usd_per_million_tokens": 1.0,
            "output_usd_per_million_tokens": 1.0,
            "allow_development_verification": True,
            "verification_checks": [],
            "max_tool_calls": 4,
            "max_attempts": 1,
            "max_spend_usd": 0.0,
        },
        "versions": {"replay": "real-repo-replay-v1", "retriever": "v1", "verifier": "v1"},
    })

    def agent_factory(prepared):
        broker = modules["InProcessSandboxBroker"](modules["LocalSubprocessDriver"]())
        verifier = modules["Verifier"](broker)
        return modules["RepairAgent"](_refusing_provider(modules, counter), verifier, None)

    response = asyncio.run(modules["RepairEngine"](agent_factory).repair(request))
    dumped = response.model_dump(mode="json")
    evidence = dumped.get("evidence") or {}
    candidate_list = dumped.get("candidates") or []
    verification_states = [
        (candidate.get("verification") or {}).get("status")
        for candidate in candidate_list
    ]
    groups = evidence.get("groups") or []
    template_report: dict[str, Any] = {}
    for group in groups:
        if isinstance(group, dict) and isinstance(group.get("templates"), dict):
            template_report.update(group["templates"])
    return {
        "outcome": dumped.get("state"),
        "reason": (dumped.get("reason") or {}).get("code"),
        "candidate_count": len(candidate_list),
        "verification_states": verification_states,
        "verification_passed": any(state == "passed" for state in verification_states),
        "verification_level": evidence.get("verification_level"),
        "limitations": [str(item)[:200] for item in (evidence.get("limitations") or [])],
        "skipped": [item.get("code") for item in (dumped.get("skipped") or []) if isinstance(item, dict)],
        "templates": template_report,
    }


# --- entry point ----------------------------------------------------------------------------


def main() -> int:
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out_path = Path(sys.argv[2])

    started = time.perf_counter()
    analysis = run_analysis(payload)
    remediation_result = _stage(
        "remediation",
        lambda: run_remediation(payload, analysis["findings"]) if payload.get("run_remediation", True) else {},
    )

    record = {
        "repo": payload["repo"],
        "number": payload["number"],
        "head_sha": payload["head_sha"],
        "files": len(payload["files"]),
        "files_with_content": sum(1 for item in payload["files"] if item.get("content")),
        "bytes_patch": sum(len(item["patch"].encode("utf-8")) for item in payload["files"]),
        "bytes_content": sum(len(item.get("content", "").encode("utf-8")) for item in payload["files"]),
        "analysis": {key: value for key, value in analysis.items() if key != "findings"},
        "findings": analysis["findings"],
        "remediation": remediation_result.get("value") if remediation_result["ok"] else None,
        "remediation_stage": _strip(remediation_result),
        "limitations": payload.get("limitations", []),
        "duration_ms": int((time.perf_counter() - started) * 1000),
    }
    out_path.write_text(json.dumps(record), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
