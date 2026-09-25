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
# A before-and-after measurement runs one fixed finding set through two versions of the
# remediation service, so the service source is a setting rather than a constant. It is the
# working tree's own unless REPLAY_REMEDIATION_ROOT names another checkout of it; nothing else
# about the run changes, so the two columns differ only in the service under measurement.
REMEDIATION_ROOT = Path(os.environ.get("REPLAY_REMEDIATION_ROOT") or (REPO_ROOT / "services" / "remediation-service"))

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


def load_pair_modules() -> dict[str, Any]:
    """The two generators and the verification path, for the per-pair measurement.

    The engine calls exactly these: `generate_proof` and `generate_template` decide the two
    halves, `static_gate` decides which findings ever reach them, and `build_patch_bundle` plus
    `Verifier` are what turns a pair into a run on both trees. Nothing here re-implements any
    of it, so a pair measured here is the pair the engine would have built.
    """
    modules = load_remediation_modules()
    from src.gates import static_gate  # noqa: PLC0415
    from src.patches import PatchPolicyError, build_patch_bundle  # noqa: PLC0415

    try:
        from src.patches import path_forbidden  # noqa: PLC0415
    except ImportError:
        # The base branch refuses a forbidden path inside `build_patch_bundle` instead of
        # exporting the question, so a measurement of it sees the refusal one step later.
        path_forbidden = None
    from src.proofs import GeneratedProof, generate_proof  # noqa: PLC0415
    from src.retrieval import Snapshot, SnapshotError  # noqa: PLC0415
    from src.templates import TemplateFallback, generate_template  # noqa: PLC0415

    modules.update({
        "Snapshot": Snapshot,
        "SnapshotError": SnapshotError,
        "GeneratedProof": GeneratedProof,
        "TemplateFallback": TemplateFallback,
        "PatchPolicyError": PatchPolicyError,
        "build_patch_bundle": build_patch_bundle,
        "generate_proof": generate_proof,
        "generate_template": generate_template,
        "static_gate": static_gate,
        "path_forbidden": path_forbidden,
    })
    return modules


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


# --- pairs ----------------------------------------------------------------------------------

# How much of a check's captured output a pair row keeps. The driver already bounds the output
# and keeps its own tail; this is the tail of that tail, so a table row stays readable.
PAIR_OUTPUT_TAIL_CHARS = 1200


def _pair_check_record(evidence: dict[str, Any], check_id: str) -> dict[str, Any]:
    """One check's baseline and candidate outcome, as the sandbox evidence carries them."""
    for result in evidence.get("checks") or []:
        if isinstance(result, dict) and result.get("check_id") == check_id:
            return result
    return {}


def _pair_variant(result: dict[str, Any], variant: str) -> dict[str, Any]:
    outcome = result.get(variant) if isinstance(result.get(variant), dict) else {}
    tail = outcome.get("output_tail")
    return {
        "completed": outcome.get("completed"),
        # `failed` on the original tree and `passed` on the patched tree is what a pair has to
        # show; anything else is why it does not verify.
        "status": outcome.get("status"),
        "exit_code": outcome.get("exit_code"),
        "reason_code": outcome.get("reason_code"),
        "output_tail": str(tail)[-PAIR_OUTPUT_TAIL_CHARS:] if tail else None,
    }


# A snapshot the remediation service will accept: `max_snapshot_files` is 500 by default, and a
# corpus tree is far larger than that. The budget is spent nearest the finding first, because
# what a proof needs from the rest of the tree is the module its subject imports and the root
# manifest that proves a dependency, both of which are near it or at the root.
PAIR_SNAPSHOT_MAX_FILES = 400
PAIR_ROOT_FILES = ("package.json", "requirements.txt", "setup.py", "pyproject.toml")
# `max_file_bytes` in the default policy. A file over it is refused by the snapshot, so it is
# left out here rather than failing the whole request; a finding in one is skipped outright.
PAIR_MAX_FILE_BYTES = 512_000


def _pair_snapshot_files(modules: dict[str, Any], payload: dict[str, Any], required_path: str) -> list[dict[str, str]]:
    """The affected file, the root manifests, then the rest by directory distance from it."""
    by_path = {
        item["path"]: item.get("content", "")
        for item in payload["files"]
        if item.get("content") and len(item["content"].encode("utf-8")) <= PAIR_MAX_FILE_BYTES
    }
    if required_path not in by_path:
        return []
    home = required_path.rsplit("/", 1)[0] if "/" in required_path else ""

    def distance(path: str) -> tuple[int, str]:
        directory = path.rsplit("/", 1)[0] if "/" in path else ""
        shared = 0
        for left, right in zip(home.split("/"), directory.split("/")):
            if left != right:
                break
            shared += 1
        return (-shared, path)

    first = [required_path] + [name for name in PAIR_ROOT_FILES if name in by_path]
    ordered = first + sorted((path for path in by_path if path not in first), key=distance)
    files: list[dict[str, str]] = []
    total = 0
    for path in ordered:
        content = by_path[path]
        size = len(content.encode("utf-8"))
        if files and (len(files) >= PAIR_SNAPSHOT_MAX_FILES or total + size > SNAPSHOT_BYTE_BUDGET):
            continue
        files.append({"path": path, "content": content, "sha": modules["git_blob_sha1"](content.encode("utf-8"))})
        total += size
    return files


def _pair_request(modules: dict[str, Any], payload: dict[str, Any], finding: dict[str, Any], index: int) -> Any:
    files = _pair_snapshot_files(modules, payload, finding["file_path"])
    if not files:
        return None
    entries = [modules["GitTreeEntry"](path=item["path"], mode="100644", type="blob", sha=item["sha"]) for item in files]
    return modules["RepairRequest"].model_validate({
        "schema_version": "v1",
        "job_id": f"pairs-{payload['repo'].replace('/', '-')}-{index}",
        "tenant_id": "replay",
        "repository_id": payload["repo"],
        "head_sha": payload["head_sha"],
        "base_sha": payload["base_sha"],
        "head_tree_oid": modules["compute_tree_oid"](entries),
        "tree_entries": [entry.model_dump() for entry in entries],
        "tree_truncated": False,
        "findings": [_finding_snapshot_payload(finding, index)],
        "files": files,
        "profile": {"source": "pairs_measurement"},
        "policy": {
            "policy_version": "replay-pairs-v1",
            "input_usd_per_million_tokens": 1.0,
            "output_usd_per_million_tokens": 1.0,
            "allow_development_verification": True,
            "verification_checks": [],
            "max_tool_calls": 4,
            "max_attempts": 1,
            "max_spend_usd": 0.0,
            # With the install on, the loadability gate stops refusing a package the
            # repository's own manifest declares, because the workspace will carry it.
            "install_dependencies": bool(payload.get("install_dependencies")),
        },
        "versions": {"replay": "replay-pairs-v1", "retriever": "v1", "verifier": "v1"},
    })


def _measure_pair(modules: dict[str, Any], request: Any, snapshot: Any, template: Any, proof: Any) -> dict[str, Any]:
    """Runs one finding's proof against the original tree and against its templated repair.

    This is the engine's own template pass narrowed to one finding: the same bundle builder, the
    same verifier, the same local sandbox. What it adds is that the two tree outcomes are
    reported separately instead of collapsing into one verdict, because the question here is
    which of the two a pair fails on.
    """
    import asyncio  # noqa: PLC0415

    try:
        bundle = modules["build_patch_bundle"](request, snapshot, template.changes, [proof.spec()])
    except modules["PatchPolicyError"] as exc:
        return {"verified": False, "verifier_reason": f"patch_policy:{exc.code}", "limitations": [], "original": {}, "patched": {}}

    broker = modules["InProcessSandboxBroker"](modules["LocalSubprocessDriver"]())
    verification = asyncio.run(modules["Verifier"](broker).verify(request, snapshot, bundle))
    evidence = verification.evidence if isinstance(verification.evidence, dict) else {}
    finding_id = request.findings[0].stable_id
    check_id = verification.regression_checks.get(finding_id)
    result = _pair_check_record(evidence, check_id) if check_id else {}
    unproven = {item.get("finding_id"): item for item in verification.unproven_findings}
    verdict = unproven.get(finding_id) or {}
    return {
        "verified": finding_id in verification.proven_finding_ids,
        "status": verification.status,
        "verifier_reason": verdict.get("code") or verification.reason_code,
        "verifier_message": verdict.get("message"),
        "verification_level": verification.verification_level,
        "limitations": [str(item)[:200] for item in verification.limitations],
        "proof_path": proof.path,
        # The proof and the repair themselves, because a pair that does not verify is diagnosed
        # by reading them side by side and nothing else in the record carries them.
        "proof_content": proof.content,
        "proof_description": proof.description,
        "patch_description": template.description,
        "patch_changes": template.changes,
        "check_argv": list(result.get("argv") or []),
        "original": _pair_variant(result, "baseline"),
        "patched": _pair_variant(result, "candidate"),
    }


# One repository's dependencies are installed once and every one of its workspaces is pointed at
# the result. A pair materializes the workspace twice per check and a repository has dozens of
# pairs, so installing per workspace here would cost hours per repository and measure nothing the
# one install does not. The service itself installs per workspace, which is the isolation this
# measurement gives up in order to be runnable.
DEPENDENCY_INSTALL_TIMEOUT_SECONDS = 600
DEPENDENCY_INSTALL_MAX_BYTES = 4_000_000_000
INSTALL_MARKER = ".mitig8it-dependencies.json"


def install_repository_dependencies(payload: dict[str, Any]) -> dict[str, Any]:
    """Installs the pinned tree's declared dependencies and tells the local driver where they are.

    The install is the remediation service's own `install_dependencies`, so what is measured here
    is what `policy.install_dependencies` does rather than a harness approximation of it. The
    result is cached beside the tree by the lockfile digest, because a rerun over the same cache
    must not pay for the same `npm ci` again.
    """
    from src.sandbox.dependencies import (  # noqa: PLC0415
        DEPENDENCY_ROOTS_ENV,
        NODE_MODULES,
        VENV_DIRECTORY,
        install_dependencies,
    )

    tree = Path(payload["dependency_tree"])
    marker = tree / INSTALL_MARKER
    if marker.is_file():
        record = json.loads(marker.read_text(encoding="utf-8"))
        record["cached"] = True
    else:
        started = time.perf_counter()
        result = install_dependencies(tree, DEPENDENCY_INSTALL_TIMEOUT_SECONDS, DEPENDENCY_INSTALL_MAX_BYTES)
        record = result.as_dict()
        record["site_packages"] = list(result.site_packages)
        record["cached"] = False
        record["wall_ms"] = int((time.perf_counter() - started) * 1000)
        marker.write_text(json.dumps(record), encoding="utf-8")

    roots: dict[str, Any] = {}
    if (tree / NODE_MODULES).is_dir():
        roots[NODE_MODULES] = str(tree / NODE_MODULES)
    site_packages = [item for item in (record.get("site_packages") or []) if Path(item).is_dir()]
    if not site_packages:
        site_packages = [str(path) for path in sorted((tree / VENV_DIRECTORY).glob("lib/python*/site-packages"))]
    if site_packages:
        roots["site_packages"] = site_packages
    record["roots"] = roots
    if roots:
        os.environ[DEPENDENCY_ROOTS_ENV] = json.dumps(roots)
    return record


def run_pairs(payload: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Both halves per finding, and the two tree outcomes for every finding that has both.

    The reach counts (a template patch, a service proof, both) come from calling the two
    generators over the same fixed finding set, which is the only way to compare them without
    the scanner's run-to-run variation in the way. A finding with both halves then has its proof
    run on the original tree and on the patched tree.
    """
    modules = load_pair_modules()
    install: dict[str, Any] = {"dependencies_installed": False}
    if payload.get("install_dependencies") and payload.get("dependency_tree"):
        install = install_repository_dependencies(payload)
    by_path = {item["path"]: item.get("content", "") for item in payload["files"] if item.get("content")}

    rows: list[dict[str, Any]] = []
    counts = {"supported": 0, "patch": 0, "proof": 0, "both": 0, "verified": 0}
    exceptions: list[dict[str, Any]] = []

    for index, finding in enumerate(findings):
        path = finding.get("file_path") or ""
        shim = _FindingShim(finding)
        family = modules["rule_family"](shim)
        language = modules["language_of_path"](path)
        if not family or not language or not modules["family_supported"](family, language):
            continue
        if path not in by_path:
            continue
        counts["supported"] += 1

        row: dict[str, Any] = {
            "repo": payload["repo"],
            "ref": payload["head_sha"],
            "path": path,
            "line_start": finding.get("line_start"),
            "rule_id": finding.get("rule_id"),
            "family": family,
            "language": language,
        }
        try:
            request = _pair_request(modules, payload, finding, index)
            if request is None:
                row["skipped"] = "head_content_unavailable"
                rows.append(row)
                continue
            snapshot = modules["Snapshot"](request)
            snapshot_finding = request.findings[0]
            if modules["path_forbidden"] is not None and modules["path_forbidden"](path, request):
                row["skipped"] = "protected_path"
                rows.append(row)
                continue
            gate = modules["static_gate"](snapshot, snapshot_finding, family, language)
            if gate is not None:
                row["skipped"] = f"static_gate:{gate[0]}"
                rows.append(row)
                continue
            proof = modules["generate_proof"](snapshot, snapshot_finding, family, language)
            template = modules["generate_template"](snapshot, snapshot_finding, family, language)
            has_proof = isinstance(proof, modules["GeneratedProof"])
            has_patch = not isinstance(template, modules["TemplateFallback"])
            row["proof"] = "yes" if has_proof else f"no:{proof.reason}"
            row["patch"] = "yes" if has_patch else f"no:{template.reason}"
            counts["patch"] += int(has_patch)
            counts["proof"] += int(has_proof)
            if not (has_patch and has_proof):
                rows.append(row)
                continue
            counts["both"] += 1
            started = time.perf_counter()
            row["pair"] = _measure_pair(modules, request, snapshot, template, proof)
            row["pair"]["duration_ms"] = int((time.perf_counter() - started) * 1000)
            counts["verified"] += int(bool(row["pair"]["verified"]))
        except BaseException as exc:  # noqa: BLE001 - a measurement records every failure shape.
            row["error"] = {"type": type(exc).__name__, "message": str(exc)[:500]}
            exceptions.append({"path": path, "rule_id": finding.get("rule_id"),
                               "error_type": type(exc).__name__, "traceback": traceback.format_exc()[-4000:]})
        rows.append(row)

    return {"counts": counts, "rows": rows, "exceptions": exceptions, "install": install}


# --- entry point ----------------------------------------------------------------------------


def main() -> int:
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out_path = Path(sys.argv[2])

    if payload.get("mode") == "pairs":
        result = _stage("pairs", lambda: run_pairs(payload, payload["findings"]))
        out_path.write_text(json.dumps({
            "repo": payload["repo"],
            "ref": payload["head_sha"],
            "pairs": result.get("value") if result["ok"] else None,
            "pairs_stage": _strip(result),
        }), encoding="utf-8")
        return 0

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
