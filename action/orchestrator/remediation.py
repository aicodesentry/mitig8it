"""Running the repair engine in process, against local backends only.

The engine is the service's own, imported rather than reimplemented. What the action supplies is
the wiring production gets from its deployment: an in-process sandbox broker over the local
subprocess driver, no execution store, no checkpoints, and a model provider only when the
workflow chose to give one.

Two things about this path deserve to be stated plainly, because they are the honest difference
between the action and the app:

The sandbox is the runner. `LocalSubprocessDriver` runs the repository's checks as ordinary
subprocesses in this container, with a scrubbed environment and no network isolation, kernel
isolation or read-only root. Every candidate it verifies is therefore `development_unverified`,
and the published fix says so in its own words.

Without a model key, the agent loop never runs. The engine builds its agent before the template
pass, so an engine left to construct its own would abort the whole request on a missing key
before a single template was tried. The action passes an agent whose provider abstains, which
makes the template pass the only path that can produce a fix and lets it produce one.
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REMEDIATION_ROOT_ENV = "MITIG8IT_REMEDIATION_ROOT"
DEFAULT_REMEDIATION_ROOT = "/opt/mitig8it/services/remediation-service"

# The engine refuses to run without a per-million-token price, because a repair loop that cannot
# cost what it spends cannot enforce a spend ceiling. On the template-only path nothing is spent;
# the figures below are the list prices the engine needs to compute a bound, not a bill.
DEFAULT_INPUT_USD_PER_MILLION = 1.0
DEFAULT_OUTPUT_USD_PER_MILLION = 1.0

# The engine caps a request at 100 findings. Repairs are attempted for the most severe first.
MAX_REPAIR_FINDINGS = 100
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def remediation_root() -> Path:
    configured = os.environ.get(REMEDIATION_ROOT_ENV)
    if configured:
        return Path(configured)
    packaged = Path(DEFAULT_REMEDIATION_ROOT)
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[2] / "services/remediation-service"


@lru_cache(maxsize=1)
def _modules():
    root = remediation_root()
    if not (root / "src" / "engine.py").is_file():
        raise RuntimeError(f"the remediation service was not found at {root}")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from src import families, git_tree  # noqa: PLC0415
    from src.agent import RepairAgent  # noqa: PLC0415
    from src.agent.provider import ProviderAction  # noqa: PLC0415
    from src.digests import git_blob_sha1  # noqa: PLC0415
    from src.engine import RepairEngine  # noqa: PLC0415
    from src.models import RepairRequest  # noqa: PLC0415
    from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver  # noqa: PLC0415
    from src.verification import Verifier  # noqa: PLC0415

    return {
        "families": families,
        "git_tree": git_tree,
        "git_blob_sha1": git_blob_sha1,
        "RepairAgent": RepairAgent,
        "ProviderAction": ProviderAction,
        "RepairEngine": RepairEngine,
        "RepairRequest": RepairRequest,
        "InProcessSandboxBroker": InProcessSandboxBroker,
        "LocalSubprocessDriver": LocalSubprocessDriver,
        "Verifier": Verifier,
    }


class AbstainingProvider:
    """A model provider that declines every turn.

    Handed to the agent when the workflow supplied no key. The agent loop still runs its
    scaffolding and records an abstention, so a finding no template covers is reported as
    unrepaired rather than crashing the request, and no model is contacted.
    """

    max_output_tokens = 4096

    def __init__(self, provider_action) -> None:
        self._action = provider_action

    async def next_action(self, messages, tools):  # noqa: ARG002 - provider protocol
        return self._action(
            "abstain",
            {
                "reason_code": "model_not_configured",
                "explanation": (
                    "No model key was given to the action, so only template repairs were "
                    "attempted."
                ),
            },
        )


def supported_findings(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The findings the engine has a repair family and a language for.

    Asking it to repair anything else wastes a request and produces a skip record, so the filter
    runs here using the engine's own `rule_family` and `family_supported`.
    """
    modules = _modules()
    families = modules["families"]
    supported: List[Dict[str, Any]] = []
    for finding in findings:
        path = str(finding.get("file_path") or finding.get("path") or "")
        if not path:
            continue
        family = families.rule_family(_finding_view(finding))
        language = families.language_of_path(path)
        if not family or not language:
            continue
        if families.family_supported(family, language):
            supported.append(finding)
    return supported


class _FindingView:
    """The attribute shape `rule_family` reads, over a plain analysis finding dict."""

    def __init__(self, finding: Dict[str, Any]) -> None:
        self.rule_id = str(finding.get("rule_id") or "")
        self.cwe_id = str(finding.get("cwe_id") or "")
        self.category = str(finding.get("category") or "")
        self.title = str(finding.get("title") or "")
        self.message = str(finding.get("description") or finding.get("message") or "")
        self.file_path = str(finding.get("file_path") or finding.get("path") or "")
        self.affected_path = self.file_path


def _finding_view(finding: Dict[str, Any]) -> _FindingView:
    return _FindingView(finding)


def rank_findings(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Most severe first, then by path, matching the order production repairs in."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_RANK.get(str(f.get("severity") or "").lower(), 4),
            str(f.get("file_path") or ""),
            int(f.get("line_start") or 0),
        ),
    )


def build_request(
    *,
    repository_full_name: str,
    pull_request_number: int,
    head_sha: str,
    base_sha: str,
    findings: Sequence[Dict[str, Any]],
    files: Dict[str, str],
    tree_entries: Sequence[Dict[str, Any]],
    tree_truncated: bool,
    model_configured: bool,
):
    """Assemble the engine's request from what the action already read from GitHub.

    Only the files the repair touches are sent as content; the tree entries cover the whole
    commit, because the engine verifies each file's hash against its entry and would otherwise
    have nothing to verify against.
    """
    modules = _modules()
    git_blob_sha1 = modules["git_blob_sha1"]
    compute_tree_oid = modules["git_tree"].compute_tree_oid

    snapshot_files = [
        {"path": path, "content": content, "sha": git_blob_sha1(content)}
        for path, content in sorted(files.items())
    ]
    if not snapshot_files:
        raise ValueError("a repair request needs at least one file")

    entries = [
        {
            "path": str(entry.get("path") or ""),
            "mode": str(entry.get("mode") or ""),
            "type": str(entry.get("type") or ""),
            "sha": str(entry.get("sha") or ""),
        }
        for entry in tree_entries
    ]

    snapshots = []
    for index, finding in enumerate(findings[:MAX_REPAIR_FINDINGS]):
        snapshots.append(
            {
                "snapshot_id": str(finding.get("fingerprint") or f"finding-{index}"),
                "rule_id": str(finding.get("rule_id") or ""),
                "cwe_id": str(finding.get("cwe_id") or ""),
                "category": str(finding.get("category") or ""),
                "title": str(finding.get("title") or ""),
                "message": str(finding.get("description") or ""),
                "file_path": str(finding.get("file_path") or ""),
                "line_start": max(1, int(finding.get("line_start") or 1)),
                "line_end": max(
                    max(1, int(finding.get("line_start") or 1)),
                    int(finding.get("line_end") or finding.get("line_start") or 1),
                ),
            }
        )

    payload = {
        "schema_version": "v1",
        "job_id": f"action-{uuid.uuid4().hex[:16]}",
        "tenant_id": "github-action",
        "repository_id": repository_full_name,
        "repository_full_name": repository_full_name,
        "pull_request_number": pull_request_number,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "findings": snapshots,
        "files": snapshot_files,
        "tree_entries": entries,
        "head_tree_oid": compute_tree_oid(entries),
        "tree_truncated": bool(tree_truncated),
        "versions": {"orchestrator": "action-v1"},
        "policy": {
            # The runner is the sandbox. Nothing here is isolated, and the engine is told so
            # rather than left to assume a production sandbox it does not have.
            "allow_development_verification": True,
            "sandbox_image_digest": None,
            "input_usd_per_million_tokens": DEFAULT_INPUT_USD_PER_MILLION,
            "output_usd_per_million_tokens": DEFAULT_OUTPUT_USD_PER_MILLION,
        },
    }
    if model_configured:
        payload["versions"]["repair_model"] = os.environ.get("REPAIR_LLM_MODEL", "")
    return modules["RepairRequest"].model_validate(payload)


def _agent_factory(model_configured: bool):
    modules = _modules()

    def factory(group_request):  # noqa: ARG001 - engine passes the scoped request
        broker = modules["InProcessSandboxBroker"](modules["LocalSubprocessDriver"]())
        verifier = modules["Verifier"](broker)
        if model_configured:
            from src.agent.provider import OpenAICompatibleProvider  # noqa: PLC0415

            provider = OpenAICompatibleProvider.from_env()
        else:
            provider = AbstainingProvider(modules["ProviderAction"])
        return modules["RepairAgent"](provider, verifier, None)

    return factory


def repair(request, model_configured: bool):
    """Run the engine once and return its response."""
    modules = _modules()
    engine = modules["RepairEngine"](_agent_factory(model_configured))
    return asyncio.run(engine.repair(request, None))


def fix_sections(response, findings_by_id: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Turn engine candidates into the sections the publisher hands to github-service.

    The section shape is the service's own contract, so the published comment is built by the
    same code the app uses. Only single-file, single-region candidates become suggestion blocks;
    the publisher renders the rest as a diff, exactly as it does for the app.
    """
    sections: List[Dict[str, Any]] = []
    for candidate in getattr(response, "candidates", []) or []:
        preview = getattr(candidate, "preview", {}) or {}
        evidence = preview.get("evidence") or {}
        changes = preview.get("changes") or []
        for finding_id in getattr(candidate, "finding_ids", []) or []:
            finding = findings_by_id.get(str(finding_id))
            if not finding:
                continue
            section: Dict[str, Any] = {
                "finding_fingerprint": str(finding_id),
                "candidate_id": str(getattr(candidate, "candidate_id", "")),
                "path": str(finding.get("file_path") or ""),
                "finding_line": int(finding.get("line_start") or 1),
                "verification_level": str(evidence.get("verification_level") or ""),
                "stated_intent": str(getattr(candidate, "intended_behavior", "")),
                "proof": str(evidence.get("summary") or ""),
                "limitations": list(evidence.get("limitations") or []),
                "evidence": [],
                "finding_ids": [str(finding_id)],
            }
            change = _change_for_path(changes, section["path"])
            if change:
                section["unified_diff"] = str(change.get("unified_diff") or "")
            if len(changes) > 1:
                section["not_suggestable_reason"] = "multiple_files"
            sections.append(section)
    return sections


def _change_for_path(changes: Sequence[Dict[str, Any]], path: str) -> Optional[Dict[str, Any]]:
    for change in changes:
        if str(change.get("path") or "") == path:
            return change
    return changes[0] if changes else None
