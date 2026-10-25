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
from typing import Any, Dict, List, Sequence

from . import analysis, inline_fixes

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

# Files the engine reads besides the ones it repairs: dependency manifests and lockfiles decide
# which imports a repair may add and what the sandbox installs. They travel with the request when
# the pull request carries them; every other file without a repairable finding stays behind.
DEPENDENCY_FILE_NAMES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
        "pdm.lock",
        "uv.lock",
    }
)


def _is_dependency_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return name in DEPENDENCY_FILE_NAMES or (name.startswith("requirements") and name.endswith(".txt"))


def request_files(files: Dict[str, str], findings: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    """The files a repair request carries: those with a repairable finding, and dependency files.

    Sending every file in the pull request meant one file the action could not read faithfully
    (not UTF-8, or too large for the contents API) was in every request. Its content no longer
    matched its blob, and the engine refused the whole request, so no file was repaired.
    """
    wanted = {str(finding.get("file_path") or "") for finding in findings}
    return {
        path: content
        for path, content in files.items()
        if path in wanted or _is_dependency_file(path)
    }


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
    from src import families, git_tree, proofs  # noqa: PLC0415
    from src.agent import RepairAgent  # noqa: PLC0415
    from src.agent.provider import ProviderAction  # noqa: PLC0415
    from src.digests import git_blob_sha1  # noqa: PLC0415
    from src.engine import RepairEngine  # noqa: PLC0415
    from src.models import GitTreeEntry, RepairRequest  # noqa: PLC0415
    from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver  # noqa: PLC0415
    from src.verification import Verifier  # noqa: PLC0415

    return {
        "families": families,
        "proofs": proofs,
        "git_tree": git_tree,
        "git_blob_sha1": git_blob_sha1,
        "RepairAgent": RepairAgent,
        "ProviderAction": ProviderAction,
        "RepairEngine": RepairEngine,
        "RepairRequest": RepairRequest,
        "GitTreeEntry": GitTreeEntry,
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
    head_tree_oid: str | None = None,
):
    """Assemble the engine's request from what the action already read from GitHub.

    Only the files with a repairable finding, and the dependency files beside them, are sent as
    content; the tree entries cover the whole commit, because the engine verifies each file's
    hash against its entry and would otherwise have nothing to verify against.

    `head_tree_oid` is the tree sha GitHub reported for the head commit. The engine checks the
    entries against it, which is what binds them to the commit. Without it the oid is computed
    from the same entries it is then checked against, which binds nothing; that fallback stays
    only until every caller passes the sha.
    """
    modules = _modules()
    git_blob_sha1 = modules["git_blob_sha1"]
    compute_tree_oid = modules["git_tree"].compute_tree_oid

    # git_blob_sha1 hashes the bytes git would store, so the text is encoded first. The engine
    # checks each of these against the commit's tree entry and refuses the findings in any file
    # that differs, which is what stops a repair being built against content the commit never had.
    snapshot_files = [
        {"path": path, "content": content, "sha": git_blob_sha1(content.encode("utf-8"))}
        for path, content in sorted(request_files(files, findings[:MAX_REPAIR_FINDINGS]).items())
    ]
    if not snapshot_files:
        raise ValueError("a repair request needs at least one file")

    # compute_tree_oid reads the entries as models, so they are validated here rather than
    # passed through as the dicts the REST API returned.
    entry_model = modules["GitTreeEntry"]
    entries = [
        entry_model.model_validate(
            {
                "path": str(entry.get("path") or ""),
                "mode": str(entry.get("mode") or ""),
                "type": str(entry.get("type") or ""),
                "sha": str(entry.get("sha") or ""),
            }
        )
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
        "tree_entries": [entry.model_dump() for entry in entries],
        "head_tree_oid": str(head_tree_oid) if head_tree_oid else compute_tree_oid(entries),
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
    same code the app uses. What decides whether that code can render a suggestion block is
    `hunk`: `suggestionFor` in githubInternalOperations.js refuses without one and the comment
    falls back to a fenced diff. This builder therefore does what `buildSections` in
    services/api-service/src/services/remediationInlineFixes.js does, using the same ported
    geometry: the candidate's change in the finding's file is split into its contiguous regions,
    the region on the finding's line becomes the hunk, and the rest travel as extra hunks that
    github-service publishes as suggestions of their own where the diff shows their lines.

    The `not_suggestable_reason` values are the App's, in the App's order of precedence, so the
    sentence a reader gets when a fix cannot be a suggestion says the same thing in both products.
    """
    sections: List[Dict[str, Any]] = []
    for candidate in getattr(response, "candidates", []) or []:
        preview = getattr(candidate, "preview", {}) or {}
        evidence = preview.get("evidence") or {}
        changes = list(preview.get("changes") or [])
        # The App publishes the whole candidate's diff under each of its findings, truncated
        # once, rather than only the part that touches the finding's own file.
        unified_diff = inline_fixes.truncate_diff(
            "\n".join(
                str(change.get("unified_diff") or "")
                for change in changes
                if change.get("unified_diff")
            )
        )
        # The level decides which proof sentence is true: a static assertion ran no test.
        level = str(
            getattr(candidate, "verification_level", "") or evidence.get("verification_level") or ""
        )
        for finding_id in getattr(candidate, "finding_ids", []) or []:
            finding = findings_by_id.get(str(finding_id))
            if not finding:
                continue
            path = str(finding.get("file_path") or "")
            finding_line = int(finding.get("line_start") or 1)
            hunk, extra_hunks, reason = _hunks_for_finding(changes, path, finding_line)
            sections.append(
                {
                    "finding_fingerprint": str(finding_id),
                    "candidate_id": str(getattr(candidate, "candidate_id", "")),
                    "path": path,
                    "finding_line": finding_line,
                    "hunk": hunk,
                    "extra_hunks": extra_hunks,
                    "unified_diff": unified_diff,
                    "not_suggestable_reason": reason,
                    "verification_level": level,
                    "stated_intent": str(getattr(candidate, "intended_behavior", "")),
                    "proof": inline_fixes.proof_line(evidence, finding, level),
                    "limitations": [str(item) for item in (evidence.get("limitations") or [])],
                    "evidence": inline_fixes.evidence_lines(evidence, level),
                    "finding_ids": [str(finding_id)],
                }
            )
    return sections


def _hunks_for_finding(
    changes: Sequence[Dict[str, Any]],
    path: str,
    finding_line: int,
):
    """The App's `buildSections` decision, in its own order.

    A candidate that does not touch the finding's file cannot be a suggestion on it; one that
    touches several files cannot be applied by a suggestion at all. For one file, the suggestion
    spans every changed region so the click applies exactly what verification evaluated.
    """
    change = next((item for item in changes if str(item.get("path") or "") == path), None)
    if change is None:
        return None, [], "changes_other_file"
    if len(changes) > 1:
        return None, [], "multiple_files"
    hunk = inline_fixes.compute_hunk(
        change.get("original"), change.get("replacement"), finding_line
    )
    if not hunk:
        return None, [], "no_line_change"
    return hunk, [], ""


# The engine's own sentence for a finding outside every family, so the action and the App say the
# same thing about the same finding.
OUTSIDE_FAMILIES_MESSAGE = "This finding is outside the enabled repair families."
# How many modules beyond the changed files one run may read to let a proof load its subject.
MAX_LOCAL_IMPORTS = 50


def with_local_imports(files: Dict[str, str], tree_paths, fetch) -> Dict[str, str]:
    """`files` plus every local module they load, read with `fetch(paths) -> {path: text}`.

    The action reads only the changed files, and the sandbox materializes only what the request
    carries, so a JavaScript module that requires an unchanged sibling (`require('./db')`) cannot
    load in a proof, and its finding is refused. The closure is followed through the same
    specifiers and resolution the proof's loadability check uses, bounded by `MAX_LOCAL_IMPORTS`.
    """
    resolve = _modules()["proofs"].js_local_import_paths
    paths = set(tree_paths)
    merged = dict(files)
    pending = dict(files)
    fetched = 0
    while pending and fetched < MAX_LOCAL_IMPORTS:
        wanted: List[str] = []
        for path, text in pending.items():
            for found in resolve(path, text, paths):
                if found not in merged and found not in wanted:
                    wanted.append(found)
        wanted = wanted[: MAX_LOCAL_IMPORTS - fetched]
        if not wanted:
            break
        got = fetch(wanted) or {}
        fetched += len(wanted)
        pending = {path: text for path, text in got.items() if path not in merged}
        merged.update(pending)
    return merged


def no_fix_sections(
    findings: Sequence[Dict[str, Any]],
    sections: Sequence[Dict[str, Any]],
    *,
    skipped: Sequence[Dict[str, Any]] = (),
    fallback: str,
) -> List[Dict[str, Any]]:
    """One `No automatic fix` section for each reported finding that has no fix section.

    The reason is the engine's own when it gave one (`response.skipped`), the engine's sentence
    for a finding outside every family when the action never sent it, and otherwise `fallback`,
    the run's reason (the engine's response-level reason, or why no repair was attempted).
    Informational findings are not repaired and get nothing, as in the App. github-service
    renders a section with `skipped_reason` and no `candidate_id` as that one line.
    """
    covered = {str(section.get("finding_fingerprint") or "") for section in sections}
    reasons = {str(item.get("finding_id") or ""): str(item.get("message") or item.get("code") or "") for item in skipped or []}
    try:
        supported = {str(item.get("fingerprint") or "") for item in supported_findings(findings)}
    except RuntimeError:
        supported = {str(item.get("fingerprint") or "") for item in findings}
    out: List[Dict[str, Any]] = []
    for finding in findings:
        fingerprint = str(finding.get("fingerprint") or "")
        if not fingerprint or fingerprint in covered or analysis.is_informational(finding):
            continue
        covered.add(fingerprint)
        reason = reasons.get(fingerprint) or (OUTSIDE_FAMILIES_MESSAGE if fingerprint not in supported else "") or fallback
        out.append(
            {
                "finding_fingerprint": fingerprint,
                "candidate_id": "",
                "path": str(finding.get("file_path") or ""),
                "finding_line": int(finding.get("line_start") or 0),
                "hunk": None,
                "extra_hunks": [],
                "unified_diff": "",
                "not_suggestable_reason": "",
                "skipped_reason": reason[:500],
                "finding_ids": [fingerprint],
            }
        )
    return out
