from __future__ import annotations

import json
import re
from typing import Any, Callable

from dataclasses import dataclass

from .agent import OpenAICompatibleProvider, ProviderError, RepairAgent
from .agent.checkpoint import AgentCheckpointStore, GroupScopedCheckpointStore
from .batch import BatchPolicyError, ImmutableBatch, build_immutable_batch
from .digests import digest_json
from .git_tree import GitTreeError, compute_tree_oid, validate_snapshot_tree
from .grouping import group_findings
from .models import Candidate, FindingSnapshot, RepairPolicy, RepairRequest, RepairResponse, VerificationSummary
from .patches import PatchBundle, PatchPolicyError, bundles_conflict, combine_patch_bundles
from .retrieval import Snapshot, SnapshotError
from .sandbox import BrokerConfigurationError, HttpSandboxBroker
from . import telemetry
from .verification import VerificationResult, Verifier
from .verification.verifier import DEVELOPMENT_VERIFICATION_LEVEL, VERIFICATION_LEVELS

AgentFactory = Callable[[RepairRequest], RepairAgent]

# Per-group floors for the job budget split. A group that cannot be given at least this much
# of the remaining budget is not launched at all: a half-funded agent loop would burn budget
# and abstain, which is worse than an explicit, attributable `budget_exhausted` reason.
GROUP_TOOL_CALL_FLOOR = 4
GROUP_TOKEN_FLOOR = 4_000
GROUP_SPEND_FLOOR_USD = 0.02
BUDGET_EXHAUSTED_MESSAGE = (
    "The job's remaining tool, token, and spend budget was below the per-group floor, so no "
    "agent was launched for this finding group."
)


def _rule_family(finding: Any) -> str | None:
    text = " ".join(
        str(value or "")
        for value in (finding.rule_id, finding.cwe_id, finding.category, finding.title, finding.message)
    ).lower()
    if "cwe-89" in text or "sql injection" in text:
        return "sql_parameterization"
    if "cwe-78" in text or "command injection" in text:
        return "command_arguments"
    if "cwe-22" in text or "path traversal" in text or "path containment" in text:
        return "path_containment"
    return None


def _reason_response(
    request: RepairRequest,
    state: str,
    code: str,
    message: str,
    request_digest: str,
    context_digest: str | None = None,
    extra_evidence: dict[str, Any] | None = None,
) -> RepairResponse:
    return RepairResponse(
        state=state,
        job_id=request.job_id,
        tenant_id=request.tenant_id,
        repository_id=request.repository_id,
        head_sha=request.head_sha,
        base_sha=request.base_sha,
        request_digest=request_digest,
        evidence={"context_manifest_digest": context_digest, "verification_level": "none", **(extra_evidence or {})},
        reason={"code": code, "message": message},
    )


@dataclass(frozen=True)
class GroupOutcome:
    """What one connected finding group produced, whether or not it reached a candidate."""

    index: int
    finding_ids: list[str]
    state: str
    reason_code: str | None
    message: str | None
    candidate: Candidate | None
    bundle: PatchBundle | None
    verification: VerificationResult | None
    trace: list[dict[str, Any]]
    usage: dict[str, Any]
    agent_ran: bool

    def report(self) -> dict[str, Any]:
        return {
            "group_index": self.index,
            "finding_ids": self.finding_ids,
            "state": self.state,
            "reason": None if self.reason_code is None else {"code": self.reason_code, "message": self.message},
            "candidate_id": self.candidate.candidate_id if self.candidate else None,
        }


def _split_budget(total: int, groups: int, remaining: int, floor: int) -> int:
    """An even share with a floor, never more than the job total or what is still unspent."""
    return max(1, min(total, remaining, max(floor, total // groups)))


def _split_spend(total: float, groups: int, remaining: float, floor: float) -> float:
    return min(total, remaining, max(floor, total / groups))


def _group_request(
    request: RepairRequest,
    group: list[FindingSnapshot],
    groups: int,
    remaining_tool_calls: int,
    remaining_tokens: int,
    remaining_usd: float,
) -> RepairRequest:
    policy: RepairPolicy = request.policy.model_copy(
        update={
            "max_tool_calls": _split_budget(request.policy.max_tool_calls, groups, remaining_tool_calls, GROUP_TOOL_CALL_FLOOR),
            "max_total_tokens": _split_budget(request.policy.max_total_tokens, groups, remaining_tokens, GROUP_TOKEN_FLOOR),
            "max_spend_usd": _split_spend(request.policy.max_spend_usd, groups, remaining_usd, GROUP_SPEND_FLOOR_USD),
        }
    )
    return request.model_copy(update={"findings": list(group), "policy": policy})


def _aggregate_usage(outcomes: list[GroupOutcome]) -> dict[str, Any]:
    request_ids: list[str] = []
    for outcome in outcomes:
        request_ids.extend(outcome.usage.get("provider_request_ids") or [])
    return {
        "input_tokens": sum(int(outcome.usage.get("input_tokens", 0) or 0) for outcome in outcomes),
        "output_tokens": sum(int(outcome.usage.get("output_tokens", 0) or 0) for outcome in outcomes),
        "provider_request_ids": request_ids,
    }


@dataclass(frozen=True)
class CombinedVerification:
    bundle: PatchBundle
    verified_tree_oid: str
    verification: VerificationResult


async def combine_and_verify(
    request: RepairRequest,
    snapshot: Snapshot,
    verifier: Verifier,
    entries: list[tuple[Candidate, PatchBundle, VerificationResult]],
) -> CombinedVerification:
    """Produces the tree the batch would apply, and the verification run that covers it.

    A single candidate was already verified on exactly its own tree, so its evidence stands.
    Two or more candidates are combined into one tree and verified again on that combination,
    because independent per-candidate evidence never covers their interaction.
    """
    if not entries:
        raise PatchPolicyError("batch_contains_no_candidates")
    if len(entries) == 1:
        candidate, bundle, verification = entries[0]
        return CombinedVerification(bundle, candidate.verified_tree_oid, verification)
    combined = combine_patch_bundles(request, snapshot, [bundle for _, bundle, _ in entries])
    verified_tree_oid = compute_tree_oid(
        request.tree_entries,
        {patch.path: patch.replacement_content for patch in combined.patches},
    )
    verification = await verifier.verify(request, snapshot, combined)
    return CombinedVerification(combined, verified_tree_oid, verification)


async def build_verified_batch(
    request: RepairRequest,
    snapshot: Snapshot,
    verifier: Verifier,
    entries: list[tuple[Candidate, PatchBundle, VerificationResult]],
) -> tuple[ImmutableBatch, CombinedVerification]:
    with telemetry.stage_span("verification", **telemetry.request_attributes(request)) as span:
        combined = await combine_and_verify(request, snapshot, verifier, entries)
        telemetry.record_outcome(
            span,
            combined.verification.status,
            None if combined.verification.status == "passed" else combined.verification.reason_code,
        )
    if combined.verification.status != "passed" or not combined.verification.evidence_digest:
        raise BatchPolicyError(combined.verification.reason_code or "combined_tree_verification_failed")
    with telemetry.stage_span("batch", **telemetry.request_attributes(request)) as span:
        batch = build_immutable_batch(
            request,
            snapshot.manifest_digest,
            [candidate for candidate, _, _ in entries],
            combined.verified_tree_oid,
            combined.verification.evidence_digest,
        )
        telemetry.record_outcome(span, "built")
    return batch, combined


def _build_candidate(request: RepairRequest, snapshot: Snapshot, finding_ids: list[str], result: Any) -> Candidate:
    """Builds the immutable candidate for one connected finding group.

    `finding_ids` are exactly the group's findings, so a candidate always states which findings
    its evidence covers rather than every finding the job carried.
    """
    candidate_id = digest_json(
        {
            "job_id": request.job_id,
            "finding_ids": finding_ids,
            "artifact_digest": result.bundle.artifact_digest,
            "evidence_digest": result.verification.evidence_digest,
        }
    )
    verified_tree_oid = compute_tree_oid(
        request.tree_entries,
        {patch.path: patch.replacement_content for patch in result.bundle.patches},
    )
    return Candidate(
        candidate_id=candidate_id,
        finding_ids=finding_ids,
        hypothesis=result.proposal["hypothesis"],
        intended_behavior=result.proposal["intended_behavior"],
        assumptions=result.proposal["assumptions"],
        citations=result.proposal["citations"],
        patch=list(result.bundle.patches),
        file_manifest=result.bundle.file_manifest,
        artifact_digest=result.bundle.artifact_digest,
        context_manifest_digest=snapshot.manifest_digest,
        verified_tree_oid=verified_tree_oid,
        verification=VerificationSummary(status="passed", evidence_digest=result.verification.evidence_digest),
        preview={
            "changes": [
                {
                    "path": patch.path,
                    "original": snapshot.full_content(patch.path),
                    "replacement": patch.replacement_content,
                    "unified_diff": patch.unified_diff,
                    "new_sha256": patch.new_sha256,
                }
                for patch in result.bundle.patches
            ],
            "rationale": result.proposal["hypothesis"],
            "reasoning": {
                "hypothesis": result.proposal["hypothesis"],
                "intended_behavior": result.proposal["intended_behavior"],
                "assumptions": result.proposal["assumptions"],
            },
            "evidence": {
                "status": "passed",
                "evidence_digest": result.verification.evidence_digest,
                "verified_tree_oid": verified_tree_oid,
                # Per-candidate, not per-response: the API persists this level on the
                # candidate row and the finding view renders this candidate's limitations.
                "verification_level": result.verification.verification_level,
                "limitations": list(result.verification.limitations)
                + [item for item in result.bundle.limitations if item not in result.verification.limitations],
            },
        },
    )


class RepairEngine:
    def __init__(self, agent_factory: AgentFactory | None = None):
        self.agent_factory = agent_factory

    def _default_agent(self, request: RepairRequest, checkpoints: AgentCheckpointStore | None = None) -> RepairAgent:
        expected_model = request.versions.get("repair_model")
        provider = OpenAICompatibleProvider.from_env(expected_model)
        provider.max_output_tokens = min(provider.max_output_tokens, request.policy.max_output_tokens_per_call)
        broker = HttpSandboxBroker.from_env()
        return RepairAgent(provider, Verifier(broker), checkpoints)

    async def repair(self, request: RepairRequest, checkpoints: AgentCheckpointStore | None = None) -> RepairResponse:
        request_digest = digest_json(request.model_dump(mode="json"))
        with telemetry.stage_span("snapshot_bind", **telemetry.request_attributes(request)):
            try:
                snapshot = Snapshot(request)
            except SnapshotError as exc:
                return _reason_response(request, "unsupported", "invalid_snapshot", str(exc), request_digest)
            if request.tree_truncated or not request.head_tree_oid or not request.tree_entries:
                return _reason_response(request, "unsupported", "complete_git_tree_required", "A complete, non-truncated head Git tree is required for an applicable repair.", request_digest, snapshot.manifest_digest)
            if request.policy.input_usd_per_million_tokens <= 0 or request.policy.output_usd_per_million_tokens <= 0:
                return _reason_response(request, "unsupported", "provider_pricing_missing", "Versioned provider pricing is required for spend enforcement.", request_digest, snapshot.manifest_digest)
            try:
                validate_snapshot_tree(
                    request.tree_entries,
                    request.head_tree_oid,
                    {path: snapshot.full_content(path) for path in snapshot.paths},
                )
            except GitTreeError as exc:
                return _reason_response(request, "unsupported", "invalid_git_tree", str(exc), request_digest, snapshot.manifest_digest)

        with telemetry.stage_span("retrieval", **telemetry.request_attributes(request)):
            families = {_rule_family(finding) for finding in request.findings}
            if None in families:
                return _reason_response(request, "unsupported", "unsupported_rule_family", "At least one finding is outside the enabled repair families.", request_digest, snapshot.manifest_digest)
            if not families.issubset(set(request.policy.allowed_rule_families)):
                return _reason_response(request, "unsupported", "rule_family_disabled", "The repair family is disabled by policy.", request_digest, snapshot.manifest_digest)
            for finding in request.findings:
                if not finding.affected_path or finding.affected_path not in snapshot.paths:
                    return _reason_response(request, "unsupported", "affected_source_missing", "The exact affected source file is absent from the snapshot.", request_digest, snapshot.manifest_digest)
            if not any(path.rsplit(".", 1)[-1].lower() in {"js", "jsx", "ts", "tsx", "mjs", "cjs"} for path in snapshot.paths):
                return _reason_response(request, "unsupported", "unsupported_language", "No JavaScript or TypeScript application source was supplied.", request_digest, snapshot.manifest_digest)
            if "sql_parameterization" in families:
                pg_present = False
                for path in snapshot.paths:
                    if path.rsplit("/", 1)[-1] != "package.json":
                        continue
                    try:
                        manifest = json.loads(snapshot.full_content(path))
                    except (TypeError, ValueError):
                        continue
                    dependencies = {**(manifest.get("dependencies") or {}), **(manifest.get("devDependencies") or {})}
                    pg_present = pg_present or "pg" in dependencies
                if not pg_present:
                    return _reason_response(request, "unsupported", "pg_dependency_not_proven", "SQL auto-repair requires an exact package manifest proving the pg driver.", request_digest, snapshot.manifest_digest)
            if "command_arguments" in families:
                for finding in request.findings:
                    if _rule_family(finding) != "command_arguments" or not finding.line_start:
                        continue
                    hit = snapshot.read(finding.affected_path, max(1, finding.line_start - 3), (finding.line_end or finding.line_start) + 3)
                    if re.search(r"\b(?:exec|spawn)\s*\([^\n]*(?:\||shell\s*:\s*true)", hit.content):
                        return _reason_response(request, "unsupported", "shell_pipeline_unsupported", "Shell pipelines and shell-mode process execution require manual handling.", request_digest, snapshot.manifest_digest)

        groups = group_findings(request.findings)
        group_count = len(groups)
        outcomes: list[GroupOutcome] = []
        accepted: list[tuple[Candidate, PatchBundle, VerificationResult]] = []
        verifier: Verifier | None = None
        remaining_tool_calls = request.policy.max_tool_calls
        remaining_tokens = request.policy.max_total_tokens
        remaining_usd = float(request.policy.max_spend_usd)

        # One bounded agent loop per connected group, sequentially, sharing the job's budget.
        for index, group in enumerate(groups):
            finding_ids = sorted(finding.stable_id for finding in group)
            if index > 0 and (
                remaining_tool_calls < GROUP_TOOL_CALL_FLOOR
                or remaining_tokens < GROUP_TOKEN_FLOOR
                or remaining_usd < GROUP_SPEND_FLOOR_USD
            ):
                outcomes.append(
                    GroupOutcome(index, finding_ids, "unsupported", "budget_exhausted", BUDGET_EXHAUSTED_MESSAGE, None, None, None, [], {}, False)
                )
                continue
            group_request = (
                request
                if group_count == 1
                else _group_request(request, group, group_count, remaining_tool_calls, remaining_tokens, remaining_usd)
            )
            group_checkpoints = (
                checkpoints
                if group_count == 1 or checkpoints is None
                else GroupScopedCheckpointStore(checkpoints, digest_json(finding_ids))
            )
            try:
                agent = self.agent_factory(group_request) if self.agent_factory else self._default_agent(group_request, group_checkpoints)
            except (ProviderError, BrokerConfigurationError, ValueError) as exc:
                return _reason_response(request, "unsupported", "runtime_prerequisite_missing", str(exc), request_digest, snapshot.manifest_digest)
            with telemetry.stage_span(
                "agent_attempt", **telemetry.request_attributes(request), **{"mitig8it.attempt": index + 1}
            ) as span:
                result = await agent.run(group_request, snapshot)
                telemetry.record_outcome(
                    span,
                    result.state,
                    None if result.state == "ready" else result.reason_code,
                    **{
                        "mitig8it.input_tokens": int(result.usage.get("input_tokens", 0) or 0),
                        "mitig8it.output_tokens": int(result.usage.get("output_tokens", 0) or 0),
                    },
                )
            if verifier is None:
                verifier = agent.verifier
            spent_input = int(result.usage.get("input_tokens", 0) or 0)
            spent_output = int(result.usage.get("output_tokens", 0) or 0)
            remaining_tool_calls = max(0, remaining_tool_calls - len(result.trace))
            remaining_tokens = max(0, remaining_tokens - spent_input - spent_output)
            remaining_usd = max(
                0.0,
                remaining_usd
                - (
                    spent_input * request.policy.input_usd_per_million_tokens
                    + spent_output * request.policy.output_usd_per_million_tokens
                )
                / 1_000_000,
            )

            if result.state != "ready" or not result.bundle or not result.proposal or not result.verification:
                outcomes.append(
                    GroupOutcome(
                        index,
                        finding_ids,
                        result.state,
                        result.reason_code or "no_verified_candidate",
                        result.explanation or "No verified repair was produced.",
                        None,
                        None,
                        result.verification,
                        result.trace,
                        result.usage,
                        True,
                    )
                )
                continue
            verification_level = result.verification.verification_level
            if verification_level not in VERIFICATION_LEVELS or (
                verification_level == DEVELOPMENT_VERIFICATION_LEVEL and not request.policy.allow_development_verification
            ):
                outcomes.append(
                    GroupOutcome(
                        index,
                        finding_ids,
                        "inconclusive",
                        "verification_level_not_permitted",
                        "The verification evidence does not carry a verification level this policy accepts.",
                        None,
                        None,
                        result.verification,
                        result.trace,
                        result.usage,
                        False,
                    )
                )
                continue
            if bundles_conflict(snapshot, [bundle for _, bundle, _ in accepted], result.bundle):
                outcomes.append(
                    GroupOutcome(
                        index,
                        finding_ids,
                        "unsupported",
                        "overlapping_candidates",
                        "This group's patch changes a line range an earlier verified candidate already changes.",
                        None,
                        None,
                        result.verification,
                        result.trace,
                        result.usage,
                        False,
                    )
                )
                continue
            candidate = _build_candidate(request, snapshot, finding_ids, result)
            accepted.append((candidate, result.bundle, result.verification))
            outcomes.append(
                GroupOutcome(index, finding_ids, "ready", None, None, candidate, result.bundle, result.verification, result.trace, result.usage, True)
            )

        group_report = [outcome.report() for outcome in outcomes]
        agent_trace = [entry for outcome in outcomes for entry in outcome.trace]
        usage = _aggregate_usage(outcomes)

        if not accepted:
            primary = outcomes[0]
            if not primary.agent_ran:
                return _reason_response(
                    request,
                    primary.state,
                    primary.reason_code or "no_verified_candidate",
                    primary.message or "No verified repair was produced.",
                    request_digest,
                    snapshot.manifest_digest,
                    {"groups": group_report},
                )
            return RepairResponse(
                state=primary.state,
                job_id=request.job_id,
                tenant_id=request.tenant_id,
                repository_id=request.repository_id,
                head_sha=request.head_sha,
                base_sha=request.base_sha,
                request_digest=request_digest,
                candidates=[],
                manifest_digest=None,
                evidence={
                    "context_manifest_digest": snapshot.manifest_digest,
                    "verification_level": "none",
                    "agent_trace": agent_trace,
                    "usage": usage,
                    "verification": primary.verification.evidence if primary.verification else None,
                    "groups": group_report,
                },
                reason={"code": primary.reason_code or "no_verified_candidate", "message": primary.message or "No verified repair was produced."},
            )

        try:
            batch, combined = await build_verified_batch(request, snapshot, verifier, accepted)
        except PatchPolicyError as exc:
            return _reason_response(request, "unsupported", "overlapping_candidates" if "overlapping" in str(exc) else "batch_rejected", str(exc), request_digest, snapshot.manifest_digest, {"groups": group_report})
        except BatchPolicyError as exc:
            return _reason_response(request, "inconclusive", "combined_verification_failed", str(exc), request_digest, snapshot.manifest_digest, {"groups": group_report})
        combined_level = combined.verification.verification_level
        if combined_level not in VERIFICATION_LEVELS or (
            combined_level == DEVELOPMENT_VERIFICATION_LEVEL and not request.policy.allow_development_verification
        ):
            return _reason_response(
                request,
                "inconclusive",
                "verification_level_not_permitted",
                "The combined verification evidence does not carry a verification level this policy accepts.",
                request_digest,
                snapshot.manifest_digest,
                {"groups": group_report},
            )
        limitations = list(combined.verification.limitations) + [
            item for item in combined.bundle.limitations if item not in combined.verification.limitations
        ]
        return RepairResponse(
            state="ready",
            job_id=request.job_id,
            tenant_id=request.tenant_id,
            repository_id=request.repository_id,
            head_sha=request.head_sha,
            base_sha=request.base_sha,
            request_digest=request_digest,
            candidates=[candidate for candidate, _, _ in accepted],
            manifest_digest=batch.manifest_digest,
            evidence={
                "context_manifest_digest": snapshot.manifest_digest,
                "candidate_snapshot_digest": combined.verification.evidence.get("candidate_tree_digest"),
                "head_tree_oid": request.head_tree_oid,
                "verified_tree_oid": combined.verified_tree_oid,
                "verification_level": combined_level,
                "verification_run": combined.verification.evidence,
                "batch_manifest": batch.manifest,
                "agent_trace": agent_trace,
                "usage": usage,
                "limitations": limitations,
                "groups": group_report,
            },
        )
