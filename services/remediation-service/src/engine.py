from __future__ import annotations

import asyncio
import functools
import re
from typing import Any, Callable

from dataclasses import dataclass, field as dataclass_field, replace as dataclass_replace

from .agent import OpenAICompatibleProvider, ProviderError, RepairAgent
from .agent.checkpoint import AgentCheckpointStore, GroupScopedCheckpointStore
from .batch import BatchPolicyError, ImmutableBatch, build_immutable_batch
from .digests import digest_json
from .families import declares_static_assertion, family_supported, language_of_path, rule_family
from .gates import UNSUPPORTED_LANGUAGE_MESSAGE, static_gate
from .git_tree import GitTreeError, compute_tree_oid, validate_snapshot_tree
from .grouping import group_findings_by_language
from .models import Candidate, FindingSnapshot, RepairPolicy, RepairRequest, RepairResponse, VerificationSummary
from .patches import (
    PatchBundle,
    PatchPolicyError,
    build_patch_bundle,
    bundles_conflict,
    combine_patch_bundles,
    path_forbidden,
)
from .proofs import GeneratedProof, generate_proof
from .retrieval import Snapshot, SnapshotError
from .sandbox import BrokerConfigurationError, create_sandbox_broker
from .splitting import DEPENDENT_HUNK_UNPROVEN, split_hunks
from .templates import MODEL, TEMPLATE, TemplateFallback, combine_templates, generate_template
from . import telemetry
from .verification import VerificationResult, Verifier, create_rule_oracle
from .verification.verifier import (
    DEVELOPMENT_VERIFICATION_LEVEL,
    STATIC_ASSERTION_VERIFICATION_LEVEL,
    VERIFICATION_LEVELS,
)

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
# A finding still unproven after the group pass gets one focused single-finding agent run with
# this many verification attempts, funded from what the job has left.
RETRY_ATTEMPTS = 2
RETRY_SOURCE = "retry"
# The pass that produces a `static_assertion` candidate. It runs last, over findings every
# executed pass failed to prove, and only where the reason execution could not prove them is
# recorded. It is never tried before the executed passes and never instead of one.
STATIC_ASSERTION_SOURCE = "static_assertion"
STATIC_ASSERTION_NOT_COMBINABLE = (
    "This job also produced a candidate verified by execution, and a batch carries one kind of "
    "evidence: the statically asserted candidate is not shipped beside it."
)
PROTECTED_PATH_MESSAGE = (
    "Policy will not change this file, so no repair of it could be applied. It is a test "
    "directory, a lock file, or a CI or infrastructure path."
)


# The family decides support here and is named to the model by the agent loop.
_rule_family = rule_family


def _reason_response(
    request: RepairRequest,
    state: str,
    code: str,
    message: str,
    request_digest: str,
    context_digest: str | None = None,
    extra_evidence: dict[str, Any] | None = None,
    skipped: list[dict[str, str]] | None = None,
) -> RepairResponse:
    return RepairResponse(
        skipped=list(skipped or []),
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
    # One candidate per finding the group proved, each carrying only that finding's hunks.
    candidates: list[Candidate]
    bundle: PatchBundle | None
    verification: VerificationResult | None
    trace: list[dict[str, Any]]
    usage: dict[str, Any]
    agent_ran: bool
    # Numeric evidence the agent attached to its reason, such as a denied budget reservation.
    evidence: dict[str, Any] = dataclass_field(default_factory=dict)
    # The group's findings the candidate does not claim, each with the verifier's reason.
    unproven: list[dict[str, str]] = dataclass_field(default_factory=list)
    # Coverage revisions the agent ran for this group and why they stopped.
    coverage: dict[str, Any] = dataclass_field(default_factory=dict)
    # The toolchain that checked this group, from its findings' file extension.
    language: str | None = None

    def report(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "group_index": self.index,
            "finding_ids": self.finding_ids,
            "state": self.state,
            "reason": None if self.reason_code is None else {"code": self.reason_code, "message": self.message},
            "candidate_id": self.candidates[0].candidate_id if self.candidates else None,
            "candidate_ids": [candidate.candidate_id for candidate in self.candidates],
        }
        if self.language:
            report["language"] = self.language
        if self.candidates:
            report["repaired_finding_ids"] = [finding_id for candidate in self.candidates for finding_id in candidate.finding_ids]
        if self.unproven:
            report["unproven_findings"] = list(self.unproven)
        if self.coverage:
            report["coverage"] = dict(self.coverage)
        if self.evidence:
            report["reason_evidence"] = self.evidence
        return report


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


def _level_permitted(level: str, policy: RepairPolicy) -> bool:
    """Whether policy accepts a candidate carrying this verification level.

    One function rather than a chain repeated per call site, because a level added to
    `VERIFICATION_LEVELS` without a decision here would otherwise be silently accepted.
    """
    if level not in VERIFICATION_LEVELS:
        return False
    if level == DEVELOPMENT_VERIFICATION_LEVEL:
        return policy.allow_development_verification
    if level == STATIC_ASSERTION_VERIFICATION_LEVEL:
        return policy.allow_static_assertion_verification
    return True


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
    # A batch carries one kind of evidence, so either every entry here was asserted statically or
    # none was; `repair` has already dropped the asserted ones when an executed candidate exists.
    asserted_only = all(verification.verification_level == STATIC_ASSERTION_VERIFICATION_LEVEL for _, _, verification in entries)
    # Combining shells out for syntax and load checks and diffs every hunk pair, so it
    # runs off the loop: the worker's lease renewal shares this loop and a combine
    # longer than the lease would otherwise lose the job mid-verification. An all-asserted batch
    # combines without the load check, because requiring the union would execute repository code
    # that no candidate in the batch claims was executed.
    combined = await asyncio.to_thread(
        functools.partial(combine_patch_bundles, load_checks=not asserted_only),
        request,
        snapshot,
        [bundle for _, bundle, _ in entries],
    )
    verified_tree_oid = compute_tree_oid(
        request.tree_entries,
        {patch.path: patch.replacement_content for patch in combined.patches},
    )
    claimed = {finding_id for candidate, _, _ in entries for finding_id in candidate.finding_ids}
    if asserted_only:
        # Every candidate here was asserted rather than executed, so the union is asserted too:
        # a sandbox run over this tree would produce evidence no candidate in it claims. The
        # combined assertion re-checks every claimed finding against the union, so a patch that
        # only holds when applied alone does not ship. `repair` has already established that no
        # executed candidate is in this batch, because a batch carries one kind of evidence.
        narrowed = request.model_copy(
            update={"findings": [finding for finding in request.findings if finding.stable_id in claimed]}
        )
        verification = await verifier.verify_static_assertion(
            narrowed, snapshot, combined, reason="combined_static_assertion"
        )
        return CombinedVerification(combined, verified_tree_oid, verification)
    for candidate, _, verification in entries:
        if (
            candidate.verified_tree_oid == verified_tree_oid
            and verification.status == "passed"
            and verification.evidence_digest
            and claimed <= set(verification.proven_finding_ids)
        ):
            # Per-finding candidates that share one hunk union to a tree a run already verified
            # with every claimed finding's test, so that evidence covers the batch.
            return CombinedVerification(combined, verified_tree_oid, verification)
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
    if len(entries) > 1:
        # Each candidate's claims must survive the combined run: a finding whose reproducer
        # passed alone but not on the union is not repaired by the batch.
        claimed = {finding_id for candidate, _, _ in entries for finding_id in candidate.finding_ids}
        if claimed - set(combined.verification.proven_finding_ids):
            raise BatchPolicyError("combined_regression_tests_not_proven")
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


# Limitations that say a check was skipped, unavailable, or never completed; the evidence
# summary repeats them so a reviewer sees what did not run beside what did.
_NOT_RUN_RE = re.compile(r"\b(?:not run|did not complete|skipped|unavailable|inconclusive|not supplied)\b|^no .* was run", re.I)
_CHECK_LABELS = {
    "typecheck": "Syntax check",
    "build": "Build",
    "existing_test": "Repository test suite",
    "behavior": "Behavior check",
    "scanner": "Scanner comparison",
    "exploit": "Exploit check",
}


def evidence_summary(bundle: PatchBundle, verification: VerificationResult, limitations: list[str]) -> list[str]:
    """One line per piece of evidence behind a candidate, in the words the publication uses.

    The regression test line states both halves of the proof, because a candidate exists only
    when its finding's test failed on the original code and passed on the fix. Every other check
    in the run is named with its outcome, and every limitation that says a check did not run is
    repeated, so absent evidence is never read as coverage.
    """
    lines = [
        f"Regression test {test.path} failed on the original code and passed on the fix."
        for test in bundle.generated_tests
    ]
    checks = verification.evidence.get("checks") if isinstance(verification.evidence, dict) else None
    regression_ids = set(verification.regression_checks.values())
    for check in checks if isinstance(checks, list) else []:
        if not isinstance(check, dict) or check.get("check_id") in regression_ids or check.get("kind") == "exploit":
            continue
        label = f"{_CHECK_LABELS.get(str(check.get('kind')), 'Check')} ({check.get('check_id')})"
        baseline = check.get("baseline") if isinstance(check.get("baseline"), dict) else {}
        candidate = check.get("candidate") if isinstance(check.get("candidate"), dict) else {}
        if baseline.get("completed") is True and candidate.get("completed") is True and candidate.get("status") == "passed":
            lines.append(f"{label} passed on the fix.")
        else:
            lines.append(f"{label} did not complete.")
    lines.extend(f"Not run: {item.rstrip('.')}." for item in limitations if _NOT_RUN_RE.search(item))
    return lines


def _build_candidate(
    request: RepairRequest,
    snapshot: Snapshot,
    finding_ids: list[str],
    proposal: dict[str, Any],
    bundle: PatchBundle,
    verification: VerificationResult,
    source: str = MODEL,
) -> Candidate:
    """Builds the immutable candidate for one proven finding.

    `finding_ids` are exactly the findings whose own regression test failed on the baseline and
    passed on this bundle, and the bundle holds only the hunks attributed to them, so a candidate
    states what its evidence covers rather than every finding the group carried.
    """
    verified_tree_oid = compute_tree_oid(
        request.tree_entries,
        {patch.path: patch.replacement_content for patch in bundle.patches},
    )
    # A candidate's identity is what it changes and what it claims to repair, and nothing else.
    #
    # It used to include `job_id` and `evidence_digest`, and both of those move on every run over
    # identical code. `job_id` is a fresh row per job in the App and a fresh `uuid4` per run in the
    # Action. `evidence_digest` is worse: it hashes the broker's whole evidence document, which
    # binds `request_nonce` from `secrets.token_hex(32)` in `verification/verifier.py`, freshly
    # minted per verification and required by `sandbox/broker.py` to come back unchanged. That
    # nonce is an anti-replay property of the verification contract and it is supposed to move,
    # which is exactly why nothing durable may be keyed by it.
    #
    # The consequence was visible to maintainers. `candidate_id` is the `<!-- mitig8it-fix:... -->`
    # marker that the publisher matches a fix block by, so a re-run over an unchanged head found no
    # marker it recognised and rewrote the block, with byte-identical suggestion text. The ten
    # repository trial recorded it on pygoat, where a commit touching only the README rewrote two
    # fix comments: docs/validation/action-trial-2026-09.md, "The findings are not stable between
    # runs on identical code".
    #
    # `artifact_digest` is the patch content and `verified_tree_oid` is the tree the patch produces,
    # so two runs that write the same repair for the same findings now agree on the identity, and
    # any change to the repair changes it. The evidence digest keeps its job: it stays on the
    # candidate's `verification` summary and in `preview.evidence` for the audit trail, where a
    # per-run value belongs.
    candidate_id = digest_json(
        {
            "finding_ids": finding_ids,
            "artifact_digest": bundle.artifact_digest,
            "verified_tree_oid": verified_tree_oid,
        }
    )
    limitations = list(verification.limitations) + [item for item in bundle.limitations if item not in verification.limitations]
    return Candidate(
        candidate_id=candidate_id,
        finding_ids=finding_ids,
        hypothesis=proposal["hypothesis"],
        intended_behavior=proposal["intended_behavior"],
        assumptions=proposal["assumptions"],
        citations=proposal["citations"],
        patch=list(bundle.patches),
        file_manifest={"files": bundle.file_manifest, "verified_tree_oid": verified_tree_oid},
        generated_tests=bundle.generated_test_manifest,
        artifact_digest=bundle.artifact_digest,
        context_manifest_digest=snapshot.manifest_digest,
        verified_tree_oid=verified_tree_oid,
        verification=VerificationSummary(status="passed", evidence_digest=verification.evidence_digest),
        preview={
            "changes": [
                {
                    "path": patch.path,
                    "original": snapshot.full_content(patch.path),
                    "replacement": patch.replacement_content,
                    "unified_diff": patch.unified_diff,
                    "new_sha256": patch.new_sha256,
                }
                for patch in bundle.patches
            ],
            "hunks": bundle.hunk_manifest,
            "rationale": proposal["hypothesis"],
            "reasoning": {
                "hypothesis": proposal["hypothesis"],
                "intended_behavior": proposal["intended_behavior"],
                "assumptions": proposal["assumptions"],
            },
            "evidence": {
                "status": "passed",
                "evidence_digest": verification.evidence_digest,
                "verified_tree_oid": verified_tree_oid,
                # Generated reproducers are verification artifacts: reviewers see them beside
                # the diff, but they are never part of the tree the batch applies.
                "generated_tests": bundle.generated_test_manifest,
                # Per-candidate, not per-response: the API persists this level on the
                # candidate row and the finding view renders this candidate's limitations.
                "verification_level": verification.verification_level,
                "limitations": limitations,
                "summary": evidence_summary(bundle, verification, limitations),
                # Which path wrote the hunks: a deterministic template or the model.
                "candidate_source": source,
            },
        },
    )


def _dependent(finding_id: str, detail: str) -> dict[str, str]:
    return {
        "finding_id": finding_id,
        "code": DEPENDENT_HUNK_UNPROVEN,
        "message": f"This finding was proven only together with hunks that are not shipped: {detail}.",
    }


async def _per_finding_candidates(
    request: RepairRequest,
    group_request: RepairRequest,
    snapshot: Snapshot,
    verifier: Verifier,
    result: Any,
    proven: list[str],
) -> tuple[list[tuple[Candidate, PatchBundle, VerificationResult]], list[dict[str, str]]]:
    """Splits one verified group proposal into one candidate per proven finding.

    Each candidate holds the hunks attributed to its finding plus the prerequisites they use,
    and nothing owned by an unproven finding. A candidate whose tree equals the tree the group
    verification ran on keeps that evidence; any other candidate is verified on its own, and a
    finding whose test does not pass on its own candidate is reported `dependent_hunk_unproven`
    rather than shipped with the hunks it depended on.
    """
    if not result.bundle.hunks:
        # A bundle without located hunks cannot be split; it ships as one candidate for every
        # finding it proved, exactly as before per-finding candidates existed.
        candidate = _build_candidate(request, snapshot, list(proven), result.proposal, result.bundle, result.verification, getattr(result, "source", MODEL))
        return [(candidate, result.bundle, result.verification)], []
    findings = list(group_request.findings)
    by_id = {finding.stable_id: finding for finding in findings}
    plan = split_hunks(findings, result.bundle.hunks, proven)
    tests = {test.finding_id: test.spec() for test in result.bundle.generated_tests}
    full_tree = {patch.path: patch.replacement_content for patch in result.bundle.patches}
    accepted: list[tuple[Candidate, PatchBundle, VerificationResult]] = []
    dependent: list[dict[str, str]] = []
    for finding_id in proven:
        hunks = plan.get(finding_id) or []
        if not hunks:
            dependent.append(_dependent(finding_id, "no hunk is attributed to this finding once the hunks of unproven findings are dropped"))
            continue
        try:
            # Off the event loop: the bundle build shells out to the syntax and load checks.
            bundle = await asyncio.to_thread(
                build_patch_bundle,
                group_request,
                snapshot,
                [hunk.spec() for hunk in hunks],
                [tests[finding_id]] if finding_id in tests else None,
            )
        except PatchPolicyError as exc:
            dependent.append(_dependent(finding_id, f"a candidate holding only this finding's hunks was rejected as {exc.code}"))
            continue
        if {patch.path: patch.replacement_content for patch in bundle.patches} == full_tree:
            verification = result.verification
        else:
            narrowed = group_request.model_copy(update={"findings": [by_id[finding_id]]})
            verification = await verifier.verify(narrowed, snapshot, bundle)
            if verification.status != "passed" or finding_id not in verification.proven_finding_ids or not verification.evidence_digest:
                detail = "its regression test does not pass on a candidate holding only this finding's hunks"
                if verification.reason_code:
                    detail += f" ({verification.reason_code})"
                dependent.append(_dependent(finding_id, detail))
                continue
        candidate = _build_candidate(request, snapshot, [finding_id], result.proposal, bundle, verification, getattr(result, "source", MODEL))
        accepted.append((candidate, bundle, verification))
    return accepted, dependent


@dataclass
class _Budget:
    """What the job still has to spend on agent runs, charged after every run."""

    tool_calls: int
    tokens: int
    usd: float

    def allows(self) -> bool:
        return self.tool_calls >= GROUP_TOOL_CALL_FLOOR and self.tokens >= GROUP_TOKEN_FLOOR and self.usd >= GROUP_SPEND_FLOOR_USD

    def charge(self, policy: RepairPolicy, result: Any) -> None:
        spent_input = int(result.usage.get("input_tokens", 0) or 0)
        spent_output = int(result.usage.get("output_tokens", 0) or 0)
        self.tool_calls = max(0, self.tool_calls - len(result.trace))
        self.tokens = max(0, self.tokens - spent_input - spent_output)
        self.usd = max(
            0.0,
            self.usd - (spent_input * policy.input_usd_per_million_tokens + spent_output * policy.output_usd_per_million_tokens) / 1_000_000,
        )


@dataclass
class _Pass:
    """One attempt at a group or a finding: a template candidate, a model run, or a focused retry."""

    source: str
    request: RepairRequest
    state: str
    proposal: dict[str, Any] | None
    bundle: PatchBundle | None
    verification: VerificationResult | None
    reason_code: str | None
    explanation: str | None
    trace: list[dict[str, Any]]
    usage: dict[str, Any]
    evidence: dict[str, Any] = dataclass_field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return self.state == "ready" and self.bundle is not None and self.proposal is not None and self.verification is not None

    @property
    def proven(self) -> set[str]:
        return set(self.verification.proven_finding_ids) if self.ready else set()


def _agent_pass(source: str, request: RepairRequest, result: Any) -> _Pass:
    return _Pass(
        source, request, result.state, result.proposal, result.bundle, result.verification,
        result.reason_code, result.explanation, list(result.trace), dict(result.usage), dict(result.evidence),
    )


def static_assertion_reason(family: str | None, proof_entry: str | None) -> str | None:
    """Why this finding would be asserted statically rather than executed, or None.

    Two routes, and only two. A family may declare it, which is for the categories no regression
    test could ever cover. Otherwise the service has to have refused to write a proof for this
    site, and then the refusal's own code is the recorded reason. A finding with a service proof
    never reaches here: a repair that can be executed is executed.
    """
    if declares_static_assertion(family):
        return "family_declares_static_assertion"
    entry = str(proof_entry or "")
    if entry.startswith("model:"):
        return f"execution_not_available:{entry[len('model:'):]}"
    return None


def build_proofs(snapshot: Snapshot, findings: list[FindingSnapshot]) -> tuple[dict[str, GeneratedProof], dict[str, str]]:
    """The service-generated proof per finding, and per finding which path supplies its test."""
    proofs: dict[str, GeneratedProof] = {}
    report: dict[str, str] = {}
    for finding in findings:
        generated = generate_proof(snapshot, finding, _rule_family(finding) or "", language_of_path(finding.affected_path) or "")
        if isinstance(generated, GeneratedProof):
            proofs[finding.stable_id] = generated
            report[finding.stable_id] = "service"
        else:
            report[finding.stable_id] = f"model:{generated.reason}"
    return proofs, report


def _proof_specs(proofs: dict[str, GeneratedProof], findings: list[FindingSnapshot]) -> dict[str, dict[str, Any]]:
    return {
        finding.stable_id: {**proofs[finding.stable_id].spec(), "description": proofs[finding.stable_id].description}
        for finding in findings
        if finding.stable_id in proofs
    }


def _failure_entries(request: RepairRequest, bundle: PatchBundle | None, verification: VerificationResult | None, source: str) -> dict[str, dict[str, Any]]:
    """Per unproven finding: the verifier's reason and its test's failure tail, tagged with the pass."""
    if verification is None:
        return {}
    if bundle is None:
        return {
            str(item.get("finding_id")): {"source": source, "code": item.get("code"), "message": item.get("message")}
            for item in verification.unproven_findings
        }
    entries = RepairAgent._unproven_entries(request, bundle, verification)
    return {
        str(entry["finding_id"]): {
            "source": source,
            "code": entry.get("code"),
            "message": entry.get("message"),
            **({"test_failure_tail": entry["test_failure_tail"]} if entry.get("test_failure_tail") else {}),
        }
        for entry in entries
    }


class RepairEngine:
    def __init__(self, agent_factory: AgentFactory | None = None):
        self.agent_factory = agent_factory

    def _default_agent(self, request: RepairRequest, checkpoints: AgentCheckpointStore | None = None) -> RepairAgent:
        expected_model = request.versions.get("repair_model")
        provider = OpenAICompatibleProvider.from_env(expected_model)
        provider.max_output_tokens = min(provider.max_output_tokens, request.policy.max_output_tokens_per_call)
        broker = create_sandbox_broker()
        # The oracle is optional. A deployment with no analysis service reachable simply has no
        # static assertion level available, and the verifier refuses rather than passes.
        return RepairAgent(provider, Verifier(broker, create_rule_oracle()), checkpoints)

    async def _template_pass(
        self,
        group_request: RepairRequest,
        snapshot: Snapshot,
        verifier: Verifier,
        proofs: dict[str, GeneratedProof],
        report: dict[str, str],
        failures: dict[str, dict[str, Any]],
    ) -> _Pass | None:
        """A deterministic candidate for every finding whose shape a template recognizes.

        The template hunks of the group are combined into one bundle with the service proofs and
        verified exactly like a model proposal. `report` records per finding whether the template
        proved it, was not proven, or was not attempted and why.
        """
        by_id = {finding.stable_id: finding for finding in group_request.findings}
        patches = []
        for finding in group_request.findings:
            finding_id = finding.stable_id
            if finding_id not in proofs:
                report[finding_id] = "not_attempted:no_service_proof"
                continue
            template = generate_template(snapshot, finding, _rule_family(finding) or "", language_of_path(finding.affected_path) or "")
            if isinstance(template, TemplateFallback):
                report[finding_id] = f"not_attempted:{template.reason}"
                continue
            patches.append(template)
        if not patches:
            return None
        changes, dropped = combine_templates(patches)
        for finding_id, reason in dropped.items():
            report[finding_id] = f"not_attempted:{reason}"
        templated = [patch for patch in patches if patch.finding_id not in dropped]
        narrowed = group_request.model_copy(update={"findings": [by_id[patch.finding_id] for patch in templated]})
        tests = [proofs[patch.finding_id].spec() for patch in templated]
        step = {"sequence": 0, "tool": "template_patch", "arguments_digest_only": {"finding_ids": [patch.finding_id for patch in templated], "paths": sorted({change["path"] for change in changes})}, "outcome": "ok", "reason": None, "result_bytes": 0}
        try:
            bundle = await asyncio.to_thread(build_patch_bundle, narrowed, snapshot, changes, tests)
        except PatchPolicyError as exc:
            step["outcome"] = "rejected"
            step["reason"] = str(exc.code)[:120]
            for patch in templated:
                report[patch.finding_id] = f"rejected:{exc.code}"
                failures[patch.finding_id] = {"source": TEMPLATE, "code": exc.code, "message": str(exc.guidance or exc.code)[:400]}
            return _Pass(TEMPLATE, narrowed, "unsupported", None, None, None, exc.code, str(exc.guidance or exc.code)[:400], [step], {"input_tokens": 0, "output_tokens": 0, "provider_request_ids": []})
        with telemetry.stage_span("template_verification", **telemetry.request_attributes(group_request)) as span:
            verification = await verifier.verify(narrowed, snapshot, bundle)
            telemetry.record_outcome(span, verification.status, None if verification.status == "passed" else verification.reason_code)
        for patch in templated:
            if patch.finding_id in verification.proven_finding_ids:
                report[patch.finding_id] = "proven"
            else:
                report[patch.finding_id] = "not_proven"
        failures.update(_failure_entries(narrowed, bundle, verification, TEMPLATE))
        proposal = {
            "hypothesis": "Deterministic template repair: " + "; ".join(f"{patch.finding_id}: {patch.description}" for patch in templated) + ".",
            "intended_behavior": "Legitimate input behaves as before; only the injected value is kept out of the sink.",
            "assumptions": [],
            "citations": [
                {"path": change["path"], "line_start": int(change["start_line"]), "line_end": int(change["start_line"]) + len(change["original_lines"]) - 1}
                for change in changes
            ],
        }
        if verification.status != "passed" or not verification.proven_finding_ids:
            step["outcome"] = "not_proven"
            step["reason"] = str(verification.reason_code or "no_finding_proven")[:120]
            return _Pass(TEMPLATE, narrowed, verification.status if verification.status in ("unsupported", "inconclusive") else "inconclusive", proposal, bundle, verification, verification.reason_code or "verification_failed", "The template candidate did not prove its findings.", [step], {"input_tokens": 0, "output_tokens": 0, "provider_request_ids": []})
        return _Pass(TEMPLATE, narrowed, "ready", proposal, bundle, verification, None, None, [step], {"input_tokens": 0, "output_tokens": 0, "provider_request_ids": []})

    async def _static_assertion_passes(
        self,
        group_request: RepairRequest,
        snapshot: Snapshot,
        verifier: Verifier,
        findings: list[FindingSnapshot],
        proof_report: dict[str, str],
        report: dict[str, str],
        failures: dict[str, dict[str, Any]],
    ) -> list[_Pass]:
        """One statically asserted candidate per finding no executed pass could prove.

        Reached only after the template pass, the model pass and every focused retry have run and
        left the finding unproven, and only for a finding where `static_assertion_reason` says why
        execution was not available. Each finding gets its own bundle, because a static assertion
        is a claim about one file: one finding's refusal must not sink another's.

        There is no generated regression test, and that is the point rather than an omission: the
        level exists for findings no test could cover. `verify_static_assertion` records that
        nothing ran, and `_static_assertion_limitations` says which checks did not.
        """
        if not group_request.policy.allow_static_assertion_verification:
            return []
        if verifier.rule_oracle is None:
            # No analysis service to re-run the rule, so this level is not available here at all.
            # The pass is skipped rather than run and refused: a deployment without an oracle must
            # report each finding's executed-path reason, not a refusal from a level it never had.
            # `Verifier.verify_static_assertion` still refuses a direct call, as the backstop.
            return []
        passes: list[_Pass] = []
        for finding in findings:
            finding_id = finding.stable_id
            family = _rule_family(finding) or ""
            reason = static_assertion_reason(family, proof_report.get(finding_id))
            if reason is None:
                continue
            template = generate_template(snapshot, finding, family, language_of_path(finding.affected_path) or "")
            if isinstance(template, TemplateFallback):
                report[finding_id] = f"not_attempted:{template.reason}"
                continue
            narrowed = group_request.model_copy(update={"findings": [finding]})
            step = {
                "sequence": 0,
                "tool": "static_assertion",
                "arguments_digest_only": {"finding_ids": [finding_id], "paths": sorted({change["path"] for change in template.changes}), "reason": reason},
                "outcome": "ok",
                "reason": None,
                "result_bytes": 0,
            }
            try:
                # No generated test: the bundle is the patch alone, and no load check, because
                # clause 5 is that nothing was executed and a load check requires the patched
                # module. Off the loop like every other bundle build, because it still shells out
                # to the parse-only syntax check.
                bundle = await asyncio.to_thread(
                    functools.partial(build_patch_bundle, load_checks=False),
                    narrowed, snapshot, template.changes, None,
                )
            except PatchPolicyError as exc:
                step["outcome"], step["reason"] = "rejected", str(exc.code)[:120]
                report[finding_id] = f"rejected:{exc.code}"
                failures[finding_id] = {"source": STATIC_ASSERTION_SOURCE, "code": exc.code, "message": str(exc.guidance or exc.code)[:400]}
                continue
            with telemetry.stage_span("static_assertion", **telemetry.request_attributes(group_request)) as span:
                verification = await verifier.verify_static_assertion(narrowed, snapshot, bundle, reason=reason)
                telemetry.record_outcome(span, verification.status, None if verification.status == "passed" else verification.reason_code)
            proposal = {
                "hypothesis": f"Deterministic template repair, asserted statically ({reason}): {template.description}.",
                "intended_behavior": "Legitimate input behaves as before; only the injected value is kept out of the sink.",
                "assumptions": [
                    "Nothing was executed. The rule that flagged the finding was re-run over the original "
                    "and the patched file, and no other rule started matching.",
                ],
                "citations": [
                    {"path": change["path"], "line_start": int(change["start_line"]), "line_end": int(change["start_line"]) + len(change["original_lines"]) - 1}
                    for change in template.changes
                ],
            }
            usage = {"input_tokens": 0, "output_tokens": 0, "provider_request_ids": []}
            if verification.status != "passed" or finding_id not in verification.proven_finding_ids:
                step["outcome"] = "not_proven"
                step["reason"] = str(verification.reason_code or "static_assertion_failed")[:120]
                report[finding_id] = f"not_asserted:{verification.reason_code or 'static_assertion_failed'}"
                failures.update(_failure_entries(narrowed, bundle, verification, STATIC_ASSERTION_SOURCE))
                passes.append(_Pass(
                    STATIC_ASSERTION_SOURCE, narrowed,
                    verification.status if verification.status in ("unsupported", "inconclusive") else "inconclusive",
                    proposal, bundle, verification, verification.reason_code or "static_assertion_failed",
                    "The patch was not asserted against the rule that produced the finding.", [step], usage,
                ))
                continue
            report[finding_id] = "asserted"
            passes.append(_Pass(STATIC_ASSERTION_SOURCE, narrowed, "ready", proposal, bundle, verification, None, None, [step], usage))
        return passes

    async def _retry_agent(self, retry_request: RepairRequest, checkpoints: AgentCheckpointStore | None, finding_id: str) -> RepairAgent:
        if self.agent_factory:
            return self.agent_factory(retry_request)
        scoped = None if checkpoints is None else GroupScopedCheckpointStore(checkpoints, digest_json([finding_id, RETRY_SOURCE]))
        return self._default_agent(retry_request, scoped)

    async def _repair_group(
        self,
        request: RepairRequest,
        group_request: RepairRequest,
        group: list[FindingSnapshot],
        index: int,
        snapshot: Snapshot,
        agent: RepairAgent,
        verifier: Verifier,
        accepted: list[tuple[Candidate, PatchBundle, VerificationResult]],
        budget: _Budget,
        checkpoints: AgentCheckpointStore | None,
    ) -> tuple[GroupOutcome, list[tuple[Candidate, PatchBundle, VerificationResult]], list[dict[str, str]]]:
        """Repairs one connected group: templates first, then the model for what is left, then
        one focused retry per finding still unproven, each verified with the service proofs."""
        finding_ids = sorted(finding.stable_id for finding in group)
        by_id = {finding.stable_id: finding for finding in group}
        proofs, proof_report = build_proofs(snapshot, group)
        template_report: dict[str, str] = {}
        failures: dict[str, dict[str, Any]] = {}
        passes: list[_Pass] = []
        agent_ran = False

        template = await self._template_pass(group_request, snapshot, verifier, proofs, template_report, failures)
        if template is not None:
            passes.append(template)
        proven: set[str] = set().union(*(item.proven for item in passes))

        remaining = [finding for finding in group if finding.stable_id not in proven]
        model_pass: _Pass | None = None
        if remaining:
            model_request = group_request.model_copy(update={"findings": remaining})
            with telemetry.stage_span("agent_attempt", **telemetry.request_attributes(request), **{"mitig8it.attempt": index + 1}) as span:
                result = await agent.run(
                    model_request, snapshot,
                    proofs=_proof_specs(proofs, remaining),
                    prior_attempts={finding.stable_id: failures[finding.stable_id] for finding in remaining if finding.stable_id in failures} or None,
                )
                telemetry.record_outcome(
                    span, result.state, None if result.state == "ready" else result.reason_code,
                    **{"mitig8it.input_tokens": int(result.usage.get("input_tokens", 0) or 0), "mitig8it.output_tokens": int(result.usage.get("output_tokens", 0) or 0)},
                )
            agent_ran = True
            budget.charge(request.policy, result)
            model_pass = _agent_pass(MODEL, model_request, result)
            passes.append(model_pass)
            proven |= model_pass.proven
            failures.update(_failure_entries(model_request, model_pass.bundle, model_pass.verification, MODEL))

        retries: dict[str, str] = {}
        # A deliberate stop (an abstention or a repeated rejection) is not retried: the model
        # said why it cannot repair the finding. A partial or failed verification is.
        retry_allowed = model_pass is None or model_pass.state != "unsupported"
        for finding in group:
            finding_id = finding.stable_id
            if finding_id in proven or not retry_allowed:
                continue
            if not budget.allows():
                retries[finding_id] = "budget_exhausted"
                continue
            outstanding = max(1, sum(1 for item in group if item.stable_id not in proven))
            policy = group_request.policy.model_copy(
                update={
                    "max_attempts": RETRY_ATTEMPTS,
                    "max_revisions": 0,
                    "max_tool_calls": _split_budget(group_request.policy.max_tool_calls, outstanding, budget.tool_calls, GROUP_TOOL_CALL_FLOOR),
                    "max_total_tokens": _split_budget(group_request.policy.max_total_tokens, outstanding, budget.tokens, GROUP_TOKEN_FLOOR),
                    "max_spend_usd": _split_spend(group_request.policy.max_spend_usd, outstanding, budget.usd, GROUP_SPEND_FLOOR_USD),
                }
            )
            retry_request = group_request.model_copy(update={"findings": [finding], "policy": policy})
            try:
                retry_agent = await self._retry_agent(retry_request, checkpoints, finding_id)
            except (ProviderError, BrokerConfigurationError, ValueError) as exc:
                retries[finding_id] = f"runtime_prerequisite_missing:{str(exc)[:80]}"
                continue
            with telemetry.stage_span("agent_retry", **telemetry.request_attributes(request), **{"mitig8it.finding_id": finding_id}) as span:
                result = await retry_agent.run(
                    retry_request, snapshot,
                    proofs=_proof_specs(proofs, [finding]),
                    prior_attempts={finding_id: failures[finding_id]} if finding_id in failures else None,
                )
                telemetry.record_outcome(span, result.state, None if result.state == "ready" else result.reason_code)
            agent_ran = True
            budget.charge(request.policy, result)
            retry_pass = _agent_pass(RETRY_SOURCE, retry_request, result)
            passes.append(retry_pass)
            retries[finding_id] = "proven" if finding_id in retry_pass.proven else (result.reason_code or result.state)
            proven |= retry_pass.proven
            failures.update(_failure_entries(retry_request, retry_pass.bundle, retry_pass.verification, RETRY_SOURCE))

        # Last, and only for what every executed pass left unproven: the static assertion. It is
        # the weakest level the product has, so nothing reaches it that execution could have
        # proven, and a finding is only asserted when the reason execution was unavailable to it
        # is recorded. `assertion_report` goes into the group's evidence beside the proof and
        # template reports.
        assertion_report: dict[str, str] = {}
        unasserted = [finding for finding in group if finding.stable_id not in proven]
        if unasserted:
            for item in await self._static_assertion_passes(
                group_request, snapshot, verifier, unasserted, proof_report, assertion_report, failures
            ):
                passes.append(item)
                proven |= item.proven

        # One candidate per proven finding, from whichever pass proved it first, each verified
        # on its own hunks; a pass whose evidence policy refuses, or whose patch overlaps an
        # earlier candidate, contributes nothing and says so.
        entries: list[tuple[Candidate, PatchBundle, VerificationResult]] = []
        claimed: set[str] = set()
        candidate_sources: dict[str, str] = {}
        dependent: list[dict[str, str]] = []
        rejected_reason: tuple[str, str] | None = None
        for item in passes:
            if not item.ready:
                continue
            level = item.verification.verification_level
            if not _level_permitted(level, request.policy):
                rejected_reason = ("verification_level_not_permitted", "The verification evidence does not carry a verification level this policy accepts.")
                continue
            if await asyncio.to_thread(bundles_conflict, snapshot, [bundle for _, bundle, _ in accepted + entries], item.bundle):
                rejected_reason = ("overlapping_candidates", "This pass's patch changes a line range an earlier verified candidate already changes.")
                continue
            newly = [finding_id for finding_id in finding_ids if finding_id in item.proven and finding_id not in claimed]
            if not newly:
                continue
            group_candidates, pass_dependent = await _per_finding_candidates(request, item.request, snapshot, verifier, item, newly)
            dependent.extend(pass_dependent)
            for candidate, bundle, verification in group_candidates:
                entries.append((candidate, bundle, verification))
                for finding_id in candidate.finding_ids:
                    claimed.add(finding_id)
                    candidate_sources[finding_id] = item.source

        unproven: list[dict[str, str]] = []
        dependent_by_id = {str(item["finding_id"]): item for item in dependent}
        for finding_id in finding_ids:
            if finding_id in claimed:
                continue
            if finding_id in dependent_by_id:
                unproven.append(dependent_by_id[finding_id])
            elif finding_id in failures:
                failure = failures[finding_id]
                unproven.append({"finding_id": finding_id, "code": str(failure.get("code") or "not_repaired"), "message": str(failure.get("message") or "No candidate proved this finding.")})
            else:
                unproven.append({"finding_id": finding_id, "code": "not_repaired", "message": "No regression test reproduced this finding, so no candidate claims it."})

        trace = [entry for item in passes for entry in item.trace]
        usage = _aggregate_usage([GroupOutcome(index, finding_ids, item.state, None, None, [], None, None, item.trace, item.usage, True) for item in passes])
        # The group's reason is the group pass's own: a focused retry that stopped is recorded
        # under `retries`, and the verification-based reason of the pass before it stands.
        last = model_pass if model_pass is not None else (passes[-1] if passes else None)
        evidence: dict[str, Any] = {
            "proofs": proof_report,
            "templates": template_report,
            "candidate_sources": candidate_sources,
        }
        if assertion_report:
            evidence["static_assertions"] = assertion_report
        if retries:
            evidence["retries"] = retries
        if model_pass is not None:
            evidence.update({key: value for key, value in model_pass.evidence.items() if key != "coverage"})
        coverage = dict(model_pass.evidence.get("coverage") or {}) if model_pass is not None else {}
        if entries:
            outcome = GroupOutcome(
                index, finding_ids, "ready", None, None, [candidate for candidate, _, _ in entries], entries[0][1],
                last.verification if last else None, trace, usage, agent_ran, evidence, unproven, coverage,
            )
            return outcome, entries, unproven
        if rejected_reason is not None:
            code, message = rejected_reason
            state = "inconclusive" if code == "verification_level_not_permitted" else "unsupported"
            return GroupOutcome(index, finding_ids, state, code, message, [], None, last.verification if last else None, trace, usage, agent_ran, evidence, unproven, coverage), [], unproven
        if last is None:
            return GroupOutcome(index, finding_ids, "unsupported", "budget_exhausted", BUDGET_EXHAUSTED_MESSAGE, [], None, None, [], usage, False, evidence, unproven), [], unproven
        if dependent and all(finding_id in dependent_by_id for finding_id in finding_ids if finding_id in proven):
            code, message = DEPENDENT_HUNK_UNPROVEN, "Every proven finding in this group depended on a hunk owned by an unproven finding, so no candidate ships."
        elif last.ready:
            code, message = "regression_test_not_reproducing", "No finding in this group was shown repaired by its own regression test."
        else:
            code, message = last.reason_code or "no_verified_candidate", last.explanation or "No verified repair was produced."
        state = last.state if last.state in ("unsupported", "inconclusive") else "inconclusive"
        return GroupOutcome(index, finding_ids, state, code, message, [], None, last.verification, trace, usage, agent_ran, evidence, unproven, coverage), [], unproven

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
            # Partial coverage: a finding outside the enabled families, whose exact source is
            # absent, whose file is in a language neither toolchain checks, or whose code the
            # static gates cannot repair safely is skipped with a reason, and the remaining
            # findings are still repaired.
            skipped: list[dict[str, str]] = []
            supported = []
            allowed = set(request.policy.allowed_rule_families)
            for finding in request.findings:
                finding_id = str(finding.snapshot_id or finding.id or finding.rule_id or "")
                family = _rule_family(finding)
                language = language_of_path(finding.affected_path)
                if family is None:
                    skipped.append({"finding_id": finding_id, "code": "unsupported_rule_family", "message": "This finding is outside the enabled repair families."})
                elif family not in allowed:
                    skipped.append({"finding_id": finding_id, "code": "rule_family_disabled", "message": "The repair family is disabled by policy."})
                elif not finding.affected_path or finding.affected_path not in snapshot.paths:
                    skipped.append({"finding_id": finding_id, "code": "affected_source_missing", "message": "The exact affected source file is absent from the snapshot."})
                elif path_forbidden(finding.affected_path, request):
                    # Policy will not change this file, so no patch built for it could ever be
                    # applied. Asking here rather than at `build_patch_bundle` is what keeps a
                    # template and a proof from being produced for a repair that cannot ship.
                    skipped.append({"finding_id": finding_id, "code": "protected_path", "message": PROTECTED_PATH_MESSAGE})
                elif language is None:
                    skipped.append({"finding_id": finding_id, "code": "unsupported_language", "message": UNSUPPORTED_LANGUAGE_MESSAGE})
                elif not family_supported(family, language):
                    skipped.append({"finding_id": finding_id, "code": "unsupported_rule_family", "message": f"The {family} family is not repaired for {language} sources yet."})
                elif (gate := static_gate(snapshot, finding, family, language)) is not None:
                    skipped.append({"finding_id": finding_id, "code": gate[0], "message": gate[1]})
                else:
                    supported.append(finding)
            if not supported:
                codes = {item["code"] for item in skipped}
                if len(codes) == 1 and skipped:
                    # One reason explains the whole request, so the response carries it rather
                    # than a generic family message the skip list would contradict.
                    return _reason_response(request, "unsupported", skipped[0]["code"], skipped[0]["message"], request_digest, snapshot.manifest_digest, skipped=skipped)
                return _reason_response(request, "unsupported", "unsupported_rule_family", "No selected finding is inside the enabled repair families.", request_digest, snapshot.manifest_digest, skipped=skipped)
            request = request.model_copy(update={"findings": supported})

        groups = group_findings_by_language(request.findings)
        group_count = len(groups)
        outcomes: list[GroupOutcome] = []
        accepted: list[tuple[Candidate, PatchBundle, VerificationResult]] = []
        verifier: Verifier | None = None
        remaining_tool_calls = request.policy.max_tool_calls
        remaining_tokens = request.policy.max_total_tokens
        remaining_usd = float(request.policy.max_spend_usd)

        group_languages: dict[int, str | None] = {}

        # One bounded agent loop per connected group, sequentially, sharing the job's budget.
        for index, group in enumerate(groups):
            finding_ids = sorted(finding.stable_id for finding in group)
            group_languages[index] = language_of_path(group[0].affected_path)
            if index > 0 and (
                remaining_tool_calls < GROUP_TOOL_CALL_FLOOR
                or remaining_tokens < GROUP_TOKEN_FLOOR
                or remaining_usd < GROUP_SPEND_FLOOR_USD
            ):
                outcomes.append(
                    GroupOutcome(index, finding_ids, "unsupported", "budget_exhausted", BUDGET_EXHAUSTED_MESSAGE, [], None, None, [], {}, False)
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
                return _reason_response(request, "unsupported", "runtime_prerequisite_missing", str(exc), request_digest, snapshot.manifest_digest, skipped=skipped)
            if verifier is None:
                verifier = agent.verifier
            budget = _Budget(remaining_tool_calls, remaining_tokens, remaining_usd)
            outcome, entries, unproven = await self._repair_group(
                request, group_request, list(group), index, snapshot, agent, verifier, accepted, budget, group_checkpoints
            )
            remaining_tool_calls, remaining_tokens, remaining_usd = budget.tool_calls, budget.tokens, budget.usd
            outcomes.append(outcome)
            accepted.extend(entries)
            if outcome.evidence.get("candidate_sources") or outcome.reason_code == DEPENDENT_HUNK_UNPROVEN:
                # A finding the group could not prove beside one it did is reported, never
                # carried silently; a group that proved nothing carries its reason instead.
                skipped.extend(
                    {"finding_id": str(item["finding_id"]), "code": str(item["code"]), "message": str(item["message"])}
                    for item in unproven
                )

        # A batch carries one kind of evidence. A statically asserted candidate says nothing ran;
        # an executed one says a test failed before the change and passed after it. Shipping both
        # under one response-level verification level would mean labelling the batch with whichever
        # of the two the reader happened to look at, so when the job produced any executed
        # candidate the asserted ones are dropped here and reported with the reason. Combining
        # them properly is possible and is not implemented; `contracts/repair-v1.md` says so.
        executed = [item for item in accepted if item[2].verification_level != STATIC_ASSERTION_VERIFICATION_LEVEL]
        if executed and len(executed) != len(accepted):
            for candidate, _, verification in accepted:
                if verification.verification_level != STATIC_ASSERTION_VERIFICATION_LEVEL:
                    continue
                skipped.extend(
                    {"finding_id": finding_id, "code": "static_assertion_not_combined", "message": STATIC_ASSERTION_NOT_COMBINABLE}
                    for finding_id in candidate.finding_ids
                )
            accepted = executed

        outcomes = [dataclass_replace(outcome, language=group_languages.get(outcome.index)) for outcome in outcomes]
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
                skipped=skipped,
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
                    **primary.evidence,
                },
                reason={"code": primary.reason_code or "no_verified_candidate", "message": primary.message or "No verified repair was produced."},
            )

        try:
            batch, combined = await build_verified_batch(request, snapshot, verifier, accepted)
        except PatchPolicyError as exc:
            return _reason_response(request, "unsupported", "overlapping_candidates" if "overlapping" in str(exc) else "batch_rejected", str(exc), request_digest, snapshot.manifest_digest, {"groups": group_report}, skipped=skipped)
        except BatchPolicyError as exc:
            return _reason_response(request, "inconclusive", "combined_verification_failed", str(exc), request_digest, snapshot.manifest_digest, {"groups": group_report}, skipped=skipped)
        combined_level = combined.verification.verification_level
        if not _level_permitted(combined_level, request.policy):
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
                skipped=skipped,
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
                "generated_tests": combined.bundle.generated_test_manifest,
                "groups": group_report,
            },
        )
