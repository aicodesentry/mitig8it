from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Literal

from ..digests import digest_json
from ..git_tree import compute_tree_oid
from ..models import RepairRequest
from ..patches import PatchBundle, candidate_tree_digest
from ..retrieval import Snapshot
from ..sandbox import BrokerEvidenceError, BrokerTransportError, SandboxBroker
from ..sandbox.broker import evidence_digest
from ..sandbox.execution import aggregate_outcome
from .checks import EffectiveChecks, build_effective_checks, generated_snapshot_entries
from .static_assertion import (
    NOT_REPAIRED,
    NOTHING_EXECUTED,
    ORACLE_SCANNER_UNAVAILABLE,
    RuleOracle,
    RuleOracleError,
    assert_statically,
)

PRODUCTION_VERIFICATION_LEVEL = "independent_sandbox"
# Between the two: the check pair ran in separate Cloud Run job containers, each under its own
# unprivileged user, on a network its probes measured as unreachable. It is not the production
# level, because it offers neither a gVisor runtime class nor a read-only root filesystem, and
# it is nothing like the development level, because no repository code touches this service.
ISOLATED_JOB_VERIFICATION_LEVEL = "isolated_job"
DEVELOPMENT_VERIFICATION_LEVEL = "development_unverified"
# Weaker than all three above, and weaker in kind rather than in degree: nothing ran. The three
# levels above differ in how well isolated the thing that executed the repair was; this one is
# the level for a candidate where nothing executed at all, and the rule that flagged the line
# was re-run over the file text instead. `contracts/repair-v1.md` states its five clauses.
#
# `workflow_hardening` is the first family that can only ever use it, and that family's gate asks
# whether the level has arrived by asking `STATIC_ASSERTION_VERIFICATION_LEVEL in
# VERIFICATION_LEVELS` (`gates.static_assertion_level_available`). It is in that set now, so the
# family is on; before it was, every candidate of the family was refused by name.
STATIC_ASSERTION_VERIFICATION_LEVEL = "static_assertion"
# The levels a sandbox's own evidence may claim. The static assertion is deliberately absent: it
# is produced by the verifier itself from a scanner answer, never reported by a driver, so a
# broker that claims it is a broker claiming something it cannot have measured.
SANDBOX_VERIFICATION_LEVELS = {
    PRODUCTION_VERIFICATION_LEVEL,
    ISOLATED_JOB_VERIFICATION_LEVEL,
    DEVELOPMENT_VERIFICATION_LEVEL,
}
# Every level a candidate may carry. Membership here is what makes a level real: a family whose
# repairs can only be asserted rather than executed asks `STATIC_ASSERTION_VERIFICATION_LEVEL in
# VERIFICATION_LEVELS` before it lets a candidate through (`gates.static_assertion_level_available`),
# and until the level was implemented that question answered false and the family was refused.
VERIFICATION_LEVELS = SANDBOX_VERIFICATION_LEVELS | {STATIC_ASSERTION_VERIFICATION_LEVEL}
# Weakest first. A caller that has to compare two levels orders them by this list rather than
# by string, so adding a level never silently reorders anything.
VERIFICATION_LEVEL_ORDER = (
    STATIC_ASSERTION_VERIFICATION_LEVEL,
    DEVELOPMENT_VERIFICATION_LEVEL,
    ISOLATED_JOB_VERIFICATION_LEVEL,
    PRODUCTION_VERIFICATION_LEVEL,
)
ISOLATED_JOB_ENVIRONMENT_KIND = "cloud-run-job"
# The three targets a Cloud Run job task probes from the check's own user before the check
# runs. Evidence that does not carry all three as an explicit `false` is not this level.
ISOLATED_JOB_PROBE_TARGETS = ("metadata", "internet", "dns")


@dataclass(frozen=True)
class VerificationResult:
    status: Literal["passed", "failed", "inconclusive", "unsupported"]
    evidence: dict[str, Any]
    evidence_digest: str | None
    reason_code: str | None = None
    verification_level: str = "none"
    limitations: list[str] = field(default_factory=list)
    # Findings whose own regression test failed on the baseline tree and passed on the candidate
    # tree, and every other finding with the reason it was not shown repaired. A candidate
    # claims exactly `proven_finding_ids`; the rest are reported, never silently included.
    proven_finding_ids: list[str] = field(default_factory=list)
    unproven_findings: list[dict[str, str]] = field(default_factory=list)
    # Which evidence check ran each finding's regression test, so a caller can show the
    # test's own failure output for a finding that was not proven.
    regression_checks: dict[str, str] = field(default_factory=dict)


NOT_REPRODUCING = "regression_test_not_reproducing"


@dataclass(frozen=True)
class FindingVerdicts:
    proven: list[str]
    unproven: list[dict[str, str]]
    # Regression checks whose finding is unproven. They are left out of the pass/fail outcome:
    # the finding is dropped from the candidate instead of failing the whole verification.
    excluded_check_ids: frozenset[str]
    # The check that decided each finding: its failing test when it has one, else its first test.
    checks_by_finding: dict[str, str] = field(default_factory=dict)


STATIC_ASSERTION_NOT_PERMITTED = "static_assertion_verification_not_permitted"
STATIC_ASSERTION_ORACLE_UNAVAILABLE = "static_assertion_rule_oracle_unavailable"
# The reason code for the one outcome this level must never blur into any other: the rule was
# never evaluated. Every refusal below carries it, so a caller reading a static assertion that did
# not complete can tell "no rule was run over this patch" from "a clause was decided and failed"
# without knowing which transport gave out. The oracle's own code is kept alongside it in
# `oracle_reason_code`, because "the scanner is not installed" and "the analysis service did not
# answer" need different things done about them.
STATIC_ASSERTION_RULE_NOT_EVALUATED = "static_assertion_rule_not_evaluated"
# What a reviewer is told when nothing evaluated the rule. It says the claim was not made rather
# than that it failed, because no clause was reached.
RULE_NOT_EVALUATED_LIMITATION = (
    "the rule that flagged the finding was never evaluated over the patched file, so nothing here "
    "says whether it still matches"
)
# The limitation a static assertion always carries. It is not a caveat that undoes the level; it
# is the level, said out loud, so nobody reads a static assertion as a test result.
STATIC_ASSERTION_LIMITATION = (
    "nothing was executed: the repair was checked by re-running the rule that flagged the "
    "finding over the original and the patched file, not by running a test"
)


class Verifier:
    def __init__(self, broker: SandboxBroker, rule_oracle: RuleOracle | None = None):
        self.broker = broker
        # Supplied rather than constructed here, so a caller that has no analysis service (and
        # therefore no static assertion) is a configuration fact rather than a failure mode.
        self.rule_oracle = rule_oracle

    async def verify_static_assertion(
        self,
        request: RepairRequest,
        snapshot: Snapshot,
        bundle: PatchBundle,
        *,
        reason: str,
    ) -> VerificationResult:
        """Verify this candidate at the `static_assertion` level. Nothing is executed.

        The findings are the request's own, exactly as `verify` reads them. Never an upgrade and
        never a fallback the verifier reaches for on its own: the caller has already established
        that these findings' repairs cannot be proven by execution, or that the family declares
        the static assertion, and `reason` records which.
        """
        findings = list(request.findings)
        if not request.policy.allow_static_assertion_verification:
            return VerificationResult(
                "unsupported",
                {"reason_code": STATIC_ASSERTION_NOT_PERMITTED, "verification_level": STATIC_ASSERTION_VERIFICATION_LEVEL},
                None,
                STATIC_ASSERTION_NOT_PERMITTED,
                STATIC_ASSERTION_VERIFICATION_LEVEL,
                ["a static assertion was the only available evidence and policy does not allow it"],
                [],
                [self._untested(finding.stable_id) for finding in findings],
            )
        if self.rule_oracle is None:
            # No oracle is not an empty match set. The candidate is refused.
            return self._static_assertion_refusal(
                findings, STATIC_ASSERTION_ORACLE_UNAVAILABLE,
                "No analysis service is configured to re-run the rule, so the patch was not asserted.",
            )
        try:
            outcome = await assert_statically(request, snapshot, bundle, findings, self.rule_oracle, reason=reason)
        except RuleOracleError as exc:
            detail = (
                "the scanner that runs the rule is not installed where the assertion was decided"
                if exc.code == ORACLE_SCANNER_UNAVAILABLE
                else f"the oracle reported {exc.code}"
            )
            return self._static_assertion_refusal(
                findings, exc.code,
                f"The rule that flagged this finding was never evaluated over the patched file, so nothing "
                f"was asserted about it ({detail}).",
            )
        evidence = {
            **outcome.evidence,
            "outcome": "passed" if outcome.proven else "failed",
            "summary": outcome.message,
        }
        limitations = [STATIC_ASSERTION_LIMITATION, *self._static_assertion_limitations(bundle)]
        digest = digest_json(evidence)
        if not outcome.proven:
            return VerificationResult(
                "failed", evidence, digest, outcome.reason_code or "verification_failed",
                STATIC_ASSERTION_VERIFICATION_LEVEL, limitations, [], outcome.unproven,
            )
        # Some proven and some not is a normal outcome and is reported the way an executed run
        # reports it: the candidate claims exactly `proven`, and the rest carry their reason.
        return VerificationResult(
            "passed", evidence, digest, None, STATIC_ASSERTION_VERIFICATION_LEVEL,
            limitations, outcome.proven, outcome.unproven,
        )

    @staticmethod
    def _static_assertion_limitations(bundle: PatchBundle) -> list[str]:
        limitations = [
            "no regression test reproduced this finding, so nothing demonstrates that the vulnerability "
            "was present before the change or absent after it",
            "the repository's original test suite was not run",
            "no type check or build was run",
        ]
        limitations.extend(str(item)[:200] for item in bundle.limitations[:20])
        return limitations

    @staticmethod
    def _static_assertion_refusal(findings: list[Any], code: str, message: str) -> VerificationResult:
        """Refuse a candidate whose rule was never evaluated, and say that is what happened.

        Every path here is a non-evaluation, by construction: `code` is either
        `STATIC_ASSERTION_ORACLE_UNAVAILABLE` or one of `RULE_NOT_EVALUATED_CODES`, and none of
        those carries match sets. So the result's `reason_code` is
        `STATIC_ASSERTION_RULE_NOT_EVALUATED` regardless of which one it was: a caller's first
        question is not which transport gave out, it is whether a clause was decided, and here
        none was. `oracle_reason_code` keeps the cause, and no `clauses` map is written at all, so
        nothing downstream can read a held clause out of a refusal.
        """
        evidence = {
            "reason_code": STATIC_ASSERTION_RULE_NOT_EVALUATED,
            "oracle_reason_code": code,
            "verification_level": STATIC_ASSERTION_VERIFICATION_LEVEL,
            # Not "no rule matched": no rule was run. The two are the same shape and opposite
            # claims, so the evidence states which one this is.
            "rule_evaluated": False,
            "executed": False,
            "nothing_executed": NOTHING_EXECUTED,
        }
        return VerificationResult(
            "inconclusive", evidence, None, STATIC_ASSERTION_RULE_NOT_EVALUATED,
            STATIC_ASSERTION_VERIFICATION_LEVEL,
            [RULE_NOT_EVALUATED_LIMITATION, f"the static assertion did not complete: {code}"], [],
            [{"finding_id": finding.stable_id, "code": code, "message": message} for finding in findings],
        )

    async def verify(self, request: RepairRequest, snapshot: Snapshot, bundle: PatchBundle) -> VerificationResult:
        if request.policy.sandbox_image_digest is None and not request.policy.allow_development_verification:
            return self._unsupported("sandbox_image_digest_missing")
        if request.policy.require_generated_regression_test and not bundle.generated_tests:
            # Plan section 8 step 4: without a reproducer there is no evidence that separates a
            # repair from disabling the feature, whatever the other checks report.
            return VerificationResult(
                "inconclusive",
                {"reason_code": NOT_REPRODUCING},
                None,
                NOT_REPRODUCING,
                "none",
                ["the candidate supplied no generated regression test, so the finding was never reproduced"],
                [],
                [self._untested(finding.stable_id) for finding in request.findings],
            )
        effective = build_effective_checks(request, snapshot, bundle)
        checks = list(effective.checks)
        check_kinds = effective.kinds
        if not checks:
            return self._unsupported("verification_profile_missing")
        if "exploit" not in check_kinds:
            return self._unsupported("independent_exploit_check_required")
        if not check_kinds & {"behavior", "existing_test", "typecheck", "build"}:
            return self._unsupported("independent_exploit_and_behavior_checks_required")

        candidate_tree = candidate_tree_digest(snapshot, bundle)
        verified_tree_oid = compute_tree_oid(
            request.tree_entries,
            {patch.path: patch.replacement_content for patch in bundle.patches},
        )
        nonce = secrets.token_hex(32)
        core = {
            "schema_version": "v1",
            "execution_id": digest_json(
                {
                    "job_id": request.job_id,
                    "artifact_digest": bundle.artifact_digest,
                    "policy_version": request.policy.policy_version,
                    "verifier_version": request.versions.get("verifier", "unspecified"),
                }
            ),
            "request_nonce": nonce,
            "repository": {
                "tenant_id": request.tenant_id,
                "repository_id": request.repository_id,
                "head_sha": request.head_sha,
                "base_sha": request.base_sha,
                "context_manifest_digest": snapshot.manifest_digest,
                "original_tree_digest": snapshot.tree_digest,
                "candidate_tree_digest": candidate_tree,
                "head_tree_oid": request.head_tree_oid,
                "verified_tree_oid": verified_tree_oid,
            },
            "snapshot": generated_snapshot_entries(snapshot, effective),
            "patches": [patch.model_dump(mode="json") for patch in bundle.patches],
            "execution_policy": {
                "image_digest": request.policy.sandbox_image_digest,
                "network": "deny",
                "read_only_root": True,
                "commands": [check.model_dump(mode="json") for check in checks],
                "max_output_chars": request.policy.max_output_chars,
                "deadline_seconds": request.policy.request_timeout_seconds,
                # The one step of a run that is allowed to reach a registry, and only while the
                # snapshot is being materialized. `network: deny` above is still what every
                # check runs under. Only the development-only local driver acts on this; the
                # isolated drivers ignore it, for the reason `contracts/repair-v1.md` gives
                # under "Installed dependencies".
                "install_dependencies": request.policy.install_dependencies,
                "dependency_install_timeout_seconds": request.policy.dependency_install_timeout_seconds,
                "max_dependency_install_bytes": request.policy.max_dependency_install_bytes,
            },
            "versions": request.versions,
        }
        payload = {**core, "request_digest": digest_json(core)}
        try:
            # The policy value is the sandbox deadline the broker enforces; the transport
            # derives its own, longer, wait from it so it never gives up on a verification
            # the broker is still allowed to finish.
            evidence = await self.broker.verify(payload, request.policy.request_timeout_seconds)
            level = self._verification_level(evidence)
            if level == DEVELOPMENT_VERIFICATION_LEVEL and not request.policy.allow_development_verification:
                return VerificationResult(
                    "unsupported",
                    {"reason_code": "development_verification_not_permitted", "verification_level": level},
                    None,
                    "development_verification_not_permitted",
                    level,
                    ["the sandbox reported development-only evidence and policy does not allow it"],
                )
            if level == ISOLATED_JOB_VERIFICATION_LEVEL and not request.policy.allow_isolated_job_verification:
                return VerificationResult(
                    "unsupported",
                    {"reason_code": "isolated_job_verification_not_permitted", "verification_level": level},
                    None,
                    "isolated_job_verification_not_permitted",
                    level,
                    ["the sandbox reported isolated Cloud Run job evidence and policy does not allow it"],
                )
            halted = self._driver_halt(evidence)
            if halted is not None:
                # The driver ran no check and said why: a sandbox whose network probes came
                # back reachable, an image digest that did not match, an unattested cluster.
                # Its reason survives here instead of collapsing into a generic evidence error.
                status, reason = halted
                return VerificationResult(
                    status,
                    evidence,
                    evidence_digest(evidence),
                    reason,
                    level,
                    [f"verification did not run: {reason}"],
                    [],
                    [self._untested(finding.stable_id) for finding in request.findings],
                )
            verdicts = self._finding_verdicts(request, effective, evidence)
            status = self._effective_outcome(evidence, verdicts.excluded_check_ids)
            self._validate_evidence(
                request, snapshot, bundle, evidence, candidate_tree, level, effective, status, verdicts.excluded_check_ids
            )
        except BrokerTransportError:
            return self._inconclusive("sandbox_broker_unavailable")
        except BrokerEvidenceError:
            return self._inconclusive("sandbox_evidence_invalid")

        limitations = self._limitations(effective, evidence, level)
        digest = evidence_digest(evidence)
        unproven = verdicts.unproven
        checks_by_finding = verdicts.checks_by_finding
        if not verdicts.proven:
            # Nothing was shown repaired. A reproducer that passed on the original code is an
            # unusable reproducer, not a failing repair; a reproducer that still fails on the
            # candidate is a failed repair the agent can inspect and correct.
            if any(item["code"] == NOT_REPRODUCING for item in unproven):
                return VerificationResult("inconclusive", evidence, digest, NOT_REPRODUCING, level, limitations, [], unproven, checks_by_finding)
            return VerificationResult("failed", evidence, digest, "verification_failed", level, limitations, [], unproven, checks_by_finding)
        if status == "passed":
            scanner_status, scanner_reason = self._scanner_verdict(request, evidence)
            if scanner_status != "passed":
                return VerificationResult(scanner_status, evidence, digest, scanner_reason, level, limitations, [], unproven, checks_by_finding)
            return VerificationResult("passed", evidence, digest, None, level, limitations, verdicts.proven, unproven, checks_by_finding)
        if status == "failed":
            return VerificationResult("failed", evidence, digest, "verification_failed", level, limitations, [], unproven, checks_by_finding)
        if status == "unsupported":
            return VerificationResult("unsupported", evidence, digest, "sandbox_profile_unsupported", level, limitations, [], unproven, checks_by_finding)
        return VerificationResult("inconclusive", evidence, digest, "verification_inconclusive", level, limitations, [], unproven, checks_by_finding)

    @staticmethod
    def _untested(finding_id: str) -> dict[str, str]:
        return {
            "finding_id": finding_id,
            "code": NOT_REPAIRED,
            "message": "No regression test reproduced this finding, so the candidate does not claim it.",
        }

    @staticmethod
    def _finding_verdicts(request: RepairRequest, effective: EffectiveChecks, evidence: dict[str, Any]) -> FindingVerdicts:
        """Decides per finding whether its own reproducer failed on the baseline and passed on the candidate.

        A finding with no test is proven only when policy does not require generated tests, in
        which case the policy-supplied checks are its evidence. Every unproven finding carries
        the reason: `regression_test_not_reproducing` when its test also passed on the original
        code, `not_repaired` otherwise.
        """
        results: dict[str, dict[str, Any]] = {}
        for result in evidence.get("checks", []) if isinstance(evidence.get("checks"), list) else []:
            if isinstance(result, dict) and isinstance(result.get("check_id"), str):
                results[result["check_id"]] = result
        # Every test of a finding, in check order: a finding with a service-generated proof and a
        # model-written test beside it is proven only when both prove it.
        tested: dict[str, list[tuple[str, dict[str, str] | None]]] = {}
        excluded: set[str] = set()
        for check_id, finding_id in effective.regression_findings.items():
            result = results.get(check_id) or {}
            baseline = result.get("baseline") if isinstance(result.get("baseline"), dict) else {}
            candidate = result.get("candidate") if isinstance(result.get("candidate"), dict) else {}
            if baseline.get("completed") is True and baseline.get("status") != "failed":
                verdict = {
                    "finding_id": finding_id,
                    "code": NOT_REPRODUCING,
                    "message": "The regression test for this finding also passes on the original code, so it does not reproduce the finding.",
                }
            elif baseline.get("completed") is True and candidate.get("completed") is True and candidate.get("status") == "passed":
                verdict = None
            elif candidate.get("completed") is True:
                verdict = {
                    "finding_id": finding_id,
                    "code": NOT_REPAIRED,
                    "message": "The regression test for this finding still fails on the patched code.",
                }
            else:
                verdict = {
                    "finding_id": finding_id,
                    "code": NOT_REPAIRED,
                    "message": "The regression test for this finding did not complete on both trees.",
                }
            tested.setdefault(finding_id, []).append((check_id, verdict))
        for finding_id, verdicts in tested.items():
            if any(verdict is not None for _, verdict in verdicts):
                excluded.update(check_id for check_id, _ in verdicts)
        proven: list[str] = []
        unproven: list[dict[str, str]] = []
        checks_by_finding: dict[str, str] = {}
        for finding in request.findings:
            finding_id = finding.stable_id
            if finding_id in tested:
                failed = [(check_id, verdict) for check_id, verdict in tested[finding_id] if verdict is not None]
                checks_by_finding[finding_id] = failed[0][0] if failed else tested[finding_id][0][0]
                if not failed:
                    proven.append(finding_id)
                else:
                    unproven.append(failed[0][1])
            elif request.policy.require_generated_regression_test:
                unproven.append(Verifier._untested(finding_id))
            else:
                proven.append(finding_id)
        return FindingVerdicts(proven, unproven, frozenset(excluded), checks_by_finding)

    @staticmethod
    def _effective_outcome(evidence: dict[str, Any], excluded: frozenset[str]) -> str:
        """The check outcome over every check except the regression checks of unproven findings."""
        if evidence.get("outcome") == "unsupported":
            return "unsupported"
        records = [
            result
            for result in (evidence.get("checks") if isinstance(evidence.get("checks"), list) else [])
            if isinstance(result, dict) and isinstance(result.get("kind"), str) and result.get("check_id") not in excluded
        ]
        return aggregate_outcome(records)

    @staticmethod
    def _driver_halt(evidence: dict[str, Any]) -> tuple[str, str] | None:
        """A driver that executed no check and named the reason, or None.

        Only an empty check list qualifies. A driver that ran checks and still reported a
        reason code does not take this path, because the checks themselves are the evidence
        and `_effective_outcome` must decide from them.
        """
        outcome = evidence.get("outcome")
        reason = evidence.get("reason_code")
        if outcome not in {"inconclusive", "unsupported"} or evidence.get("checks"):
            return None
        if not isinstance(reason, str) or not reason or len(reason) > 120:
            return None
        return str(outcome), reason

    @staticmethod
    def _verification_level(evidence: dict[str, Any]) -> str:
        if not isinstance(evidence, dict):
            raise BrokerEvidenceError("broker evidence is not an object")
        level = evidence.get("verification_level", PRODUCTION_VERIFICATION_LEVEL)
        # The sandbox set, not every level: a broker that reported `static_assertion` would be
        # claiming a level no driver can measure, and that is rejected rather than trusted.
        if level not in SANDBOX_VERIFICATION_LEVELS:
            raise BrokerEvidenceError("broker verification level is unrecognized")
        return str(level)

    def _scanner_verdict(self, request: RepairRequest, evidence: dict[str, Any]) -> tuple[str, str | None]:
        """Plan section 8 step 6: a candidate that introduces scanner findings is not a repair."""
        scanner_ids = {check.check_id for check in request.policy.verification_checks if check.kind == "scanner"}
        if not scanner_ids:
            return "passed", None
        for result in evidence.get("checks", []):
            if result.get("check_id") not in scanner_ids:
                continue
            baseline = (result.get("baseline") or {}).get("scanner_findings")
            candidate = (result.get("candidate") or {}).get("scanner_findings")
            if not isinstance(baseline, list) or not isinstance(candidate, list):
                return "inconclusive", "scanner_findings_report_missing"
            if set(candidate) - set(baseline):
                return "failed", "scanner_findings_regression"
        return "passed", None

    @staticmethod
    def _limitations(effective: EffectiveChecks, evidence: dict[str, Any], level: str) -> list[str]:
        """Names every required verification that was not run. Absent evidence is never coverage."""
        kinds = effective.kinds
        limitations: list[str] = list(effective.limitations)
        if level == DEVELOPMENT_VERIFICATION_LEVEL:
            limitations.append(
                "verification ran in the development local sandbox without network, kernel, or filesystem isolation"
            )
        if level == ISOLATED_JOB_VERIFICATION_LEVEL:
            # An honest limitation, not a caveat that undoes the level: the checks did run in
            # separate containers on a network their own probes measured as unreachable. What
            # this level does not carry is the production level's read-only root filesystem and
            # gVisor runtime class, so it says exactly that and nothing weaker.
            limitations.append(
                "verification ran in an isolated Cloud Run job container without a read-only root "
                "filesystem or a gVisor runtime class"
            )
        if "existing_test" not in kinds:
            limitations.append("the repository's original test suite was not run")
        if "typecheck" not in kinds and "build" not in kinds:
            limitations.append("no type check or build was run")
        if "scanner" not in kinds:
            limitations.append("no scanner baseline/candidate finding comparison was run")
        for result in evidence.get("checks", []):
            for variant in ("baseline", "candidate"):
                outcome = result.get(variant) or {}
                if outcome.get("completed") is not True:
                    limitations.append(f"check {result.get('check_id')} did not complete on the {variant} tree")
        gaps = evidence.get("coverage_gaps")
        if isinstance(gaps, list):
            limitations.extend(str(gap)[:200] for gap in gaps[:20])
        return limitations

    def _validate_evidence(
        self,
        request: RepairRequest,
        snapshot: Snapshot,
        bundle: PatchBundle,
        evidence: dict[str, Any],
        candidate_tree: str,
        level: str,
        effective: EffectiveChecks,
        status: str,
        excluded: frozenset[str],
    ) -> None:
        if evidence.get("outcome") not in {"passed", "failed", "inconclusive", "unsupported"}:
            raise BrokerEvidenceError("broker outcome is invalid")
        if evidence.get("original_tree_digest") != snapshot.tree_digest:
            raise BrokerEvidenceError("original tree digest mismatch")
        if evidence.get("candidate_tree_digest") != candidate_tree:
            raise BrokerEvidenceError("candidate tree digest mismatch")
        verified_tree_oid = compute_tree_oid(
            request.tree_entries,
            {patch.path: patch.replacement_content for patch in bundle.patches},
        )
        if evidence.get("head_tree_oid") != request.head_tree_oid or evidence.get("verified_tree_oid") != verified_tree_oid:
            raise BrokerEvidenceError("Git tree identity mismatch")
        runner = evidence.get("runner")
        if not isinstance(runner, dict):
            raise BrokerEvidenceError("runner identity is absent")
        if level == PRODUCTION_VERIFICATION_LEVEL:
            if runner.get("image_digest") != request.policy.sandbox_image_digest:
                raise BrokerEvidenceError("runner image digest mismatch")
            if runner.get("network") != "deny" or runner.get("read_only_root") is not True:
                raise BrokerEvidenceError("runner isolation claims do not satisfy policy")
        elif level == ISOLATED_JOB_VERIFICATION_LEVEL:
            self._validate_isolated_job_runner(request, runner, evidence)
        elif runner.get("runtime_class") != "local-subprocess":
            raise BrokerEvidenceError("development evidence does not identify the local development runner")

        results = evidence.get("checks")
        if not isinstance(results, list):
            raise BrokerEvidenceError("broker check evidence is absent")
        expected = {check.check_id: check for check in effective.checks}
        actual: dict[str, dict[str, Any]] = {}
        for result in results:
            if not isinstance(result, dict) or not isinstance(result.get("check_id"), str):
                raise BrokerEvidenceError("invalid check result")
            if result["check_id"] in actual:
                raise BrokerEvidenceError("duplicate check result")
            actual[result["check_id"]] = result
        if set(actual) != set(expected):
            raise BrokerEvidenceError("check result set does not match policy")

        for check_id, check in expected.items():
            result = actual[check_id]
            if result.get("kind") != check.kind or list(result.get("argv") or []) != check.argv:
                raise BrokerEvidenceError("executed check differs from policy")
            baseline, candidate = result.get("baseline"), result.get("candidate")
            if not isinstance(baseline, dict) or not isinstance(candidate, dict):
                raise BrokerEvidenceError("baseline/candidate check evidence missing")
            if check_id in excluded:
                # An unproven finding's reproducer: its outcome drops the finding from the
                # candidate and is never part of a passed verdict.
                continue
            if baseline.get("completed") is not True or candidate.get("completed") is not True:
                if status == "passed":
                    raise BrokerEvidenceError("passed evidence contains incomplete checks")
                continue
            if status != "passed":
                continue
            if candidate.get("status") != "passed":
                raise BrokerEvidenceError("passed evidence contains failing candidate check")
            if check.kind in {"existing_test", "typecheck", "build", "behavior"} and baseline.get("status") != "passed":
                raise BrokerEvidenceError("passed evidence relies on a failing baseline behavior check")
            if check.kind == "exploit" and baseline.get("status") != "failed":
                raise BrokerEvidenceError("exploit check did not demonstrate the original vulnerability")

    @staticmethod
    def _validate_isolated_job_runner(request: RepairRequest, runner: dict[str, Any], evidence: dict[str, Any]) -> None:
        """What the `isolated_job` level has to have measured before it may be claimed.

        The production level is validated on declared isolation properties, because the cluster
        enforces them. This level is validated on *measurements*: the driver may claim a denied
        network only once every task that completed reported every probe target as explicitly
        unreachable from the check's own user. `reached: null` is a probe that did not run, and
        it fails here exactly like a probe that connected.
        """
        if runner.get("image_digest") != request.policy.sandbox_image_digest:
            raise BrokerEvidenceError("runner image digest mismatch")
        if runner.get("environment_kind") != ISOLATED_JOB_ENVIRONMENT_KIND:
            raise BrokerEvidenceError("isolated job evidence does not identify a Cloud Run job container")
        executions = runner.get("job_executions")
        if not isinstance(executions, list) or not executions or not all(isinstance(name, str) and name for name in executions):
            raise BrokerEvidenceError("isolated job evidence does not name the job executions that produced it")
        if runner.get("network") != "deny":
            raise BrokerEvidenceError("isolated job evidence does not claim a denied network")
        results = evidence.get("checks") if isinstance(evidence.get("checks"), list) else []
        for result in results:
            if not isinstance(result, dict):
                continue
            for variant in ("baseline", "candidate"):
                outcome = result.get(variant)
                if not isinstance(outcome, dict) or outcome.get("completed") is not True:
                    continue
                probes = outcome.get("network_probes")
                if not isinstance(probes, dict):
                    raise BrokerEvidenceError("isolated job evidence carries no network probes")
                for target in ISOLATED_JOB_PROBE_TARGETS:
                    probe = probes.get(target)
                    if not isinstance(probe, dict) or probe.get("reached") is not False:
                        raise BrokerEvidenceError(f"isolated job network probe {target} did not report unreachable")
                if not isinstance(outcome.get("job_execution"), str) or not outcome["job_execution"]:
                    raise BrokerEvidenceError("isolated job check result does not name its job execution")

    @staticmethod
    def _unsupported(code: str) -> VerificationResult:
        return VerificationResult("unsupported", {"reason_code": code}, None, code, "none", [f"verification did not run: {code}"])

    @staticmethod
    def _inconclusive(code: str) -> VerificationResult:
        return VerificationResult("inconclusive", {"reason_code": code}, None, code, "none", [f"verification did not complete: {code}"])
