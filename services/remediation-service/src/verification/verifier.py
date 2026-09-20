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

PRODUCTION_VERIFICATION_LEVEL = "independent_sandbox"
DEVELOPMENT_VERIFICATION_LEVEL = "development_unverified"
VERIFICATION_LEVELS = {PRODUCTION_VERIFICATION_LEVEL, DEVELOPMENT_VERIFICATION_LEVEL}


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


NOT_REPAIRED = "not_repaired"
NOT_REPRODUCING = "regression_test_not_reproducing"


@dataclass(frozen=True)
class FindingVerdicts:
    proven: list[str]
    unproven: list[dict[str, str]]
    # Regression checks whose finding is unproven. They are left out of the pass/fail outcome:
    # the finding is dropped from the candidate instead of failing the whole verification.
    excluded_check_ids: frozenset[str]


class Verifier:
    def __init__(self, broker: SandboxBroker):
        self.broker = broker

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
            },
            "versions": request.versions,
        }
        payload = {**core, "request_digest": digest_json(core)}
        try:
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
        checks_by_finding = {finding_id: check_id for check_id, finding_id in effective.regression_findings.items()}
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
        tested: dict[str, dict[str, str] | None] = {}
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
            tested[finding_id] = verdict
            if verdict is not None:
                excluded.add(check_id)
        proven: list[str] = []
        unproven: list[dict[str, str]] = []
        for finding in request.findings:
            finding_id = finding.stable_id
            if finding_id in tested:
                if tested[finding_id] is None:
                    proven.append(finding_id)
                else:
                    unproven.append(tested[finding_id])
            elif request.policy.require_generated_regression_test:
                unproven.append(Verifier._untested(finding_id))
            else:
                proven.append(finding_id)
        return FindingVerdicts(proven, unproven, frozenset(excluded))

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
    def _verification_level(evidence: dict[str, Any]) -> str:
        if not isinstance(evidence, dict):
            raise BrokerEvidenceError("broker evidence is not an object")
        level = evidence.get("verification_level", PRODUCTION_VERIFICATION_LEVEL)
        if level not in VERIFICATION_LEVELS:
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
    def _unsupported(code: str) -> VerificationResult:
        return VerificationResult("unsupported", {"reason_code": code}, None, code, "none", [f"verification did not run: {code}"])

    @staticmethod
    def _inconclusive(code: str) -> VerificationResult:
        return VerificationResult("inconclusive", {"reason_code": code}, None, code, "none", [f"verification did not complete: {code}"])
