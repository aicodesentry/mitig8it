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
                {"reason_code": "regression_test_not_reproducing"},
                None,
                "regression_test_not_reproducing",
                "none",
                ["the candidate supplied no generated regression test, so the finding was never reproduced"],
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
            self._validate_evidence(request, snapshot, bundle, evidence, candidate_tree, level, effective)
        except BrokerTransportError:
            return self._inconclusive("sandbox_broker_unavailable")
        except BrokerEvidenceError:
            return self._inconclusive("sandbox_evidence_invalid")

        limitations = self._limitations(effective, evidence, level)
        status = evidence["outcome"]
        digest = evidence_digest(evidence)
        if self._regression_not_reproducing(effective, evidence):
            # The reproducer passed on the original code, so it does not demonstrate the
            # finding. That is an unusable reproducer, not a failing repair.
            return VerificationResult(
                "inconclusive", evidence, digest, "regression_test_not_reproducing", level, limitations
            )
        if status == "passed":
            scanner_status, scanner_reason = self._scanner_verdict(request, evidence)
            if scanner_status != "passed":
                return VerificationResult(scanner_status, evidence, digest, scanner_reason, level, limitations)
            return VerificationResult("passed", evidence, digest, None, level, limitations)
        if status == "failed":
            return VerificationResult("failed", evidence, digest, "verification_failed", level, limitations)
        if status == "unsupported":
            return VerificationResult("unsupported", evidence, digest, "sandbox_profile_unsupported", level, limitations)
        return VerificationResult("inconclusive", evidence, digest, "verification_inconclusive", level, limitations)

    @staticmethod
    def _regression_not_reproducing(effective: EffectiveChecks, evidence: dict[str, Any]) -> bool:
        """True when a generated reproducer completed on the baseline tree without failing."""
        for result in evidence.get("checks", []):
            if not isinstance(result, dict) or result.get("check_id") not in effective.regression_check_ids:
                continue
            baseline = result.get("baseline") or {}
            if baseline.get("completed") is True and baseline.get("status") != "failed":
                return True
        return False

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
            if baseline.get("completed") is not True or candidate.get("completed") is not True:
                if evidence.get("outcome") == "passed":
                    raise BrokerEvidenceError("passed evidence contains incomplete checks")
                continue
            if evidence.get("outcome") != "passed":
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
