from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .digests import digest_json
from .models import Candidate, RepairRequest


class BatchPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ImmutableBatch:
    manifest: dict[str, Any]
    manifest_digest: str


def build_immutable_batch(
    request: RepairRequest,
    context_manifest_digest: str,
    candidates: list[Candidate],
    combined_tree_oid: str | None = None,
    combined_evidence_digest: str | None = None,
) -> ImmutableBatch:
    """Builds the immutable batch manifest.

    Without `combined_tree_oid` every candidate must already share one independently verified
    tree, which is only true for a single-candidate batch. A multi-candidate batch must supply
    the tree OID and evidence digest of a verification run on the combined tree; overlapping
    candidates are rejected before that run by `combine_patch_bundles`.
    """
    if not candidates:
        raise BatchPolicyError("batch_contains_no_candidates")
    paths: set[str] = set()
    tree_oids = set()
    for candidate in candidates:
        if candidate.verification.status != "passed" or not candidate.verification.evidence_digest:
            raise BatchPolicyError("batch_contains_unverified_candidate")
        tree_oids.add(candidate.verified_tree_oid)
        for patch in candidate.patch:
            if patch.path in paths and combined_tree_oid is None:
                raise BatchPolicyError(f"overlapping_candidate_path:{patch.path}")
            paths.add(patch.path)
    if combined_tree_oid is None:
        if len(tree_oids) != 1:
            raise BatchPolicyError("candidates_do_not_share_combined_verified_tree")
        combined_tree_oid = next(iter(tree_oids))
        combined_evidence_digest = combined_evidence_digest or candidates[0].verification.evidence_digest
    elif not combined_evidence_digest:
        raise BatchPolicyError("combined_verification_evidence_required")
    manifest = {
        "schema_version": "v1",
        "job_id": request.job_id,
        "tenant_id": request.tenant_id,
        "repository_id": request.repository_id,
        "head_sha": request.head_sha,
        "base_sha": request.base_sha,
        "analysis_run_id": request.analysis_run_id,
        "context_manifest_digest": context_manifest_digest,
        "ordered_candidate_ids": [candidate.candidate_id for candidate in candidates],
        "candidate_artifact_digests": [candidate.artifact_digest for candidate in candidates],
        "verification_evidence_digests": [candidate.verification.evidence_digest for candidate in candidates],
        # Generated regression tests are reviewed with the batch and tracked apart from the
        # application files, because they are evidence rather than part of the applied tree.
        "generated_tests": [entry for candidate in candidates for entry in candidate.generated_tests],
        "head_tree_oid": request.head_tree_oid,
        "verified_tree_oid": combined_tree_oid,
        "combined_verification_evidence_digest": combined_evidence_digest,
        "versions": request.versions,
        "policy_version": request.policy.policy_version,
    }
    return ImmutableBatch(manifest, digest_json(manifest))
