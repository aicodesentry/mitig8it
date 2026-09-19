import pytest

from tests.conftest import whole_file_change

from src.batch import BatchPolicyError, build_immutable_batch
from src.models import Candidate, FilePatch, RepairRequest, VerificationSummary


def candidate(identifier, path="src/a.ts", tree="a" * 40):
    return Candidate(
        candidate_id=identifier,
        finding_ids=[identifier],
        hypothesis="h",
        intended_behavior="b",
        assumptions=[],
        citations=[],
        patch=[FilePatch(path=path, base_sha256="sha256:" + "1" * 64, replacement_content="x", contents_base64="eA==", new_sha256="sha256:" + "2" * 64, unified_diff="diff")],
        file_manifest=[],
        artifact_digest="sha256:" + "3" * 64,
        context_manifest_digest="sha256:" + "4" * 64,
        verified_tree_oid=tree,
        verification=VerificationSummary(status="passed", evidence_digest="sha256:" + "5" * 64),
        preview={},
    )


def test_batch_rejects_overlapping_candidates(request_payload):
    request = RepairRequest.model_validate(request_payload)
    with pytest.raises(BatchPolicyError, match="overlapping"):
        build_immutable_batch(request, "sha256:" + "0" * 64, [candidate("one"), candidate("two")])


def test_batch_binds_order_and_verified_tree(request_payload):
    request = RepairRequest.model_validate(request_payload)
    batch = build_immutable_batch(request, "sha256:" + "0" * 64, [candidate("one")])
    assert batch.manifest["ordered_candidate_ids"] == ["one"]
    assert batch.manifest["verified_tree_oid"] == "a" * 40
    assert batch.manifest_digest.startswith("sha256:")


PARAMETERIZED = "export function loadUser(db, id) {\n  return db.query('SELECT * FROM users WHERE id = $1', [id]);\n}\n"
COMMENTED = "export function loadUser(db, id) {\n  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n}\n// audited\n"
ALTERNATIVE = "export function loadUser(db, id) {\n  return db.query('SELECT * FROM users WHERE id = ?', [id]);\n}\n"


def _bundle(request, snapshot, replacement):
    from src.digests import content_sha256
    from src.patches import build_patch_bundle

    return build_patch_bundle(
        request,
        snapshot,
        [whole_file_change("src/db.ts", snapshot.full_content("src/db.ts"), replacement)],
    )


def _verified_candidate(identifier, bundle, tree_oid):
    return Candidate(
        candidate_id=identifier,
        finding_ids=[identifier],
        hypothesis="h",
        intended_behavior="b",
        assumptions=[],
        citations=[],
        patch=list(bundle.patches),
        file_manifest=bundle.file_manifest,
        artifact_digest=bundle.artifact_digest,
        context_manifest_digest="sha256:" + "4" * 64,
        verified_tree_oid=tree_oid,
        verification=VerificationSummary(status="passed", evidence_digest="sha256:" + "5" * 64),
        preview={},
    )


class CombinedPassingVerifier:
    def __init__(self):
        self.calls = 0

    async def verify(self, request, snapshot, bundle):
        from src.verification import VerificationResult

        self.calls += 1
        return VerificationResult("passed", {"outcome": "passed"}, "sha256:" + "7" * 64, None, "independent_sandbox", [])


def test_non_overlapping_candidates_combine_into_one_tree(request_payload):
    from src.git_tree import compute_tree_oid
    from src.patches import combine_patch_bundles
    from src.retrieval import Snapshot

    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    first, second = _bundle(request, snapshot, PARAMETERIZED), _bundle(request, snapshot, COMMENTED)
    combined = combine_patch_bundles(request, snapshot, [first, second])
    merged = combined.patches[0].replacement_content
    assert "$1" in merged and "// audited" in merged
    combined_oid = compute_tree_oid(request.tree_entries, {"src/db.ts": merged})
    assert combined_oid not in {
        compute_tree_oid(request.tree_entries, {"src/db.ts": PARAMETERIZED}),
        compute_tree_oid(request.tree_entries, {"src/db.ts": COMMENTED}),
    }


def test_overlapping_candidates_are_rejected(request_payload):
    from src.patches import PatchPolicyError, combine_patch_bundles
    from src.retrieval import Snapshot

    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    bundles = [_bundle(request, snapshot, PARAMETERIZED), _bundle(request, snapshot, ALTERNATIVE)]
    with pytest.raises(PatchPolicyError, match="overlapping_candidates"):
        combine_patch_bundles(request, snapshot, bundles)


@pytest.mark.asyncio
async def test_batch_of_two_candidates_uses_the_recombined_verified_tree(request_payload):
    from src.engine import build_verified_batch
    from src.git_tree import compute_tree_oid
    from src.retrieval import Snapshot
    from src.verification import VerificationResult

    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    first, second = _bundle(request, snapshot, PARAMETERIZED), _bundle(request, snapshot, COMMENTED)
    individual = VerificationResult("passed", {"outcome": "passed"}, "sha256:" + "6" * 64, None, "independent_sandbox", [])
    entries = [
        (_verified_candidate("one", first, compute_tree_oid(request.tree_entries, {"src/db.ts": PARAMETERIZED})), first, individual),
        (_verified_candidate("two", second, compute_tree_oid(request.tree_entries, {"src/db.ts": COMMENTED})), second, individual),
    ]
    verifier = CombinedPassingVerifier()
    batch, combined = await build_verified_batch(request, snapshot, verifier, entries)
    assert verifier.calls == 1
    assert batch.manifest["ordered_candidate_ids"] == ["one", "two"]
    assert batch.manifest["verified_tree_oid"] == combined.verified_tree_oid
    assert batch.manifest["verified_tree_oid"] not in {entry[0].verified_tree_oid for entry in entries}
    assert batch.manifest["combined_verification_evidence_digest"] == "sha256:" + "7" * 64


@pytest.mark.asyncio
async def test_overlapping_candidates_never_reach_a_combined_verification(request_payload):
    from src.engine import build_verified_batch
    from src.git_tree import compute_tree_oid
    from src.patches import PatchPolicyError
    from src.retrieval import Snapshot
    from src.verification import VerificationResult

    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    first, second = _bundle(request, snapshot, PARAMETERIZED), _bundle(request, snapshot, ALTERNATIVE)
    individual = VerificationResult("passed", {"outcome": "passed"}, "sha256:" + "6" * 64, None, "independent_sandbox", [])
    entries = [
        (_verified_candidate("one", first, compute_tree_oid(request.tree_entries, {"src/db.ts": PARAMETERIZED})), first, individual),
        (_verified_candidate("two", second, compute_tree_oid(request.tree_entries, {"src/db.ts": ALTERNATIVE})), second, individual),
    ]
    verifier = CombinedPassingVerifier()
    with pytest.raises(PatchPolicyError, match="overlapping_candidates"):
        await build_verified_batch(request, snapshot, verifier, entries)
    assert verifier.calls == 0


def test_multi_candidate_batch_requires_combined_verification_evidence(request_payload):
    request = RepairRequest.model_validate(request_payload)
    with pytest.raises(BatchPolicyError, match="combined_verification_evidence_required"):
        build_immutable_batch(request, "sha256:" + "0" * 64, [candidate("one")], "a" * 40, None)
