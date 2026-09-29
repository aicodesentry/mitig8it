"""A fix keeps its identity across runs over identical code.

`candidate_id` is the `<!-- mitig8it-fix:<candidate id> -->` marker that both products match a
published fix block by, so it decides whether a re-analysis edits the block it already wrote or
replaces it. It used to be a digest over `job_id` and `evidence_digest`, and neither of those can
repeat:

- `job_id` is a fresh row per job in the App and, before this change, a fresh `uuid4` per run in
  the Action.
- `evidence_digest` hashes the broker's evidence document, which binds `request_nonce` from
  `secrets.token_hex(32)`. `sandbox/broker.py` requires that nonce to come back unchanged, so it is
  an anti-replay property of the verification contract and it is *supposed* to differ every run.

The ten repository trial recorded the consequence on pygoat, where a commit that touched only the
README rewrote two fix comments whose suggestion text was byte for byte identical
(`docs/validation/action-trial-2026-09.md`, "The findings are not stable between runs on identical
code"). A review that changes its mind without the code changing teaches maintainers to stop
reading it.

Identity is now the patch and the findings it repairs. These tests pin both halves: the same repair
keeps its id across runs, and a different repair does not inherit it.
"""
from __future__ import annotations

import pytest

from src.models import RepairRequest
from tests.conftest import with_source
from tests.test_engine import _ready_engine


@pytest.mark.asyncio
async def test_a_rerun_over_the_same_code_produces_the_same_candidate_id(request_payload, source):
    """Two jobs, same tree, same repair. The marker a re-run looks for has to still be there."""
    first = await _ready_engine({**request_payload, "job_id": "job-1"}, source)
    second = await _ready_engine({**request_payload, "job_id": "job-2"}, source)

    assert first.state == "ready" and second.state == "ready"
    # The premise: these really are two separate verification runs, not one cached answer.
    assert first.candidates[0].verification.evidence_digest != second.candidates[0].verification.evidence_digest

    assert first.candidates[0].candidate_id == second.candidates[0].candidate_id
    assert first.candidates[0].artifact_digest == second.candidates[0].artifact_digest
    assert first.candidates[0].verified_tree_oid == second.candidates[0].verified_tree_oid


@pytest.mark.asyncio
async def test_the_candidate_id_does_not_carry_the_job_or_the_evidence(request_payload, source):
    """Stated as a property, because the failure mode is a field creeping back into the digest."""
    response = await _ready_engine({**request_payload, "job_id": "job-distinctive"}, source)
    candidate = response.candidates[0]

    assert "job-distinctive" not in candidate.candidate_id
    assert candidate.verification.evidence_digest not in candidate.candidate_id
    # The digest keeps its own job: the audit trail, where a per-run value belongs.
    assert candidate.preview["evidence"]["evidence_digest"] == candidate.verification.evidence_digest


@pytest.mark.asyncio
async def test_a_different_repair_gets_a_different_candidate_id(request_payload, source):
    """Stability must not become collision: change the patch and the marker has to move."""
    baseline = await _ready_engine(request_payload, source)

    # The same finding on the same line, in a file whose surrounding text differs, so the
    # replacement content and therefore the artifact digest differ.
    altered_source = f"// a preceding comment\n{source}"
    altered = with_source(request_payload, altered_source, line=3)

    other = await _ready_engine(altered, altered_source)
    assert other.state == "ready"
    assert other.candidates[0].artifact_digest != baseline.candidates[0].artifact_digest
    assert other.candidates[0].candidate_id != baseline.candidates[0].candidate_id


@pytest.mark.asyncio
async def test_the_request_nonce_is_still_fresh_on_every_verification(request_payload, source):
    """The reason the evidence digest may not be an identity, asserted rather than assumed.

    If this ever stops being true the anti-replay binding in `sandbox/broker.py` has been weakened,
    and that is a security regression, not a convenience.
    """
    first = await _ready_engine(request_payload, source)
    second = await _ready_engine(request_payload, source)
    assert first.candidates[0].verification.evidence_digest != second.candidates[0].verification.evidence_digest


@pytest.mark.asyncio
async def test_the_request_validates_without_a_job_id_change_affecting_identity(request_payload, source):
    """A guard on the fixture itself: `job_id` is still a required, honoured request field."""
    request = RepairRequest.model_validate({**request_payload, "job_id": "job-77"})
    assert request.job_id == "job-77"
