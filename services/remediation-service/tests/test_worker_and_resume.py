from __future__ import annotations

import pytest

from tests.conftest import whole_file_change

import src.worker as worker
from src.agent import RepairAgent
from src.digests import content_sha256
from src.models import RepairRequest, RepairResponse
from src.retrieval import Snapshot
from src.verification import Verifier


class StubRecord:
    execution_id = "sha256:" + "1" * 64
    state = "running"
    request_digest = "sha256:" + "2" * 64
    request_artifact_uri = "file:///input#sha256:x"
    result_artifact_uri = None
    trace_context = None


class StubBackend:
    def __init__(self, request, published: bool):
        self.request = request
        self.published = published
        self.claims = 0

    def claim(self, worker_id, lease_seconds=60):
        self.claims += 1
        return StubRecord() if self.claims == 1 else None

    def read_request(self, record):
        return self.request

    def heartbeat(self, execution_id, worker_id, lease_seconds=60):
        return True

    def complete(self, execution_id, worker_id, result):
        return self.published


def response_for(request):
    return RepairResponse(
        state="unsupported",
        job_id=request.job_id,
        tenant_id=request.tenant_id,
        repository_id=request.repository_id,
        head_sha=request.head_sha,
        base_sha=request.base_sha,
        request_digest="sha256:" + "3" * 64,
        evidence={"verification_level": "none"},
        reason={"code": "test", "message": "test"},
    )


class StubEngine:
    def __init__(self, agent_factory=None):
        pass

    async def repair(self, request, checkpoints=None):
        return response_for(request)


@pytest.mark.asyncio
async def test_rejected_completion_is_counted_and_logged_not_treated_as_success(monkeypatch, caplog, request_payload):
    monkeypatch.setattr(worker, "RepairEngine", StubEngine)
    monkeypatch.setitem(worker.COUNTERS, "completions_rejected", 0)
    monkeypatch.setitem(worker.COUNTERS, "results_published", 0)
    request = RepairRequest.model_validate(request_payload)
    backend = StubBackend(request, published=False)
    with caplog.at_level("ERROR"):
        assert await worker.run_once(backend, "worker-a") is True
    assert worker.COUNTERS["completions_rejected"] == 1
    assert worker.COUNTERS["results_published"] == 0
    assert any("was not published" in record.message for record in caplog.records)


@pytest.mark.asyncio
async def test_published_completion_increments_only_the_success_counter(monkeypatch, request_payload):
    monkeypatch.setattr(worker, "RepairEngine", StubEngine)
    monkeypatch.setitem(worker.COUNTERS, "completions_rejected", 0)
    monkeypatch.setitem(worker.COUNTERS, "results_published", 0)
    request = RepairRequest.model_validate(request_payload)
    assert await worker.run_once(StubBackend(request, published=True), "worker-a") is True
    assert worker.COUNTERS["completions_rejected"] == 0
    assert worker.COUNTERS["results_published"] == 1


class ResumeCheckpointStore:
    def __init__(self, checkpoint):
        self.checkpoint = checkpoint

    async def load(self):
        return self.checkpoint

    async def reserve_provider_call(self, sequence, tokens, usd):
        return True

    async def save_provider_action(self, state, action, actual_tokens, actual_usd):
        return None

    async def save_completed_step(self, state):
        return None


class UnusedProvider:
    async def next_action(self, messages, tools):
        raise AssertionError("the resumed proposal must be rejected before any provider call")


class UnusedBroker:
    async def verify(self, payload, timeout_seconds):
        raise AssertionError("verification must not run for a rejected proposal")


@pytest.mark.asyncio
async def test_resumed_proposal_that_violates_patch_policy_is_a_structured_abstention(request_payload):
    test_content = "test('x', () => {})\n"
    request_payload["files"].append({"path": "tests/db.test.ts", "content": test_content})
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    checkpoint = {
        "context_manifest_digest": snapshot.manifest_digest,
        "messages": [],
        "trace": [],
        "proposal_arguments": {
            "hypothesis": "h",
            "intended_behavior": "b",
            "assumptions": [],
            "citations": [{"path": "tests/db.test.ts", "line_start": 1, "line_end": 1}],
            "changes": [whole_file_change("tests/db.test.ts", test_content, "")],
        },
    }
    agent = RepairAgent(UnusedProvider(), Verifier(UnusedBroker()), ResumeCheckpointStore(checkpoint))
    result = await agent.run(request, snapshot)
    assert result.state == "unsupported"
    assert result.reason_code == "resumed_proposal_rejected"
    assert "protected_path" in result.explanation
