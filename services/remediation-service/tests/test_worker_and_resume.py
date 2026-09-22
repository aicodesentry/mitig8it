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


class HeartbeatCountingBackend(StubBackend):
    """Records every heartbeat so a starved event loop is visible as a gap in renewals."""

    def __init__(self, request):
        super().__init__(request, published=True)
        self.heartbeats = 0

    def heartbeat(self, execution_id, worker_id, lease_seconds=60):
        self.heartbeats += 1
        return True


@pytest.mark.asyncio
async def test_a_slow_repair_keeps_the_lease_alive(monkeypatch, request_payload):
    """A model or sandbox call that takes many heartbeat intervals must not cost the lease."""
    import asyncio

    request = RepairRequest.model_validate(request_payload)
    backend = HeartbeatCountingBackend(request)

    class SlowEngine:
        def __init__(self, agent_factory=None):
            pass

        async def repair(self, req, checkpoints):
            await asyncio.sleep(0.25)
            return response_for(req)

    monkeypatch.setenv("REMEDIATION_WORKER_HEARTBEAT_SECONDS", "0.02")
    monkeypatch.setattr(worker, "RepairEngine", SlowEngine)

    assert await worker.run_once(backend, "worker-a") is True
    # Several renewals across 0.25s of work, where a starved loop would send none.
    assert backend.heartbeats >= 3
    assert worker.COUNTERS["results_published"] >= 1


@pytest.mark.asyncio
async def test_blocking_work_inside_the_repair_still_lets_heartbeats_through(monkeypatch, request_payload):
    """The regression: a synchronous subprocess on the loop stops every renewal.

    `build_patch_bundle` shells out to `node --check`, so the loop runs it in a worker thread.
    This encodes that contract with a blocking sleep standing in for the subprocess.
    """
    import asyncio
    import time

    request = RepairRequest.model_validate(request_payload)
    backend = HeartbeatCountingBackend(request)

    class BlockingEngine:
        def __init__(self, agent_factory=None):
            pass

        async def repair(self, req, checkpoints):
            await asyncio.to_thread(time.sleep, 0.25)
            return response_for(req)

    monkeypatch.setenv("REMEDIATION_WORKER_HEARTBEAT_SECONDS", "0.02")
    monkeypatch.setattr(worker, "RepairEngine", BlockingEngine)

    assert await worker.run_once(backend, "worker-a") is True
    assert backend.heartbeats >= 3


def test_the_lease_is_never_shorter_than_three_heartbeat_intervals(monkeypatch):
    monkeypatch.setenv("REMEDIATION_WORKER_HEARTBEAT_SECONDS", "15")
    monkeypatch.setenv("REMEDIATION_WORKER_LEASE_SECONDS", "20")
    assert worker.lease_seconds() == 45

    monkeypatch.setenv("REMEDIATION_WORKER_LEASE_SECONDS", "600")
    assert worker.lease_seconds() == 600

    monkeypatch.delenv("REMEDIATION_WORKER_HEARTBEAT_SECONDS")
    monkeypatch.delenv("REMEDIATION_WORKER_LEASE_SECONDS")
    assert worker.lease_seconds() >= worker.heartbeat_seconds() * 3


@pytest.mark.asyncio
async def test_combining_candidates_keeps_the_lease_alive(monkeypatch, request_payload):
    """`combine_patch_bundles` runs subprocess syntax and load checks and diffs every hunk pair.

    Called on the loop it stopped every renewal for as long as it took, which for a large
    batch was longer than the lease. `combine_and_verify` now runs it in a worker thread.
    A blocking sleep longer than several heartbeat intervals stands in for the subprocesses.
    """
    import asyncio
    import time
    from types import SimpleNamespace

    import src.engine as engine
    from src.verification import VerificationResult

    request = RepairRequest.model_validate(request_payload)
    backend = HeartbeatCountingBackend(request)

    def blocking_combine(req, snapshot, bundles):
        time.sleep(0.25)
        return SimpleNamespace(patches=[])

    monkeypatch.setattr(engine, "combine_patch_bundles", blocking_combine)

    class StubVerifier:
        async def verify(self, req, snapshot, bundle):
            return VerificationResult("passed", {}, "sha256:" + "4" * 64, None, "independent_sandbox", proven_finding_ids=["f1", "f2"])

    def entry(finding_id):
        candidate = SimpleNamespace(finding_ids=[finding_id], verified_tree_oid="not-the-combined-tree")
        return candidate, SimpleNamespace(patches=[]), VerificationResult("passed", {}, None)

    lost = asyncio.Event()
    renewals = asyncio.create_task(worker.renew_lease(backend, "exec", "worker-a", 60, 0.02, lost))
    try:
        combined = await engine.combine_and_verify(request, SimpleNamespace(), StubVerifier(), [entry("f1"), entry("f2")])
    finally:
        await worker._cancel(renewals)

    assert combined.verification.status == "passed"
    # Several renewals across 0.25s of combining, where a blocked loop sends only the first.
    assert backend.heartbeats >= 3


@pytest.mark.asyncio
async def test_the_claim_and_heartbeat_use_the_configured_lease(monkeypatch, request_payload):
    """The configured lease has to reach the store, or configuring it changes nothing."""
    import asyncio

    request = RepairRequest.model_validate(request_payload)
    seen: dict[str, object] = {}

    class RecordingBackend(StubBackend):
        def claim(self, worker_id, lease_seconds=60):
            seen["claim"] = lease_seconds
            return super().claim(worker_id, lease_seconds)

        def heartbeat(self, execution_id, worker_id, lease_seconds=60):
            seen["heartbeat"] = lease_seconds
            return True

    class SlowEngine:
        def __init__(self, agent_factory=None):
            pass

        async def repair(self, req, checkpoints):
            await asyncio.sleep(0.05)
            return response_for(req)

    monkeypatch.setenv("REMEDIATION_WORKER_HEARTBEAT_SECONDS", "0.01")
    monkeypatch.setenv("REMEDIATION_WORKER_LEASE_SECONDS", "123")
    monkeypatch.setattr(worker, "RepairEngine", SlowEngine)

    await worker.run_once(RecordingBackend(request, published=True), "worker-a")
    assert seen["claim"] == 123
    assert seen["heartbeat"] == 123


class SettleTrackingResumeStore(ResumeCheckpointStore):
    """A store that refuses an unreserved settle exactly as the durable stores do."""

    def __init__(self, checkpoint):
        super().__init__(checkpoint)
        self.reservations: list[int] = []
        self.settles: list[int] = []
        self.pending_reserved: int | None = None

    async def reserve_provider_call(self, sequence, tokens, usd):
        self.reservations.append(sequence)
        self.pending_reserved = tokens
        return True

    async def save_provider_action(self, state, action, actual_tokens, actual_usd):
        from src.agent.checkpoint import CheckpointError
        from src.executions import _settlement

        if self.pending_reserved is None:
            raise CheckpointError("provider reservation is absent")
        settlement = _settlement(self.pending_reserved, 1.0, actual_tokens, actual_usd)
        self.pending_reserved = None
        self.settles.append(actual_tokens)
        return settlement


def _resume_checkpoint(snapshot, **extra):
    return {
        "context_manifest_digest": snapshot.manifest_digest,
        "messages": [{"role": "system", "content": "s"}],
        "trace": [{"sequence": 1, "tool": "read_file", "arguments_digest_only": {}, "outcome": "ok", "reason": None, "result_bytes": 10}],
        "input_tokens": 100,
        "output_tokens": 20,
        "provider_request_ids": ["chatcmpl-earlier"],
        **extra,
    }


@pytest.mark.asyncio
async def test_resume_after_a_checkpointed_provider_action_does_not_settle_it_twice(request_payload):
    """The checkpointed action was settled when it was written, so resuming must not re-settle.

    `save_provider_action` clears the pending reservation in the same statement that stores the
    action, so a resumed action has no reservation to settle against. Settling it again would
    both double charge and raise `provider reservation is absent`.
    """
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    checkpoint = _resume_checkpoint(
        snapshot,
        pending_action={
            "name": "abstain",
            "arguments": {"reason_code": "no_repair", "explanation": "nothing to do"},
            "call_id": "call-9",
            "request_id": "chatcmpl-pending",
            "input_tokens": 50,
            "output_tokens": 5,
        },
    )
    store = SettleTrackingResumeStore(checkpoint)

    result = await RepairAgent(UnusedProvider(), Verifier(UnusedBroker()), store).run(request, snapshot)

    # The resumed action ran without a fresh reservation and without a second settlement.
    assert store.reservations == []
    assert store.settles == []
    assert result.state == "unsupported"
    assert result.reason_code == "no_repair"
    assert result.reason_code != "checkpoint_unavailable"
    # The already-charged call keeps its place in the trace after the restored step.
    assert [step["tool"] for step in result.trace] == ["read_file", "abstain"]


@pytest.mark.asyncio
async def test_resume_after_a_tool_result_reserves_and_settles_the_next_call_normally(request_payload):
    """With no pending action the next call is a fresh one: it reserves, then settles."""
    from tests.test_agent_budget import FailingVerifier, RecordingProvider, _abstain

    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    store = SettleTrackingResumeStore(_resume_checkpoint(snapshot, pending_action=None))

    result = await RepairAgent(RecordingProvider([_abstain()]), FailingVerifier(), store).run(request, snapshot)

    assert store.reservations == [2]
    assert len(store.settles) == 1
    assert result.reason_code == "no_repair"
    # The restored usage is carried forward rather than restarted.
    assert result.usage["input_tokens"] >= 100
    assert "chatcmpl-earlier" in result.usage["provider_request_ids"]
    assert result.evidence["budget_reservation"]["settled_calls"] == 1


class SlowCheckpoints:
    async def load(self):
        return None

    async def reserve_provider_call(self, sequence, tokens, usd):
        return True

    async def save_provider_action(self, state, action, actual_tokens, actual_usd):
        return None

    async def save_completed_step(self, state):
        return None


def _local_backend(tmp_path, request):
    from src.executions import LocalExecutionBackend

    backend = LocalExecutionBackend(tmp_path / "state")
    backend.enqueue(request)
    return backend


@pytest.mark.asyncio
async def test_the_lease_survives_a_provider_and_sandbox_call_three_times_its_length(monkeypatch, tmp_path, request_payload):
    """The live failure: one attempt held the lease for its whole length without one renewal.

    The renewals run on their own task, so a model call and a blocking sandbox run that
    together last three leases must still finish under the first attempt.
    """
    import asyncio
    import time

    from src.executions import LocalExecutionBackend

    request = RepairRequest.model_validate(request_payload)
    backend = _local_backend(tmp_path, request)
    monkeypatch.setenv("REMEDIATION_WORKER_HEARTBEAT_SECONDS", "0.05")
    monkeypatch.setenv("REMEDIATION_WORKER_LEASE_SECONDS", "1")
    lease = worker.lease_seconds()

    class SlowEngine:
        def __init__(self, agent_factory=None):
            pass

        async def repair(self, req, checkpoints):
            # A model call that never yields to a renewal, then a sandbox run in a thread.
            await asyncio.sleep(lease * 1.6)
            await asyncio.to_thread(time.sleep, lease * 1.6)
            return response_for(req)

    monkeypatch.setattr(worker, "RepairEngine", SlowEngine)
    assert await worker.run_once(backend, "worker-slow") is True

    with backend._lock, backend._connect() as connection:
        state, attempt = connection.execute("SELECT state, attempt FROM executions").fetchone()
    assert attempt == 1, "the lease was lost and the execution was reclaimed"
    assert state == "unsupported"
    assert isinstance(backend, LocalExecutionBackend)


@pytest.mark.asyncio
async def test_a_lost_lease_cancels_the_running_attempt_before_the_reclaim(monkeypatch, request_payload):
    """Two attempts must never run at once, so the abandoned one is stopped and waited for."""
    import asyncio

    request = RepairRequest.model_validate(request_payload)
    cancelled = asyncio.Event()

    class RefusingBackend(StubBackend):
        def __init__(self, req):
            super().__init__(req, published=True)
            self.heartbeats = 0

        def heartbeat(self, execution_id, worker_id, lease_seconds=60):
            self.heartbeats += 1
            return False

    class NeverEndingEngine:
        def __init__(self, agent_factory=None):
            pass

        async def repair(self, req, checkpoints):
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled.set()
                raise
            return response_for(req)

    monkeypatch.setenv("REMEDIATION_WORKER_HEARTBEAT_SECONDS", "0.05")
    monkeypatch.setattr(worker, "RepairEngine", NeverEndingEngine)
    backend = RefusingBackend(request)
    assert await worker.run_once(backend, "worker-a") is True
    # Set by the time run_once returns: the attempt is stopped before the loop can reclaim.
    assert cancelled.is_set()
    assert backend.heartbeats >= 1
    assert worker.COUNTERS["results_published"] >= 0


@pytest.mark.asyncio
async def test_an_unexpected_attempt_error_releases_the_lease_and_is_logged(monkeypatch, tmp_path, request_payload, caplog):
    """A raised attempt used to hold the lease to its full length with no log line."""
    request = RepairRequest.model_validate(request_payload)
    backend = _local_backend(tmp_path, request)

    class RaisingEngine:
        def __init__(self, agent_factory=None):
            pass

        async def repair(self, req, checkpoints):
            raise FileNotFoundError("the sandbox workspace root is absent")

    monkeypatch.setattr(worker, "RepairEngine", RaisingEngine)
    with caplog.at_level("ERROR"):
        assert await worker.run_once(backend, "worker-a") is True
    assert any("unexpected error" in record.message for record in caplog.records)

    with backend._lock, backend._connect() as connection:
        state, owner, expires, history = connection.execute(
            "SELECT state, lease_owner, lease_expires_at, attempt_history FROM executions"
        ).fetchone()
    assert (state, owner, expires) == ("queued", None, None), "the lease was held after a failed attempt"
    import json as _json

    attempts = _json.loads(history)
    assert attempts[-1]["attempt"] == 1
    assert attempts[-1]["reason"] == "internal_error:FileNotFoundError"
    assert attempts[-1]["claimed_at"] and attempts[-1]["ended_at"]
    # The released lease means the next attempt starts at once instead of waiting it out.
    assert backend.claim("worker-b", 90) is not None
