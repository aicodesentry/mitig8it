from __future__ import annotations

import pytest

import src.main as main
from src.executions import (
    ExecutionConfigurationError,
    ExecutionConflict,
    LocalExecutionBackend,
    MAX_WORKER_ATTEMPTS,
    create_execution_backend,
    selected_backend_kind,
)
from src.models import RepairRequest, RepairResponse


def response_for(request: RepairRequest, state: str = "unsupported") -> RepairResponse:
    return RepairResponse(
        state=state,
        job_id=request.job_id,
        tenant_id=request.tenant_id,
        repository_id=request.repository_id,
        head_sha=request.head_sha,
        base_sha=request.base_sha,
        request_digest="sha256:" + "9" * 64,
        evidence={"verification_level": "none"},
        reason={"code": "test", "message": "test"},
    )


def test_local_backend_is_not_the_production_default(monkeypatch):
    monkeypatch.delenv("REMEDIATION_EXECUTION_BACKEND", raising=False)
    assert selected_backend_kind() == "postgres"
    monkeypatch.setenv("REMEDIATION_EXECUTION_BACKEND", "sqlite")
    with pytest.raises(ExecutionConfigurationError):
        selected_backend_kind()


def test_local_backend_selection_requires_a_state_directory(monkeypatch):
    monkeypatch.setenv("REMEDIATION_EXECUTION_BACKEND", "local")
    monkeypatch.delenv("REMEDIATION_LOCAL_STATE_DIR", raising=False)
    monkeypatch.delenv("REMEDIATION_DATA_DIR", raising=False)
    with pytest.raises(ExecutionConfigurationError):
        create_execution_backend()


def test_local_backend_accepts_the_container_data_directory(monkeypatch, tmp_path):
    """The image creates REMEDIATION_DATA_DIR owned by the runtime UID; compose mounts it there."""
    monkeypatch.setenv("REMEDIATION_EXECUTION_BACKEND", "local")
    monkeypatch.delenv("REMEDIATION_LOCAL_STATE_DIR", raising=False)
    monkeypatch.setenv("REMEDIATION_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(main, "execution_backend", None)
    backend = create_execution_backend()
    assert isinstance(backend, LocalExecutionBackend)
    assert backend.directory == tmp_path / "data"


def test_local_backend_is_selected_and_warns(monkeypatch, tmp_path, caplog, request_payload):
    monkeypatch.setenv("REMEDIATION_EXECUTION_BACKEND", "local")
    monkeypatch.setenv("REMEDIATION_LOCAL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(main, "execution_backend", None)
    with caplog.at_level("WARNING"):
        backend = create_execution_backend()
    assert isinstance(backend, LocalExecutionBackend)
    assert any("development-only" in record.message for record in caplog.records)


def test_local_backend_enqueue_is_idempotent_and_fence_bound(tmp_path, request_payload):
    backend = LocalExecutionBackend(tmp_path / "state")
    request = RepairRequest.model_validate(request_payload)
    first = backend.enqueue(request)
    assert backend.enqueue(request).execution_id == first.execution_id
    changed = request.model_copy(deep=True)
    changed.files[0].content += "// changed\n"
    with pytest.raises(ExecutionConflict):
        backend.enqueue(changed)


def test_local_backend_lease_claim_heartbeat_and_complete(tmp_path, request_payload):
    backend = LocalExecutionBackend(tmp_path / "state")
    request = RepairRequest.model_validate(request_payload)
    record = backend.enqueue(request)
    claimed = backend.claim("worker-a")
    assert claimed is not None and claimed.execution_id == record.execution_id
    assert backend.claim("worker-b") is None
    assert backend.read_request(claimed).job_id == request.job_id
    assert backend.heartbeat(record.execution_id, "worker-a") is True
    assert backend.heartbeat(record.execution_id, "worker-b") is False
    assert backend.complete(record.execution_id, "worker-b", response_for(request)) is False
    assert backend.complete(record.execution_id, "worker-a", response_for(request)) is True
    terminal = backend.get(record.execution_id)
    assert terminal.state == "unsupported"
    assert backend.read_result(terminal).reason["code"] == "test"


def test_local_backend_dead_letters_after_the_attempt_cap(tmp_path, request_payload):
    backend = LocalExecutionBackend(tmp_path / "state")
    request = RepairRequest.model_validate(request_payload)
    record = backend.enqueue(request)
    for _ in range(MAX_WORKER_ATTEMPTS):
        assert backend.claim("worker-a", lease_seconds=-1) is not None
    assert backend.claim("worker-a", lease_seconds=-1) is None
    assert backend.get(record.execution_id).state == "failed"


def test_local_backend_cancel_blocks_publication(tmp_path, request_payload):
    backend = LocalExecutionBackend(tmp_path / "state")
    request = RepairRequest.model_validate(request_payload)
    record = backend.enqueue(request)
    claimed = backend.claim("worker-a")
    assert backend.cancel(record.execution_id) is True
    assert backend.complete(claimed.execution_id, "worker-a", response_for(request)) is False
    assert backend.get(record.execution_id).state == "cancelled"


def _claimed_store(tmp_path, request_payload, **policy):
    """A running execution with a durable checkpoint store, ready to settle provider calls."""
    from src.executions import create_checkpoint_store

    payload = {**request_payload, "policy": {**request_payload["policy"], **policy}}
    request = RepairRequest.model_validate(payload)
    backend = LocalExecutionBackend(tmp_path / "state")
    backend.enqueue(request)
    claimed = backend.claim("worker-a", lease_seconds=900)
    return backend, claimed, create_checkpoint_store(backend, claimed.execution_id, "worker-a", request)


def _spend(backend, claimed):
    """The execution row's settled actual tokens and USD."""
    with backend._lock, backend._connect() as connection:
        row = connection.execute(
            "SELECT actual_tokens, actual_usd FROM executions WHERE execution_id=?", (claimed.execution_id,)
        ).fetchone()
    return int(row[0]), float(row[1])


def _action():
    from src.agent.provider import ProviderAction

    return ProviderAction("abstain", {"reason_code": "no_repair", "explanation": "none"}, call_id="call-1")


@pytest.mark.asyncio
async def test_usage_above_the_reservation_settles_as_an_overage(tmp_path, request_payload):
    """A reservation is an estimate: an underestimate is charged at the real cost, not refused."""
    backend, claimed, store = _claimed_store(tmp_path, request_payload)
    assert await store.reserve_provider_call(1, 100, 0.001) is True

    settlement = await store.save_provider_action({"group_key": "g"}, _action(), 250, 0.004)

    assert settlement["reserved_tokens"] == 100
    assert settlement["actual_tokens"] == 250
    assert settlement["overage_tokens"] == 150
    assert settlement["overage_usd"] == pytest.approx(0.003)
    # The execution is charged what the call really cost, not what it guessed.
    assert _spend(backend, claimed) == (250, pytest.approx(0.004))


@pytest.mark.asyncio
async def test_usage_within_the_reservation_records_no_overage(tmp_path, request_payload):
    _, _, store = _claimed_store(tmp_path, request_payload)
    assert await store.reserve_provider_call(1, 500, 0.01) is True

    settlement = await store.save_provider_action({"group_key": "g"}, _action(), 400, 0.008)

    assert (settlement["overage_tokens"], settlement["overage_usd"]) == (0, 0.0)


@pytest.mark.asyncio
async def test_a_settlement_without_a_reservation_still_raises(tmp_path, request_payload):
    """An unannounced call is a protocol violation, not an estimate that came in high."""
    from src.agent.checkpoint import BudgetCapExceeded, CheckpointError

    _, _, store = _claimed_store(tmp_path, request_payload)

    with pytest.raises(CheckpointError) as raised:
        await store.save_provider_action({"group_key": "g"}, _action(), 10, 0.001)
    assert not isinstance(raised.value, BudgetCapExceeded)
    assert "reservation is absent" in str(raised.value)


@pytest.mark.asyncio
async def test_cumulative_spend_past_the_hard_cap_fails_as_budget_cap_exceeded(tmp_path, request_payload):
    """Only the caps bind, and crossing one is a budget decision, not a durability failure."""
    from src.agent.checkpoint import BudgetCapExceeded

    backend, claimed, store = _claimed_store(tmp_path, request_payload, max_total_tokens=1_000, max_spend_usd=1.0)
    assert await store.reserve_provider_call(1, 900, 0.5) is True

    with pytest.raises(BudgetCapExceeded) as raised:
        await store.save_provider_action({"group_key": "g"}, _action(), 1_200, 0.6)

    settlement = raised.value.settlement
    assert settlement["overage_tokens"] == 300
    assert settlement["cumulative_actual_tokens"] == 1_200
    assert settlement["max_total_tokens"] == 1_000
    # The spend is recorded before the cap stops the run, so the cost is never lost.
    assert _spend(backend, claimed)[0] == 1_200


@pytest.mark.asyncio
async def test_spend_past_the_usd_cap_alone_fails_as_budget_cap_exceeded(tmp_path, request_payload):
    from src.agent.checkpoint import BudgetCapExceeded

    _, _, store = _claimed_store(tmp_path, request_payload, max_total_tokens=1_000_000, max_spend_usd=0.01)
    assert await store.reserve_provider_call(1, 100, 0.005) is True

    with pytest.raises(BudgetCapExceeded) as raised:
        await store.save_provider_action({"group_key": "g"}, _action(), 120, 0.05)
    assert raised.value.settlement["cumulative_actual_usd"] == pytest.approx(0.05)
