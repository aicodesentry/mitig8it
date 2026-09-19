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
