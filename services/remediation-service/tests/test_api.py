from __future__ import annotations

from fastapi.testclient import TestClient

import src.main as main
from src.executions import ExecutionRecord
from src.models import RepairResponse

app = main.app


class FakeBackend:
    def __init__(self, payload):
        self.record = ExecutionRecord("sha256:" + "1" * 64, "queued", "sha256:" + "2" * 64, "gs://bucket/input#sha256:x")
        self.payload = payload
        self.terminal = None

    def enqueue(self, request, trace_context=None):
        self.trace_context = trace_context
        return self.record

    def get(self, execution_id):
        if execution_id != self.record.execution_id:
            return None
        return self.record if self.terminal is None else self.record.__class__(self.record.execution_id, self.terminal.state, self.record.request_digest, self.record.request_artifact_uri, "gs://bucket/result#sha256:y")

    def read_result(self, record):
        return self.terminal

    def cancel(self, execution_id):
        if execution_id != self.record.execution_id:
            return False
        self.record = self.record.__class__(self.record.execution_id, "cancelled", self.record.request_digest, self.record.request_artifact_uri)
        return True


def test_health_is_public():
    assert TestClient(app).get("/health").json()["status"] == "ok"


def test_repair_requires_configured_auth(monkeypatch, request_payload):
    monkeypatch.setenv("REMEDIATION_SERVICE_INTERNAL_SECRET", "secret")
    client = TestClient(app)
    assert client.post("/v1/repair", json=request_payload).status_code == 401
    response = client.post("/v1/repair", json=request_payload, headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 401


def test_invalid_payload_is_422_after_auth(monkeypatch):
    monkeypatch.setenv("REMEDIATION_SERVICE_INTERNAL_SECRET", "secret")
    response = TestClient(app).post("/v1/repair", json={}, headers={"Authorization": "Bearer secret"})
    assert response.status_code == 422


def test_durable_intake_returns_handle_and_polling_result(monkeypatch, request_payload):
    monkeypatch.setenv("REMEDIATION_SERVICE_INTERNAL_SECRET", "secret")
    backend = FakeBackend(request_payload)
    monkeypatch.setattr(main, "execution_backend", backend)
    client = TestClient(app)
    accepted = client.post("/v1/repair", json=request_payload, headers={"Authorization": "Bearer secret"})
    assert accepted.status_code == 202
    execution_id = accepted.json()["execution_id"]
    assert client.get(f"/v1/repair/{execution_id}", headers={"Authorization": "Bearer secret"}).json()["state"] == "running"
    backend.terminal = RepairResponse(
        state="unsupported",
        job_id=request_payload["job_id"],
        tenant_id=request_payload["tenant_id"],
        repository_id=request_payload["repository_id"],
        head_sha=request_payload["head_sha"],
        base_sha=request_payload["base_sha"],
        request_digest="sha256:" + "2" * 64,
        evidence={"verification_level": "none"},
        reason={"code": "test", "message": "test"},
    )
    terminal = client.get(f"/v1/repair/{execution_id}", headers={"Authorization": "Bearer secret"}).json()
    assert terminal["state"] == "unsupported"
    assert terminal["result"]["candidates"] == []


def test_cancel_revokes_durable_execution(monkeypatch, request_payload):
    monkeypatch.setenv("REMEDIATION_SERVICE_INTERNAL_SECRET", "secret")
    backend = FakeBackend(request_payload)
    monkeypatch.setattr(main, "execution_backend", backend)
    client = TestClient(app)
    execution_id = client.post("/v1/repair", json=request_payload, headers={"Authorization": "Bearer secret"}).json()["execution_id"]
    cancelled = client.post(f"/v1/repair/{execution_id}/cancel", headers={"Authorization": "Bearer secret"})
    assert cancelled.status_code == 200
    assert client.get(f"/v1/repair/{execution_id}", headers={"Authorization": "Bearer secret"}).json()["state"] == "cancelled"
