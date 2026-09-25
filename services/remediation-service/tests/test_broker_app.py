from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import src.sandbox.broker_app as broker_app
from src.digests import digest_json
from src.sandbox import LocalSubprocessDriver


class CountingDriver:
    verification_level = "development_unverified"

    def __init__(self):
        self.executions = 0
        self.cancelled: list[str] = []

    def runner_identity(self, payload):
        return {"image_digest": None, "network": "unrestricted", "read_only_root": False, "runtime_class": "local-subprocess"}

    def execute(self, payload, deadline_seconds):
        self.executions += 1
        return {"outcome": "passed", "checks": []}

    def cancel(self, request_digest):
        self.cancelled.append(request_digest)


def payload_for(nonce: str = "nonce-1") -> dict:
    core = {
        "schema_version": "v1",
        "execution_id": "sha256:" + "1" * 64,
        "request_nonce": nonce,
        "repository": {
            "original_tree_digest": "sha256:" + "2" * 64,
            "candidate_tree_digest": "sha256:" + "3" * 64,
            "head_tree_oid": "a" * 40,
            "verified_tree_oid": "b" * 40,
        },
        "snapshot": [],
        "patches": [],
        "execution_policy": {"image_digest": None, "commands": [], "deadline_seconds": 30},
    }
    return {**core, "request_digest": digest_json(core)}


@pytest.fixture
def broker(monkeypatch):
    monkeypatch.setenv("SANDBOX_BROKER_TOKEN", "broker-token")
    monkeypatch.setenv("SANDBOX_BROKER_ATTESTATION_SECRET", "attest-secret")
    monkeypatch.setenv("SANDBOX_BROKER_ATTESTATION_KEY_ID", "key-1")
    driver = CountingDriver()
    monkeypatch.setattr(broker_app, "_driver", driver)
    monkeypatch.setattr(broker_app, "_idempotent_results", broker_app.OrderedDict())
    return driver


def test_kubernetes_is_the_default_driver(monkeypatch):
    monkeypatch.delenv("SANDBOX_DRIVER", raising=False)
    assert broker_app.selected_driver_kind() == "kubernetes"
    sentinel = object()
    monkeypatch.setattr(broker_app, "build_selected_driver", lambda kind=None: sentinel if kind == "kubernetes" else None)
    assert broker_app.build_driver() is sentinel


def test_an_unknown_driver_fails_closed(monkeypatch):
    monkeypatch.setenv("SANDBOX_DRIVER", "docker")
    with pytest.raises(HTTPException) as failure:
        broker_app.selected_driver_kind()
    assert failure.value.status_code == 503


def test_local_driver_is_opt_in(monkeypatch):
    monkeypatch.setenv("SANDBOX_DRIVER", "local")
    assert isinstance(broker_app.build_driver(), LocalSubprocessDriver)


@pytest.mark.asyncio
async def test_driver_is_constructed_once_per_process(monkeypatch):
    monkeypatch.setattr(broker_app, "_driver", None)
    constructed = []

    def build():
        constructed.append(1)
        return CountingDriver()

    monkeypatch.setattr(broker_app, "build_driver", build)
    first = await broker_app.get_driver()
    second = await broker_app.get_driver()
    assert first is second
    assert len(constructed) == 1


def test_repeated_idempotency_key_returns_the_prior_attested_result(broker):
    client = TestClient(broker_app.app)
    headers = {"Authorization": "Bearer broker-token", "Idempotency-Key": "key-a"}
    payload = payload_for()
    first = client.post("/v1/verifications", json=payload, headers=headers)
    second = client.post("/v1/verifications", json=payload, headers=headers)
    assert first.status_code == 200
    assert second.json() == first.json()
    assert broker.executions == 1


def test_reused_idempotency_key_with_a_different_payload_is_a_conflict(broker):
    client = TestClient(broker_app.app)
    headers = {"Authorization": "Bearer broker-token", "Idempotency-Key": "key-a"}
    assert client.post("/v1/verifications", json=payload_for("nonce-1"), headers=headers).status_code == 200
    conflict = client.post("/v1/verifications", json=payload_for("nonce-2"), headers=headers)
    assert conflict.status_code == 409
    assert broker.executions == 1


def test_evidence_carries_the_driver_verification_level(broker):
    client = TestClient(broker_app.app)
    response = client.post("/v1/verifications", json=payload_for(), headers={"Authorization": "Bearer broker-token"})
    evidence = response.json()
    assert evidence["verification_level"] == "development_unverified"
    assert evidence["runner"]["runtime_class"] == "local-subprocess"
    assert evidence["attestation"]["algorithm"] == "HMAC-SHA256"
