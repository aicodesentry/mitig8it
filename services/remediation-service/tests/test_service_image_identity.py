import asyncio
import copy

from fastapi.testclient import TestClient
import pytest

import src.engine as engine
import src.main as main
from src.models import RepairRequest
from src.release_identity import service_image_matches


IMAGE = "registry.example/remediation@sha256:" + "a" * 64
OTHER = "registry.example/remediation@sha256:" + "b" * 64


@pytest.mark.parametrize("expected,mounted,allowed", [
    (None, None, True), (IMAGE, IMAGE, True), (IMAGE, None, False), (None, IMAGE, False),
    (IMAGE, OTHER, False), ("registry/image:latest", "registry/image:latest", False),
    ("", "", False), (IMAGE, "", False),
])
def test_service_identity_requires_exact_pinned_request_and_mounted_binary(request_payload, monkeypatch, expected, mounted, allowed):
    payload = copy.deepcopy(request_payload)
    if expected is not None:
        payload.setdefault("versions", {})["repair_service_image"] = expected
    if mounted is None:
        monkeypatch.delenv("REMEDIATION_SERVICE_IMAGE_DIGEST", raising=False)
    else:
        monkeypatch.setenv("REMEDIATION_SERVICE_IMAGE_DIGEST", mounted)
    if expected == "":
        with pytest.raises(ValueError, match="versions"):
            RepairRequest.model_validate(payload)
        assert not allowed
        return
    assert service_image_matches(RepairRequest.model_validate(payload)) is allowed


def test_wrong_binary_is_refused_before_enqueue(request_payload, monkeypatch):
    monkeypatch.setenv("REMEDIATION_SERVICE_INTERNAL_SECRET", "test-secret")
    monkeypatch.setenv("REMEDIATION_SERVICE_IMAGE_DIGEST", OTHER)
    payload = copy.deepcopy(request_payload)
    payload.setdefault("versions", {})["repair_service_image"] = IMAGE
    monkeypatch.setattr(main, "get_execution_backend", lambda: pytest.fail("Mismatch must not enqueue or access artifact storage"))
    response = TestClient(main.app).post("/v1/repair", json=payload, headers={"x-internal-secret": "test-secret"})
    assert response.status_code == 503
    assert "mounted release identity" in response.json()["detail"]


def test_resumed_request_is_refused_before_snapshot_model_or_sandbox(request_payload, monkeypatch):
    monkeypatch.setenv("REMEDIATION_SERVICE_IMAGE_DIGEST", OTHER)
    payload = copy.deepcopy(request_payload)
    payload.setdefault("versions", {})["repair_service_image"] = IMAGE
    monkeypatch.setattr(engine, "Snapshot", lambda _: pytest.fail("Mismatch must be checked before any repair work"))
    result = asyncio.run(engine.RepairEngine().repair(RepairRequest.model_validate(payload)))
    assert result.state == "unsupported"
    assert result.reason["code"] == "service_image_identity_mismatch"
    assert not result.candidates
