from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
from collections import OrderedDict
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException

from ..digests import canonical_json, digest_json
from .execution import build_evidence
from .kubernetes_driver import KubernetesExecutionError, KubernetesJobDriver
from .local_driver import LocalExecutionError, LocalSubprocessDriver

app = FastAPI(title="Mitig8it Sandbox Broker", version="1.0.0")

logger = logging.getLogger("mitig8it.remediation.sandbox.broker")

MAX_IDEMPOTENCY_ENTRIES = 256

_driver: Any = None
_driver_lock = asyncio.Lock()
# Idempotency-Key -> (request_digest, attested evidence). Bounded, process-local, and
# development/single-replica scoped; a multi-replica deployment must back this with the
# control plane's durable idempotency records.
_idempotent_results: "OrderedDict[str, tuple[str, dict[str, Any]]]" = OrderedDict()
_idempotency_lock = asyncio.Lock()


def selected_driver_kind() -> str:
    kind = os.getenv("SANDBOX_DRIVER", "kubernetes").strip().lower() or "kubernetes"
    if kind not in {"kubernetes", "local"}:
        raise HTTPException(503, "SANDBOX_DRIVER must be 'kubernetes' or 'local'")
    return kind


def build_driver() -> Any:
    """Production default is the Kubernetes/gVisor driver. `local` is development only."""
    if selected_driver_kind() == "local":
        return LocalSubprocessDriver()
    return KubernetesJobDriver()


async def get_driver() -> Any:
    """Constructs the driver once per process; Kubernetes clients are reused across requests."""
    global _driver
    if _driver is None:
        async with _driver_lock:
            if _driver is None:
                _driver = build_driver()
    return _driver


def authenticate(authorization: str | None = Header(default=None)) -> None:
    expected = os.getenv("SANDBOX_BROKER_TOKEN", "")
    supplied = authorization.removeprefix("Bearer ") if authorization and authorization.startswith("Bearer ") else ""
    if not expected:
        raise HTTPException(503, "Sandbox broker authentication is not configured")
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(401, "Unauthorized")


def _attest(evidence: dict[str, Any]) -> dict[str, Any]:
    key = os.getenv("SANDBOX_BROKER_ATTESTATION_SECRET", "").encode("utf-8")
    key_id = os.getenv("SANDBOX_BROKER_ATTESTATION_KEY_ID", "")
    if not key or not key_id:
        raise HTTPException(503, "Sandbox broker attestation is not configured")
    signed = {key: value for key, value in evidence.items() if key != "attestation"}
    return {
        **signed,
        "attestation": {
            "algorithm": "HMAC-SHA256",
            "key_id": key_id,
            "signature": hmac.new(key, canonical_json(signed), hashlib.sha256).hexdigest(),
        },
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "sandbox-broker"}


@app.post("/v1/verifications", dependencies=[Depends(authenticate)])
async def verify(payload: dict[str, Any], idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")) -> dict[str, Any]:
    core = {key: value for key, value in payload.items() if key != "request_digest"}
    if payload.get("schema_version") != "v1" or payload.get("request_digest") != digest_json(core):
        raise HTTPException(422, "Request digest or schema is invalid")
    if idempotency_key is not None:
        if not idempotency_key or len(idempotency_key) > 256:
            raise HTTPException(422, "Idempotency-Key is invalid")
        async with _idempotency_lock:
            stored = _idempotent_results.get(idempotency_key)
        if stored is not None:
            if stored[0] != payload["request_digest"]:
                raise HTTPException(409, "Idempotency-Key was already used with a different request payload")
            return stored[1]
    driver = await get_driver()
    try:
        result = await asyncio.to_thread(driver.execute, payload, int(payload["execution_policy"]["deadline_seconds"]))
    except (KubernetesExecutionError, LocalExecutionError, KeyError, TypeError, ValueError):
        result = {"outcome": "inconclusive", "reason_code": "sandbox_execution_failed", "checks": []}
    evidence = _attest(build_evidence(payload, result, driver.runner_identity(payload), driver.verification_level))
    if idempotency_key is not None:
        async with _idempotency_lock:
            existing = _idempotent_results.get(idempotency_key)
            if existing is not None:
                if existing[0] != payload["request_digest"]:
                    raise HTTPException(409, "Idempotency-Key was already used with a different request payload")
                return existing[1]
            _idempotent_results[idempotency_key] = (payload["request_digest"], evidence)
            while len(_idempotent_results) > MAX_IDEMPOTENCY_ENTRIES:
                _idempotent_results.popitem(last=False)
    return evidence


@app.delete("/v1/verifications/{request_digest}", dependencies=[Depends(authenticate)], status_code=202)
async def cancel_verification(request_digest: str) -> dict[str, str]:
    if not request_digest.startswith("sha256:") or len(request_digest) != 71:
        raise HTTPException(422, "Invalid request digest")
    driver = await get_driver()
    try:
        await asyncio.to_thread(driver.cancel, request_digest)
    except (KubernetesExecutionError, LocalExecutionError) as exc:
        raise HTTPException(503, "Sandbox cancellation could not be confirmed") from exc
    return {"schema_version": "v1", "request_digest": request_digest, "state": "cancelled"}
