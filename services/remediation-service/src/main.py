from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from .executions import (
    ExecutionConfigurationError,
    ExecutionConflict,
    LocalExecutionBackend,
    PostgresExecutionBackend,
    create_execution_backend,
)
from .models import RepairRequest
from .worker import inprocess_enabled, run_worker_loop
from . import telemetry

logger = logging.getLogger("mitig8it.remediation.api")

execution_backend = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Optionally owns the durable worker loop so one container is a complete deployment.

    The task shares this process's backend instance, so the HTTP handlers and the worker
    read and write one execution store. Cancellation on shutdown releases the current lease
    rather than publishing under it; the lease then expires and the recovery budget applies.
    """
    task: asyncio.Task[None] | None = None
    if inprocess_enabled():
        logger.warning(
            "REMEDIATION_WORKER_INPROCESS=true runs the durable worker loop inside the API process. "
            "It is intended for a single-instance development deployment, not for production."
        )
        task = asyncio.create_task(run_worker_loop(get_execution_backend()))
    try:
        yield
    finally:
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


app = FastAPI(title="Mitig8it Remediation Service", version="1.0.0", lifespan=lifespan)


def get_execution_backend() -> PostgresExecutionBackend | LocalExecutionBackend:
    """Returns the configured durable backend.

    `REMEDIATION_EXECUTION_BACKEND` selects `postgres` (default, production) or
    `local` (development-only file-backed store; it logs a warning on construction).
    """
    global execution_backend
    if execution_backend is None:
        execution_backend = create_execution_backend()
    return execution_backend


def require_internal_auth(
    authorization: str | None = Header(default=None),
    x_internal_secret: str | None = Header(default=None),
) -> None:
    expected = os.getenv("REMEDIATION_SERVICE_INTERNAL_SECRET", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Remediation service authentication is not configured")
    bearer = ""
    if authorization and authorization.startswith("Bearer "):
        bearer = authorization.removeprefix("Bearer ")
    # Behind Cloud Run the Authorization bearer is the caller's Google identity token, so
    # the shared secret arrives in x-internal-secret. Accept the secret from either header.
    candidates = [value for value in (x_internal_secret or "", bearer) if value]
    if not any(secrets.compare_digest(value, expected) for value in candidates):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "remediation-service"}


@app.post("/v1/repair", status_code=202, dependencies=[Depends(require_internal_auth)])
async def repair(payload: RepairRequest, request: Request) -> dict[str, str]:
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")
    # The incoming W3C trace context continues the caller's trace here and is persisted on the
    # execution row so the worker links its own span back to this request.
    with telemetry.request_span("remediation.intake", request.headers.get("traceparent"), **telemetry.request_attributes(payload)) as span:
        try:
            record = await asyncio.to_thread(get_execution_backend().enqueue, payload, telemetry.current_traceparent())
        except ExecutionConfigurationError as exc:
            telemetry.record_outcome(span, "rejected", "configuration_missing")
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ExecutionConflict as exc:
            telemetry.record_outcome(span, "rejected", "execution_conflict")
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        telemetry.record_outcome(span, "accepted")
    return {"schema_version": "v1", "execution_id": record.execution_id, "state": "running" if record.state == "running" else "queued"}


@app.post("/v1/repair-stages", status_code=202, dependencies=[Depends(require_internal_auth)])
async def repair_stage_alias(payload: RepairRequest, request: Request) -> dict[str, str]:
    """Compatibility alias. It requires the same complete immutable input as /v1/repair."""
    return await repair(payload, request)


@app.get("/v1/repair/{execution_id}", dependencies=[Depends(require_internal_auth)])
async def repair_status(execution_id: str) -> dict[str, object]:
    try:
        record = await asyncio.to_thread(get_execution_backend().get, execution_id)
    except ExecutionConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="Execution not found")
    if record.state in {"queued", "running"}:
        return {"schema_version": "v1", "execution_id": record.execution_id, "state": "running"}
    if record.state == "failed" and not record.result_artifact_uri:
        return {"schema_version": "v1", "execution_id": record.execution_id, "state": "failed", "reason": {"code": "worker_attempts_exhausted", "message": "The durable execution exhausted its worker recovery budget."}}
    if record.state == "cancelled":
        return {"schema_version": "v1", "execution_id": record.execution_id, "state": "cancelled"}
    try:
        result = await asyncio.to_thread(get_execution_backend().read_result, record)
    except ExecutionConflict as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"schema_version": "v1", "execution_id": record.execution_id, "state": result.state, "result": result.model_dump(mode="json")}


@app.post("/v1/repair/{execution_id}/cancel", dependencies=[Depends(require_internal_auth)])
async def cancel_repair(execution_id: str) -> dict[str, str]:
    try:
        cancelled = await asyncio.to_thread(get_execution_backend().cancel, execution_id)
    except ExecutionConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not cancelled:
        raise HTTPException(status_code=409, detail="Execution is absent or no longer cancellable")
    return {"schema_version": "v1", "execution_id": execution_id, "state": "cancelled"}
