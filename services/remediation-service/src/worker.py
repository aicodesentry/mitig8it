from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import time
import uuid
from math import ceil
from typing import Any

from . import telemetry
from .engine import RepairEngine
from .executions import (
    LocalExecutionBackend,
    PostgresExecutionBackend,
    create_checkpoint_store,
    create_execution_backend,
)

logger = logging.getLogger("mitig8it.remediation.worker")

# Bounded in-process counters. A rejected completion means a lease was lost or
# fenced; it is never a successful publication and must stay visible.
COUNTERS = {"completions_rejected": 0, "results_published": 0, "attempts_failed": 0}

Backend = PostgresExecutionBackend | LocalExecutionBackend

# A lease is only as good as the heartbeats that renew it. The loop renews every
# HEARTBEAT_SECONDS and the lease is held for LEASE_SECONDS, so a lease survives missed
# renewals rather than expiring on the first one. Anything under 3x turns one slow turn of the
# event loop into a lost lease, a reclaimed attempt, and a resumed job.
DEFAULT_HEARTBEAT_SECONDS = 15.0
MIN_HEARTBEAT_SECONDS = 0.05
DEFAULT_LEASE_SECONDS = 90
MIN_LEASE_TO_HEARTBEAT_RATIO = 3


def heartbeat_seconds() -> float:
    try:
        value = float(os.getenv("REMEDIATION_WORKER_HEARTBEAT_SECONDS", DEFAULT_HEARTBEAT_SECONDS))
    except ValueError:
        value = DEFAULT_HEARTBEAT_SECONDS
    # A floor only clamps a nonsensical setting; the default is what production runs.
    return max(MIN_HEARTBEAT_SECONDS, value)


def lease_seconds() -> int:
    """The lease length, never shorter than three heartbeat intervals."""
    try:
        configured = int(float(os.getenv("REMEDIATION_WORKER_LEASE_SECONDS", DEFAULT_LEASE_SECONDS)))
    except ValueError:
        configured = DEFAULT_LEASE_SECONDS
    floor = ceil(heartbeat_seconds() * MIN_LEASE_TO_HEARTBEAT_RATIO)
    return max(floor, configured)


async def renew_lease(backend: Backend, execution_id: str, worker_id: str, lease: int, interval: float, lost: asyncio.Event) -> None:
    """Renews the lease on a task of its own until the lease is definitively gone.

    It never awaits the repair, so no model call, sandbox run, or checkpoint write can delay a
    renewal. A renewal that the store *refuses* means the row is no longer this worker's and the
    lease is lost now. A renewal that *raises* is a transient store failure, and the lease
    survives missed renewals by design, so it keeps trying until the lease would have expired
    anyway. Both cases are logged with the observed timestamps.
    """
    last_renewed = time.monotonic()
    while True:
        await asyncio.sleep(interval)
        failure: str | None = None
        try:
            renewed = await asyncio.to_thread(backend.heartbeat, execution_id, worker_id, lease)
        except Exception as exc:  # noqa: BLE001 - the type is reported; the text may carry source.
            renewed, failure = False, type(exc).__name__
        if renewed:
            last_renewed = time.monotonic()
            continue
        held_for = time.monotonic() - last_renewed
        logger.warning(
            "remediation lease heartbeat did not renew",
            extra={
                "execution_id": execution_id,
                "worker_id": worker_id,
                "seconds_since_last_renewal": round(held_for, 3),
                "lease_seconds": lease,
                "heartbeat_seconds": interval,
                "store_error": failure,
                "refused_by_store": failure is None,
            },
        )
        if failure is None or held_for >= lease:
            lost.set()
            return


async def _cancel(task: asyncio.Task[Any]) -> None:
    """Cancels a task and waits for it to actually stop, swallowing whatever it ends with."""
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await task


async def run_once(backend: Backend, worker_id: str) -> bool:
    lease = lease_seconds()
    interval = heartbeat_seconds()
    record = await asyncio.to_thread(backend.claim, worker_id, lease)
    if record is None:
        return False
    request = await asyncio.to_thread(backend.read_request, record)
    checkpoints = create_checkpoint_store(backend, record.execution_id, worker_id, request)
    lost = asyncio.Event()
    lost_waiter = asyncio.create_task(lost.wait())
    renewals = asyncio.create_task(renew_lease(backend, record.execution_id, worker_id, lease, interval, lost))
    # A span link, not a child span: the intake request finished long before this resumption.
    with telemetry.linked_span("remediation.repair", record.trace_context, **telemetry.request_attributes(request)) as span:
        task = asyncio.create_task(RepairEngine().repair(request, checkpoints))
        try:
            await asyncio.wait({task, lost_waiter}, return_when=asyncio.FIRST_COMPLETED)
            if lost.is_set() and not task.done():
                # The attempt is stopped and waited for before returning, so the reclaim that
                # follows can never run a second attempt beside this one.
                await _cancel(task)
                telemetry.record_outcome(span, "abandoned", "lease_lost")
                await _record_attempt_end(backend, record.execution_id, worker_id, "lease_lost", release=False)
                return True
            result = await task
        except Exception as exc:  # noqa: BLE001 - the type is reported; the text may carry source.
            # Before this, an unexpected failure left the lease held to its full length with no
            # log line, so the next attempt could only start once the lease expired and the
            # recovery budget drained in silence. Release it and say what happened.
            COUNTERS["attempts_failed"] += 1
            logger.error(
                "remediation attempt ended with an unexpected error; releasing the lease",
                extra={
                    "job_id": request.job_id,
                    "execution_id": record.execution_id,
                    "worker_id": worker_id,
                    "error_type": type(exc).__name__,
                },
            )
            telemetry.record_outcome(span, "failed", "internal_error")
            await _record_attempt_end(backend, record.execution_id, worker_id, f"internal_error:{type(exc).__name__}", release=True)
            return True
        finally:
            await _cancel(renewals)
            await _cancel(lost_waiter)
        telemetry.record_outcome(span, result.state, (result.reason or {}).get("code") if result.state != "ready" else None)
    published = await asyncio.to_thread(backend.complete, record.execution_id, worker_id, result)
    if not published:
        COUNTERS["completions_rejected"] += 1
        logger.error(
            "remediation result was not published: the lease was expired, fenced, or cancelled",
            extra={"job_id": request.job_id, "execution_id": record.execution_id, "worker_id": worker_id},
        )
    else:
        COUNTERS["results_published"] += 1
    await _record_attempt_end(backend, record.execution_id, worker_id, "published" if published else "completion_fenced", release=False)
    return True


async def _record_attempt_end(backend: Backend, execution_id: str, worker_id: str, reason: str, release: bool) -> None:
    """Closes the attempt entry. A store that cannot record it must not fail the attempt."""
    recorder = getattr(backend, "record_attempt_end", None)
    if recorder is None:
        return
    try:
        await asyncio.to_thread(recorder, execution_id, worker_id, reason, release)
    except Exception:  # noqa: BLE001 - a diagnostic write is never worth losing the outcome over.
        logger.warning(
            "the remediation attempt history could not be recorded",
            extra={"execution_id": execution_id, "worker_id": worker_id},
        )


def new_worker_id() -> str:
    return f"{socket.gethostname()}-{uuid.uuid4()}"


def inprocess_enabled() -> bool:
    """True when the worker loop runs inside the API process instead of its own Deployment.

    A single-instance deployment has no separate worker container, so the API process owns
    the loop. It is off by default: the dedicated `python -m src.worker` Deployment stays
    the production arrangement.
    """
    return os.getenv("REMEDIATION_WORKER_INPROCESS", "").strip().lower() == "true"


async def run_worker_loop(backend: Backend, worker_id: str | None = None) -> None:
    """The claim/execute/publish loop. Cancellation stops it; nothing else does."""
    identity = worker_id or new_worker_id()
    while True:
        try:
            worked = await run_once(backend, identity)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - the type is reported; the text may carry source.
            # `run_once` already handles a failed attempt. Reaching here means the claim or the
            # request read failed, which is still worth a line rather than a silent retry.
            logger.error(
                "the remediation worker loop could not start an attempt",
                extra={"worker_id": identity, "error_type": type(exc).__name__},
            )
            worked = True
            await asyncio.sleep(2)
        if not worked:
            await asyncio.sleep(float(os.getenv("REMEDIATION_WORKER_POLL_SECONDS", "2")))


async def main() -> None:
    await run_worker_loop(create_execution_backend())


if __name__ == "__main__":
    asyncio.run(main())
