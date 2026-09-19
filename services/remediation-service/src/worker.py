from __future__ import annotations

import asyncio
import logging
import os
import socket
import uuid

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
COUNTERS = {"completions_rejected": 0, "results_published": 0}

Backend = PostgresExecutionBackend | LocalExecutionBackend


async def run_once(backend: Backend, worker_id: str) -> bool:
    record = await asyncio.to_thread(backend.claim, worker_id)
    if record is None:
        return False
    request = await asyncio.to_thread(backend.read_request, record)
    checkpoints = create_checkpoint_store(backend, record.execution_id, worker_id, request)
    # A span link, not a child span: the intake request finished long before this resumption.
    with telemetry.linked_span("remediation.repair", record.trace_context, **telemetry.request_attributes(request)) as span:
        task = asyncio.create_task(RepairEngine().repair(request, checkpoints))
        while not task.done():
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=15)
            except TimeoutError:
                if not await asyncio.to_thread(backend.heartbeat, record.execution_id, worker_id):
                    task.cancel()
                    telemetry.record_outcome(span, "abandoned", "lease_lost")
                    return True
        result = await task
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
    return True


async def main() -> None:
    backend = create_execution_backend()
    worker_id = f"{socket.gethostname()}-{uuid.uuid4()}"
    while True:
        try:
            worked = await run_once(backend, worker_id)
        except Exception:
            # The lease expires and the bounded recovery budget handles retry/dead-letter.
            # Do not log arbitrary exception text because provider/artifact errors may contain source.
            worked = True
            await asyncio.sleep(2)
        if not worked:
            await asyncio.sleep(float(os.getenv("REMEDIATION_WORKER_POLL_SECONDS", "2")))


if __name__ == "__main__":
    asyncio.run(main())
