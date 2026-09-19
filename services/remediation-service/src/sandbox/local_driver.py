"""Development-only local subprocess sandbox driver.

This driver runs each baseline/candidate check as an ordinary host subprocess in a fresh
temporary directory. It provides no network isolation, no filesystem isolation beyond the
temporary directory, no kernel isolation, and no resource enforcement other than a wall-clock
timeout. Evidence it produces is therefore labelled `development_unverified` and can never be
presented as the production `independent_sandbox` verification level.
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .execution import aggregate_outcome, build_evidence, parse_scanner_findings
from .runner import materialize_tree

logger = logging.getLogger("mitig8it.remediation.sandbox.local")

LOCAL_DRIVER_WARNING = (
    "SANDBOX_DRIVER=local selects the development-only local subprocess driver. Repository code "
    "runs on this host without network, kernel, or filesystem isolation, and its evidence is "
    "labelled development_unverified. Never enable it for production traffic."
)

VERIFICATION_LEVEL = "development_unverified"
MAX_CAPTURED_CHARS = 200_000


class LocalExecutionError(RuntimeError):
    pass


class LocalSubprocessDriver:
    verification_level = VERIFICATION_LEVEL

    def __init__(self, workspace_root: str | None = None):
        self.workspace_root = workspace_root or os.getenv("SANDBOX_LOCAL_WORKSPACE_ROOT") or None
        logger.warning(LOCAL_DRIVER_WARNING)

    def runner_identity(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Reports what actually ran. It never claims deny-network or read-only-root isolation."""
        return {
            "image_digest": payload["execution_policy"].get("image_digest"),
            "network": "unrestricted",
            "read_only_root": False,
            "runtime_class": "local-subprocess",
        }

    def _run_variant(self, payload: dict[str, Any], variant: str, check: dict[str, Any], budget_seconds: float) -> dict[str, Any]:
        started = time.monotonic()
        if budget_seconds <= 0:
            return self._incomplete(started, "job_deadline_exceeded")
        workspace = Path(tempfile.mkdtemp(prefix="mitig8it-local-", dir=self.workspace_root))
        repository = workspace / "repo"
        try:
            materialize_tree(repository, payload, variant)
        except (ValueError, OSError) as error:
            shutil.rmtree(workspace, ignore_errors=True)
            return self._incomplete(started, f"materializer_failed:{type(error).__name__}")
        timeout = max(0.1, min(float(check["timeout_seconds"]), budget_seconds))
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv from the trusted control plane.
                list(check["argv"]),
                cwd=repository,
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "HOME": str(workspace / "no-home"),
                    "CI": "true",
                    "NO_COLOR": "1",
                    "NODE_OPTIONS": "--disable-proto=throw",
                },
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self._incomplete(started, "check_timed_out")
        except (OSError, ValueError) as error:
            return self._incomplete(started, f"check_not_executable:{type(error).__name__}")
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
        output = (completed.stdout or "") + (completed.stderr or "")
        truncated = len(output) > MAX_CAPTURED_CHARS
        bounded = output[:MAX_CAPTURED_CHARS]
        return {
            "completed": True,
            "status": "passed" if completed.returncode == 0 else "failed",
            "exit_code": completed.returncode,
            "stdout_digest": f"sha256:{hashlib.sha256(bounded.encode('utf-8')).hexdigest()}",
            "output_truncated": truncated,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "scanner_findings": parse_scanner_findings(bounded) if check["kind"] == "scanner" else None,
        }

    @staticmethod
    def _incomplete(started: float, reason: str) -> dict[str, Any]:
        return {
            "completed": False,
            "status": "inconclusive",
            "exit_code": None,
            "stdout_digest": None,
            "output_truncated": False,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "reason_code": reason,
            "scanner_findings": None,
        }

    def execute(self, payload: dict[str, Any], deadline_seconds: int) -> dict[str, Any]:
        started = time.monotonic()
        records: list[dict[str, Any]] = []
        for check in payload["execution_policy"]["commands"]:
            record: dict[str, Any] = {"check_id": check["check_id"], "kind": check["kind"], "argv": list(check["argv"])}
            for variant in ("baseline", "candidate"):
                remaining = deadline_seconds - (time.monotonic() - started)
                record[variant] = self._run_variant(payload, variant, check, remaining)
            records.append(record)
        return {"outcome": aggregate_outcome(records), "checks": records}

    def cancel(self, request_digest: str) -> None:
        """Local checks are synchronous subprocesses bounded by their timeout; nothing outlives them."""
        return None


class InProcessSandboxBroker:
    """In-process broker for local development and the benchmark harness.

    It performs the broker's evidence assembly without HTTP or HMAC, because there is no
    transport trust boundary inside one process. The evidence still carries the driver's
    honest verification level, which the verifier enforces against policy.
    """

    def __init__(self, driver: Any | None = None):
        self.driver = driver or LocalSubprocessDriver()

    async def verify(self, payload: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
        import asyncio

        deadline = int(payload["execution_policy"].get("deadline_seconds") or timeout_seconds)
        try:
            result = await asyncio.to_thread(self.driver.execute, payload, deadline)
        except (LocalExecutionError, KeyError, TypeError, ValueError):
            result = {"outcome": "inconclusive", "reason_code": "sandbox_execution_failed", "checks": []}
        return build_evidence(payload, result, self.driver.runner_identity(payload), self.driver.verification_level)
