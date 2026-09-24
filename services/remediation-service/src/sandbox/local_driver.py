"""Development-only local subprocess sandbox driver.

This driver runs each baseline/candidate check as an ordinary host subprocess in a fresh
temporary directory. It provides no network isolation, no filesystem isolation beyond the
temporary directory, no kernel isolation, and no resource enforcement other than a wall-clock
timeout. Evidence it produces is therefore labelled `development_unverified` and can never be
presented as the production `independent_sandbox` verification level.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from functools import lru_cache
from pathlib import Path, PurePath
from typing import Any

from .execution import aggregate_outcome, build_evidence, output_tail, parse_scanner_findings
from .runner import materialize_tree

logger = logging.getLogger("mitig8it.remediation.sandbox.local")

LOCAL_DRIVER_WARNING = (
    "SANDBOX_DRIVER=local selects the development-only local subprocess driver. Repository code "
    "runs on this host without network, kernel, or filesystem isolation, and its evidence is "
    "labelled development_unverified. Never enable it for production traffic."
)

VERIFICATION_LEVEL = "development_unverified"
MAX_CAPTURED_CHARS = 200_000

# The service test harness (sandbox/harness.js) compiles TypeScript with Node's own type
# stripper and installs its resolver through `module.registerHooks`. Both arrived in Node 22:
# `stripTypeScriptTypes` in 22.13 and `registerHooks` in 22.15, and the flags the harness is
# launched with are younger than Node 20 too. `services/remediation-service/Dockerfile` pins the
# runtime that carries them in `ARG NODE_VERSION`, and every environment that runs this driver
# has to match it.
#
# On an older runtime nothing about a candidate is ever exercised: Node rejects the flag set
# before it reads a line of repository code, so the check fails identically on the baseline and
# the candidate tree and the pipeline reports a repair that did not prove itself. That reads as
# a bad repair. It is a bad toolchain. The driver probes `node` once and names what is missing,
# so the next reader of a failing run sees the runtime rather than the candidate.
NODE_EXECUTABLE_NAMES = frozenset({"node", "node.exe"})
REQUIRED_NODE_FEATURES = ("module.stripTypeScriptTypes", "module.registerHooks")
NODE_PROBE_PROGRAM = (
    "const m = require('node:module');"
    "const missing = ["
    "typeof m.stripTypeScriptTypes === 'function' ? null : 'module.stripTypeScriptTypes',"
    "typeof m.registerHooks === 'function' ? null : 'module.registerHooks',"
    "].filter(Boolean);"
    "process.stdout.write(JSON.stringify({ version: process.version, missing }));"
)
NODE_PROBE_TIMEOUT_SECONDS = 30
NODE_RUNTIME_REASON = "node_runtime_missing_features"
MAX_REASON_FEATURE_CHARS = 200


class NodeRuntimeReport:
    """What this host's `node` is, and which harness features it does not have."""

    def __init__(self, version: str | None, missing: tuple[str, ...]):
        self.version = version
        self.missing = missing

    def detail(self) -> str:
        return (
            f"the sandbox test harness needs Node features this runtime does not provide: "
            f"{', '.join(self.missing)}. `node` here reports {self.version or 'an unknown version'}; "
            "the supported runtime is the one services/remediation-service/Dockerfile pins in "
            "ARG NODE_VERSION. No repository code ran, so this says nothing about the candidate."
        )

    def reason_code(self) -> str:
        return f"{NODE_RUNTIME_REASON}:{','.join(self.missing)}"[: len(NODE_RUNTIME_REASON) + MAX_REASON_FEATURE_CHARS]


def typescript_flags() -> tuple[str, ...]:
    """The flag set the harness is launched with, read from its one definition.

    Imported here rather than at module scope because `src.patches` imports `src.sandbox`
    for the harness paths, so a top-level import would close the cycle.
    """
    from ..patches import NODE_TYPESCRIPT_FLAGS  # noqa: PLC0415 - breaks an import cycle.

    return tuple(NODE_TYPESCRIPT_FLAGS)


def _probe_node(flags: tuple[str, ...]) -> tuple[str | None, tuple[str, ...]] | None:
    """Runs the feature probe under `flags`. None means the probe itself could not complete."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, no repository input.
            ["node", *flags, "-e", NODE_PROBE_PROGRAM],
            env={"PATH": os.environ.get("PATH", ""), "NO_COLOR": "1"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=NODE_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    try:
        report = json.loads(completed.stdout.strip() or "null")
    except ValueError:
        return None
    if not isinstance(report, dict) or not isinstance(report.get("missing"), list):
        return None
    missing = tuple(item for item in report["missing"] if isinstance(item, str))
    version = report.get("version") if isinstance(report.get("version"), str) else None
    return version, missing


@lru_cache(maxsize=1)
def node_runtime_report() -> NodeRuntimeReport:
    """This host's Node capability, probed once per process.

    An empty `missing` also covers the case where `node` could not be probed at all: an absent
    or unrunnable binary is already reported per check as `check_not_executable`, and inventing
    a feature gap for it would be a worse diagnosis than the one that path already gives.
    """
    flags = typescript_flags()
    probed = _probe_node(flags)
    if probed is not None:
        version, missing = probed
        report = NodeRuntimeReport(version, missing)
    else:
        # Node rejected the flag set itself, which is exactly what an unknown
        # `--experimental-strip-types` does. Ask again without the flags, so the answer can name
        # the missing APIs as well as the options Node would not accept.
        bare = _probe_node(())
        if bare is None:
            return NodeRuntimeReport(None, ())
        version, missing = bare
        report = NodeRuntimeReport(version, (*missing, *flags))
    if report.missing:
        logger.error(report.detail())
    return report


class LocalExecutionError(RuntimeError):
    pass


class LocalSubprocessDriver:
    verification_level = VERIFICATION_LEVEL

    def __init__(self, workspace_root: str | None = None):
        self.workspace_root = workspace_root or os.getenv("SANDBOX_LOCAL_WORKSPACE_ROOT") or None
        if self.workspace_root:
            # A configured root is a deployment's choice of scratch directory, not a promise
            # that something else created it. Creating it here keeps an absent directory from
            # turning every check into a raised OSError.
            try:
                Path(self.workspace_root).mkdir(parents=True, exist_ok=True)
            except OSError:
                logger.warning(
                    "the configured local sandbox workspace root could not be created; checks will be inconclusive",
                    extra={"workspace_root": self.workspace_root},
                )
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
        if PurePath(str(check["argv"][0])).name in NODE_EXECUTABLE_NAMES:
            node = node_runtime_report()
            if node.missing:
                return self._incomplete(started, node.reason_code(), node.detail())
        try:
            workspace = Path(tempfile.mkdtemp(prefix="mitig8it-local-", dir=self.workspace_root))
        except OSError as error:
            # An unwritable or missing workspace root is a sandbox failure, so it is recorded as
            # an inconclusive check. Raising here would escape the broker and the verifier and
            # end the worker's attempt while it still holds the lease.
            logger.warning(
                "the local sandbox workspace could not be created",
                extra={"workspace_root": self.workspace_root, "error": type(error).__name__},
            )
            return self._incomplete(started, f"workspace_unavailable:{type(error).__name__}")
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
                    # Python checks: no .pyc litter in the workspace, no site customization.
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONNOUSERSITE": "1",
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
            "output_tail": output_tail(bounded, completed.returncode),
            "duration_ms": round((time.monotonic() - started) * 1000),
            "scanner_findings": parse_scanner_findings(bounded) if check["kind"] == "scanner" else None,
        }

    @staticmethod
    def _incomplete(started: float, reason: str, detail: str | None = None) -> dict[str, Any]:
        """A check that did not run. `detail` is a sentence for a human reading the evidence."""
        return {
            "completed": False,
            "status": "inconclusive",
            "exit_code": None,
            "stdout_digest": None,
            "output_truncated": False,
            "output_tail": detail,
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

    async def verify(self, payload: dict[str, Any], deadline_seconds: int) -> dict[str, Any]:
        import asyncio

        deadline = int(payload["execution_policy"].get("deadline_seconds") or deadline_seconds)
        try:
            result = await asyncio.to_thread(self.driver.execute, payload, deadline)
        except (RuntimeError, OSError, KeyError, TypeError, ValueError):
            # OSError included deliberately: the driver touches the filesystem, and a raised
            # driver failure that escapes here ends the worker's attempt with the lease still
            # held instead of producing inconclusive evidence. RuntimeError covers every
            # driver's own failure type (LocalExecutionError, CloudRunJobExecutionError,
            # KubernetesExecutionError) without importing the cloud clients on this path.
            result = {"outcome": "inconclusive", "reason_code": "sandbox_execution_failed", "checks": []}
        return build_evidence(payload, result, self.driver.runner_identity(payload), self.driver.verification_level)
