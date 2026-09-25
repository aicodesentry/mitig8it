"""Cloud Run Jobs sandbox driver: the isolation level the product can actually deploy.

The Kubernetes driver beside this one is the stronger design and stays the production target,
but it needs a GKE cluster with a gVisor node pool. This product runs on Cloud Run, so its
deployed verification ran in the development local subprocess driver, inside the service
container, with no isolation of any kind. This driver is the third option: real container
isolation, a separate identity for the check, a network the check cannot use, and evidence
that says exactly which of those were measured rather than assumed.

Shape of one verification
-------------------------
The driver materializes the baseline tree and the candidate tree once, through the same
trusted `sandbox/runner.py` materializer both other drivers use, packages each into a
deterministic tar.gz, and uploads the two archives to the snapshots bucket under one
execution-scoped prefix. It then starts **one Cloud Run Job execution per check, with two
tasks**: task 0 runs the baseline archive, task 1 runs the candidate archive.

Two tasks in one execution rather than two executions per check, because:

* the evidence shape is unchanged: each task writes its own result object, so a check still
  carries one independent baseline record and one independent candidate record, produced in
  separate containers that never share a filesystem;
* the two halves of a check pair run concurrently, which halves the wall-clock cost of the
  part of a verification that is dominated by job start latency;
* the driver polls one execution per check instead of two, and cancels one name per check.

A single task per variant per check (two executions) would be the same evidence at twice the
API calls and twice the latency; running both variants sequentially inside one task would
share a container between the baseline and the candidate, which is exactly the property the
Kubernetes driver refuses to give up.

What the sandbox does and does not deny
---------------------------------------
Snapshot transport is object-store-shaped, so the container needs no inbound network and the
driver needs no channel into it. The check's argv, its timeout, the object names, their
sha256, and a per-execution HMAC nonce travel as container overrides.

Inside the task, `job_entrypoint.py` downloads and digest-verifies its archive, extracts it,
clears `/etc/resolv.conf`, drops to a separate unprivileged user that holds none of the task's
credentials, and moves that user into a private network namespace where nothing but loopback
exists. It then measures, from the check's own user and context, whether the metadata server,
a public address, and DNS are reachable, and reports each measurement.

This driver refuses to call anything verified unless every one of those measurements came
back an explicit `false`. A probe that could not run, or that reached its target, ends the
verification as `sandbox_network_not_denied`: the sandbox did not do what the level claims,
so the level is not claimed. What the probes do *not* establish is spelled out in
`docs/runbooks/sandbox-cloud-run-job.md`; in short, they are a measurement of one moment from
one process, not a proof about the whole task lifetime, and this driver never claims the
read-only root filesystem or the gVisor runtime class the production level requires.
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import io
import json
import logging
import os
import secrets
import shutil
import tarfile
import tempfile
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .execution import aggregate_outcome, output_tail, parse_scanner_findings
from .job_entrypoint import (
    ENV_CHECK,
    ENV_CHECK_USER,
    ENV_JOB,
    ENV_NONCE,
    ENV_PROJECT,
    ENV_REGION,
    ENV_RESULT_BUCKET,
    ENV_RESULT_PREFIX,
    ENV_SNAPSHOT_BUCKET,
    ENV_SNAPSHOT_MANIFEST,
    ENVIRONMENT_KIND,
    MAX_CAPTURED_CHARS,
    PROBES,
    VARIANTS,
)
from .runner import materialize_tree

logger = logging.getLogger("mitig8it.remediation.sandbox.cloud_run_job")

VERIFICATION_LEVEL = "isolated_job"
RESULT_SCHEMA_VERSION = "v1"
PROBE_TARGETS = tuple(probe["target"] for probe in PROBES)

DEFAULT_TASK_TIMEOUT_SECONDS = 300
DEFAULT_POLL_INTERVAL_SECONDS = 2.0
# Cloud Run schedules a task in seconds, not milliseconds. A check whose own budget is 30 s
# must not be abandoned because the container took 20 s to start, so the driver waits the
# check's budget plus this margin before it calls an execution lost.
EXECUTION_START_MARGIN_SECONDS = 180
MAX_TRACKED_EXECUTIONS = 64


class CloudRunJobExecutionError(RuntimeError):
    pass


class CloudRunJobConfigurationError(CloudRunJobExecutionError):
    pass


@dataclass(frozen=True)
class CloudRunJobDriverConfig:
    job_name: str
    region: str
    project: str
    snapshot_bucket: str
    result_bucket: str
    image_digest: str
    check_user: str = "sandboxcheck"
    task_timeout_seconds: int = DEFAULT_TASK_TIMEOUT_SECONDS
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS

    @property
    def job_path(self) -> str:
        return f"projects/{self.project}/locations/{self.region}/jobs/{self.job_name}"

    @classmethod
    def from_env(cls) -> "CloudRunJobDriverConfig":
        required = {
            "SANDBOX_JOB_NAME": os.getenv("SANDBOX_JOB_NAME", ""),
            "SANDBOX_JOB_REGION": os.getenv("SANDBOX_JOB_REGION", ""),
            "SANDBOX_JOB_PROJECT": os.getenv("SANDBOX_JOB_PROJECT", ""),
            "SANDBOX_BUCKET": os.getenv("SANDBOX_BUCKET", ""),
            "SANDBOX_IMAGE_DIGEST": os.getenv("SANDBOX_IMAGE_DIGEST", ""),
        }
        missing = sorted(name for name, value in required.items() if not value.strip())
        if missing:
            raise CloudRunJobConfigurationError(
                f"the Cloud Run job sandbox driver requires {', '.join(missing)}"
            )
        snapshots = required["SANDBOX_BUCKET"].strip()
        return cls(
            job_name=required["SANDBOX_JOB_NAME"].strip(),
            region=required["SANDBOX_JOB_REGION"].strip(),
            project=required["SANDBOX_JOB_PROJECT"].strip(),
            snapshot_bucket=snapshots,
            # Two buckets, not one bucket with IAM conditions on object prefixes: the job
            # identity then has no role at all on the bucket that holds other tenants'
            # snapshots beyond read, and none whatsoever that could list or read results.
            result_bucket=(os.getenv("SANDBOX_RESULTS_BUCKET", "").strip() or _paired_result_bucket(snapshots)),
            image_digest=required["SANDBOX_IMAGE_DIGEST"].strip(),
            check_user=os.getenv("SANDBOX_JOB_CHECK_USER", "sandboxcheck").strip() or "sandboxcheck",
            task_timeout_seconds=_positive_int("SANDBOX_JOB_TIMEOUT_SECONDS", DEFAULT_TASK_TIMEOUT_SECONDS),
            poll_interval_seconds=_positive_float("SANDBOX_JOB_POLL_INTERVAL_SECONDS", DEFAULT_POLL_INTERVAL_SECONDS),
        )


def _paired_result_bucket(snapshots: str) -> str:
    """The results bucket Terraform creates beside a given snapshots bucket.

    `cloud_run_job.tf` names them `<prefix>-snapshots` and `<prefix>-results`, so the default
    has to replace that suffix rather than append to it: `<prefix>-snapshots-results` is a
    bucket that does not exist, and the failure would surface as every result being
    unavailable rather than as a configuration error. `SANDBOX_RESULTS_BUCKET` overrides this
    for any installation whose buckets are not named in pairs.
    """
    return f"{snapshots.removesuffix('-snapshots')}-results"


def _positive_int(name: str, fallback: int) -> int:
    try:
        value = int(os.getenv(name, "") or fallback)
    except ValueError:
        return fallback
    return value if value > 0 else fallback


def _positive_float(name: str, fallback: float) -> float:
    try:
        value = float(os.getenv(name, "") or fallback)
    except ValueError:
        return fallback
    return value if value > 0 else fallback


def pack_tree(payload: dict[str, Any], variant: str, workspace_root: str | None = None) -> bytes:
    """A deterministic tar.gz of one variant's materialized tree.

    The tree is written by the shared trusted materializer, so the same path rules and the
    same digest-bound patch application that guard the Kubernetes init container and the local
    driver guard this transport too. The archive is then built from a sorted walk with fixed
    ownership, mode, and mtime, and gzipped with no timestamp, so the same payload and variant
    always produce the same bytes and therefore the same sha256 the job is told to expect.
    """
    workspace = Path(tempfile.mkdtemp(prefix="mitig8it-pack-", dir=workspace_root))
    try:
        root = workspace / "repo"
        materialize_tree(root, payload, variant)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as bundle:
            for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
                if path.is_symlink() or not path.is_file():
                    continue
                info = tarfile.TarInfo(path.relative_to(root).as_posix())
                body = path.read_bytes()
                info.size = len(body)
                info.mtime = 0
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                bundle.addfile(info, io.BytesIO(body))
        compressed = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as handle:
            handle.write(raw.getvalue())
        return compressed.getvalue()
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def _execution_finished(execution: Any) -> bool:
    """True once Cloud Run has recorded a completion time for the execution."""
    completion = getattr(execution, "completion_time", None)
    if not completion:
        return False
    try:
        return completion.timestamp() > 0
    except (AttributeError, TypeError, ValueError, OSError):
        return True


class CloudRunJobDriver:
    """Runs each check as one Cloud Run Job execution of two tasks, one per variant."""

    verification_class = VERIFICATION_LEVEL
    verification_level = VERIFICATION_LEVEL

    def __init__(
        self,
        settings: CloudRunJobDriverConfig | None = None,
        *,
        jobs_client: Any | None = None,
        executions_client: Any | None = None,
        storage_client: Any | None = None,
    ):
        self.settings = settings or CloudRunJobDriverConfig.from_env()
        self._jobs = jobs_client
        self._executions = executions_client
        self._storage = storage_client
        # request_digest -> the runner identity this driver's last execution of it produced.
        # `runner_identity` is called by the broker after `execute` returns, so the execution
        # names and the digest the tasks reported have to survive that hop.
        self._identities: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        # request_digest -> execution names still worth cancelling.
        self._in_flight: "OrderedDict[str, list[str]]" = OrderedDict()

    # -- lazily constructed Google clients ------------------------------------------------

    def _job_client(self) -> Any:
        if self._jobs is None:
            from google.api_core.client_options import ClientOptions  # noqa: PLC0415
            from google.cloud import run_v2  # noqa: PLC0415

            self._jobs = run_v2.JobsClient(
                client_options=ClientOptions(api_endpoint=f"{self.settings.region}-run.googleapis.com")
            )
        return self._jobs

    def _execution_client(self) -> Any:
        if self._executions is None:
            from google.api_core.client_options import ClientOptions  # noqa: PLC0415
            from google.cloud import run_v2  # noqa: PLC0415

            self._executions = run_v2.ExecutionsClient(
                client_options=ClientOptions(api_endpoint=f"{self.settings.region}-run.googleapis.com")
            )
        return self._executions

    def _storage_client(self) -> Any:
        if self._storage is None:
            from google.cloud import storage  # noqa: PLC0415

            self._storage = storage.Client(project=self.settings.project)
        return self._storage

    # -- object transport -----------------------------------------------------------------

    def _upload(self, bucket: str, name: str, body: bytes, content_type: str) -> None:
        self._storage_client().bucket(bucket).blob(name).upload_from_string(body, content_type=content_type)

    def _download(self, bucket: str, name: str) -> bytes | None:
        blob = self._storage_client().bucket(bucket).blob(name)
        try:
            return blob.download_as_bytes()
        except Exception as error:  # noqa: BLE001 - google.cloud.exceptions.NotFound and transport errors alike.
            logger.info("sandbox result object is unavailable", extra={"object": name, "error": type(error).__name__})
            return None

    def _delete(self, bucket: str, name: str) -> None:
        try:
            self._storage_client().bucket(bucket).blob(name).delete()
        except Exception:  # noqa: BLE001 - the bucket's one-day lifecycle rule is the backstop.
            logger.info("sandbox snapshot object could not be deleted", extra={"object": name})

    # -- evidence -------------------------------------------------------------------------

    def runner_identity(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Reports what actually ran, including the identity fields the verifier validates.

        `network: deny` is claimed only when every task measured every probe target as
        unreachable; otherwise `execute` has already refused the run, so this never labels an
        unmeasured sandbox as denied. `read_only_root` is false: a Cloud Run job container has
        a writable overlay filesystem, and this driver does not pretend otherwise.
        """
        recorded = self._identities.get(payload.get("request_digest", ""))
        if recorded is not None:
            return recorded
        return {
            "image_digest": None,
            "network": "unknown",
            "read_only_root": False,
            "runtime_class": ENVIRONMENT_KIND,
            "environment_kind": ENVIRONMENT_KIND,
            "job_executions": [],
        }

    def _record_identity(self, digest: str, identity: dict[str, Any]) -> None:
        self._identities[digest] = identity
        while len(self._identities) > MAX_TRACKED_EXECUTIONS:
            self._identities.popitem(last=False)

    # -- one execution --------------------------------------------------------------------

    def _start(self, prefix: str, index: int, check: dict[str, Any], manifest: dict[str, Any], nonce: str) -> str:
        from google.cloud import run_v2  # noqa: PLC0415

        overrides = run_v2.RunJobRequest.Overrides(
            container_overrides=[
                run_v2.RunJobRequest.Overrides.ContainerOverride(
                    env=[
                        run_v2.EnvVar(name=ENV_SNAPSHOT_BUCKET, value=self.settings.snapshot_bucket),
                        run_v2.EnvVar(name=ENV_SNAPSHOT_MANIFEST, value=json.dumps(manifest, sort_keys=True)),
                        run_v2.EnvVar(name=ENV_RESULT_BUCKET, value=self.settings.result_bucket),
                        run_v2.EnvVar(name=ENV_RESULT_PREFIX, value=f"{prefix}/{index}"),
                        run_v2.EnvVar(name=ENV_CHECK, value=json.dumps(check, sort_keys=True)),
                        run_v2.EnvVar(name=ENV_NONCE, value=nonce),
                        run_v2.EnvVar(name=ENV_CHECK_USER, value=self.settings.check_user),
                        run_v2.EnvVar(name=ENV_PROJECT, value=self.settings.project),
                        run_v2.EnvVar(name=ENV_REGION, value=self.settings.region),
                        run_v2.EnvVar(name=ENV_JOB, value=self.settings.job_name),
                    ]
                )
            ],
            task_count=len(VARIANTS),
        )
        operation = self._job_client().run_job(
            request=run_v2.RunJobRequest(name=self.settings.job_path, overrides=overrides)
        )
        name = getattr(getattr(operation, "metadata", None), "name", "") or ""
        if not name:
            raise CloudRunJobExecutionError("Cloud Run did not name the execution it started")
        return name

    def _await(self, name: str, budget_seconds: float) -> bool:
        client = self._execution_client()
        cutoff = time.monotonic() + budget_seconds
        while time.monotonic() < cutoff:
            if _execution_finished(client.get_execution(name=name)):
                return True
            time.sleep(self.settings.poll_interval_seconds)
        return False

    def _collect(self, prefix: str, index: int, variant: str, nonce: str) -> dict[str, Any] | None:
        """Downloads one task's result object and verifies it was written by that task."""
        body = self._download(self.settings.result_bucket, f"{prefix}/{index}/{variant}.json")
        if body is None:
            return None
        try:
            envelope = json.loads(body)
            payload = envelope["payload"]
            signature = envelope["signature"]
        except (ValueError, KeyError, TypeError):
            logger.warning("sandbox result object is malformed", extra={"variant": variant})
            return None
        if not isinstance(payload, str) or not isinstance(signature, str):
            return None
        expected = hmac.new(nonce.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            logger.warning("sandbox result signature did not verify", extra={"variant": variant})
            return None
        try:
            document = json.loads(payload)
        except ValueError:
            return None
        return document if isinstance(document, dict) else None

    # -- mapping a task result onto the shared evidence shape ------------------------------

    @staticmethod
    def _incomplete(reason: str, duration_ms: int = 0, **extra: Any) -> dict[str, Any]:
        return {
            "completed": False,
            "status": "inconclusive",
            "exit_code": None,
            "stdout_digest": None,
            "output_truncated": False,
            "duration_ms": duration_ms,
            "reason_code": reason,
            "scanner_findings": None,
            **extra,
        }

    def _variant_record(self, document: dict[str, Any] | None, check: dict[str, Any], variant: str) -> dict[str, Any]:
        if document is None:
            return self._incomplete("sandbox_result_unavailable", network_probes={})
        if document.get("check_id") != check["check_id"] or document.get("variant") != variant:
            # The nonce proves the writer held this execution's secret; this proves the object
            # is the one this check asked for and not another check's result replayed into it.
            return self._incomplete("sandbox_result_mismatched", network_probes={})
        probes = document.get("probes") if isinstance(document.get("probes"), dict) else {}
        runner = document.get("runner") if isinstance(document.get("runner"), dict) else {}
        duration = int(document.get("duration_ms") or 0)
        if document.get("completed") is not True:
            reason = str(document.get("reason_code") or "sandbox_check_incomplete")[:120]
            return self._incomplete(reason, duration, network_probes=probes, job_execution=runner.get("job_execution"))
        output = str(document.get("output") or "")[:MAX_CAPTURED_CHARS]
        exit_code = document.get("exit_code")
        if not isinstance(exit_code, int):
            return self._incomplete("sandbox_exit_code_missing", duration, network_probes=probes)
        return {
            "completed": True,
            "status": "passed" if exit_code == 0 else "failed",
            "exit_code": exit_code,
            "stdout_digest": f"sha256:{hashlib.sha256(output.encode('utf-8')).hexdigest()}",
            "output_truncated": bool(document.get("output_truncated")),
            "output_tail": output_tail(output, exit_code),
            "duration_ms": duration,
            "scanner_findings": parse_scanner_findings(output) if check["kind"] == "scanner" else None,
            "network_probes": probes,
            "job_execution": runner.get("job_execution"),
        }

    @staticmethod
    def _probe_verdict(records: list[dict[str, Any]]) -> str | None:
        """None when every completed task measured every probe target as explicitly unreachable."""
        for record in records:
            for variant in VARIANTS:
                outcome = record.get(variant) or {}
                if outcome.get("completed") is not True:
                    continue
                probes = outcome.get("network_probes") or {}
                for target in PROBE_TARGETS:
                    probe = probes.get(target)
                    if not isinstance(probe, dict) or probe.get("reached") is not False:
                        return f"{record['check_id']}:{variant}:{target}"
        return None

    @staticmethod
    def _reported_digests(documents: dict[tuple[str, str], dict[str, Any]]) -> set[str | None]:
        """Every image digest the tasks read back from the Cloud Run Admin API, `None` included."""
        digests: set[str | None] = set()
        for document in documents.values():
            runner = document.get("runner") if isinstance(document.get("runner"), dict) else {}
            digests.add(runner.get("image_digest"))
        return digests

    # -- the driver protocol ---------------------------------------------------------------

    def execute(self, payload: dict[str, Any], deadline_seconds: int) -> dict[str, Any]:
        started = time.monotonic()
        digest = str(payload.get("request_digest", ""))
        suffix = digest.removeprefix("sha256:")[:20] or secrets.token_hex(10)
        prefix = f"snapshots/{suffix}"
        nonce = secrets.token_hex(32)
        checks = list(payload["execution_policy"]["commands"])
        objects: list[str] = []
        try:
            manifest: dict[str, Any] = {}
            for variant in VARIANTS:
                archive = pack_tree(payload, variant)
                name = f"{prefix}/{variant}.tar.gz"
                self._upload(self.settings.snapshot_bucket, name, archive, "application/gzip")
                objects.append(name)
                manifest[variant] = {"object": name, "sha256": f"sha256:{hashlib.sha256(archive).hexdigest()}"}

            records: list[dict[str, Any]] = []
            documents: dict[tuple[str, str], dict[str, Any]] = {}
            executions: list[str] = []
            for index, check in enumerate(checks):
                record: dict[str, Any] = {"check_id": check["check_id"], "kind": check["kind"], "argv": list(check["argv"])}
                remaining = deadline_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    for variant in VARIANTS:
                        record[variant] = self._incomplete("job_deadline_exceeded", network_probes={})
                    records.append(record)
                    continue
                name = self._start(prefix, index, check, manifest, nonce)
                executions.append(name)
                self._in_flight[digest] = list(executions)
                budget = min(
                    remaining,
                    float(check["timeout_seconds"]) + EXECUTION_START_MARGIN_SECONDS,
                    float(self.settings.task_timeout_seconds) + EXECUTION_START_MARGIN_SECONDS,
                )
                finished = self._await(name, budget)
                for variant in VARIANTS:
                    document = self._collect(prefix, index, variant, nonce) if finished else None
                    if document is not None:
                        documents[(check["check_id"], variant)] = document
                    record[variant] = (
                        self._variant_record(document, check, variant)
                        if finished
                        else self._incomplete("check_deadline_exceeded", network_probes={}, job_execution=name)
                    )
                records.append(record)

            identity = {
                "image_digest": self.settings.image_digest,
                "network": "deny",
                "read_only_root": False,
                "runtime_class": ENVIRONMENT_KIND,
                "environment_kind": ENVIRONMENT_KIND,
                "job_executions": executions,
            }

            reported = self._reported_digests(documents)
            if reported and reported != {self.settings.image_digest}:
                # The job ran an image the deployment did not pin, or could not tell the driver
                # which image it ran. Either way the evidence is not about a known runner.
                self._record_identity(digest, {**identity, "network": "unknown", "image_digest": None})
                return {"outcome": "inconclusive", "reason_code": "sandbox_image_digest_mismatch", "checks": []}

            reached = self._probe_verdict(records)
            if reached is not None:
                logger.warning("the Cloud Run job sandbox did not deny the network", extra={"probe": reached})
                self._record_identity(digest, {**identity, "network": "unknown"})
                return {"outcome": "inconclusive", "reason_code": "sandbox_network_not_denied", "checks": []}

            self._record_identity(digest, identity)
            return {"outcome": aggregate_outcome(records), "checks": records}
        except (KeyError, TypeError, ValueError) as error:
            raise CloudRunJobExecutionError("Cloud Run job sandbox execution failed") from error
        finally:
            self._in_flight.pop(digest, None)
            for name in objects:
                self._delete(self.settings.snapshot_bucket, name)

    def cancel(self, request_digest: str) -> None:
        """Cancels this request's in-flight executions and removes its snapshot objects."""
        suffix = request_digest.removeprefix("sha256:")[:20]
        for name in self._in_flight.pop(request_digest, []):
            try:
                self._execution_client().cancel_execution(name=name)
            except Exception:  # noqa: BLE001 - an execution that already finished is not an error.
                logger.info("sandbox execution could not be cancelled", extra={"execution": name})
        for variant in VARIANTS:
            self._delete(self.settings.snapshot_bucket, f"snapshots/{suffix}/{variant}.tar.gz")
