from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

import psycopg
from google.api_core.exceptions import PreconditionFailed
from google.cloud import storage

from .digests import canonical_json, digest_json, sha256_bytes
from .agent.checkpoint import BudgetCapExceeded, CheckpointError
from .agent.provider import ProviderAction
from .models import RepairRequest, RepairResponse



def _settlement(reserved_tokens: int, reserved_usd: float, actual_tokens: int, actual_usd: float) -> dict[str, Any]:
    """What one provider call reserved, what it really cost, and the difference.

    A reservation is an estimate, so actual usage above it is settled at the actual figure and
    recorded as an overage. Only the hard caps refuse a call.
    """
    return {
        "reserved_tokens": int(reserved_tokens),
        "reserved_usd": round(float(reserved_usd), 6),
        "actual_tokens": int(actual_tokens),
        "actual_usd": round(float(actual_usd), 6),
        "overage_tokens": max(0, int(actual_tokens) - int(reserved_tokens)),
        "overage_usd": round(max(0.0, float(actual_usd) - float(reserved_usd)), 6),
    }


def _cap_context(cumulative_tokens: int, cumulative_usd: float, max_tokens: int, max_usd: float) -> dict[str, Any]:
    return {
        "cumulative_actual_tokens": int(cumulative_tokens),
        "cumulative_actual_usd": round(float(cumulative_usd), 6),
        "max_total_tokens": int(max_tokens),
        "max_spend_usd": float(max_usd),
    }


class ExecutionConfigurationError(RuntimeError):
    pass


class ExecutionConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class ExecutionRecord:
    execution_id: str
    state: str
    request_digest: str
    request_artifact_uri: str
    result_artifact_uri: str | None = None
    # The W3C `traceparent` captured at intake. The worker links its span to it instead of
    # starting an unrelated root trace when it resumes the job.
    trace_context: str | None = None


class ExecutionBackend(Protocol):
    def enqueue(self, request: RepairRequest, trace_context: str | None = None) -> ExecutionRecord: ...
    def get(self, execution_id: str) -> ExecutionRecord | None: ...
    def read_result(self, record: ExecutionRecord) -> RepairResponse: ...
    def cancel(self, execution_id: str) -> bool: ...


class GcsArtifactStore:
    def __init__(self, bucket_name: str, kms_key_name: str, client: storage.Client | None = None):
        if not bucket_name or not kms_key_name:
            raise ExecutionConfigurationError("artifact bucket and KMS key are required")
        self.client = client or storage.Client()
        self.bucket = self.client.bucket(bucket_name)
        self.kms_key_name = kms_key_name

    def put_json(self, name: str, value: Any) -> str:
        raw = canonical_json(value)
        blob = self.bucket.blob(name, kms_key_name=self.kms_key_name)
        try:
            blob.upload_from_string(raw, content_type="application/json", if_generation_match=0, checksum="crc32c")
        except PreconditionFailed:
            existing = blob.download_as_bytes(checksum="crc32c")
            if existing != raw:
                raise ExecutionConflict("content-addressed artifact collision")
        return f"gs://{self.bucket.name}/{name}#{sha256_bytes(raw)}"

    def get_json(self, uri: str) -> Any:
        prefix = f"gs://{self.bucket.name}/"
        if not uri.startswith(prefix) or "#sha256:" not in uri:
            raise ExecutionConflict("artifact URI is outside the configured bucket")
        name, expected = uri[len(prefix) :].rsplit("#", 1)
        raw = self.bucket.blob(name).download_as_bytes(checksum="crc32c")
        if sha256_bytes(raw) != expected:
            raise ExecutionConflict("artifact digest mismatch")
        return json.loads(raw)


class PostgresExecutionBackend:
    def __init__(self, dsn: str, artifacts: GcsArtifactStore):
        if not dsn:
            raise ExecutionConfigurationError("REMEDIATION_DATABASE_URL is required")
        self.dsn = dsn
        self.artifacts = artifacts

    @classmethod
    def from_env(cls) -> "PostgresExecutionBackend":
        return cls(
            os.getenv("REMEDIATION_DATABASE_URL", ""),
            GcsArtifactStore(
                os.getenv("REMEDIATION_ARTIFACT_BUCKET", ""),
                os.getenv("REMEDIATION_ARTIFACT_KMS_KEY", ""),
            ),
        )

    @staticmethod
    def execution_identity(request: RepairRequest) -> tuple[str, str]:
        request_digest = digest_json(request.model_dump(mode="json"))
        execution_id = digest_json(
            {
                "job_id": request.job_id,
                "tenant_id": request.tenant_id,
                "repository_id": request.repository_id,
                "fencing_token": request.fencing_token,
                "request_digest": request_digest,
            }
        )
        return execution_id, request_digest

    def enqueue(self, request: RepairRequest, trace_context: str | None = None) -> ExecutionRecord:
        execution_id, request_digest = self.execution_identity(request)
        artifact_name = f"remediation-inputs/{execution_id.removeprefix('sha256:')}.json"
        uri = self.artifacts.put_json(artifact_name, request.model_dump(mode="json"))
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET LOCAL app.remediation_worker = 'on'")
            cursor.execute(
                """
                INSERT INTO remediation_service_executions
                    (execution_id, job_id, tenant_id, repository_id, fencing_token, request_digest, request_artifact_uri, state, trace_context)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'queued', %s)
                ON CONFLICT (job_id, fencing_token) DO NOTHING
                RETURNING execution_id, state, request_digest, request_artifact_uri, result_artifact_uri, trace_context
                """,
                (execution_id, request.job_id, request.tenant_id, request.repository_id, request.fencing_token, request_digest, uri, trace_context),
            )
            row = cursor.fetchone()
            if row is None:
                cursor.execute(
                    "SELECT execution_id, state, request_digest, request_artifact_uri, result_artifact_uri, trace_context FROM remediation_service_executions WHERE job_id=%s AND fencing_token IS NOT DISTINCT FROM %s",
                    (request.job_id, request.fencing_token),
                )
                row = cursor.fetchone()
            if row is None or row[2] != request_digest:
                raise ExecutionConflict("job/fencing token was already used with a different request")
            return ExecutionRecord(*row)

    def get(self, execution_id: str) -> ExecutionRecord | None:
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET LOCAL app.remediation_worker = 'on'")
            cursor.execute(
                "SELECT execution_id, state, request_digest, request_artifact_uri, result_artifact_uri, trace_context FROM remediation_service_executions WHERE execution_id=%s",
                (execution_id,),
            )
            row = cursor.fetchone()
            return ExecutionRecord(*row) if row else None

    def read_result(self, record: ExecutionRecord) -> RepairResponse:
        if not record.result_artifact_uri:
            raise ExecutionConflict("terminal execution has no result artifact")
        return RepairResponse.model_validate(self.artifacts.get_json(record.result_artifact_uri))

    def cancel(self, execution_id: str) -> bool:
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET LOCAL app.remediation_worker = 'on'")
            cursor.execute(
                """
                UPDATE remediation_service_executions
                SET state='cancelled', lease_owner=NULL, lease_expires_at=NULL,
                    completed_at=now(), updated_at=now()
                WHERE execution_id=%s AND state IN ('queued', 'running')
                """,
                (execution_id,),
            )
            if cursor.rowcount == 1:
                return True
            cursor.execute("SELECT state FROM remediation_service_executions WHERE execution_id=%s", (execution_id,))
            row = cursor.fetchone()
            return bool(row and row[0] == "cancelled")

    def claim(self, worker_id: str, lease_seconds: int = 60) -> ExecutionRecord | None:
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET LOCAL app.remediation_worker = 'on'")
            # Provider reservations and tool trajectory are durable, so a reclaimed
            # attempt resumes with the remaining job-level budget. An ambiguous call's
            # full reservation stays charged.
            max_attempts = 5
            cursor.execute(
                """
                UPDATE remediation_service_executions
                SET state='failed', lease_owner=NULL, lease_expires_at=NULL, completed_at=now(), updated_at=now()
                WHERE attempt >= %s AND (state='queued' OR (state='running' AND lease_expires_at < now()))
                """,
                (max_attempts,),
            )
            cursor.execute(
                """
                WITH selected AS (
                    SELECT execution_id FROM remediation_service_executions
                    WHERE attempt < %s AND (state='queued' OR (state='running' AND lease_expires_at < now()))
                    ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
                )
                UPDATE remediation_service_executions e
                SET state='running', lease_owner=%s, lease_expires_at=now() + (%s * interval '1 second'),
                    attempt=attempt+1, updated_at=now()
                FROM selected WHERE e.execution_id=selected.execution_id
                RETURNING e.execution_id, e.state, e.request_digest, e.request_artifact_uri, e.result_artifact_uri
                """,
                (max_attempts, worker_id, lease_seconds),
            )
            row = cursor.fetchone()
            return ExecutionRecord(*row) if row else None

    def read_request(self, record: ExecutionRecord) -> RepairRequest:
        return RepairRequest.model_validate(self.artifacts.get_json(record.request_artifact_uri))

    def heartbeat(self, execution_id: str, worker_id: str, lease_seconds: int = 60) -> bool:
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET LOCAL app.remediation_worker = 'on'")
            cursor.execute(
                "UPDATE remediation_service_executions SET lease_expires_at=now() + (%s * interval '1 second'), updated_at=now() WHERE execution_id=%s AND state='running' AND lease_owner=%s AND lease_expires_at > now()",
                (lease_seconds, execution_id, worker_id),
            )
            return cursor.rowcount == 1

    def complete(self, execution_id: str, worker_id: str, result: RepairResponse) -> bool:
        artifact_name = f"remediation-results/{execution_id.removeprefix('sha256:')}-{result.manifest_digest or result.state}.json"
        uri = self.artifacts.put_json(artifact_name, result.model_dump(mode="json"))
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET LOCAL app.remediation_worker = 'on'")
            cursor.execute(
                """
                UPDATE remediation_service_executions SET state=%s, result_artifact_uri=%s,
                    lease_owner=NULL, lease_expires_at=NULL, completed_at=now(), updated_at=now()
                WHERE execution_id=%s AND state='running' AND lease_owner=%s AND lease_expires_at > now()
                """,
                (result.state, uri, execution_id, worker_id),
            )
            return cursor.rowcount == 1


class ExecutionCheckpointStore:
    """Lease-fenced, encrypted artifact checkpoints and atomic provider reservations."""

    def __init__(self, backend: PostgresExecutionBackend, execution_id: str, worker_id: str, request: RepairRequest):
        self.backend = backend
        self.execution_id = execution_id
        self.worker_id = worker_id
        self.max_tokens = request.policy.max_total_tokens
        self.max_usd = request.policy.max_spend_usd

    async def load(self) -> dict[str, Any] | None:
        import asyncio

        return await asyncio.to_thread(self._load)

    def _load(self) -> dict[str, Any] | None:
        with psycopg.connect(self.backend.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET LOCAL app.remediation_worker = 'on'")
            cursor.execute(
                """
                SELECT checkpoint_artifact_uri, pending_call_sequence
                FROM remediation_service_executions
                WHERE execution_id=%s AND state='running' AND lease_owner=%s AND lease_expires_at > now()
                FOR UPDATE
                """,
                (self.execution_id, self.worker_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise CheckpointError("execution lease is no longer valid")
            uri, pending = row
            if pending is not None:
                # The provider outcome is ambiguous. Keep the full reservation charged,
                # discard any unavailable response, and resume from the last checkpoint.
                cursor.execute(
                    "UPDATE remediation_service_executions SET pending_call_sequence=NULL, pending_reserved_tokens=NULL, pending_reserved_usd=NULL WHERE execution_id=%s",
                    (self.execution_id,),
                )
            return self.backend.artifacts.get_json(uri) if uri else None

    async def reserve_provider_call(self, sequence: int, tokens: int, usd: float) -> bool:
        import asyncio

        return await asyncio.to_thread(self._reserve_provider_call, sequence, tokens, usd)

    def _reserve_provider_call(self, sequence: int, tokens: int, usd: float) -> bool:
        with psycopg.connect(self.backend.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET LOCAL app.remediation_worker = 'on'")
            cursor.execute(
                """
                UPDATE remediation_service_executions
                SET charged_tokens=charged_tokens+%s, charged_usd=charged_usd+%s,
                    pending_call_sequence=%s, pending_reserved_tokens=%s, pending_reserved_usd=%s,
                    updated_at=now()
                WHERE execution_id=%s AND state='running' AND lease_owner=%s AND lease_expires_at > now()
                    AND pending_call_sequence IS NULL
                    AND charged_tokens+%s <= %s AND charged_usd+%s <= %s
                """,
                (tokens, usd, sequence, tokens, usd, self.execution_id, self.worker_id, tokens, self.max_tokens, usd, self.max_usd),
            )
            return cursor.rowcount == 1

    async def save_provider_action(self, state: dict[str, Any], action: ProviderAction, actual_tokens: int, actual_usd: float) -> dict[str, Any]:
        import asyncio

        return await asyncio.to_thread(self._save_provider_action, state, action, actual_tokens, actual_usd)

    def _save_provider_action(self, state: dict[str, Any], action: ProviderAction, actual_tokens: int, actual_usd: float) -> dict[str, Any]:
        checkpoint = {**state, "pending_action": {"name": action.name, "arguments": action.arguments, "call_id": action.call_id, "request_id": action.request_id, "input_tokens": action.input_tokens, "output_tokens": action.output_tokens}}
        with psycopg.connect(self.backend.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET LOCAL app.remediation_worker = 'on'")
            cursor.execute("SELECT checkpoint_version, pending_reserved_tokens, pending_reserved_usd, actual_tokens, actual_usd FROM remediation_service_executions WHERE execution_id=%s FOR UPDATE", (self.execution_id,))
            row = cursor.fetchone()
            if row is None or row[1] is None:
                # No reservation to settle against means the call was never announced, which is a
                # protocol violation rather than a bad estimate.
                raise CheckpointError("provider reservation is absent")
            version, reserved_tokens, reserved_usd, prior_tokens, prior_usd = row
            settlement = _settlement(reserved_tokens, float(reserved_usd), actual_tokens, actual_usd)
            cumulative_tokens = int(prior_tokens or 0) + actual_tokens
            cumulative_usd = float(prior_usd or 0.0) + actual_usd
            uri = self.backend.artifacts.put_json(f"remediation-checkpoints/{self.execution_id.removeprefix('sha256:')}/{version + 1}.json", checkpoint)
            cursor.execute(
                """
                UPDATE remediation_service_executions
                SET checkpoint_version=checkpoint_version+1, checkpoint_artifact_uri=%s,
                    charged_tokens=charged_tokens-pending_reserved_tokens+%s,
                    charged_usd=charged_usd-pending_reserved_usd+%s,
                    actual_tokens=actual_tokens+%s, actual_usd=actual_usd+%s,
                    pending_call_sequence=NULL, pending_reserved_tokens=NULL, pending_reserved_usd=NULL, updated_at=now()
                WHERE execution_id=%s AND checkpoint_version=%s AND state='running'
                    AND lease_owner=%s AND lease_expires_at > now()
                """,
                (uri, actual_tokens, actual_usd, actual_tokens, actual_usd, self.execution_id, version, self.worker_id),
            )
            if cursor.rowcount != 1:
                raise CheckpointError("checkpoint fencing conflict")
        # The spend is settled and recorded before the cap is enforced, so a run stopped by the
        # cap still reports what it actually cost.
        if cumulative_tokens > self.max_tokens or cumulative_usd > self.max_usd:
            raise BudgetCapExceeded(settlement | _cap_context(cumulative_tokens, cumulative_usd, self.max_tokens, self.max_usd))
        return settlement

    async def save_completed_step(self, state: dict[str, Any]) -> None:
        import asyncio

        await asyncio.to_thread(self._save_completed_step, state)

    def _save_completed_step(self, state: dict[str, Any]) -> None:
        checkpoint = {**state, "pending_action": None}
        with psycopg.connect(self.backend.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET LOCAL app.remediation_worker = 'on'")
            cursor.execute("SELECT checkpoint_version FROM remediation_service_executions WHERE execution_id=%s FOR UPDATE", (self.execution_id,))
            row = cursor.fetchone()
            if row is None:
                raise CheckpointError("execution checkpoint row missing")
            version = row[0]
            uri = self.backend.artifacts.put_json(f"remediation-checkpoints/{self.execution_id.removeprefix('sha256:')}/{version + 1}.json", checkpoint)
            cursor.execute(
                """
                UPDATE remediation_service_executions SET checkpoint_version=checkpoint_version+1,
                    checkpoint_artifact_uri=%s, updated_at=now()
                WHERE execution_id=%s AND checkpoint_version=%s AND state='running'
                    AND lease_owner=%s AND lease_expires_at > now()
                """,
                (uri, self.execution_id, version, self.worker_id),
            )
            if cursor.rowcount != 1:
                raise CheckpointError("checkpoint fencing conflict")


LOCAL_BACKEND_WARNING = (
    "REMEDIATION_EXECUTION_BACKEND=local selects the development-only file-backed execution store. "
    "It has no managed encryption, no multi-host coordination, and no retention controls. "
    "Never enable it for production traffic."
)

MAX_WORKER_ATTEMPTS = 5

logger = logging.getLogger("mitig8it.remediation.executions")


class LocalArtifactStore:
    """Development-only content-addressed JSON store on the local filesystem."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def put_json(self, name: str, value: Any) -> str:
        raw = canonical_json(value)
        target = self.directory / name
        if any(part in {"", ".", ".."} for part in PurePosixPath(name).parts):
            raise ExecutionConflict("artifact name is unsafe")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != raw:
            raise ExecutionConflict("content-addressed artifact collision")
        temporary = target.with_name(target.name + f".{os.getpid()}.tmp")
        temporary.write_bytes(raw)
        os.replace(temporary, target)
        return f"file://{target}#{sha256_bytes(raw)}"

    def get_json(self, uri: str) -> Any:
        if not uri.startswith("file://") or "#sha256:" not in uri:
            raise ExecutionConflict("artifact URI is not a local artifact reference")
        path_text, expected = uri.removeprefix("file://").rsplit("#", 1)
        path = Path(path_text)
        if not path.is_file() or self.directory.resolve() not in path.resolve().parents:
            raise ExecutionConflict("artifact URI is outside the configured directory")
        raw = path.read_bytes()
        if sha256_bytes(raw) != expected:
            raise ExecutionConflict("artifact digest mismatch")
        return json.loads(raw)


class LocalExecutionBackend:
    """Development-only SQLite-backed execution store with the same lease semantics as Postgres.

    It implements the `ExecutionBackend` interface plus the worker's claim/heartbeat/complete
    operations so a local run exercises leases, fencing, retries, and dead-lettering. It must
    not be used in production: there is no managed key, tenant isolation, or retention control.
    """

    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.artifacts = LocalArtifactStore(self.directory / "artifacts")
        self.database_path = self.directory / "executions.sqlite3"
        self._lock = threading.Lock()
        self._initialize()
        logger.warning(LOCAL_BACKEND_WARNING)

    DEFAULT_DATA_DIR = "/var/lib/remediation"

    @classmethod
    def from_env(cls) -> "LocalExecutionBackend":
        """Resolves the development state directory.

        `REMEDIATION_LOCAL_STATE_DIR` is the explicit setting. `REMEDIATION_DATA_DIR` is the
        container's mounted data directory, which the image creates with the runtime UID's
        ownership, and is accepted so the compose stack does not need a second variable for
        the same path.
        """
        directory = os.getenv("REMEDIATION_LOCAL_STATE_DIR", "") or os.getenv("REMEDIATION_DATA_DIR", "")
        if not directory:
            raise ExecutionConfigurationError(
                "REMEDIATION_LOCAL_STATE_DIR or REMEDIATION_DATA_DIR is required for the local execution backend"
            )
        return cls(directory)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    repository_id TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL,
                    request_digest TEXT NOT NULL,
                    request_artifact_uri TEXT NOT NULL,
                    result_artifact_uri TEXT,
                    state TEXT NOT NULL,
                    attempt INTEGER NOT NULL DEFAULT 0,
                    lease_owner TEXT,
                    lease_expires_at REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    completed_at REAL,
                    checkpoint_version INTEGER NOT NULL DEFAULT 0,
                    checkpoint_artifact_uri TEXT,
                    charged_tokens INTEGER NOT NULL DEFAULT 0,
                    charged_usd REAL NOT NULL DEFAULT 0,
                    actual_tokens INTEGER NOT NULL DEFAULT 0,
                    actual_usd REAL NOT NULL DEFAULT 0,
                    pending_call_sequence INTEGER,
                    pending_reserved_tokens INTEGER,
                    pending_reserved_usd REAL,
                    dead_letter_reason TEXT,
                    trace_context TEXT,
                    UNIQUE (job_id, fencing_token)
                )
                """
            )
            # Idempotent forward migration for a state directory created before trace context
            # was persisted. SQLite has no ADD COLUMN IF NOT EXISTS.
            columns = {row[1] for row in connection.execute("PRAGMA table_info(executions)")}
            if "trace_context" not in columns:
                connection.execute("ALTER TABLE executions ADD COLUMN trace_context TEXT")

    @staticmethod
    def execution_identity(request: RepairRequest) -> tuple[str, str]:
        return PostgresExecutionBackend.execution_identity(request)

    @staticmethod
    def _record(row: Any) -> ExecutionRecord:
        return ExecutionRecord(row[0], row[1], row[2], row[3], row[4], row[5])

    def enqueue(self, request: RepairRequest, trace_context: str | None = None) -> ExecutionRecord:
        execution_id, request_digest = self.execution_identity(request)
        uri = self.artifacts.put_json(f"remediation-inputs/{execution_id.removeprefix('sha256:')}.json", request.model_dump(mode="json"))
        now = time.time()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT OR IGNORE INTO executions
                    (execution_id, job_id, tenant_id, repository_id, fencing_token, request_digest,
                     request_artifact_uri, state, created_at, updated_at, trace_context)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)
                """,
                (execution_id, request.job_id, request.tenant_id, request.repository_id, request.fencing_token, request_digest, uri, now, now, trace_context),
            )
            row = connection.execute(
                "SELECT execution_id, state, request_digest, request_artifact_uri, result_artifact_uri, trace_context FROM executions WHERE job_id=? AND fencing_token=?",
                (request.job_id, request.fencing_token),
            ).fetchone()
            connection.execute("COMMIT")
        if row is None or row[2] != request_digest:
            raise ExecutionConflict("job/fencing token was already used with a different request")
        return self._record(row)

    def get(self, execution_id: str) -> ExecutionRecord | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT execution_id, state, request_digest, request_artifact_uri, result_artifact_uri, trace_context FROM executions WHERE execution_id=?",
                (execution_id,),
            ).fetchone()
        return self._record(row) if row else None

    def read_result(self, record: ExecutionRecord) -> RepairResponse:
        if not record.result_artifact_uri:
            raise ExecutionConflict("terminal execution has no result artifact")
        return RepairResponse.model_validate(self.artifacts.get_json(record.result_artifact_uri))

    def read_request(self, record: ExecutionRecord) -> RepairRequest:
        return RepairRequest.model_validate(self.artifacts.get_json(record.request_artifact_uri))

    def cancel(self, execution_id: str) -> bool:
        now = time.time()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE executions SET state='cancelled', lease_owner=NULL, lease_expires_at=NULL, completed_at=?, updated_at=? WHERE execution_id=? AND state IN ('queued','running')",
                (now, now, execution_id),
            )
            changed = cursor.rowcount == 1
            row = connection.execute("SELECT state FROM executions WHERE execution_id=?", (execution_id,)).fetchone()
            connection.execute("COMMIT")
        return changed or bool(row and row[0] == "cancelled")

    def claim(self, worker_id: str, lease_seconds: int = 60) -> ExecutionRecord | None:
        now = time.time()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE executions
                SET state='failed', lease_owner=NULL, lease_expires_at=NULL, completed_at=?, updated_at=?,
                    dead_letter_reason='worker_attempts_exhausted'
                WHERE attempt >= ? AND (state='queued' OR (state='running' AND lease_expires_at < ?))
                """,
                (now, now, MAX_WORKER_ATTEMPTS, now),
            )
            row = connection.execute(
                """
                SELECT execution_id FROM executions
                WHERE attempt < ? AND (state='queued' OR (state='running' AND lease_expires_at < ?))
                ORDER BY created_at LIMIT 1
                """,
                (MAX_WORKER_ATTEMPTS, now),
            ).fetchone()
            claimed = None
            if row is not None:
                connection.execute(
                    "UPDATE executions SET state='running', lease_owner=?, lease_expires_at=?, attempt=attempt+1, updated_at=? WHERE execution_id=?",
                    (worker_id, now + lease_seconds, now, row[0]),
                )
                claimed = connection.execute(
                    "SELECT execution_id, state, request_digest, request_artifact_uri, result_artifact_uri, trace_context FROM executions WHERE execution_id=?",
                    (row[0],),
                ).fetchone()
            connection.execute("COMMIT")
        return self._record(claimed) if claimed else None

    def heartbeat(self, execution_id: str, worker_id: str, lease_seconds: int = 60) -> bool:
        now = time.time()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE executions SET lease_expires_at=?, updated_at=? WHERE execution_id=? AND state='running' AND lease_owner=? AND lease_expires_at > ?",
                (now + lease_seconds, now, execution_id, worker_id, now),
            )
            changed = cursor.rowcount == 1
            connection.execute("COMMIT")
        return changed

    def complete(self, execution_id: str, worker_id: str, result: RepairResponse) -> bool:
        uri = self.artifacts.put_json(
            f"remediation-results/{execution_id.removeprefix('sha256:')}-{result.manifest_digest or result.state}.json",
            result.model_dump(mode="json"),
        )
        now = time.time()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE executions SET state=?, result_artifact_uri=?, lease_owner=NULL, lease_expires_at=NULL,
                    completed_at=?, updated_at=?
                WHERE execution_id=? AND state='running' AND lease_owner=? AND lease_expires_at > ?
                """,
                (result.state, uri, now, now, execution_id, worker_id, now),
            )
            changed = cursor.rowcount == 1
            connection.execute("COMMIT")
        return changed


class LocalCheckpointStore:
    """Development-only checkpoint/reservation store with the Postgres fencing semantics."""

    def __init__(self, backend: LocalExecutionBackend, execution_id: str, worker_id: str, request: RepairRequest):
        self.backend = backend
        self.execution_id = execution_id
        self.worker_id = worker_id
        self.max_tokens = request.policy.max_total_tokens
        self.max_usd = request.policy.max_spend_usd

    async def load(self) -> dict[str, Any] | None:
        return await asyncio.to_thread(self._load)

    def _load(self) -> dict[str, Any] | None:
        with self.backend._lock, self.backend._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT checkpoint_artifact_uri, pending_call_sequence FROM executions WHERE execution_id=? AND state='running' AND lease_owner=? AND lease_expires_at > ?",
                (self.execution_id, self.worker_id, time.time()),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                raise CheckpointError("execution lease is no longer valid")
            if row[1] is not None:
                connection.execute(
                    "UPDATE executions SET pending_call_sequence=NULL, pending_reserved_tokens=NULL, pending_reserved_usd=NULL WHERE execution_id=?",
                    (self.execution_id,),
                )
            connection.execute("COMMIT")
        return self.backend.artifacts.get_json(row[0]) if row[0] else None

    async def reserve_provider_call(self, sequence: int, tokens: int, usd: float) -> bool:
        return await asyncio.to_thread(self._reserve_provider_call, sequence, tokens, usd)

    def _reserve_provider_call(self, sequence: int, tokens: int, usd: float) -> bool:
        now = time.time()
        with self.backend._lock, self.backend._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE executions
                SET charged_tokens=charged_tokens+?, charged_usd=charged_usd+?,
                    pending_call_sequence=?, pending_reserved_tokens=?, pending_reserved_usd=?, updated_at=?
                WHERE execution_id=? AND state='running' AND lease_owner=? AND lease_expires_at > ?
                    AND pending_call_sequence IS NULL
                    AND charged_tokens+? <= ? AND charged_usd+? <= ?
                """,
                (tokens, usd, sequence, tokens, usd, now, self.execution_id, self.worker_id, now, tokens, self.max_tokens, usd, self.max_usd),
            )
            reserved = cursor.rowcount == 1
            connection.execute("COMMIT")
        return reserved

    async def save_provider_action(self, state: dict[str, Any], action: ProviderAction, actual_tokens: int, actual_usd: float) -> dict[str, Any]:
        return await asyncio.to_thread(self._save_provider_action, state, action, actual_tokens, actual_usd)

    def _save_provider_action(self, state: dict[str, Any], action: ProviderAction, actual_tokens: int, actual_usd: float) -> dict[str, Any]:
        checkpoint = {
            **state,
            "pending_action": {
                "name": action.name,
                "arguments": action.arguments,
                "call_id": action.call_id,
                "request_id": action.request_id,
                "input_tokens": action.input_tokens,
                "output_tokens": action.output_tokens,
            },
        }
        now = time.time()
        with self.backend._lock, self.backend._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT checkpoint_version, pending_reserved_tokens, pending_reserved_usd, actual_tokens, actual_usd"
                " FROM executions WHERE execution_id=?",
                (self.execution_id,),
            ).fetchone()
            if row is None or row[1] is None:
                connection.execute("COMMIT")
                # No reservation to settle against means the call was never announced, which is a
                # protocol violation rather than a bad estimate.
                raise CheckpointError("provider reservation is absent")
            version = row[0]
            settlement = _settlement(row[1], float(row[2]), actual_tokens, actual_usd)
            cumulative_tokens = int(row[3] or 0) + actual_tokens
            cumulative_usd = float(row[4] or 0.0) + actual_usd
            uri = self.backend.artifacts.put_json(
                f"remediation-checkpoints/{self.execution_id.removeprefix('sha256:')}/{version + 1}.json", checkpoint
            )
            cursor = connection.execute(
                """
                UPDATE executions
                SET checkpoint_version=checkpoint_version+1, checkpoint_artifact_uri=?,
                    charged_tokens=charged_tokens-pending_reserved_tokens+?,
                    charged_usd=charged_usd-pending_reserved_usd+?,
                    actual_tokens=actual_tokens+?, actual_usd=actual_usd+?,
                    pending_call_sequence=NULL, pending_reserved_tokens=NULL, pending_reserved_usd=NULL, updated_at=?
                WHERE execution_id=? AND checkpoint_version=? AND state='running' AND lease_owner=? AND lease_expires_at > ?
                """,
                (uri, actual_tokens, actual_usd, actual_tokens, actual_usd, now, self.execution_id, version, self.worker_id, now),
            )
            changed = cursor.rowcount == 1
            connection.execute("COMMIT")
        if not changed:
            raise CheckpointError("checkpoint fencing conflict")
        # The spend is settled and recorded before the cap is enforced, so a run stopped by the
        # cap still reports what it actually cost.
        if cumulative_tokens > self.max_tokens or cumulative_usd > self.max_usd:
            raise BudgetCapExceeded(settlement | _cap_context(cumulative_tokens, cumulative_usd, self.max_tokens, self.max_usd))
        return settlement

    async def save_completed_step(self, state: dict[str, Any]) -> None:
        await asyncio.to_thread(self._save_completed_step, state)

    def _save_completed_step(self, state: dict[str, Any]) -> None:
        checkpoint = {**state, "pending_action": None}
        now = time.time()
        with self.backend._lock, self.backend._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT checkpoint_version FROM executions WHERE execution_id=?", (self.execution_id,)).fetchone()
            if row is None:
                connection.execute("COMMIT")
                raise CheckpointError("execution checkpoint row missing")
            version = row[0]
            uri = self.backend.artifacts.put_json(
                f"remediation-checkpoints/{self.execution_id.removeprefix('sha256:')}/{version + 1}.json", checkpoint
            )
            cursor = connection.execute(
                """
                UPDATE executions SET checkpoint_version=checkpoint_version+1, checkpoint_artifact_uri=?, updated_at=?
                WHERE execution_id=? AND checkpoint_version=? AND state='running' AND lease_owner=? AND lease_expires_at > ?
                """,
                (uri, now, self.execution_id, version, self.worker_id, now),
            )
            changed = cursor.rowcount == 1
            connection.execute("COMMIT")
        if not changed:
            raise CheckpointError("checkpoint fencing conflict")


def selected_backend_kind() -> str:
    kind = os.getenv("REMEDIATION_EXECUTION_BACKEND", "postgres").strip().lower() or "postgres"
    if kind not in {"local", "postgres"}:
        raise ExecutionConfigurationError("REMEDIATION_EXECUTION_BACKEND must be 'postgres' or 'local'")
    return kind


def create_execution_backend() -> PostgresExecutionBackend | LocalExecutionBackend:
    """Production default is Postgres. The local backend is development only."""
    if selected_backend_kind() == "local":
        return LocalExecutionBackend.from_env()
    return PostgresExecutionBackend.from_env()


def create_checkpoint_store(
    backend: PostgresExecutionBackend | LocalExecutionBackend,
    execution_id: str,
    worker_id: str,
    request: RepairRequest,
) -> ExecutionCheckpointStore | LocalCheckpointStore:
    if isinstance(backend, LocalExecutionBackend):
        return LocalCheckpointStore(backend, execution_id, worker_id, request)
    return ExecutionCheckpointStore(backend, execution_id, worker_id, request)
