"""The Cloud Run job driver against fake Cloud Run and GCS clients.

The fakes are deliberately thin: they record what the driver asked for and let a test decide
what the job "wrote back". Everything between those two points, including the real
`google.cloud.run_v2` override protos, is the code under test.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import types
from datetime import datetime, timezone

import pytest

from src.sandbox.cloud_run_job_driver import (
    CloudRunJobConfigurationError,
    CloudRunJobDriver,
    CloudRunJobDriverConfig,
    pack_tree,
)
from src.sandbox.job_entrypoint import (
    ENV_CHECK,
    ENV_NONCE,
    ENV_RESULT_BUCKET,
    ENV_RESULT_PREFIX,
    ENV_SNAPSHOT_BUCKET,
    ENV_SNAPSHOT_MANIFEST,
    PROBES,
    VARIANTS,
    sign_result,
)

IMAGE_DIGEST = "us-central1-docker.pkg.dev/p/r/remediation-job@sha256:" + "a" * 64
SOURCE = "export function loadUser(db, id) {\n  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n}\n"
REPAIRED = "export function loadUser(db, id) {\n  return db.query('SELECT * FROM users WHERE id = $1', [id]);\n}\n"


def sha256_of(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def payload(commands: list[dict] | None = None) -> dict:
    return {
        "request_digest": "sha256:" + "d" * 64,
        "snapshot": [
            {"path": "src/db.ts", "content": SOURCE},
            {"path": "package.json", "content": '{"name":"widget"}\n'},
        ],
        "patches": [
            {
                "path": "src/db.ts",
                "base_sha256": sha256_of(SOURCE),
                "new_sha256": sha256_of(REPAIRED),
                "replacement_content": REPAIRED,
            }
        ],
        "execution_policy": {
            "commands": commands
            if commands is not None
            else [{"check_id": "exploit", "kind": "exploit", "argv": ["node", "t.js"], "timeout_seconds": 60}],
            "deadline_seconds": 300,
        },
    }


def settings(**overrides) -> CloudRunJobDriverConfig:
    base = {
        "job_name": "sandbox",
        "region": "us-central1",
        "project": "proj",
        "snapshot_bucket": "snap",
        "result_bucket": "res",
        "image_digest": IMAGE_DIGEST,
        "poll_interval_seconds": 0.001,
    }
    base.update(overrides)
    return CloudRunJobDriverConfig(**base)


# -- fakes ---------------------------------------------------------------------------------


class FakeBlob:
    def __init__(self, store: dict, key: tuple[str, str]):
        self._store, self._key = store, key

    def upload_from_string(self, body, content_type=None):  # noqa: ARG002 - matches the real signature.
        self._store[self._key] = body if isinstance(body, bytes) else body.encode("utf-8")

    def download_as_bytes(self):
        if self._key not in self._store:
            raise FileNotFoundError(self._key[1])
        return self._store[self._key]

    def delete(self):
        self._store.pop(self._key, None)


class FakeBucket:
    def __init__(self, store: dict, name: str):
        self._store, self._name = store, name

    def blob(self, name: str) -> FakeBlob:
        return FakeBlob(self._store, (self._name, name))


class FakeStorage:
    def __init__(self):
        self.objects: dict[tuple[str, str], bytes] = {}

    def bucket(self, name: str) -> FakeBucket:
        return FakeBucket(self.objects, name)


class FakeJobs:
    """Runs `responder` the moment the driver starts an execution, as a real job eventually does."""

    def __init__(self, responder):
        self.responder, self.started = responder, []

    def run_job(self, request):
        name = f"{request.name}/executions/exec-{len(self.started) + 1}"
        env = {item.name: item.value for item in request.overrides.container_overrides[0].env}
        self.started.append({"name": name, "env": env, "task_count": request.overrides.task_count})
        self.responder(name, env)
        return types.SimpleNamespace(metadata=types.SimpleNamespace(name=name))


class FakeExecutions:
    def __init__(self, finished: bool = True):
        self.finished, self.cancelled = finished, []

    def get_execution(self, name):  # noqa: ARG002 - the fake has one execution state.
        return types.SimpleNamespace(completion_time=datetime.now(timezone.utc) if self.finished else None)

    def cancel_execution(self, name):
        self.cancelled.append(name)


def denied_probes() -> dict:
    return {probe["target"]: {"reached": False, "detail": "TimeoutError", "endpoint": probe["endpoint"]} for probe in PROBES}


def task_result(env: dict, variant: str, execution: str, *, exit_code: int, probes=None, image=IMAGE_DIGEST, **extra) -> dict:
    check = json.loads(env[ENV_CHECK])
    return {
        "schema_version": "v1",
        "check_id": check["check_id"],
        "kind": check["kind"],
        "argv": list(check["argv"]),
        "variant": variant,
        "completed": True,
        "timed_out": False,
        "exit_code": exit_code,
        "output": "check output\n",
        "output_truncated": False,
        "duration_ms": 12,
        "probes": denied_probes() if probes is None else probes,
        "runner": {"job_execution": execution, "task_index": VARIANTS.index(variant), "image_digest": image,
                   "environment_kind": "cloud-run-job"},
        **extra,
    }


def passing_pair(env: dict, variant: str, execution: str) -> dict:
    """An exploit check that failed on the original tree and passed on the patched one."""
    return task_result(env, variant, execution, exit_code=1 if variant == "baseline" else 0)


def responder(storage: FakeStorage, *, nonce=None, documents=passing_pair):
    """Writes one signed result object per variant, the way a finished task pair would."""

    def respond(execution: str, env: dict):
        for variant in VARIANTS:
            document = documents(env, variant, execution)
            key = (env[ENV_RESULT_BUCKET], f"{env[ENV_RESULT_PREFIX]}/{variant}.json")
            storage.objects[key] = sign_result(document, nonce or env[ENV_NONCE])

    return respond


def driver_with(storage: FakeStorage, jobs: FakeJobs, executions: FakeExecutions | None = None, **config) -> CloudRunJobDriver:
    return CloudRunJobDriver(
        settings(**config), jobs_client=jobs, executions_client=executions or FakeExecutions(), storage_client=storage
    )


# -- configuration -------------------------------------------------------------------------


def test_configuration_names_every_missing_variable(monkeypatch):
    for name in ("SANDBOX_JOB_NAME", "SANDBOX_JOB_REGION", "SANDBOX_JOB_PROJECT", "SANDBOX_BUCKET", "SANDBOX_IMAGE_DIGEST"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(CloudRunJobConfigurationError) as failure:
        CloudRunJobDriverConfig.from_env()
    assert "SANDBOX_BUCKET" in str(failure.value) and "SANDBOX_IMAGE_DIGEST" in str(failure.value)


def test_configuration_defaults_the_results_bucket_and_the_timeouts(monkeypatch):
    monkeypatch.setenv("SANDBOX_JOB_NAME", "sandbox")
    monkeypatch.setenv("SANDBOX_JOB_REGION", "us-central1")
    monkeypatch.setenv("SANDBOX_JOB_PROJECT", "proj")
    monkeypatch.setenv("SANDBOX_BUCKET", "mitig8it-sandbox-snapshots")
    monkeypatch.setenv("SANDBOX_IMAGE_DIGEST", IMAGE_DIGEST)
    monkeypatch.delenv("SANDBOX_RESULTS_BUCKET", raising=False)
    monkeypatch.delenv("SANDBOX_JOB_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("SANDBOX_JOB_POLL_INTERVAL_SECONDS", raising=False)
    config = CloudRunJobDriverConfig.from_env()
    # The Terraform module creates `<prefix>-snapshots` and `<prefix>-results`, so the default
    # replaces the suffix. `<prefix>-snapshots-results` would be a bucket nobody created, and
    # the mistake would surface as every result being unavailable rather than as a bad config.
    assert config.snapshot_bucket == "mitig8it-sandbox-snapshots"
    assert config.result_bucket == "mitig8it-sandbox-results"
    assert config.task_timeout_seconds == 300 and config.poll_interval_seconds == 2.0
    assert config.job_path == "projects/proj/locations/us-central1/jobs/sandbox"


def test_an_explicit_results_bucket_overrides_the_paired_default(monkeypatch):
    monkeypatch.setenv("SANDBOX_JOB_NAME", "sandbox")
    monkeypatch.setenv("SANDBOX_JOB_REGION", "us-central1")
    monkeypatch.setenv("SANDBOX_JOB_PROJECT", "proj")
    monkeypatch.setenv("SANDBOX_IMAGE_DIGEST", IMAGE_DIGEST)
    monkeypatch.setenv("SANDBOX_BUCKET", "unpaired-name")
    monkeypatch.delenv("SANDBOX_RESULTS_BUCKET", raising=False)
    assert CloudRunJobDriverConfig.from_env().result_bucket == "unpaired-name-results"
    monkeypatch.setenv("SANDBOX_RESULTS_BUCKET", "somewhere-else")
    assert CloudRunJobDriverConfig.from_env().result_bucket == "somewhere-else"


# -- packaging -----------------------------------------------------------------------------


def test_packaging_is_byte_for_byte_deterministic():
    assert pack_tree(payload(), "baseline") == pack_tree(payload(), "baseline")
    assert pack_tree(payload(), "baseline") != pack_tree(payload(), "candidate")


def test_packaging_carries_the_candidate_patch_and_nothing_else():
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(pack_tree(payload(), "candidate"))), mode="r:") as bundle:
        names = sorted(bundle.getnames())
        body = bundle.extractfile("src/db.ts").read().decode("utf-8")
        modes = {member.mode for member in bundle.getmembers()}
        times = {member.mtime for member in bundle.getmembers()}
    assert names == ["package.json", "src/db.ts"]
    assert body == REPAIRED
    assert modes == {0o644} and times == {0}


def test_packaging_refuses_a_snapshot_path_that_escapes_the_workspace():
    escaping = payload()
    escaping["snapshot"] = [{"path": "../outside.ts", "content": "x"}]
    escaping["patches"] = []
    with pytest.raises(ValueError):
        pack_tree(escaping, "baseline")


def test_packaging_refuses_a_patch_whose_base_digest_does_not_match():
    tampered = payload()
    tampered["patches"][0]["base_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        pack_tree(tampered, "candidate")


# -- the happy path ------------------------------------------------------------------------


def test_a_denied_sandbox_produces_passing_evidence_and_a_full_runner_identity():
    storage = FakeStorage()
    jobs = FakeJobs(responder(storage))
    driver = driver_with(storage, jobs)
    request = payload()

    result = driver.execute(request, 300)

    assert result["outcome"] == "passed"
    check = result["checks"][0]
    assert check["baseline"]["status"] == "failed" and check["candidate"]["status"] == "passed"
    assert check["candidate"]["exit_code"] == 0 and check["candidate"]["completed"] is True
    assert check["candidate"]["job_execution"] == jobs.started[0]["name"]
    assert all(check["candidate"]["network_probes"][probe["target"]]["reached"] is False for probe in PROBES)

    identity = driver.runner_identity(request)
    assert identity["network"] == "deny"
    assert identity["image_digest"] == IMAGE_DIGEST
    assert identity["environment_kind"] == "cloud-run-job"
    assert identity["read_only_root"] is False
    assert identity["job_executions"] == [jobs.started[0]["name"]]


def test_one_execution_of_two_tasks_per_check_carries_the_overrides_the_entrypoint_reads():
    storage = FakeStorage()
    jobs = FakeJobs(responder(storage))
    driver_with(storage, jobs).execute(payload(), 300)

    started = jobs.started[0]
    assert len(jobs.started) == 1, "one execution per check, not one per variant"
    assert started["task_count"] == 2, "one task per variant, so the two halves never share a container"
    manifest = json.loads(started["env"][ENV_SNAPSHOT_MANIFEST])
    assert sorted(manifest) == ["baseline", "candidate"]
    assert started["env"][ENV_SNAPSHOT_BUCKET] == "snap"
    assert len(started["env"][ENV_NONCE]) == 64
    for variant, entry in manifest.items():
        assert entry["sha256"] == f"sha256:{hashlib.sha256(pack_tree(payload(), variant)).hexdigest()}"


def test_snapshot_objects_are_removed_when_the_verification_ends():
    storage = FakeStorage()
    driver_with(storage, FakeJobs(responder(storage))).execute(payload(), 300)
    assert not [key for key in storage.objects if key[0] == "snap"]


def test_two_checks_start_two_executions_and_both_are_named_in_the_identity():
    storage = FakeStorage()
    jobs = FakeJobs(responder(storage))
    driver = driver_with(storage, jobs)
    request = payload(
        [
            {"check_id": "exploit", "kind": "exploit", "argv": ["node", "e.js"], "timeout_seconds": 60},
            {"check_id": "behavior", "kind": "behavior", "argv": ["node", "b.js"], "timeout_seconds": 60},
        ]
    )
    result = driver.execute(request, 300)
    assert [check["check_id"] for check in result["checks"]] == ["exploit", "behavior"]
    assert driver.runner_identity(request)["job_executions"] == [item["name"] for item in jobs.started]


# -- the refusals --------------------------------------------------------------------------


def test_a_result_signed_with_another_nonce_is_not_evidence():
    storage = FakeStorage()
    driver = driver_with(storage, FakeJobs(responder(storage, nonce="f" * 64)))
    request = payload()

    result = driver.execute(request, 300)

    assert result["outcome"] == "inconclusive"
    check = result["checks"][0]
    assert check["baseline"]["reason_code"] == "sandbox_result_unavailable"
    assert check["candidate"]["completed"] is False
    assert check["candidate"]["exit_code"] is None
    # No task result survived, so nothing measured a probe and nothing is claimed about one.
    assert check["candidate"]["network_probes"] == {}


def test_a_result_naming_another_check_is_not_evidence():
    storage = FakeStorage()

    def documents(env, variant, execution):
        record = task_result(env, variant, execution, exit_code=0)
        record["check_id"] = "some-other-check"
        return record

    driver = driver_with(storage, FakeJobs(responder(storage, documents=documents)))
    result = driver.execute(payload(), 300)
    assert result["outcome"] == "inconclusive"
    assert result["checks"][0]["candidate"]["reason_code"] == "sandbox_result_mismatched"


def test_an_image_digest_the_deployment_did_not_pin_ends_the_verification():
    storage = FakeStorage()

    def documents(env, variant, execution):
        return task_result(env, variant, execution, exit_code=0, image=IMAGE_DIGEST.replace("a" * 64, "b" * 64))

    driver = driver_with(storage, FakeJobs(responder(storage, documents=documents)))
    request = payload()

    result = driver.execute(request, 300)

    assert result == {"outcome": "inconclusive", "reason_code": "sandbox_image_digest_mismatch", "checks": []}
    identity = driver.runner_identity(request)
    assert identity["image_digest"] is None and identity["network"] == "unknown"


def test_a_task_that_could_not_read_its_image_digest_ends_the_verification():
    storage = FakeStorage()

    def documents(env, variant, execution):
        return task_result(env, variant, execution, exit_code=0, image=None)

    result = driver_with(storage, FakeJobs(responder(storage, documents=documents))).execute(payload(), 300)
    assert result["reason_code"] == "sandbox_image_digest_mismatch" and result["checks"] == []


@pytest.mark.parametrize("target", ["metadata", "internet", "dns"])
def test_a_probe_that_reached_its_target_ends_the_verification(target):
    storage = FakeStorage()

    def documents(env, variant, execution):
        probes = denied_probes()
        probes[target] = {"reached": True, "detail": "connected", "endpoint": probes[target]["endpoint"]}
        return task_result(env, variant, execution, exit_code=0, probes=probes)

    driver = driver_with(storage, FakeJobs(responder(storage, documents=documents)))
    request = payload()

    result = driver.execute(request, 300)

    assert result == {"outcome": "inconclusive", "reason_code": "sandbox_network_not_denied", "checks": []}
    assert driver.runner_identity(request)["network"] == "unknown"


def test_a_probe_that_could_not_run_is_refused_exactly_like_one_that_connected():
    storage = FakeStorage()

    def documents(env, variant, execution):
        probes = denied_probes()
        probes["dns"] = {"reached": None, "detail": "probe_failed:OSError", "endpoint": None}
        return task_result(env, variant, execution, exit_code=0, probes=probes)

    result = driver_with(storage, FakeJobs(responder(storage, documents=documents))).execute(payload(), 300)
    assert result["reason_code"] == "sandbox_network_not_denied"


def test_a_check_that_timed_out_keeps_its_reason_and_never_reads_as_a_pass():
    storage = FakeStorage()

    def documents(env, variant, execution):
        if variant == "baseline":
            return task_result(env, variant, execution, exit_code=1)
        record = task_result(env, variant, execution, exit_code=0)
        record.update({"completed": False, "timed_out": True, "exit_code": None, "output": "",
                       "reason_code": "check_timed_out", "duration_ms": 60000})
        return record

    result = driver_with(storage, FakeJobs(responder(storage, documents=documents))).execute(payload(), 300)
    assert result["outcome"] == "inconclusive"
    candidate = result["checks"][0]["candidate"]
    assert candidate["completed"] is False and candidate["reason_code"] == "check_timed_out"
    assert candidate["duration_ms"] == 60000


def test_an_execution_that_never_finished_is_inconclusive_and_names_its_execution():
    storage = FakeStorage()
    jobs = FakeJobs(lambda execution, env: None)
    driver = driver_with(storage, jobs, FakeExecutions(finished=False))
    result = driver.execute(payload([{"check_id": "exploit", "kind": "exploit", "argv": ["node", "t.js"], "timeout_seconds": 1}]), 1)
    assert result["outcome"] == "inconclusive"
    assert result["checks"][0]["candidate"]["reason_code"] == "check_deadline_exceeded"
    assert result["checks"][0]["candidate"]["job_execution"] == jobs.started[0]["name"]


def test_a_check_past_the_deadline_never_starts_an_execution():
    storage = FakeStorage()
    jobs = FakeJobs(responder(storage))
    result = driver_with(storage, jobs).execute(payload(), 0)
    assert jobs.started == []
    assert result["checks"][0]["baseline"]["reason_code"] == "job_deadline_exceeded"


def test_an_unstarted_driver_reports_an_unknown_runner_rather_than_a_denied_one():
    identity = driver_with(FakeStorage(), FakeJobs(lambda execution, env: None)).runner_identity({"request_digest": "sha256:zz"})
    assert identity["network"] == "unknown" and identity["image_digest"] is None and identity["job_executions"] == []


# -- cancellation --------------------------------------------------------------------------


def test_cancel_stops_the_in_flight_executions_and_drops_the_snapshots():
    storage = FakeStorage()
    executions = FakeExecutions(finished=False)
    started: list[str] = []
    jobs = FakeJobs(lambda execution, env: started.append(execution))
    driver = driver_with(storage, jobs, executions)
    digest = "sha256:" + "d" * 64

    # An execution that is still running when the driver's own budget runs out stays tracked
    # until `execute` returns, so `cancel` during the run has a name to cancel.
    driver._in_flight[digest] = ["projects/p/locations/r/jobs/j/executions/exec-1"]
    storage.objects[("snap", f"snapshots/{digest.removeprefix('sha256:')[:20]}/baseline.tar.gz")] = b"x"

    driver.cancel(digest)

    assert executions.cancelled == ["projects/p/locations/r/jobs/j/executions/exec-1"]
    assert storage.objects == {}
