"""The `isolated_job` verification level, end to end through the real Verifier.

The driver under test here is a stand-in: it runs the check pair through the local subprocess
driver, so the baseline/candidate results are real, and then dresses each result the way the
Cloud Run job driver does. That keeps these tests about the one thing they are for, which is
what the verifier accepts as this level and what it refuses, rather than about Cloud Run.
"""
from __future__ import annotations

import sys
from typing import Any

import pytest

from src.models import RepairRequest
from src.patches import build_patch_bundle
from src.retrieval import Snapshot
from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver
from src.verification import Verifier
from src.verification.verifier import (
    DEVELOPMENT_VERIFICATION_LEVEL,
    ISOLATED_JOB_VERIFICATION_LEVEL,
    PRODUCTION_VERIFICATION_LEVEL,
    VERIFICATION_LEVEL_ORDER,
    VERIFICATION_LEVELS,
)
from tests.conftest import whole_file_change

IMAGE_DIGEST = "us-central1-docker.pkg.dev/p/r/remediation-job@sha256:" + "a" * 64
EXECUTION = "projects/p/locations/us-central1/jobs/sandbox/executions/exec-1"
REPAIRED = "export function loadUser(db, id) {\n  return db.query('SELECT * FROM users WHERE id = $1', [id]);\n}\n"

EXPLOIT = [sys.executable, "-c", "import pathlib,sys; sys.exit(1 if '${id}' in pathlib.Path('src/db.ts').read_text() else 0)"]
BEHAVIOR = [sys.executable, "-c", "import pathlib,sys; sys.exit(0 if 'loadUser' in pathlib.Path('src/db.ts').read_text() else 1)"]
CHECKS = [
    {"check_id": "exploit", "kind": "exploit", "argv": EXPLOIT, "timeout_seconds": 60},
    {"check_id": "behavior", "kind": "behavior", "argv": BEHAVIOR, "timeout_seconds": 60},
]


def denied_probes() -> dict[str, Any]:
    return {
        target: {"reached": False, "detail": "TimeoutError", "endpoint": "x"}
        for target in ("metadata", "internet", "dns")
    }


class FakeIsolatedJobDriver:
    """Real check results, labelled and dressed the way `CloudRunJobDriver` labels and dresses them."""

    verification_class = ISOLATED_JOB_VERIFICATION_LEVEL
    verification_level = ISOLATED_JOB_VERIFICATION_LEVEL

    def __init__(
        self,
        *,
        image_digest: str | None = IMAGE_DIGEST,
        probes: dict[str, Any] | None = None,
        network: str = "deny",
        environment_kind: str = "cloud-run-job",
        executions: list[str] | None = None,
        per_check_execution: str | None = EXECUTION,
        halt: dict[str, Any] | None = None,
    ):
        self._inner = LocalSubprocessDriver()
        self._image_digest = image_digest
        self._probes = denied_probes() if probes is None else probes
        self._network = network
        self._environment_kind = environment_kind
        self._executions = [EXECUTION] if executions is None else executions
        self._per_check_execution = per_check_execution
        self._halt = halt

    def execute(self, payload: dict[str, Any], deadline_seconds: int) -> dict[str, Any]:
        if self._halt is not None:
            return self._halt
        result = self._inner.execute(payload, deadline_seconds)
        for record in result.get("checks", []):
            for variant in ("baseline", "candidate"):
                outcome = record.get(variant)
                if isinstance(outcome, dict):
                    outcome["network_probes"] = self._probes
                    if self._per_check_execution is not None:
                        outcome["job_execution"] = self._per_check_execution
        return result

    def runner_identity(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "image_digest": self._image_digest,
            "network": self._network,
            "read_only_root": False,
            "runtime_class": self._environment_kind,
            "environment_kind": self._environment_kind,
            "job_executions": self._executions,
        }

    def cancel(self, request_digest: str) -> None:
        return None


def isolated_request(request_payload, source, *, allow=True, image_digest=IMAGE_DIGEST):
    request_payload["policy"]["sandbox_image_digest"] = image_digest
    request_payload["policy"]["allow_development_verification"] = False
    request_payload["policy"]["allow_isolated_job_verification"] = allow
    request_payload["policy"]["verification_checks"] = CHECKS
    request_payload["policy"]["require_generated_regression_test"] = False
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    bundle = build_patch_bundle(request, snapshot, [whole_file_change("src/db.ts", source, REPAIRED)], [])
    return request, snapshot, bundle


async def verify_with(driver, request_payload, source, **kwargs):
    request, snapshot, bundle = isolated_request(request_payload, source, **kwargs)
    return await Verifier(InProcessSandboxBroker(driver)).verify(request, snapshot, bundle)


# -- the level itself ------------------------------------------------------------------------


def test_the_level_sits_between_development_and_the_production_sandbox():
    assert VERIFICATION_LEVEL_ORDER == (
        DEVELOPMENT_VERIFICATION_LEVEL,
        ISOLATED_JOB_VERIFICATION_LEVEL,
        PRODUCTION_VERIFICATION_LEVEL,
    )
    assert ISOLATED_JOB_VERIFICATION_LEVEL in VERIFICATION_LEVELS
    assert ISOLATED_JOB_VERIFICATION_LEVEL == "isolated_job"


def test_the_policy_flag_defaults_to_allowing_the_level(request_payload):
    request_payload["policy"].pop("allow_isolated_job_verification", None)
    assert RepairRequest.model_validate(request_payload).policy.allow_isolated_job_verification is True
    assert RepairRequest.model_validate(request_payload).policy.allow_development_verification is False


# -- what the level is accepted as --------------------------------------------------------------


@pytest.mark.asyncio
async def test_measured_isolation_is_accepted_and_labelled_isolated_job(request_payload, source):
    result = await verify_with(FakeIsolatedJobDriver(), request_payload, source)

    assert result.status == "passed"
    assert result.verification_level == ISOLATED_JOB_VERIFICATION_LEVEL
    assert result.evidence["runner"]["environment_kind"] == "cloud-run-job"
    assert result.evidence["runner"]["job_executions"] == [EXECUTION]
    assert result.evidence["runner"]["read_only_root"] is False


@pytest.mark.asyncio
async def test_the_level_states_its_own_limitation_and_not_the_development_caveat(request_payload, source):
    result = await verify_with(FakeIsolatedJobDriver(), request_payload, source)

    assert any("read-only root" in item and "gVisor" in item for item in result.limitations)
    assert not any("development local sandbox" in item for item in result.limitations)


@pytest.mark.asyncio
async def test_the_level_is_refused_when_policy_does_not_allow_it(request_payload, source):
    result = await verify_with(FakeIsolatedJobDriver(), request_payload, source, allow=False)

    assert result.status == "unsupported"
    assert result.reason_code == "isolated_job_verification_not_permitted"
    assert result.verification_level == ISOLATED_JOB_VERIFICATION_LEVEL


# -- what the level is refused for ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_image_digest_that_is_not_the_pinned_one_is_not_this_level(request_payload, source):
    driver = FakeIsolatedJobDriver(image_digest=IMAGE_DIGEST.replace("a" * 64, "b" * 64))
    result = await verify_with(driver, request_payload, source)
    assert result.status == "inconclusive" and result.reason_code == "sandbox_evidence_invalid"


@pytest.mark.asyncio
async def test_evidence_that_names_no_job_execution_is_not_this_level(request_payload, source):
    result = await verify_with(FakeIsolatedJobDriver(executions=[]), request_payload, source)
    assert result.reason_code == "sandbox_evidence_invalid"


@pytest.mark.asyncio
async def test_evidence_from_something_other_than_a_cloud_run_job_is_not_this_level(request_payload, source):
    result = await verify_with(FakeIsolatedJobDriver(environment_kind="local-subprocess"), request_payload, source)
    assert result.reason_code == "sandbox_evidence_invalid"


@pytest.mark.asyncio
async def test_a_runner_that_does_not_claim_a_denied_network_is_not_this_level(request_payload, source):
    result = await verify_with(FakeIsolatedJobDriver(network="unrestricted"), request_payload, source)
    assert result.reason_code == "sandbox_evidence_invalid"


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["metadata", "internet", "dns"])
async def test_a_probe_that_reached_its_target_is_not_this_level(request_payload, source, target):
    probes = denied_probes()
    probes[target] = {"reached": True, "detail": "connected", "endpoint": "x"}
    result = await verify_with(FakeIsolatedJobDriver(probes=probes), request_payload, source)
    assert result.reason_code == "sandbox_evidence_invalid"


@pytest.mark.asyncio
async def test_a_probe_that_did_not_run_is_refused_exactly_like_one_that_connected(request_payload, source):
    probes = denied_probes()
    probes["dns"] = {"reached": None, "detail": "probe_failed:OSError", "endpoint": None}
    result = await verify_with(FakeIsolatedJobDriver(probes=probes), request_payload, source)
    assert result.reason_code == "sandbox_evidence_invalid"


@pytest.mark.asyncio
async def test_a_missing_probe_target_is_not_this_level(request_payload, source):
    probes = denied_probes()
    del probes["internet"]
    result = await verify_with(FakeIsolatedJobDriver(probes=probes), request_payload, source)
    assert result.reason_code == "sandbox_evidence_invalid"


@pytest.mark.asyncio
async def test_evidence_with_no_probes_at_all_is_not_this_level(request_payload, source):
    result = await verify_with(FakeIsolatedJobDriver(probes={}), request_payload, source)
    assert result.reason_code == "sandbox_evidence_invalid"


@pytest.mark.asyncio
async def test_a_check_result_that_does_not_name_its_execution_is_not_this_level(request_payload, source):
    result = await verify_with(FakeIsolatedJobDriver(per_check_execution=None), request_payload, source)
    assert result.reason_code == "sandbox_evidence_invalid"


# -- a driver that refused before running anything -------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["sandbox_network_not_denied", "sandbox_image_digest_mismatch"])
async def test_a_driver_that_ran_no_check_keeps_its_own_reason(request_payload, source, reason):
    halt = {"outcome": "inconclusive", "reason_code": reason, "checks": []}
    result = await verify_with(FakeIsolatedJobDriver(halt=halt), request_payload, source)

    assert result.status == "inconclusive"
    assert result.reason_code == reason, "the driver's reason must not collapse into a generic one"
    assert result.verification_level == ISOLATED_JOB_VERIFICATION_LEVEL
    assert [item["finding_id"] for item in result.unproven_findings] == ["finding-1"]
    assert result.proven_finding_ids == []


@pytest.mark.asyncio
async def test_a_halted_driver_is_still_refused_when_policy_does_not_allow_the_level(request_payload, source):
    halt = {"outcome": "inconclusive", "reason_code": "sandbox_network_not_denied", "checks": []}
    result = await verify_with(FakeIsolatedJobDriver(halt=halt), request_payload, source, allow=False)
    assert result.reason_code == "isolated_job_verification_not_permitted"
