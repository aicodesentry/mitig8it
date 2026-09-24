from __future__ import annotations

import shutil
import sys

import pytest

from src.digests import content_sha256
from src.models import RepairRequest
from src.patches import build_patch_bundle
from src.retrieval import Snapshot
from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver
from src.sandbox import local_driver
from src.verification import Verifier
from tests.conftest import whole_file_change

REPAIRED = "export function loadUser(db, id) {\n  return db.query('SELECT * FROM users WHERE id = $1', [id]);\n}\n"

EXPLOIT = [sys.executable, "-c", "import pathlib,sys; sys.exit(1 if '${id}' in pathlib.Path('src/db.ts').read_text() else 0)"]
BEHAVIOR = [sys.executable, "-c", "import pathlib,sys; sys.exit(0 if 'loadUser' in pathlib.Path('src/db.ts').read_text() else 1)"]
SCANNER = [
    sys.executable,
    "-c",
    "import json,pathlib; text=pathlib.Path('src/db.ts').read_text();"
    " print(json.dumps({'mitig8it_scanner_findings': ['sql-1'] if '${id}' in text else ['sql-1','new-1']}))",
]


def development_payload(request_payload, checks, *, allow=True, source=None, replacement=REPAIRED, regression_test=None):
    """A policy-checked request: the fixture's exploit and behavior argv are the evidence.

    Policy does not require a generated behavior test here unless one is passed in explicitly,
    so these cases stay about the driver rather than about what a reproducer proved.
    """
    request_payload["policy"]["sandbox_image_digest"] = None
    request_payload["policy"]["allow_development_verification"] = allow
    request_payload["policy"]["verification_checks"] = checks
    request_payload["policy"]["require_generated_regression_test"] = regression_test is not None
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    bundle = build_patch_bundle(
        request,
        snapshot,
        [whole_file_change("src/db.ts", source, replacement)],
        [regression_test] if regression_test else [],
    )
    return request, snapshot, bundle


def checks(*kinds):
    argv = {"exploit": EXPLOIT, "behavior": BEHAVIOR, "scanner": SCANNER}
    return [{"check_id": kind, "kind": kind, "argv": argv[kind], "timeout_seconds": 60} for kind in kinds]


@pytest.mark.asyncio
async def test_local_driver_produces_development_unverified_evidence(request_payload, source):
    request, snapshot, bundle = development_payload(request_payload, checks("exploit", "behavior"), source=source)
    result = await Verifier(InProcessSandboxBroker(LocalSubprocessDriver())).verify(request, snapshot, bundle)
    assert result.status == "passed"
    assert result.verification_level == "development_unverified"
    assert result.evidence["runner"]["runtime_class"] == "local-subprocess"
    assert result.evidence["runner"]["network"] == "unrestricted"
    assert result.evidence["runner"]["read_only_root"] is False
    exploit = next(item for item in result.evidence["checks"] if item["check_id"] == "exploit")
    assert exploit["baseline"]["status"] == "failed" and exploit["candidate"]["status"] == "passed"
    assert any("development local sandbox" in item for item in result.limitations)


@pytest.mark.asyncio
async def test_development_evidence_is_refused_unless_policy_allows_it(request_payload, source):
    request, snapshot, bundle = development_payload(request_payload, checks("exploit", "behavior"), allow=False, source=source)
    request_payload["policy"]["sandbox_image_digest"] = "ghcr.io/mitig8it/remediation-runner@sha256:" + "c" * 64
    request = RepairRequest.model_validate(request_payload)
    result = await Verifier(InProcessSandboxBroker(LocalSubprocessDriver())).verify(request, snapshot, bundle)
    assert result.status == "unsupported"
    assert result.reason_code == "development_verification_not_permitted"
    assert result.verification_level == "development_unverified"


@pytest.mark.asyncio
async def test_local_driver_rejects_a_candidate_that_adds_scanner_findings(request_payload, source):
    request, snapshot, bundle = development_payload(request_payload, checks("exploit", "behavior", "scanner"), source=source)
    result = await Verifier(InProcessSandboxBroker(LocalSubprocessDriver())).verify(request, snapshot, bundle)
    assert result.status == "failed"
    assert result.reason_code == "scanner_findings_regression"


@pytest.mark.asyncio
async def test_missing_scanner_report_is_inconclusive_not_passed(request_payload, source):
    silent = [{"check_id": "scanner", "kind": "scanner", "argv": [sys.executable, "-c", "pass"], "timeout_seconds": 30}]
    request, snapshot, bundle = development_payload(request_payload, checks("exploit", "behavior") + silent, source=source)
    result = await Verifier(InProcessSandboxBroker(LocalSubprocessDriver())).verify(request, snapshot, bundle)
    assert result.status == "inconclusive"
    assert result.reason_code == "scanner_findings_report_missing"


@pytest.mark.asyncio
async def test_limitations_name_every_check_kind_that_did_not_run(request_payload, source):
    request, snapshot, bundle = development_payload(request_payload, checks("exploit", "behavior"), source=source)
    result = await Verifier(InProcessSandboxBroker(LocalSubprocessDriver())).verify(request, snapshot, bundle)
    joined = " ".join(result.limitations)
    assert "original test suite was not run" in joined
    # The candidate patches `src/db.ts`, and a TypeScript file now derives its own parse check,
    # so the typecheck kind ran and is not among the limitations.
    assert "no type check or build was run" not in joined
    assert "no scanner baseline/candidate finding comparison" in joined


@pytest.mark.asyncio
async def test_local_driver_enforces_the_total_job_deadline(request_payload, source):
    slow = [{"check_id": "exploit", "kind": "exploit", "argv": [sys.executable, "-c", "import time; time.sleep(5)"], "timeout_seconds": 60}]
    request, snapshot, bundle = development_payload(request_payload, slow + checks("behavior"), source=source)
    driver = LocalSubprocessDriver()
    payload_checks = [check.model_dump(mode="json") for check in request.policy.verification_checks]
    result = driver.execute(
        {
            "snapshot": [{"path": path, "content": snapshot.full_content(path)} for path in snapshot.paths],
            "patches": [patch.model_dump(mode="json") for patch in bundle.patches],
            "execution_policy": {"commands": payload_checks, "image_digest": None, "deadline_seconds": 1},
        },
        1,
    )
    assert result["outcome"] == "inconclusive"
    assert any(item["baseline"].get("reason_code") for item in result["checks"])


@pytest.mark.asyncio
async def test_a_missing_workspace_root_is_inconclusive_evidence_not_a_raised_error(tmp_path, request_payload, source):
    """The live lease loss: mkdtemp under an absent root raised through broker and verifier.

    The raised OSError left the worker's attempt dead with the lease still held, so the job
    burnt its whole recovery budget in silence. A sandbox that cannot make a workspace has to
    produce inconclusive evidence instead.
    """
    absent = tmp_path / "never-created" / "sandbox"
    driver = LocalSubprocessDriver(str(absent))
    # A configured root is created rather than assumed to exist.
    assert absent.is_dir()
    absent.rmdir()
    (tmp_path / "never-created").rmdir()

    request, snapshot, bundle = development_payload(request_payload, checks("exploit", "behavior"), source=source)
    result = await Verifier(InProcessSandboxBroker(driver)).verify(request, snapshot, bundle)
    assert result.status == "inconclusive"
    assert any("did not complete" in limitation for limitation in result.limitations)


def test_an_older_node_names_the_missing_harness_features_instead_of_failing_the_candidate(monkeypatch):
    """Node 20 in CI: the harness flags were rejected and every Node check failed on both trees.

    The pipeline read that as a repair that could not prove itself, which is the one thing it
    was not. A check the runtime could not start is inconclusive, and it says which feature is
    missing, so the next reader looks at the toolchain rather than at the candidate.
    """
    report = local_driver.NodeRuntimeReport("v20.19.5", ("module.stripTypeScriptTypes", "module.registerHooks"))
    monkeypatch.setattr(local_driver, "node_runtime_report", lambda: report)
    driver = LocalSubprocessDriver()

    record = driver._run_variant(  # noqa: SLF001 - the variant record is what the evidence carries.
        {"execution_policy": {"image_digest": None}},
        "candidate",
        {"check_id": "generated_regression_test", "kind": "generated_test", "argv": ["node", "--check", "a.ts"], "timeout_seconds": 5},
        5.0,
    )

    assert record["completed"] is False
    assert record["status"] == "inconclusive"
    assert record["reason_code"].startswith("node_runtime_missing_features:")
    assert "module.stripTypeScriptTypes" in record["reason_code"]
    assert "module.registerHooks" in record["reason_code"]
    assert "v20.19.5" in record["output_tail"]
    assert "ARG NODE_VERSION" in record["output_tail"]


def test_a_python_check_is_never_blocked_by_the_node_probe(monkeypatch):
    """The gate is per interpreter: a Python check on a host with no usable Node still runs."""
    report = local_driver.NodeRuntimeReport("v20.19.5", ("module.registerHooks",))
    monkeypatch.setattr(local_driver, "node_runtime_report", lambda: report)
    driver = LocalSubprocessDriver()

    record = driver._run_variant(  # noqa: SLF001
        {"execution_policy": {"image_digest": None}, "snapshot": [], "patches": []},
        "candidate",
        {"check_id": "python", "kind": "behavior", "argv": [sys.executable, "-c", "pass"], "timeout_seconds": 10},
        10.0,
    )

    assert record["completed"] is True
    assert record["status"] == "passed"


def test_the_probe_reports_this_host_honestly_on_any_node():
    """The probe itself, against whatever `node` is on this host.

    Asserted without naming a version so the suite stays runnable on an older toolchain: what
    is pinned is that the report names the runtime it found and that every gap it lists also
    reaches the sentence a human reads. CI runs the version the Dockerfile pins, where the
    gap list is empty.
    """
    if shutil.which("node") is None:
        pytest.skip("no node toolchain on this host")
    local_driver.node_runtime_report.cache_clear()
    try:
        report = local_driver.node_runtime_report()
        assert report.version and report.version.startswith("v")
        assert set(report.missing) <= {*local_driver.REQUIRED_NODE_FEATURES, *local_driver.typescript_flags()}
        for feature in report.missing:
            assert feature in report.detail()
    finally:
        local_driver.node_runtime_report.cache_clear()
