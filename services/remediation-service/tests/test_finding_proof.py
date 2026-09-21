"""Per-finding proof, the candidate's full-file manifest, and the runtime load check.

A candidate claims exactly the findings whose own regression test fails on the baseline tree
and passes on the candidate tree. Every other finding is reported as skipped with the reason.
The candidate also carries the whole final content of every changed file, bound to the verified
Git tree, because that is what the apply path commits.
"""
from __future__ import annotations

import base64
import json
import shutil

import pytest

from src.agent import ProviderAction, RepairAgent
from src.agent.loop import _regression_tests
from src.digests import content_sha256, git_blob_sha1
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.patches import PatchPolicyError, build_patch_bundle
from src.retrieval import Snapshot
from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver
from src.verification import Verifier
from tests.conftest import whole_file_change
from tests.test_generated_regression_tests import (
    JS_REGRESSION_TEST,
    JS_REPAIRED,
    JS_SOURCE,
    JS_TEXT_ONLY_TEST,
    _no_profile_payload,
    _run_engine,
    _spec,
)

requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="these checks run under node")

SECOND_TEST_PATH = ".mitig8it/regression/finding-2.test.js"
PASSES_ON_BOTH = "require('../../src/db.js');\nprocess.exit(0);\n"
FAILS_ON_BOTH = "require('../../src/db.js');\nprocess.exit(1);\n"


def _two_finding_payload(request_payload):
    payload = _no_profile_payload(request_payload)
    payload["findings"] = [
        {"snapshot_id": "finding-1", "rule_id": "js.sql-injection", "cwe_id": "CWE-89", "file_path": "src/db.js", "line_start": 2, "line_end": 2},
        {"snapshot_id": "finding-2", "rule_id": "js.sql-injection", "cwe_id": "CWE-89", "file_path": "src/db.js", "line_start": 2, "line_end": 2},
    ]
    return payload


# --- regression test shape rules -------------------------------------------------------------


def test_a_test_that_only_reads_the_changed_file_as_text_is_rejected(request_payload):
    request = RepairRequest.model_validate(_no_profile_payload(request_payload))
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError, match="regression_test_reads_source_as_text") as info:
        build_patch_bundle(request, snapshot, [whole_file_change("src/db.js", JS_SOURCE, JS_REPAIRED)], [_spec(JS_TEXT_ONLY_TEST)])
    assert "require('../harness')" in info.value.guidance and "h.load(" in info.value.guidance


def test_a_test_naming_a_finding_outside_the_task_is_rejected(request_payload):
    request = RepairRequest.model_validate(_no_profile_payload(request_payload))
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError, match="regression_test_finding_unknown") as info:
        build_patch_bundle(
            request, snapshot, [whole_file_change("src/db.js", JS_SOURCE, JS_REPAIRED)], [_spec(JS_REGRESSION_TEST, finding_id="finding-9")]
        )
    assert "finding-1" in info.value.guidance


def test_a_finding_runs_its_proof_and_at_most_one_model_test_beside_it(request_payload):
    """A service-generated proof and one model-written test may both prove a finding; a third
    test for the same finding is rejected."""
    request = RepairRequest.model_validate(_no_profile_payload(request_payload))
    snapshot = Snapshot(request)
    bundle = build_patch_bundle(
        request,
        snapshot,
        [whole_file_change("src/db.js", JS_SOURCE, JS_REPAIRED)],
        [_spec(JS_REGRESSION_TEST), _spec(JS_REGRESSION_TEST, path=SECOND_TEST_PATH)],
    )
    assert [test.finding_id for test in bundle.generated_tests] == ["finding-1", "finding-1"]
    with pytest.raises(PatchPolicyError, match="duplicate_regression_test_finding"):
        build_patch_bundle(
            request,
            snapshot,
            [whole_file_change("src/db.js", JS_SOURCE, JS_REPAIRED)],
            [
                _spec(JS_REGRESSION_TEST),
                _spec(JS_REGRESSION_TEST, path=SECOND_TEST_PATH),
                _spec(JS_REGRESSION_TEST, path=SECOND_TEST_PATH.replace(".test.js", ".third.test.js")),
            ],
        )


def test_the_retired_single_regression_test_field_is_rejected_with_the_correction():
    with pytest.raises(PatchPolicyError, match="regression_tests_required") as info:
        _regression_tests({"regression_test": {"path": ".mitig8it/regression/x.test.js", "content": "process.exit(1);"}})
    assert "finding_id" in info.value.guidance
    with pytest.raises(PatchPolicyError, match="regression_tests_must_be_a_list"):
        _regression_tests({"regression_tests": {"finding_id": "finding-1"}})
    assert _regression_tests({}) == []


# --- per-finding verdicts on the real local driver --------------------------------------------


@requires_node
@pytest.mark.asyncio
async def test_a_finding_without_a_reproducing_test_is_dropped_and_reported_not_repaired(request_payload):
    response = await _run_engine(_two_finding_payload(request_payload), regression_tests=[_spec(JS_REGRESSION_TEST)])
    assert response.state == "ready", response.reason
    assert response.candidates[0].finding_ids == ["finding-1"]
    assert response.skipped == [
        {
            "finding_id": "finding-2",
            "code": "not_repaired",
            "message": "No regression test reproduced this finding, so the candidate does not claim it.",
        }
    ]


@requires_node
@pytest.mark.asyncio
async def test_a_test_that_passes_on_the_baseline_drops_only_its_finding(request_payload):
    tests = [_spec(JS_REGRESSION_TEST), _spec(PASSES_ON_BOTH, path=SECOND_TEST_PATH, finding_id="finding-2")]
    response = await _run_engine(_two_finding_payload(request_payload), regression_tests=tests)
    assert response.state == "ready", response.reason
    assert response.candidates[0].finding_ids == ["finding-1"]
    assert [(item["finding_id"], item["code"]) for item in response.skipped] == [("finding-2", "regression_test_not_reproducing")]
    checks = {item["check_id"]: item for item in response.evidence["verification_run"]["checks"]}
    assert checks["generated_regression_test"]["baseline"]["status"] == "failed"
    assert checks["generated_regression_test_2"]["baseline"]["status"] == "passed"


@requires_node
@pytest.mark.asyncio
async def test_a_test_that_still_fails_on_the_candidate_drops_its_finding_as_not_repaired(request_payload):
    tests = [_spec(JS_REGRESSION_TEST), _spec(FAILS_ON_BOTH, path=SECOND_TEST_PATH, finding_id="finding-2")]
    response = await _run_engine(_two_finding_payload(request_payload), regression_tests=tests)
    assert response.state == "ready", response.reason
    assert response.candidates[0].finding_ids == ["finding-1"]
    assert [(item["finding_id"], item["code"]) for item in response.skipped] == [("finding-2", "not_repaired")]
    assert "still fails on the patched code" in response.skipped[0]["message"]


@requires_node
@pytest.mark.asyncio
async def test_a_candidate_with_no_proven_finding_is_rejected(request_payload):
    """Both tests fail on the candidate tree too: nothing was repaired, so there is no candidate."""
    payload = _two_finding_payload(request_payload)
    # One attempt: a failed verification with attempts left would send the agent back to fix it.
    payload["policy"]["max_attempts"] = 1
    tests = [_spec(FAILS_ON_BOTH), _spec(FAILS_ON_BOTH, path=SECOND_TEST_PATH, finding_id="finding-2")]
    response = await _run_engine(payload, regression_tests=tests)
    assert response.state == "inconclusive"
    assert response.reason["code"] == "verification_failed"
    assert response.candidates == []


@requires_node
@pytest.mark.asyncio
async def test_verification_output_tells_the_agent_which_findings_it_proved(request_payload):
    seen: list[dict] = []

    class RecordingProvider:
        def __init__(self):
            self.actions = iter(
                [
                    ProviderAction(
                        "propose_patch",
                        {
                            "hypothesis": "Untrusted id is interpolated into SQL text.",
                            "intended_behavior": "Load the same user by id.",
                            "assumptions": [],
                            "citations": [{"path": "src/db.js", "line_start": 1, "line_end": 4}],
                            "changes": [whole_file_change("src/db.js", JS_SOURCE, JS_REPAIRED)],
                            "regression_tests": [_spec(JS_REGRESSION_TEST)],
                        },
                    ),
                    ProviderAction("request_verification", {}),
                    ProviderAction("abstain", {"reason_code": "no_further_repair", "explanation": "Nothing more to add."}),
                ]
            )

        async def next_action(self, messages, tools):
            seen.append(messages[-1])
            return next(self.actions)

    request = RepairRequest.model_validate(_two_finding_payload(request_payload))
    agent = RepairAgent(RecordingProvider(), Verifier(InProcessSandboxBroker(LocalSubprocessDriver())))
    result = await agent.run(request, Snapshot(request))
    assert result.state == "ready"
    assert result.verification.proven_finding_ids == ["finding-1"]
    assert [item["finding_id"] for item in result.verification.unproven_findings] == ["finding-2"]
    # The verification result the model saw named the unproven finding and asked for a revision.
    revision = json.loads(seen[-1]["content"])["coverage_revision"]
    assert [item["finding_id"] for item in revision["unproven"]] == ["finding-2"]
    assert revision["unproven"][0]["family"] == "sql_parameterization"
    assert result.evidence["coverage"]["stopped"] == "no_further_repair"


# --- the candidate's full-file manifest matches the verified tree -----------------------------


@requires_node
@pytest.mark.asyncio
async def test_candidate_file_manifest_carries_the_final_contents_of_the_verified_tree(request_payload):
    payload = _no_profile_payload(request_payload)
    response = await _run_engine(payload, regression_test=_spec(JS_REGRESSION_TEST))
    assert response.state == "ready", response.reason
    candidate = response.candidates[0]
    manifest = candidate.file_manifest
    assert manifest["verified_tree_oid"] == candidate.verified_tree_oid == response.evidence["verified_tree_oid"]
    assert [entry["path"] for entry in manifest["files"]] == ["src/db.js"]
    entry = manifest["files"][0]
    decoded = base64.b64decode(entry["contents_base64"], validate=True).decode("utf-8")
    assert decoded == JS_REPAIRED == candidate.patch[0].replacement_content
    assert entry["new_sha256"] == content_sha256(JS_REPAIRED)
    assert entry["blob_oid"] == git_blob_sha1(JS_REPAIRED.encode("utf-8"))
    assert entry["bytes"] == len(JS_REPAIRED.encode("utf-8"))
    assert entry["kind"] == "application"
    # The tree built from the head entries with each changed blob replaced by the manifest's
    # blob is the verified tree: committing exactly these contents reproduces it.
    entries = [
        GitTreeEntry(**{**item, "sha": entry["blob_oid"] if item["path"] == entry["path"] else item["sha"]})
        for item in payload["tree_entries"]
    ]
    assert compute_tree_oid(entries) == manifest["verified_tree_oid"]
    # Generated tests never enter the manifest that the apply path commits.
    assert all(item["kind"] == "application" for item in manifest["files"])
    assert candidate.generated_tests[0]["path"] not in {item["path"] for item in manifest["files"]}


# --- runtime load check --------------------------------------------------------------------------

USES_UNIMPORTED_EXECFILE = (
    "function run(name) {\n  return execFile('ls', [name]);\n}\n"
    "run('x');\n"
    "module.exports = { run };\n"
)
IMPORTS_EXECFILE = (
    "const { execFile } = require('node:child_process');\n"
    "function run(name) {\n  return execFile('ls', [name]);\n}\n"
    "module.exports = { run };\n"
)
REQUIRES_DECLARED_PG = "const { Pool } = require('pg');\nfunction loadUser(db, id) {\n  return db.query('SELECT 1', [id]);\n}\nmodule.exports = { loadUser, Pool };\n"
THROWS_ON_LOAD = "throw new TypeError('config missing');\n"


@requires_node
def test_a_candidate_using_an_unimported_identifier_at_load_is_rejected(request_payload):
    request = RepairRequest.model_validate(_no_profile_payload(request_payload))
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError, match="candidate_load_failed:src/db.js") as info:
        build_patch_bundle(request, snapshot, [whole_file_change("src/db.js", JS_SOURCE, USES_UNIMPORTED_EXECFILE)], [_spec(JS_REGRESSION_TEST)])
    assert "ReferenceError" in info.value.guidance and "execFile is not defined" in info.value.guidance
    assert "imported or defined" in info.value.guidance
    # The same code with the import in place loads, so the rejection was about the import.
    bundle = build_patch_bundle(request, snapshot, [whole_file_change("src/db.js", JS_SOURCE, IMPORTS_EXECFILE)], [_spec(JS_REGRESSION_TEST)])
    assert not any("runtime load check" in item for item in bundle.limitations)


@requires_node
def test_a_declared_but_uninstalled_dependency_is_a_limitation_not_a_rejection(request_payload):
    request = RepairRequest.model_validate(_no_profile_payload(request_payload))
    snapshot = Snapshot(request)
    bundle = build_patch_bundle(request, snapshot, [whole_file_change("src/db.js", JS_SOURCE, REQUIRES_DECLARED_PG)], [_spec(JS_REGRESSION_TEST)])
    limitation = next(item for item in bundle.limitations if item.startswith("runtime load check skipped for src/db.js"))
    assert "Cannot find module 'pg'" in limitation


@requires_node
def test_a_module_that_did_not_load_before_the_change_is_inconclusive_not_rejected(request_payload):
    payload = _no_profile_payload(request_payload, source=THROWS_ON_LOAD)
    request = RepairRequest.model_validate(payload)
    snapshot = Snapshot(request)
    bundle = build_patch_bundle(
        request, snapshot, [whole_file_change("src/db.js", THROWS_ON_LOAD, THROWS_ON_LOAD + "// still broken\n")], [_spec(JS_REGRESSION_TEST)]
    )
    assert any(item.startswith("runtime load check inconclusive for src/db.js") for item in bundle.limitations)


# --- a crashed test reports why ------------------------------------------------------------------

CRASHING_TEST = "require('../../src/db.js');\nconst helper = jest.fn();\nprocess.exit(0);\n"


def test_output_tail_is_kept_only_for_failed_checks():
    from src.sandbox.execution import MAX_OUTPUT_TAIL_CHARS, output_tail

    assert output_tail("all good\n", 0) is None
    assert output_tail("anything", None) is None
    assert output_tail("", 1) == ""
    assert output_tail("ReferenceError: jest is not defined\n", 1) == "ReferenceError: jest is not defined"
    assert output_tail("x" * 5000, 1) == "x" * MAX_OUTPUT_TAIL_CHARS


@requires_node
@pytest.mark.asyncio
async def test_a_crashing_test_shows_its_error_to_the_agent_through_inspect_failure(request_payload):
    """The live gap: a test that crashed on both trees left the agent with exit codes only."""
    from src.agent.loop import RepairAgent as Loop

    request = RepairRequest.model_validate(_no_profile_payload(request_payload))
    snapshot = Snapshot(request)
    bundle = build_patch_bundle(request, snapshot, [whole_file_change("src/db.js", JS_SOURCE, JS_REPAIRED)], [_spec(CRASHING_TEST)])
    result = await Verifier(InProcessSandboxBroker(LocalSubprocessDriver())).verify(request, snapshot, bundle)
    assert result.status == "failed"
    assert result.proven_finding_ids == []
    check = next(item for item in result.evidence["checks"] if item["check_id"] == "generated_regression_test")
    assert "jest is not defined" in check["candidate"]["output_tail"]
    assert "jest is not defined" in check["baseline"]["output_tail"]
    syntax = next(item for item in result.evidence["checks"] if item["check_id"] == "generated_node_syntax")
    assert syntax["candidate"]["output_tail"] is None
    inspected = Loop._bounded_failure(result)
    assert inspected["unproven_findings"][0]["code"] == "not_repaired"
    assert "jest is not defined" in inspected["checks"][0]["candidate"]["output_tail"]
