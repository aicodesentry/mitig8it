"""The service-supplied sandbox test harness.

The harness is what makes an agent-written regression test runnable with nothing installed: it
fakes express, pg, child_process, and fs, records every call, and is materialized into both
sandbox workspaces beside the tests. These tests cover the JavaScript unit spec under plain
node, the materialization path both drivers share, the manifest boundary, patch policy, and the
prompt guidance.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from src.agent import ProviderAction, RepairAgent
from src.agent.loop import SYSTEM_PROMPT
from src.agent.tools import tool_definitions
from src.engine import RepairEngine
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.patches import PatchPolicyError, apply_hunks, build_patch_bundle
from src.retrieval import Snapshot
from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver
from src.sandbox.harness import HARNESS_OCCUPIED_LIMITATION, HARNESS_PATH, MAX_HARNESS_BYTES, HARNESS_SOURCE_FILE, harness_source
from src.sandbox.kubernetes_driver import KubernetesDriverConfig, KubernetesJobDriver
from src.sandbox.runner import materialize_tree
from src.verification import Verifier
from src.verification.checks import build_effective_checks, generated_snapshot_entries
from tests.conftest import git_blob, whole_file_change
from tests.test_runner_safety import _FakeApiException

requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="the harness runs under node")

TESTS_DIR = Path(__file__).parent
ORDERS_PATH = "services/orders.js"
ORDERS_TEST_PATH = ".mitig8it/regression/finding-sqli.test.js"
PACKAGE_JSON = '{"name":"orders","dependencies":{"express":"^4.19.2","pg":"^8.12.0"}}\n'
# A real express router over pg, exactly the shape of the repositories the agent sees.
ORDERS_SOURCE = (
    "const express = require('express');\n"
    "const { Pool } = require('pg');\n"
    "const pool = new Pool({ connectionString: process.env.DATABASE_URL });\n"
    "const router = express.Router();\n"
    "router.get('/orders/:id', async (req, res) => {\n"
    "  const result = await pool.query(\"SELECT id FROM orders WHERE id = '\" + req.params.id + \"'\");\n"
    "  res.json(result.rows);\n"
    "});\n"
    "module.exports = router;\n"
)
ORDERS_REPAIRED = ORDERS_SOURCE.replace(
    "pool.query(\"SELECT id FROM orders WHERE id = '\" + req.params.id + \"'\")",
    "pool.query('SELECT id FROM orders WHERE id = $1', [req.params.id])",
)
# The test the prompt asks for: harness, load, invoke, assert on the recorded query.
HARNESS_TEST = (
    "const h = require('../harness');\n"
    "h.run(async () => {\n"
    "  const app = h.load('services/orders.js');\n"
    "  const bad = \"1' OR '1'='1\";\n"
    "  await h.invoke(app, 'get', '/orders/:id', { params: { id: bad } });\n"
    "  const q = h.pg.queries[0];\n"
    "  h.assert(q, 'no query ran');\n"
    "  h.assert.notIncludes(q.text, bad, 'input reached the SQL text');\n"
    "  h.assert.includes(JSON.stringify(q.values || []), bad, 'input must be a bound value');\n"
    "});\n"
)
SUPERTEST_TEST = (
    "const request = require('supertest');\n"
    "const app = require('../../services/orders.js');\n"
    "request(app).get('/orders/1').expect(200).end((error) => process.exit(error ? 1 : 0));\n"
)


def _orders_payload(request_payload, *, extra_files=()):
    files = [(ORDERS_PATH, ORDERS_SOURCE), ("package.json", PACKAGE_JSON), *extra_files]
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=git_blob(content)) for path, content in files]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": content, "sha": git_blob(content)} for path, content in files]
    payload["findings"] = [
        {"snapshot_id": "finding-sqli", "rule_id": "js.sql-injection", "cwe_id": "CWE-89", "file_path": ORDERS_PATH, "line_start": 6, "line_end": 6}
    ]
    payload["policy"] = {
        **request_payload["policy"],
        "sandbox_image_digest": None,
        "allow_development_verification": True,
        "verification_checks": [],
    }
    return payload


def _spec(content=HARNESS_TEST, path=ORDERS_TEST_PATH, finding_id="finding-sqli"):
    return {"finding_id": finding_id, "path": path, "content": content}


def _bundle(request, snapshot, test=None):
    changes = [whole_file_change(ORDERS_PATH, ORDERS_SOURCE, ORDERS_REPAIRED)]
    return build_patch_bundle(request, snapshot, changes, [test or _spec()])


@requires_node
def test_harness_unit_spec_passes_under_plain_node():
    """The JavaScript spec: express routing and invoke, pg, child_process, fs, error propagation."""
    completed = subprocess.run(
        ["node", "--test-reporter=tap", str(TESTS_DIR / "harness_spec.js")],
        cwd=TESTS_DIR.parent,
        env={"PATH": os.environ.get("PATH", ""), "MITIG8IT_HARNESS_SOURCE": str(HARNESS_SOURCE_FILE), "NO_COLOR": "1"},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-4000:]
    assert "# fail 0" in completed.stdout


def test_harness_source_is_bounded_and_dependency_free():
    source = harness_source()
    assert len(source.encode("utf-8")) <= MAX_HARNESS_BYTES
    assert source == HARNESS_SOURCE_FILE.read_text(encoding="utf-8")
    from src.patches import _is_builtin, module_specifiers, package_root

    for specifier in module_specifiers(source):
        assert _is_builtin(package_root(specifier) or specifier), specifier


class _CapturingDriver(LocalSubprocessDriver):
    def __init__(self, workspace_root):
        super().__init__(str(workspace_root))
        self.payloads = []

    def execute(self, payload, deadline_seconds):
        self.payloads.append(payload)
        return super().execute(payload, deadline_seconds)


@requires_node
@pytest.mark.asyncio
async def test_harness_is_materialized_in_both_trees_and_kept_out_of_the_manifest(tmp_path, request_payload):
    request = RepairRequest.model_validate(_orders_payload(request_payload))
    snapshot = Snapshot(request)
    bundle = _bundle(request, snapshot)
    driver = _CapturingDriver(tmp_path / "workspaces")
    result = await Verifier(InProcessSandboxBroker(driver)).verify(request, snapshot, bundle)

    assert result.status == "passed", (result.reason_code, result.limitations)
    assert result.proven_finding_ids == ["finding-sqli"]
    # The harness travels in the sandbox payload's file list, so the local driver and the
    # Kubernetes init container write it through the same trusted materializer.
    [payload] = driver.payloads
    paths = [entry["path"] for entry in payload["snapshot"]]
    assert paths.count(HARNESS_PATH) == 1 and ORDERS_TEST_PATH in paths
    for variant in ("baseline", "candidate"):
        root = tmp_path / variant
        materialize_tree(root, payload, variant)
        assert (root / HARNESS_PATH).read_text(encoding="utf-8") == harness_source()
        assert (root / ORDERS_TEST_PATH).read_text(encoding="utf-8") == HARNESS_TEST
    assert (tmp_path / "baseline" / ORDERS_PATH).read_text() == ORDERS_SOURCE
    assert (tmp_path / "candidate" / ORDERS_PATH).read_text() == ORDERS_REPAIRED
    # Never a patch, never a manifest entry: only the application file and the test are tracked.
    assert [patch["path"] for patch in payload["patches"]] == [ORDERS_PATH]
    assert [entry["path"] for entry in bundle.file_manifest] == [ORDERS_PATH]
    assert [entry["path"] for entry in bundle.generated_test_manifest] == [ORDERS_TEST_PATH]
    effective = build_effective_checks(request, snapshot, bundle)
    assert effective.generated_files == ({"path": ORDERS_TEST_PATH, "content": HARNESS_TEST},)
    assert [entry["path"] for entry in effective.harness_files] == [HARNESS_PATH]


def test_kubernetes_driver_ships_the_harness_to_the_runner_secret(monkeypatch, tmp_path, request_payload):
    """The Kubernetes path: the request Secret the init container materializes carries the harness."""
    import src.sandbox.kubernetes_driver as module

    request = RepairRequest.model_validate(_orders_payload(request_payload))
    snapshot = Snapshot(request)
    bundle = _bundle(request, snapshot)
    effective = build_effective_checks(request, snapshot, bundle)
    image = "ghcr.io/mitig8it/runner@sha256:" + "c" * 64
    monkeypatch.setenv("SANDBOX_ALLOWED_IMAGE_DIGESTS", image)
    monkeypatch.setenv("SANDBOX_NETWORK_POLICY_ATTESTED", "true")
    monkeypatch.setenv("SANDBOX_NODE_LIMITS_ATTESTED", "true")
    monkeypatch.setattr(module, "ApiException", _FakeApiException)
    secrets = []

    class Core:
        def create_namespaced_secret(self, namespace, secret):
            secrets.append(secret)
            return secret

        def delete_namespaced_secret(self, name, namespace):
            return None

    class Batch:
        def create_namespaced_job(self, namespace, job):
            return job

        def delete_namespaced_job(self, name, namespace, propagation_policy=None):
            return None

    driver = object.__new__(KubernetesJobDriver)
    driver.settings = KubernetesDriverConfig(namespace="sandbox", service_account_name="sandbox-no-access", poll_interval_seconds=0.01)
    driver.core = Core()
    driver.batch = Batch()
    payload = {
        "request_digest": "sha256:" + "a" * 64,
        "snapshot": generated_snapshot_entries(snapshot, effective),
        "patches": [patch.model_dump(mode="json") for patch in bundle.patches],
        "execution_policy": {
            "image_digest": image,
            "commands": [check.model_dump(mode="json") for check in effective.checks],
            "deadline_seconds": 0,
        },
    }
    result = driver.execute(payload, 0)
    assert result["outcome"] == "inconclusive"
    [secret] = secrets
    shipped = json.loads(next(iter(secret.string_data.values())))
    assert [entry["path"] for entry in shipped["snapshot"]].count(HARNESS_PATH) == 1
    for variant in ("baseline", "candidate"):
        materialize_tree(tmp_path / variant, shipped, variant)
        assert (tmp_path / variant / HARNESS_PATH).read_text(encoding="utf-8") == harness_source()


def test_a_repository_that_occupies_the_harness_path_keeps_its_file_and_gets_a_limitation(request_payload):
    payload = _orders_payload(request_payload, extra_files=((HARNESS_PATH, "module.exports = {};\n"),))
    request = RepairRequest.model_validate(payload)
    snapshot = Snapshot(request)
    effective = build_effective_checks(request, snapshot, _bundle(request, snapshot))
    assert effective.harness_files == ()
    assert HARNESS_OCCUPIED_LIMITATION in effective.limitations
    assert [entry["path"] for entry in generated_snapshot_entries(snapshot, effective)].count(HARNESS_PATH) == 1


@requires_node
@pytest.mark.asyncio
async def test_engine_marks_a_harness_backed_repair_ready_with_no_installed_dependency(request_payload):
    """End to end: express and pg are declared but not installed, and the finding is still proven."""
    arguments = {
        "hypothesis": "The order id is concatenated into SQL text.",
        "intended_behavior": "Look up the same order by id.",
        "assumptions": ["pg positional parameters are available"],
        "citations": [{"path": ORDERS_PATH, "line_start": 5, "line_end": 8}],
        "changes": [whole_file_change(ORDERS_PATH, ORDERS_SOURCE, ORDERS_REPAIRED)],
        "regression_tests": [_spec()],
    }
    actions = iter([ProviderAction("propose_patch", arguments), ProviderAction("request_verification", {})])

    class _Provider:
        async def next_action(self, messages, tools):
            return next(actions, ProviderAction("abstain", {"reason_code": "script_exhausted", "explanation": "The scripted provider has no further action."}))

    agent = RepairAgent(_Provider(), Verifier(InProcessSandboxBroker(LocalSubprocessDriver())))
    response = await RepairEngine(lambda request: agent).repair(RepairRequest.model_validate(_orders_payload(request_payload)))
    assert response.state == "ready", response.reason
    candidate = response.candidates[0]
    assert candidate.finding_ids == ["finding-sqli"]
    assert [entry["path"] for entry in candidate.file_manifest["files"]] == [ORDERS_PATH]
    assert [entry["path"] for entry in candidate.generated_tests] == [ORDERS_TEST_PATH]
    assert all(entry["path"] != HARNESS_PATH for entry in response.evidence["batch_manifest"]["generated_tests"])
    checks = {item["check_id"]: item for item in response.evidence["verification_run"]["checks"]}
    regression = checks["generated_regression_test"]
    assert regression["baseline"]["status"] == "failed" and regression["candidate"]["status"] == "passed"
    assert "MODULE_NOT_FOUND" not in (regression["baseline"].get("output_tail") or "")


def test_patch_policy_rejects_a_proposal_that_writes_the_harness(request_payload):
    request = RepairRequest.model_validate(_orders_payload(request_payload))
    snapshot = Snapshot(request)
    hunk = {"path": HARNESS_PATH, "start_line": 1, "original_lines": ["'use strict';"], "replacement_lines": ["module.exports = {};"]}
    with pytest.raises(PatchPolicyError, match="harness_path_protected") as rejected:
        apply_hunks(snapshot, [hunk])
    assert "require('../harness')" in rejected.value.guidance
    with pytest.raises(PatchPolicyError, match="protected_path:.mitig8it/regression/x.test.js"):
        apply_hunks(snapshot, [{**hunk, "path": ".mitig8it/regression/x.test.js"}])
    with pytest.raises(PatchPolicyError, match="harness_path_protected"):
        _bundle(request, snapshot, _spec(path=HARNESS_PATH))


def test_patch_policy_rejects_a_test_that_requires_a_package_and_names_the_harness(request_payload):
    request = RepairRequest.model_validate(_orders_payload(request_payload))
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError, match="missing_dependency:supertest") as rejected:
        _bundle(request, snapshot, _spec(SUPERTEST_TEST))
    guidance = rejected.value.guidance
    assert HARNESS_PATH in guidance and "require('../harness')" in guidance
    # express and pg are declared in package.json but never installed in the sandbox, so a test
    # must not require them either.
    with pytest.raises(PatchPolicyError, match="missing_dependency:express"):
        _bundle(request, snapshot, _spec("const express = require('express');\nrequire('../../services/orders.js');\nprocess.exit(1);\n"))


def test_a_harness_test_that_also_reads_a_file_is_a_behavior_test(request_payload):
    """`h.load(<repository path>)` loads the module, so the text-only rule does not fire."""
    request = RepairRequest.model_validate(_orders_payload(request_payload))
    snapshot = Snapshot(request)
    content = HARNESS_TEST.replace("h.run(async () => {\n", "h.run(async () => {\n  require('node:fs').readFileSync(__filename);\n")
    bundle = _bundle(request, snapshot, _spec(content))
    assert [test.path for test in bundle.generated_tests] == [ORDERS_TEST_PATH]


def test_prompt_and_tool_guidance_name_the_harness():
    assert "require('../harness')" in SYSTEM_PROMPT
    assert HARNESS_PATH in SYSTEM_PROMPT
    assert "Module._load" not in SYSTEM_PROMPT
    for family_hint in ("h.pg.queries", "h.child_process.calls", "h.fs.reads", "h.invoke("):
        assert family_hint in SYSTEM_PROMPT
    propose = next(tool for tool in tool_definitions() if tool["function"]["name"] == "propose_patch")
    description = propose["function"]["parameters"]["properties"]["regression_tests"]["description"]
    assert "require('../harness')" in description and "supertest" in description
