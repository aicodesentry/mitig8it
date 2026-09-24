"""Agent-generated regression tests as verification checks.

These exercise the path a real repository takes: no fixture script, no policy-supplied
verification profile, and a reproducer the agent had to write. Every run here uses the real
local subprocess driver, so the generated test is actually executed on both trees.
"""
from __future__ import annotations

import shutil

import pytest

from src.agent import ProviderAction, RepairAgent
from src.digests import content_sha256
from src.engine import RepairEngine
from src.models import RepairRequest
from src.patches import PatchPolicyError, build_patch_bundle
from src.retrieval import Snapshot
from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver
from src.verification import Verifier
from src.verification.checks import build_effective_checks
from tests.conftest import (
    MODEL_ONLY_LINE,
    MODEL_ONLY_REPAIRED,
    MODEL_ONLY_SOURCE,
    NON_REPRODUCING_REGRESSION_TEST,
    REGRESSION_TEST_PATH,
    REPRODUCING_REGRESSION_TEST,
    git_blob,
    regression_test_spec,
    whole_file_change,
)

requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="generated regression tests run under node")

# The shared model-path source: its SQL text is built a hop away, so the deterministic template
# declines it and these tests still have a model pass to exercise. See conftest.MODEL_ONLY_SOURCE.
JS_SOURCE = MODEL_ONLY_SOURCE
JS_REPAIRED = MODEL_ONLY_REPAIRED
JS_BROKEN = MODEL_ONLY_REPAIRED.replace("return db.query(sql, [id]);", "return db.query(sql, [id;")

# A method on a class. The service declines to generate a proof for one (`method_receiver_not_supported`:
# it would have to construct a receiver it cannot derive), and the template pass is skipped with it,
# so the only test this repository can ship is the model's. The two tests about what happens when
# that test reproduces, or is missing entirely, need a finding in exactly that position.
METHOD_SOURCE = (
    "class UserStore {\n"
    "  constructor(db) {\n"
    "    this.db = db;\n"
    "  }\n"
    "  loadUser(id) {\n"
    "    return this.db.query(\"SELECT * FROM users WHERE id = '\" + id + \"'\");\n"
    "  }\n"
    "}\n"
    "module.exports = { UserStore };\n"
)
METHOD_REPAIRED = METHOD_SOURCE.replace(
    "return this.db.query(\"SELECT * FROM users WHERE id = '\" + id + \"'\");",
    "return this.db.query('SELECT * FROM users WHERE id = $1', [id]);",
)
METHOD_LINE = 6
METHOD_REGRESSION_TEST = (
    "const { UserStore } = require('../../src/db.js');\n"
    "let text = '';\n"
    "new UserStore({ query: (sql) => { text = String(sql); } }).loadUser('1 OR 1=1');\n"
    "process.exit(text.includes('1 OR 1=1') ? 1 : 0);\n"
)

# Loads the changed module by relative path and exercises it with an injection payload: the
# payload reaches the SQL text on the original code and is a bound parameter on the repair.
JS_REGRESSION_TEST = (
    "const { loadUser } = require('../../src/db.js');\n"
    "let text = '';\n"
    "loadUser({ query: (sql) => { text = String(sql); } }, '1 OR 1=1');\n"
    "process.exit(text.includes('1 OR 1=1') ? 1 : 0);\n"
)
# Reads the changed file as text and never loads it: it can only assert on wording.
JS_TEXT_ONLY_TEST = (
    "const fs = require('node:fs');\n"
    "const path = require('node:path');\n"
    "const source = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'db.js'), 'utf8');\n"
    "process.exit(source.includes(\"+ id +\") ? 1 : 0);\n"
)


def _no_profile_payload(request_payload, *, source=JS_SOURCE, line=MODEL_ONLY_LINE):
    """A request that looks like a real repository: JavaScript source, no fixture checks."""
    from src.git_tree import compute_tree_oid
    from src.models import GitTreeEntry

    manifest = '{"dependencies":{"pg":"8.13.0"}}\n'
    entries = [
        GitTreeEntry(path="src/db.js", mode="100644", type="blob", sha=git_blob(source)),
        GitTreeEntry(path="package.json", mode="100644", type="blob", sha=git_blob(manifest)),
    ]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [
        {"path": "src/db.js", "content": source, "sha": git_blob(source)},
        {"path": "package.json", "content": manifest, "sha": git_blob(manifest)},
    ]
    payload["findings"] = [
        {"snapshot_id": "finding-1", "rule_id": "js.sql-injection", "cwe_id": "CWE-89", "file_path": "src/db.js", "line_start": line, "line_end": line}
    ]
    payload["policy"] = {
        **request_payload["policy"],
        "sandbox_image_digest": None,
        "allow_development_verification": True,
        # A repository with no fixture supplies no checks at all.
        "verification_checks": [],
    }
    return payload


def _spec(content, path=REGRESSION_TEST_PATH, finding_id="finding-1"):
    return {"finding_id": finding_id, "path": path, "content": content}


def _run_engine(payload, *, source=JS_SOURCE, replacement=JS_REPAIRED, regression_test=None, regression_tests=None):
    arguments = {
        "hypothesis": "Untrusted id is interpolated into SQL text.",
        "intended_behavior": "Load the same user by id.",
        "assumptions": ["pg positional parameters are available"],
        "citations": [{"path": "src/db.js", "line_start": 1, "line_end": 8}],
        "changes": [whole_file_change("src/db.js", source, replacement)],
    }
    if regression_tests is not None:
        arguments["regression_tests"] = regression_tests
    elif regression_test is not None:
        arguments["regression_tests"] = [regression_test]
    # A partial proof asks for a coverage revision; this scripted model declines it, so the
    # proven subset ships exactly as it did before revisions existed.
    actions = iter(
        [
            ProviderAction("propose_patch", arguments),
            ProviderAction("request_verification", {}),
            ProviderAction("abstain", {"reason_code": "no_further_repair", "explanation": "Nothing more to add."}),
        ]
    )

    class _Provider:
        async def next_action(self, messages, tools):
            return next(actions, ProviderAction("abstain", {"reason_code": "script_exhausted", "explanation": "The scripted provider has no further action."}))

    agent = RepairAgent(_Provider(), Verifier(InProcessSandboxBroker(LocalSubprocessDriver())))
    return RepairEngine(lambda request: agent).repair(RepairRequest.model_validate(payload))


@requires_node
@pytest.mark.asyncio
async def test_reproducing_generated_test_makes_a_repository_without_fixtures_ready(request_payload):
    """The whole point: no policy checks, and the candidate still reaches `ready`.

    A method site, so the service writes no proof of its own and the model's test is the only
    one: this is the path a repository takes when nothing deterministic reaches its finding.
    """
    payload = _no_profile_payload(request_payload, source=METHOD_SOURCE, line=METHOD_LINE)
    response = await _run_engine(
        payload, source=METHOD_SOURCE, replacement=METHOD_REPAIRED, regression_test=_spec(METHOD_REGRESSION_TEST)
    )
    assert response.state == "ready", response.reason
    candidate = response.candidates[0]
    assert candidate.finding_ids == ["finding-1"]
    assert response.skipped == []
    assert [entry["path"] for entry in candidate.generated_tests] == [REGRESSION_TEST_PATH]
    assert candidate.generated_tests[0]["kind"] == "generated_regression_test"
    assert candidate.generated_tests[0]["finding_id"] == "finding-1"
    # The generated test is evidence, not part of the applied tree.
    assert [patch.path for patch in candidate.patch] == ["src/db.js"]
    assert all(entry["kind"] == "application" for entry in candidate.file_manifest["files"])
    assert response.evidence["batch_manifest"]["generated_tests"][0]["path"] == REGRESSION_TEST_PATH

    checks = {item["check_id"]: item for item in response.evidence["verification_run"]["checks"]}
    regression = checks["generated_regression_test"]
    assert regression["kind"] == "exploit" and regression["argv"] == ["node", REGRESSION_TEST_PATH]
    assert regression["baseline"]["status"] == "failed" and regression["candidate"]["status"] == "passed"
    syntax = checks["generated_node_syntax"]
    assert syntax["argv"] == ["node", "--check", "src/db.js"] and syntax["candidate"]["status"] == "passed"


@requires_node
@pytest.mark.asyncio
async def test_a_generated_test_that_passes_on_the_baseline_is_inconclusive(request_payload):
    passing_on_both = "require('../../src/db.js');\nprocess.exit(0);\n"
    response = await _run_engine(_no_profile_payload(request_payload), regression_test=_spec(passing_on_both))
    assert response.state == "inconclusive"
    assert response.reason["code"] == "regression_test_not_reproducing"
    assert response.candidates == []


@pytest.mark.asyncio
async def test_a_missing_generated_test_is_inconclusive_and_never_ready(request_payload):
    """A method site again: with no service proof either, a missing model test leaves nothing."""
    payload = _no_profile_payload(request_payload, source=METHOD_SOURCE, line=METHOD_LINE)
    response = await _run_engine(payload, source=METHOD_SOURCE, replacement=METHOD_REPAIRED, regression_test=None)
    assert response.state == "inconclusive"
    assert response.reason["code"] == "regression_test_not_reproducing"
    assert response.candidates == []


@requires_node
def test_an_unparseable_candidate_is_rejected_before_any_verification_run(request_payload):
    """The local `node --check` in patch policy stops an unparseable candidate at proposal time."""
    request = RepairRequest.model_validate(_no_profile_payload(request_payload))
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError, match="candidate_syntax_invalid:src/db.js"):
        build_patch_bundle(
            request,
            snapshot,
            [whole_file_change("src/db.js", JS_SOURCE, JS_BROKEN)],
            [_spec(JS_REGRESSION_TEST)],
        )


@requires_node
@pytest.mark.asyncio
async def test_node_check_failure_at_verification_time_is_failed(request_payload):
    """When only the sandbox sees the parse failure, the verification run reports `failed`."""
    payload = _no_profile_payload(request_payload)
    request = RepairRequest.model_validate(payload)
    snapshot = Snapshot(request)
    bundle = build_patch_bundle(
        request,
        snapshot,
        [whole_file_change("src/db.js", JS_SOURCE, JS_REPAIRED)],
        [_spec(JS_REGRESSION_TEST)],
    )
    # Replace the validated patch with unparseable content to reach the sandbox `node --check`.
    broken = bundle.patches[0].model_copy(
        update={"replacement_content": JS_BROKEN, "new_sha256": content_sha256(JS_BROKEN)}
    )
    unchecked = bundle.__class__(
        (broken,), bundle.artifact_digest, bundle.changed_lines, bundle.limitations, bundle.generated_tests
    )
    result = await Verifier(InProcessSandboxBroker(LocalSubprocessDriver())).verify(request, snapshot, unchecked)
    assert result.status == "failed"
    assert result.reason_code == "verification_failed"
    syntax = next(item for item in result.evidence["checks"] if item["check_id"] == "generated_node_syntax")
    assert syntax["baseline"]["status"] == "passed" and syntax["candidate"]["status"] == "failed"


@pytest.mark.parametrize(
    "path",
    [
        "src/db.js",
        "tests/exploit.test.js",
        "regression/finding-1.test.js",
        ".mitig8it/regression/nested/finding-1.test.js",
        ".mitig8it/other/finding-1.test.js",
        "package.json",
    ],
)
def test_a_generated_test_outside_its_directory_is_rejected(request_payload, source, path):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError):
        build_patch_bundle(
            request,
            snapshot,
            [whole_file_change("src/db.ts", source, source + "\n")],
            [_spec(REPRODUCING_REGRESSION_TEST, path=path)],
        )


def test_a_generated_test_cannot_overwrite_an_application_file(request_payload, source):
    """Even inside the generated directory, a path the snapshot already carries is refused."""
    payload = dict(request_payload)
    occupied = dict(payload["files"][0])
    payload = {**payload, "files": list(payload["files"])}
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    assert occupied["path"] in snapshot.paths
    with pytest.raises(PatchPolicyError, match="regression_test_outside_generated_directory"):
        build_patch_bundle(
            request,
            snapshot,
            [whole_file_change("src/db.ts", source, source + "\n")],
            [_spec(REPRODUCING_REGRESSION_TEST, path=occupied["path"])],
        )


def test_a_generated_test_may_not_import_an_undeclared_dependency(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError, match="missing_dependency:supertest"):
        build_patch_bundle(
            request,
            snapshot,
            [whole_file_change("src/db.ts", source, source + "\n")],
            [_spec("require('supertest');\nprocess.exit(1);\n")],
        )


def test_policy_supplied_checks_still_run_and_generated_checks_are_additive(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    bundle = build_patch_bundle(
        request,
        snapshot,
        [whole_file_change("src/db.ts", source, source + "\n")],
        [regression_test_spec()],
    )
    effective = build_effective_checks(request, snapshot, bundle)
    identifiers = [check.check_id for check in effective.checks]
    assert identifiers[:2] == ["exploit", "behavior"]
    assert "generated_regression_test" in identifiers
    assert effective.regression_check_ids == {"generated_regression_test"}
    assert effective.generated_files == ({"path": REGRESSION_TEST_PATH, "content": REPRODUCING_REGRESSION_TEST},)
    # src/db.ts is TypeScript, so node --check cannot parse it and no syntax check is derived.
    assert not any(item.startswith("generated_node_syntax") for item in identifiers)


def test_the_repository_test_script_is_skipped_with_a_recorded_limitation(request_payload, source):
    payload = dict(request_payload)
    manifest = '{"scripts":{"test":"node --test"},"dependencies":{"pg":"8.13.0"}}\n'
    payload["files"] = [
        payload["files"][0],
        {"path": "package.json", "content": manifest, "sha": git_blob(manifest)},
    ]
    payload["tree_entries"] = [
        payload["tree_entries"][0],
        {"path": "package.json", "mode": "100644", "type": "blob", "sha": git_blob(manifest)},
    ]
    payload["policy"] = {**payload["policy"], "run_repository_tests": True}
    request = RepairRequest.model_validate(payload)
    snapshot = Snapshot(request)
    bundle = build_patch_bundle(
        request,
        snapshot,
        [whole_file_change("src/db.ts", source, source + "\n")],
        [regression_test_spec()],
    )
    effective = build_effective_checks(request, snapshot, bundle)
    assert not any(check.argv[:2] == ["npm", "test"] for check in effective.checks)
    assert any("no installed dependencies" in item for item in effective.limitations)


def test_non_reproducing_content_is_still_accepted_by_patch_policy(request_payload, source):
    """Patch policy checks shape, not behavior: only the sandbox run can prove reproduction."""
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    bundle = build_patch_bundle(
        request,
        snapshot,
        [whole_file_change("src/db.ts", source, source + "\n")],
        [regression_test_spec(NON_REPRODUCING_REGRESSION_TEST)],
    )
    assert bundle.generated_tests[0].path == REGRESSION_TEST_PATH
