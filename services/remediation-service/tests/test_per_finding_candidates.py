"""One verified candidate per finding, and no unproven hunk in any of them.

A group proposal carries hunks for several findings. After verification the engine attributes
each hunk to a finding (by the proposer's tag, else by line proximity), drops every hunk owned
by an unproven finding, rebuilds one candidate per proven finding with only its hunks and the
prerequisites they use, verifies each on its own, and verifies the combined batch as before.
"""
from __future__ import annotations

import pytest

from src.agent import ProviderAction, RepairAgent
from src.engine import RepairEngine, evidence_summary
from src.models import RepairRequest
from src.patches import LocatedHunk, PatchPolicyError, build_patch_bundle, combine_patch_bundles
from src.retrieval import Snapshot
from src.splitting import attribute_hunks, imported_names, is_import_only, split_hunks
from src.verification import Verifier
from tests.conftest import whole_file_change
from tests.test_coverage_revision import CANDIDATE_TAIL, SelectiveBroker, _abstain, _payload, _test, _verify
from tests.test_engine import PassingBroker, ScriptedProvider

SOURCE = (
    "const { Pool } = require('pg');\n"
    "const { exec } = require('child_process');\n"
    "function loadUser(db, id) {\n"
    "  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n"
    "}\n"
    "function render(id, cb) {\n"
    "  return exec(`render --order ${id}`, cb);\n"
    "}\n"
    "function archive(name, cb) {\n"
    "  return exec(`tar -czf ${name}.tgz`, cb);\n"
    "}\n"
    "module.exports = { loadUser, render, archive, Pool };\n"
)
FINDINGS = [
    {"snapshot_id": "f-sql", "rule_id": "js.sql-injection", "cwe_id": "CWE-89", "file_path": "src/app.js", "line_start": 4, "line_end": 4},
    {"snapshot_id": "f-exec", "rule_id": "js.command-injection", "cwe_id": "CWE-78", "file_path": "src/app.js", "line_start": 7, "line_end": 7},
    {"snapshot_id": "f-tar", "rule_id": "js.command-injection", "cwe_id": "CWE-78", "file_path": "src/app.js", "line_start": 10, "line_end": 10},
]
IMPORT_HUNK = {
    "path": "src/app.js",
    "finding_id": "f-exec",
    "start_line": 2,
    "original_lines": ["const { exec } = require('child_process');"],
    "replacement_lines": ["const { exec } = require('child_process');", "const { execFile } = require('child_process');"],
}
SQL_HUNK = {
    "path": "src/app.js",
    "finding_id": "f-sql",
    "start_line": 4,
    "original_lines": ["  return db.query(`SELECT * FROM users WHERE id = ${id}`);"],
    "replacement_lines": ["  return db.query('SELECT * FROM users WHERE id = $1', [id]);"],
}
EXEC_HUNK = {
    "path": "src/app.js",
    "finding_id": "f-exec",
    "start_line": 7,
    "original_lines": ["  return exec(`render --order ${id}`, cb);"],
    "replacement_lines": ["  return execFile('render', ['--order', id], cb);"],
}
TAR_HUNK = {
    "path": "src/app.js",
    "finding_id": "f-tar",
    "start_line": 10,
    "original_lines": ["  return exec(`tar -czf ${name}.tgz`, cb);"],
    "replacement_lines": ["  return execFile('tar', ['-czf', name + '.tgz'], cb);"],
}


def _request(request_payload, findings=FINDINGS, **policy):
    return RepairRequest.model_validate(_payload(request_payload, findings=findings, files=[("src/app.js", SOURCE), ("package.json", '{"dependencies":{"pg":"8.13.0"}}\n')], **policy))


def _propose(changes, finding_ids, call_id="propose"):
    return ProviderAction(
        "propose_patch",
        {
            "hypothesis": "Untrusted input reaches a sink.",
            "intended_behavior": "Preserve the documented behavior for legitimate input.",
            "assumptions": ["pg positional parameters are available"],
            "citations": [{"path": "src/app.js", "line_start": 1, "line_end": 12}],
            "changes": changes,
            "regression_tests": [_test(finding_id) for finding_id in finding_ids],
        },
        call_id=call_id,
    )


async def _repair(request, actions, broker):
    agent = RepairAgent(ScriptedProvider(actions), Verifier(broker))
    return await RepairEngine(lambda prepared: agent).repair(request)


# --- attribution -----------------------------------------------------------------------------------


def test_hunks_are_attributed_by_tag_and_untagged_ones_by_proximity(request_payload):
    request = _request(request_payload)
    snapshot = Snapshot(request)
    untagged = {key: value for key, value in TAR_HUNK.items() if key != "finding_id"}
    bundle = build_patch_bundle(request, snapshot, [IMPORT_HUNK, SQL_HUNK, EXEC_HUNK, untagged])
    attribution = attribute_hunks(request.findings, bundle.hunks)
    assert [hunk.finding_id for hunk in bundle.hunks] == ["f-exec", "f-sql", "f-exec", None]
    # The import-only hunk is a prerequisite shared by use: both execFile hunks need it, the
    # SQL hunk does not. The untagged tar hunk goes to the finding on its line.
    assert attribution.prerequisites == frozenset({0})
    assert attribution.owners == {0: "f-exec", 1: "f-sql", 2: "f-exec", 3: "f-tar"}
    assert attribution.per_finding == {"f-sql": [1], "f-exec": [0, 2], "f-tar": [0, 3]}
    assert is_import_only(bundle.hunks[0]) and not is_import_only(bundle.hunks[2])
    assert imported_names(bundle.hunks[0]) == {"execFile"}


def test_a_hunk_owned_by_an_unproven_finding_is_dropped_and_a_prerequisite_survives_by_use(request_payload):
    request = _request(request_payload)
    snapshot = Snapshot(request)
    bundle = build_patch_bundle(request, snapshot, [IMPORT_HUNK, SQL_HUNK, EXEC_HUNK, TAR_HUNK])
    plan = split_hunks(request.findings, bundle.hunks, ["f-sql", "f-tar"])
    # f-exec is unproven: its hunk is gone everywhere, but the import it was tagged with stays
    # in the f-tar candidate because that hunk uses execFile.
    assert [hunk.start_line for hunk in plan["f-sql"]] == [4]
    assert [hunk.start_line for hunk in plan["f-tar"]] == [2, 10]
    assert "f-exec" not in plan


def test_a_co_located_finding_shares_the_hunk_that_fixes_both(request_payload):
    findings = FINDINGS[:1] + [{**FINDINGS[0], "snapshot_id": "f-sql-2", "rule_id": "js.sql-concat"}]
    request = _request(request_payload, findings=findings)
    bundle = build_patch_bundle(request, Snapshot(request), [SQL_HUNK])
    plan = split_hunks(request.findings, bundle.hunks, ["f-sql", "f-sql-2"])
    assert [hunk.start_line for hunk in plan["f-sql"]] == [4]
    assert [hunk.start_line for hunk in plan["f-sql-2"]] == [4]
    # The tagged owner decides dropping: an unproven owner takes the hunk away from both.
    assert split_hunks(request.findings, bundle.hunks, ["f-sql-2"]) == {"f-sql-2": []}


def test_python_import_only_hunks_bind_their_aliases():
    hunk = LocatedHunk("app.py", 1, 1, ("import sqlite3",), ("import sqlite3", "import os", "from ast import literal_eval as parse"), None)
    assert is_import_only(hunk)
    # The retained line binds nothing new; only the added imports count.
    assert imported_names(hunk) == {"os", "parse"}
    mixed = LocatedHunk("app.py", 1, 1, ("import sqlite3",), ("import os", "KEY = os.environ['KEY']"), None)
    assert not is_import_only(mixed)
    # A widened require is still import-only, and only the names it newly binds count.
    widened = LocatedHunk(
        "src/app.js", 2, 2, ("const { exec } = require('child_process');",), ("const { exec, execFile } = require('child_process');",), None
    )
    assert is_import_only(widened) and imported_names(widened) == {"execFile"}
    rewritten = LocatedHunk("src/app.js", 2, 2, ("const { exec } = require('child_process');",), ("const cp = require('child_process');", "cp.exec('x');"), None)
    assert not is_import_only(rewritten)


def test_a_hunk_naming_an_unknown_finding_is_rejected(request_payload):
    request = _request(request_payload)
    with pytest.raises(PatchPolicyError) as error:
        build_patch_bundle(request, Snapshot(request), [{**SQL_HUNK, "finding_id": "f-other"}])
    assert error.value.code == "hunk_finding_unknown" and "f-sql" in error.value.guidance


# --- the engine ------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_unproven_findings_hunk_never_ships_and_the_proven_finding_gets_its_own_candidate(request_payload):
    """The live failure: the credential-style finding is proven, the second finding's test still
    fails on the patch, and the published diff must not carry the second finding's hunk."""
    request = _request(request_payload, findings=FINDINGS[:2])
    broker = SelectiveBroker({"f-sql"}, still_failing={"f-exec"})
    actions = [_propose([IMPORT_HUNK, SQL_HUNK, EXEC_HUNK], ["f-sql", "f-exec"]), _verify("verify-1"), _abstain()]
    response = await _repair(request, actions, broker)
    assert response.state == "ready", response.reason
    [candidate] = response.candidates
    assert candidate.finding_ids == ["f-sql"]
    replacement = candidate.patch[0].replacement_content
    assert "$1" in replacement and "execFile" not in replacement
    assert candidate.preview["hunks"] == [{"path": "src/app.js", "start_line": 4, "end_line": 4, "finding_id": "f-sql"}]
    assert [entry["path"] for entry in candidate.generated_tests] == [".mitig8it/regression/f-sql.test.js"]
    # The group run, then the f-sql candidate on its own tree; the batch of one needs no more.
    assert len(broker.runs) == 2
    assert [(item["finding_id"], item["code"]) for item in response.skipped] == [("f-exec", "not_repaired")]
    group = response.evidence["groups"][0]
    assert group["repaired_finding_ids"] == ["f-sql"] and group["candidate_ids"] == [candidate.candidate_id]
    assert candidate.preview["evidence"]["summary"][0] == (
        "Regression test .mitig8it/regression/f-sql.test.js failed on the original code and passed on the fix."
    )


@pytest.mark.asyncio
async def test_two_proven_findings_become_two_candidates_that_share_the_import_once(request_payload):
    request = _request(request_payload, findings=FINDINGS[1:])
    broker = SelectiveBroker({"f-exec", "f-tar"})
    actions = [_propose([IMPORT_HUNK, EXEC_HUNK, TAR_HUNK], ["f-exec", "f-tar"]), _verify("verify-1")]
    response = await _repair(request, actions, broker)
    assert response.state == "ready", response.reason
    assert [candidate.finding_ids for candidate in response.candidates] == [["f-exec"], ["f-tar"]]
    by_finding = {candidate.finding_ids[0]: candidate for candidate in response.candidates}
    exec_lines = by_finding["f-exec"].patch[0].replacement_content
    tar_lines = by_finding["f-tar"].patch[0].replacement_content
    assert "execFile('render'" in exec_lines and "execFile('tar'" not in exec_lines
    assert "execFile('tar'" in tar_lines and "execFile('render'" not in tar_lines
    assert exec_lines.count("const { execFile }") == 1 and tar_lines.count("const { execFile }") == 1
    # The batch applies the shared import once and is verified on the union.
    combined = response.evidence["verification_run"]
    assert response.evidence["batch_manifest"]["ordered_candidate_ids"] == [candidate.candidate_id for candidate in response.candidates]
    assert {check["argv"][-1] for check in combined["checks"] if check["kind"] == "exploit" and check["argv"][0] == "node"} == {
        ".mitig8it/regression/f-exec.test.js",
        ".mitig8it/regression/f-tar.test.js",
    }
    # Group run, two per-finding runs, one combined run.
    assert len(broker.runs) == 4
    assert response.skipped == []


@pytest.mark.asyncio
async def test_a_finding_proven_only_with_a_dropped_hunk_is_reported_dependent_hunk_unproven(request_payload):
    class DependentBroker(SelectiveBroker):
        """f-sql's test passes on a candidate only while f-exec's hunk is in the tree."""

        async def verify(self, payload, timeout_seconds):
            evidence = await super().verify(payload, timeout_seconds)
            tree = "".join(patch["replacement_content"] for patch in payload["patches"])
            for check in evidence["checks"]:
                if check["argv"][-1].endswith("f-sql.test.js") and "execFile" not in tree:
                    check["candidate"] = {"completed": True, "status": "failed", "output_tail": CANDIDATE_TAIL}
            return evidence

    request = _request(request_payload, findings=FINDINGS[:2])
    actions = [_propose([IMPORT_HUNK, SQL_HUNK, EXEC_HUNK], ["f-sql", "f-exec"]), _verify("verify-1"), _abstain()]
    response = await _repair(request, actions, DependentBroker({"f-sql"}, still_failing={"f-exec"}))
    assert response.state == "inconclusive"
    assert response.reason["code"] == "dependent_hunk_unproven"
    assert response.candidates == []
    assert [(item["finding_id"], item["code"]) for item in response.skipped] == [("f-exec", "not_repaired"), ("f-sql", "dependent_hunk_unproven")]
    assert "not shipped" in response.skipped[1]["message"]
    group = response.evidence["groups"][0]
    assert group["state"] == "inconclusive" and group["candidate_ids"] == []
    assert [item["code"] for item in group["unproven_findings"]] == ["not_repaired", "dependent_hunk_unproven"]


@pytest.mark.asyncio
async def test_a_single_proven_finding_reuses_the_group_verification(request_payload):
    request = _request(request_payload, findings=FINDINGS[:1])
    broker = SelectiveBroker({"f-sql"})
    response = await _repair(request, [_propose([SQL_HUNK], ["f-sql"]), _verify("verify-1")], broker)
    assert response.state == "ready", response.reason
    assert len(broker.runs) == 1
    [candidate] = response.candidates
    assert candidate.verification.evidence_digest == response.evidence["batch_manifest"]["combined_verification_evidence_digest"]


# --- the batch -------------------------------------------------------------------------------------


def test_combining_candidates_applies_a_shared_hunk_once_and_keeps_every_hunk(request_payload):
    request = _request(request_payload)
    snapshot = Snapshot(request)
    first = build_patch_bundle(request, snapshot, [IMPORT_HUNK, EXEC_HUNK], [_test("f-exec")])
    second = build_patch_bundle(request, snapshot, [IMPORT_HUNK, TAR_HUNK], [_test("f-tar")])
    combined = combine_patch_bundles(request, snapshot, [first, second])
    content = combined.patches[0].replacement_content
    assert content.count("const { execFile } = require('child_process');") == 1
    assert "execFile('render'" in content and "execFile('tar'" in content
    assert [hunk.start_line for hunk in combined.hunks] == [2, 7, 10]
    assert {test.finding_id for test in combined.generated_tests} == {"f-exec", "f-tar"}
    other_import = {**IMPORT_HUNK, "replacement_lines": [IMPORT_HUNK["original_lines"][0], "const cp = require('child_process');"]}
    third = build_patch_bundle(request, snapshot, [other_import, {**TAR_HUNK, "replacement_lines": ["  return cp.execFile('tar', ['-czf', name + '.tgz'], cb);"]}])
    with pytest.raises(PatchPolicyError, match="overlapping_candidates"):
        combine_patch_bundles(request, snapshot, [first, third])


# --- evidence wording ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_evidence_summary_names_the_test_the_checks_and_what_did_not_run(request_payload):
    request = _request(request_payload, findings=FINDINGS[:1])
    response = await _repair(request, [_propose([SQL_HUNK], ["f-sql"]), _verify("verify-1")], SelectiveBroker({"f-sql"}))
    [candidate] = response.candidates
    summary = candidate.preview["evidence"]["summary"]
    assert summary[0] == "Regression test .mitig8it/regression/f-sql.test.js failed on the original code and passed on the fix."
    assert "Behavior check (behavior) passed on the fix." in summary
    assert "Syntax check (generated_node_syntax) passed on the fix." in summary
    assert "Not run: the repository's original test suite was not run." in summary
    assert "Not run: no scanner baseline/candidate finding comparison was run." in summary
    assert not any("exploit" in line for line in summary)


def test_evidence_summary_marks_an_incomplete_check(request_payload):
    from src.verification import VerificationResult

    request = _request(request_payload, findings=FINDINGS[:1])
    bundle = build_patch_bundle(request, Snapshot(request), [SQL_HUNK], [_test("f-sql")])
    verification = VerificationResult(
        "passed",
        {"checks": [
            {"check_id": "generated_regression_test", "kind": "exploit", "baseline": {"completed": True, "status": "failed"}, "candidate": {"completed": True, "status": "passed"}},
            {"check_id": "behavior", "kind": "behavior", "baseline": {"completed": True, "status": "passed"}, "candidate": {"completed": False}},
        ]},
        "sha256:" + "1" * 64,
        None,
        "independent_sandbox",
        [],
        ["f-sql"],
        [],
        {"generated_regression_test": "f-sql"},
    )
    assert evidence_summary(bundle, verification, ["check behavior did not complete on the candidate tree"]) == [
        "Regression test .mitig8it/regression/f-sql.test.js failed on the original code and passed on the fix.",
        "Behavior check (behavior) did not complete.",
        "Not run: check behavior did not complete on the candidate tree.",
    ]
