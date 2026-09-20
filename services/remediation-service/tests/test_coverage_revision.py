"""Coverage revisions: proving every supported finding of a group in one run.

The task prompt names each finding with its family and lines and states that propose_patch
carries one regression test per finding. When a verification proves only a strict subset, the
loop sends the model back once per revision with the unproven findings, their family assertion,
and their own test's failure tail, then re-verifies the combined proposal. The run stops when
every finding is proven, the revision or attempt budget is spent, or the model abstains, and the
final candidate claims exactly the proven findings.
"""
from __future__ import annotations

import json

import pytest

from src.agent import ProviderAction, RepairAgent
from src.agent.loop import REVISION_INSTRUCTION
from src.engine import RepairEngine
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.verification import Verifier
from tests.conftest import git_blob, regression_test_spec, whole_file_change
from tests.test_agent_budget import SettlingCheckpointStore
from tests.test_engine import PassingBroker, ScriptedProvider

SOURCE = (
    "const { Pool } = require('pg');\n"
    "const { exec } = require('child_process');\n"
    "const fs = require('fs');\n"
    "function loadUser(db, id) {\n"
    "  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n"
    "}\n"
    "function render(id, cb) {\n"
    "  return exec(`render --order ${id}`, cb);\n"
    "}\n"
    "function download(name, cb) {\n"
    "  return fs.readFile('/srv/reports/' + name, cb);\n"
    "}\n"
    "module.exports = { loadUser, render, download, Pool };\n"
)
SQL_FIXED = SOURCE.replace("db.query(`SELECT * FROM users WHERE id = ${id}`)", "db.query('SELECT * FROM users WHERE id = $1', [id])")
ALL_FIXED = (
    SQL_FIXED.replace("const { exec } = require('child_process');", "const { execFile } = require('child_process');")
    .replace("exec(`render --order ${id}`, cb)", "execFile('render', ['--order', id], cb)")
    .replace("fs.readFile('/srv/reports/' + name, cb)", "fs.readFile('/srv/reports/' + require('path').basename(name), cb)")
)
MANIFEST = '{"dependencies":{"pg":"8.13.0"}}\n'
FINDINGS = [
    {"snapshot_id": "f-sql", "rule_id": "js.sql-injection", "cwe_id": "CWE-89", "file_path": "src/app.js", "line_start": 5, "line_end": 5},
    {"snapshot_id": "f-exec", "rule_id": "js.command-injection", "cwe_id": "CWE-78", "file_path": "src/app.js", "line_start": 8, "line_end": 8},
    {"snapshot_id": "f-path", "rule_id": "js.path-traversal", "cwe_id": "CWE-22", "file_path": "src/app.js", "line_start": 11, "line_end": 11},
]
CANDIDATE_TAIL = "harness: HarnessAssertion: command ran through a shell: render --order x; id\n"


def _payload(request_payload, *, findings=FINDINGS, files=None, **policy):
    files = files or [("src/app.js", SOURCE), ("package.json", MANIFEST)]
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=git_blob(content)) for path, content in files]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": content, "sha": git_blob(content)} for path, content in files]
    payload["findings"] = list(findings)
    payload["policy"] = {**request_payload["policy"], **policy}
    return payload


def _test(finding_id: str) -> dict[str, str]:
    return regression_test_spec(path=f".mitig8it/regression/{finding_id}.test.js", finding_id=finding_id)


def _propose(replacement: str, finding_ids: list[str], *, path: str = "src/app.js", original: str = SOURCE, call_id: str = "propose") -> ProviderAction:
    return ProviderAction(
        "propose_patch",
        {
            "hypothesis": "Untrusted input reaches a sink without parameterization or containment.",
            "intended_behavior": "Preserve the documented behavior for legitimate input.",
            "assumptions": ["pg positional parameters are available"],
            "citations": [{"path": path, "line_start": 1, "line_end": 13}],
            "changes": [whole_file_change(path, original, replacement)],
            "regression_tests": [_test(finding_id) for finding_id in finding_ids],
        },
        call_id=call_id,
    )


def _verify(call_id: str = "verify") -> ProviderAction:
    return ProviderAction("request_verification", {}, call_id=call_id)


def _abstain() -> ProviderAction:
    return ProviderAction("abstain", {"reason_code": "no_further_repair", "explanation": "Nothing more to add."})


class SelectiveBroker(PassingBroker):
    """A regression test reproduces its finding only when its finding id is in `reproducing`.

    A test for a finding in `still_failing` fails on both trees and reports a failure tail, the
    shape of a repair that did not take; any other test passes on both trees.
    """

    def __init__(self, reproducing: set[str], still_failing: set[str] = frozenset()):
        self.reproducing = set(reproducing)
        self.still_failing = set(still_failing)
        self.runs: list[list[str]] = []

    async def verify(self, payload, timeout_seconds):
        evidence = await super().verify(payload, timeout_seconds)
        self.runs.append([check["check_id"] for check in evidence["checks"]])
        for check in evidence["checks"]:
            argv = check["argv"]
            if not (check["kind"] == "exploit" and argv[0] == "node" and argv[1].startswith(".mitig8it/regression/")):
                continue
            finding_id = argv[1].rsplit("/", 1)[-1].removesuffix(".test.js")
            if finding_id in self.still_failing:
                check["baseline"] = {"completed": True, "status": "failed", "output_tail": CANDIDATE_TAIL}
                check["candidate"] = {"completed": True, "status": "failed", "output_tail": CANDIDATE_TAIL}
            elif finding_id not in self.reproducing:
                check["baseline"] = {"completed": True, "status": "passed"}
        return evidence


class RecordingProvider(ScriptedProvider):
    def __init__(self, actions):
        super().__init__(actions)
        self.seen: list[list[dict]] = []

    async def next_action(self, messages, tools):
        self.seen.append([dict(message) for message in messages])
        return await super().next_action(messages, tools)


def _tool_result(messages: list[dict], call_id: str) -> dict:
    return json.loads(next(message["content"] for message in messages if message.get("tool_call_id") == call_id))


async def _run(payload, actions, broker, checkpoints=None):
    request = RepairRequest.model_validate(payload)
    provider = RecordingProvider(actions)
    agent = RepairAgent(provider, Verifier(broker), checkpoints)
    result = await RepairEngine(lambda prepared: agent).repair(request)
    return result, provider


# --- the up-front expectation --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_task_prompt_names_every_finding_with_family_and_lines_and_the_test_expectation(request_payload):
    _, provider = await _run(_payload(request_payload), [_abstain()], SelectiveBroker(set()))
    task = json.loads(provider.seen[0][1]["content"])
    assert [(f["id"], f["family"], f["path"], f["line_start"], f["line_end"]) for f in task["findings"]] == [
        ("f-sql", "sql_parameterization", "src/app.js", 5, 5),
        ("f-exec", "command_arguments", "src/app.js", 8, 8),
        ("f-path", "path_containment", "src/app.js", 11, 11),
    ]
    assert "one regression test per finding" in task["coverage"] and "not_repaired" in task["coverage"]


@pytest.mark.asyncio
async def test_propose_patch_reports_which_findings_still_lack_a_test(request_payload):
    actions = [_propose(SQL_FIXED, ["f-sql"]), _abstain()]
    _, provider = await _run(_payload(request_payload), actions, SelectiveBroker({"f-sql"}))
    accepted = _tool_result(provider.seen[1], "propose")
    assert accepted["findings_with_test"] == ["f-sql"]
    assert accepted["findings_without_test"] == ["f-exec", "f-path"]
    assert "not_repaired" in accepted["note"]


# --- the bounded coverage revision -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_partial_proof_is_revised_once_and_the_revision_proves_the_rest(request_payload):
    """One of three findings proven, the revision proves all three, the candidate claims all three."""
    actions = [
        _propose(SQL_FIXED, ["f-sql"]),
        _verify("verify-1"),
        _propose(ALL_FIXED, ["f-sql", "f-exec", "f-path"], call_id="propose-2"),
        _verify("verify-2"),
    ]
    broker = SelectiveBroker({"f-sql", "f-exec", "f-path"})
    checkpoints = SettlingCheckpointStore()
    response, provider = await _run(_payload(request_payload), actions, broker, checkpoints)

    assert response.state == "ready", response.reason
    assert response.candidates[0].finding_ids == ["f-exec", "f-path", "f-sql"]
    assert response.skipped == []
    assert response.candidates[0].patch[0].replacement_content == ALL_FIXED
    # The revision message named exactly the unproven findings with lines, assertion, and test path.
    revision = _tool_result(provider.seen[2], "verify-1")["coverage_revision"]
    assert revision["proven_finding_ids"] == ["f-sql"]
    assert [(item["finding_id"], item["family"], item["line_start"]) for item in revision["unproven"]] == [
        ("f-exec", "command_arguments", 8),
        ("f-path", "path_containment", 11),
    ]
    assert "h.assert.argv(h.child_process.calls[0], payload)" in revision["unproven"][0]["assertion"]
    assert "h.assert.inside(r, base)" in revision["unproven"][1]["assertion"]
    assert revision["unproven"][0]["expected_test_path"] == ".mitig8it/regression/f-exec.test.js"
    assert revision["instruction"] == REVISION_INSTRUCTION
    assert revision["revision"] == 1 and revision["max_revisions"] == 2
    # Both verifications ran, the revision spent an attempt, and every provider call was reserved.
    assert len(broker.runs) == 2
    assert [step["outcome"] for step in response.evidence["agent_trace"]] == ["ok", "revision_requested", "ok", "ok"]
    assert response.evidence["agent_trace"][1]["reason"] == "partial_coverage"
    assert len(checkpoints.settled) == 4
    group = response.evidence["groups"][0]
    assert group["coverage"] == {"revisions_used": 1, "max_revisions": 2, "stopped": "all_proven", "proven_finding_ids": ["f-sql", "f-exec", "f-path"]}


@pytest.mark.asyncio
async def test_the_revision_shows_the_failure_tail_of_a_test_that_did_not_reproduce(request_payload):
    actions = [_propose(SQL_FIXED, ["f-sql", "f-exec", "f-path"]), _verify("verify-1"), _abstain()]
    broker = SelectiveBroker({"f-sql", "f-exec"}, still_failing={"f-exec"})
    response, provider = await _run(_payload(request_payload), actions, broker)
    revision = _tool_result(provider.seen[2], "verify-1")["coverage_revision"]
    by_id = {item["finding_id"]: item for item in revision["unproven"]}
    assert by_id["f-exec"]["code"] == "not_repaired"
    assert by_id["f-exec"]["test_path"] == ".mitig8it/regression/f-exec.test.js"
    assert by_id["f-exec"]["test_failure_tail"]["candidate"] == CANDIDATE_TAIL
    assert by_id["f-path"]["code"] == "regression_test_not_reproducing"
    assert "exited 0" in by_id["f-path"]["test_failure_tail"]["baseline"]
    assert response.state == "ready" and response.candidates[0].finding_ids == ["f-sql"]


@pytest.mark.asyncio
async def test_a_spent_revision_budget_leaves_the_proven_subset(request_payload):
    """max_revisions=1: the revision proves one more finding, then the run ships what was proven."""
    actions = [
        _propose(SQL_FIXED, ["f-sql"]),
        _verify("verify-1"),
        _propose(ALL_FIXED, ["f-sql", "f-exec", "f-path"], call_id="propose-2"),
        _verify("verify-2"),
        _verify("verify-3"),
    ]
    broker = SelectiveBroker({"f-sql", "f-exec"})
    response, provider = await _run(_payload(request_payload, max_revisions=1), actions, broker)
    assert response.state == "ready", response.reason
    assert response.candidates[0].finding_ids == ["f-exec", "f-sql"]
    assert [(item["finding_id"], item["code"]) for item in response.skipped] == [("f-path", "regression_test_not_reproducing")]
    assert len(provider.seen) == 4, "the run ended on the second verification"
    assert [step["outcome"] for step in response.evidence["agent_trace"]] == ["ok", "revision_requested", "ok", "ok"]
    assert response.evidence["groups"][0]["coverage"]["stopped"] == "revision_budget_spent"


@pytest.mark.asyncio
async def test_no_revision_budget_ships_the_first_proven_subset(request_payload):
    actions = [_propose(SQL_FIXED, ["f-sql"]), _verify("verify-1")]
    response, provider = await _run(_payload(request_payload, max_revisions=0), actions, SelectiveBroker({"f-sql"}))
    assert response.state == "ready" and response.candidates[0].finding_ids == ["f-sql"]
    assert len(provider.seen) == 2
    assert response.evidence["groups"][0]["coverage"]["stopped"] == "revision_budget_spent"


@pytest.mark.asyncio
async def test_a_revision_needs_an_attempt_left(request_payload):
    actions = [_propose(SQL_FIXED, ["f-sql"]), _verify("verify-1")]
    response, provider = await _run(_payload(request_payload, max_attempts=1), actions, SelectiveBroker({"f-sql"}))
    assert response.state == "ready" and response.candidates[0].finding_ids == ["f-sql"]
    assert len(provider.seen) == 2
    assert response.evidence["groups"][0]["coverage"]["stopped"] == "attempt_budget_spent"


@pytest.mark.asyncio
async def test_a_revision_that_proves_less_keeps_the_earlier_candidate(request_payload):
    """The revised proposal breaks the SQL test; the first verified candidate is what ships."""
    actions = [
        _propose(SQL_FIXED, ["f-sql", "f-exec"]),
        _verify("verify-1"),
        _propose(ALL_FIXED, ["f-sql", "f-exec", "f-path"], call_id="propose-2"),
        _verify("verify-2"),
    ]

    class BreakingBroker(SelectiveBroker):
        async def verify(self, payload, timeout_seconds):
            evidence = await super().verify(payload, timeout_seconds)
            if len(self.runs) == 2:
                for check in evidence["checks"]:
                    if check["argv"][-1].endswith("f-sql.test.js"):
                        check["candidate"] = {"completed": True, "status": "failed", "output_tail": "broken"}
            return evidence

    response, _ = await _run(_payload(request_payload, max_revisions=1), actions, BreakingBroker({"f-sql", "f-exec", "f-path"}))
    assert response.state == "ready", response.reason
    assert response.candidates[0].finding_ids == ["f-exec", "f-sql"]
    assert response.candidates[0].patch[0].replacement_content == SQL_FIXED


@pytest.mark.asyncio
async def test_a_revision_may_not_drop_a_proven_test_and_must_propose_before_reverifying(request_payload):
    actions = [
        _propose(SQL_FIXED, ["f-sql"]),
        _verify("verify-1"),
        _verify("verify-again"),
        _propose(ALL_FIXED, ["f-exec", "f-path"], call_id="propose-dropping"),
        _propose(ALL_FIXED, ["f-sql", "f-exec", "f-path"], call_id="propose-2"),
        _verify("verify-2"),
    ]
    response, provider = await _run(_payload(request_payload), actions, SelectiveBroker({"f-sql", "f-exec", "f-path"}))
    again = _tool_result(provider.seen[3], "verify-again")
    assert again["reason"] == "coverage_revision_requires_new_proposal"
    dropping = _tool_result(provider.seen[4], "propose-dropping")
    assert dropping["reason"] == "coverage_revision_drops_proven_test" and "f-sql" in dropping["guidance"]
    assert response.state == "ready" and response.candidates[0].finding_ids == ["f-exec", "f-path", "f-sql"]


@pytest.mark.asyncio
async def test_a_model_that_abstains_after_the_revision_request_ships_the_proven_subset(request_payload):
    actions = [_propose(SQL_FIXED, ["f-sql"]), _verify("verify-1"), _abstain()]
    response, _ = await _run(_payload(request_payload), actions, SelectiveBroker({"f-sql"}))
    assert response.state == "ready", response.reason
    assert response.candidates[0].finding_ids == ["f-sql"]
    assert [step["outcome"] for step in response.evidence["agent_trace"]] == ["ok", "revision_requested", "abstained"]
    coverage = response.evidence["groups"][0]["coverage"]
    assert coverage["revisions_used"] == 1 and coverage["stopped"] == "no_further_repair"


@pytest.mark.asyncio
async def test_a_run_that_exhausts_its_tool_budget_mid_revision_ships_the_proven_subset(request_payload):
    read = ProviderAction("read_file", {"path": "src/app.js", "line_start": 1, "line_end": 13}, call_id="read")
    actions = [_propose(SQL_FIXED, ["f-sql"]), _verify("verify-1"), read, read, read, read, read, read]
    response, _ = await _run(_payload(request_payload, max_tool_calls=6), actions, SelectiveBroker({"f-sql"}))
    assert response.state == "ready", response.reason
    assert response.candidates[0].finding_ids == ["f-sql"]
    assert response.evidence["groups"][0]["coverage"]["stopped"] == "tool_budget_exhausted"


@pytest.mark.asyncio
async def test_eviction_keeps_the_revision_request_in_the_working_set(request_payload):
    reads = [
        ProviderAction("read_file", {"path": "src/app.js", "line_start": 1, "line_end": 13}, call_id=f"read-{index}", output_tokens=64)
        for index in range(6)
    ]
    actions = [_propose(SQL_FIXED, ["f-sql"]), _verify("verify-1"), *reads, _abstain()]
    payload = _payload(request_payload, max_working_set_tokens=2_000, max_tool_calls=20)
    response, provider = await _run(payload, actions, SelectiveBroker({"f-sql"}))
    assert response.state == "ready"
    final = provider.seen[-1]
    verification_message = next(message for message in final if message.get("tool_call_id") == "verify-1")
    assert "coverage_revision" in verification_message["content"]
    evicted = [message for message in final if message.get("role") == "tool" and "evicted_context" in message["content"]]
    assert evicted, "earlier reads were evicted to fit the working set"


@pytest.mark.asyncio
async def test_the_checkpoint_carries_the_revision_state_and_the_best_candidate(request_payload):
    class RecordingStore(SettlingCheckpointStore):
        def __init__(self):
            super().__init__()
            self.states: list[dict] = []

        async def save_completed_step(self, state) -> None:
            self.states.append(state)

    store = RecordingStore()
    actions = [_propose(SQL_FIXED, ["f-sql"]), _verify("verify-1"), _abstain()]
    await _run(_payload(request_payload), actions, SelectiveBroker({"f-sql"}), store)
    after_verification = store.states[1]["coverage"]
    assert after_verification["revisions_used"] == 1 and after_verification["revision_pending"] is True
    assert after_verification["best"]["verification"]["proven_finding_ids"] == ["f-sql"]
    assert after_verification["best"]["proposal_arguments"]["regression_tests"] == [_test("f-sql")]


# --- end to end across files -----------------------------------------------------------------------

DB_SOURCE = "function loadUser(db, id) {\n  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n}\nmodule.exports = { loadUser };\n"
DB_FIXED = DB_SOURCE.replace("db.query(`SELECT * FROM users WHERE id = ${id}`)", "db.query('SELECT * FROM users WHERE id = $1', [id])")
CMD_SOURCE = "const { exec } = require('child_process');\nfunction render(id, cb) {\n  return exec(`render --order ${id}`, cb);\n}\nmodule.exports = { render };\n"
CMD_FIXED = "const { execFile } = require('child_process');\nfunction render(id, cb) {\n  return execFile('render', ['--order', id], cb);\n}\nmodule.exports = { render };\n"


@pytest.mark.asyncio
async def test_two_findings_across_files_in_one_group_are_both_proven_after_a_revision(request_payload):
    """The command finding's trace names the SQL file, so the two findings form one group; the
    first proposal patches only the SQL file and the revision adds the command file."""
    findings = [
        {"snapshot_id": "f-sql", "rule_id": "js.sql-injection", "cwe_id": "CWE-89", "file_path": "src/db.js", "line_start": 2, "line_end": 2},
        {
            "snapshot_id": "f-exec",
            "rule_id": "js.command-injection",
            "cwe_id": "CWE-78",
            "file_path": "src/cmd.js",
            "line_start": 3,
            "line_end": 3,
            "trace": [{"path": "src/db.js", "line": 2}, {"path": "src/cmd.js", "line": 3}],
        },
    ]
    files = [("src/db.js", DB_SOURCE), ("src/cmd.js", CMD_SOURCE), ("package.json", MANIFEST)]
    payload = _payload(request_payload, findings=findings, files=files)
    first = _propose(DB_FIXED, ["f-sql"], path="src/db.js", original=DB_SOURCE)
    second = ProviderAction(
        "propose_patch",
        {
            **first.arguments,
            "citations": [{"path": "src/db.js", "line_start": 1, "line_end": 4}, {"path": "src/cmd.js", "line_start": 1, "line_end": 5}],
            "changes": [whole_file_change("src/db.js", DB_SOURCE, DB_FIXED), whole_file_change("src/cmd.js", CMD_SOURCE, CMD_FIXED)],
            "regression_tests": [_test("f-sql"), _test("f-exec")],
        },
        call_id="propose-2",
    )
    launched: list[list[str]] = []

    def factory(prepared):
        launched.append([finding.stable_id for finding in prepared.findings])
        return RepairAgent(ScriptedProvider([first, _verify("verify-1"), second, _verify("verify-2")]), Verifier(SelectiveBroker({"f-sql", "f-exec"})))

    response = await RepairEngine(factory).repair(RepairRequest.model_validate(payload))
    assert launched == [["f-sql", "f-exec"]]
    assert response.state == "ready", response.reason
    assert len(response.candidates) == 1
    assert response.candidates[0].finding_ids == ["f-exec", "f-sql"]
    assert {patch.path for patch in response.candidates[0].patch} == {"src/db.js", "src/cmd.js"}
    assert response.skipped == []
    assert {entry["path"] for entry in response.candidates[0].generated_tests} == {
        ".mitig8it/regression/f-sql.test.js",
        ".mitig8it/regression/f-exec.test.js",
    }
    assert response.evidence["groups"][0]["coverage"]["stopped"] == "all_proven"


@pytest.mark.asyncio
async def test_a_failed_verification_names_each_unproven_finding_with_assertion_and_tail(request_payload):
    """Nothing proven: the verification result itself carries the family assertion and the tail,
    so the correction needs no inspect_failure call."""
    actions = [_propose(SQL_FIXED, ["f-exec"]), _verify("verify-1"), _abstain()]
    response, provider = await _run(_payload(request_payload), actions, SelectiveBroker(set(), still_failing={"f-exec"}))
    assert response.state == "unsupported" and response.reason["code"] == "no_further_repair"
    failed = _tool_result(provider.seen[2], "verify-1")
    assert failed["status"] == "failed" and "coverage_revision" not in failed
    by_id = {item["finding_id"]: item for item in failed["unproven_findings"]}
    assert by_id["f-exec"]["test_failure_tail"]["candidate"] == CANDIDATE_TAIL
    assert "injected input" in by_id["f-exec"]["assertion"]
    assert by_id["f-path"]["expected_test_path"] == ".mitig8it/regression/f-path.test.js"


@pytest.mark.asyncio
async def test_a_finding_on_the_same_lines_as_a_proven_one_is_named_co_located(request_payload):
    """Two scanner rules on one line: the second finding is fixed by the same hunk and needs only
    a copy of the test under its own id, which the revision says outright."""
    findings = FINDINGS + [
        {"snapshot_id": "f-path-2", "rule_id": "js.express-path-join-traversal", "cwe_id": "CWE-22", "file_path": "src/app.js", "line_start": 11, "line_end": 11},
    ]
    actions = [
        _propose(ALL_FIXED, ["f-sql", "f-exec", "f-path"]),
        _verify("verify-1"),
        _propose(ALL_FIXED, ["f-sql", "f-exec", "f-path", "f-path-2"], call_id="propose-2"),
        _verify("verify-2"),
    ]
    payload = _payload(request_payload, findings=findings)
    response, provider = await _run(payload, actions, SelectiveBroker({"f-sql", "f-exec", "f-path", "f-path-2"}))
    revision = _tool_result(provider.seen[2], "verify-1")["coverage_revision"]
    assert [item["finding_id"] for item in revision["unproven"]] == ["f-path-2"]
    assert revision["unproven"][0]["co_located_with"] == ["f-path"]
    assert "copy of its test at .mitig8it/regression/f-path-2.test.js" in revision["unproven"][0]["hint"]
    assert "same lines as a proven one" in revision["instruction"]
    assert response.state == "ready" and response.candidates[0].finding_ids == ["f-exec", "f-path", "f-path-2", "f-sql"]
