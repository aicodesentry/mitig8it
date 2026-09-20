from __future__ import annotations

import pytest

from src.agent import ProviderAction, RepairAgent
from src.digests import content_sha256
from src.engine import RepairEngine
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.verification import Verifier
from tests.conftest import regression_test_spec, whole_file_change


class ScriptedProvider:
    def __init__(self, actions):
        self.actions = iter(actions)

    async def next_action(self, messages, tools):
        return next(self.actions)


class PassingBroker:
    async def verify(self, payload, timeout_seconds):
        checks = []
        for check in payload["execution_policy"]["commands"]:
            checks.append(
                {
                    "check_id": check["check_id"],
                    "kind": check["kind"],
                    "argv": check["argv"],
                    "baseline": {"completed": True, "status": "failed" if check["kind"] == "exploit" else "passed"},
                    "candidate": {"completed": True, "status": "passed"},
                }
            )
        return {
            "schema_version": "v1",
            "execution_id": payload["execution_id"],
            "request_digest": payload["request_digest"],
            "request_nonce": payload["request_nonce"],
            "outcome": "passed",
            "original_tree_digest": payload["repository"]["original_tree_digest"],
            "candidate_tree_digest": payload["repository"]["candidate_tree_digest"],
            "head_tree_oid": payload["repository"]["head_tree_oid"],
            "verified_tree_oid": payload["repository"]["verified_tree_oid"],
            "runner": {"image_digest": payload["execution_policy"]["image_digest"], "network": "deny", "read_only_root": True},
            "checks": checks,
        }


async def _ready_engine(request_payload, source):
    replacement = source.replace("db.query(`SELECT * FROM users WHERE id = ${id}`)", "db.query('SELECT * FROM users WHERE id = $1', [id])")
    actions = [
        ProviderAction(
            "propose_patch",
            {
                "hypothesis": "Untrusted id is interpolated into SQL.",
                "intended_behavior": "Load the same user by id.",
                "assumptions": ["pg positional parameters are available"],
                "citations": [{"path": "src/db.ts", "line_start": 1, "line_end": 3}],
                "changes": [whole_file_change("src/db.ts", source, replacement)],
                "regression_tests": [regression_test_spec()],
            },
        ),
        ProviderAction("request_verification", {}),
    ]
    agent = RepairAgent(ScriptedProvider(actions), Verifier(PassingBroker()))
    return await RepairEngine(lambda request: agent).repair(RepairRequest.model_validate(request_payload))


@pytest.mark.asyncio
async def test_engine_returns_only_independently_verified_immutable_candidate(request_payload, source):
    response = await _ready_engine(request_payload, source)
    assert response.state == "ready"
    assert response.manifest_digest.startswith("sha256:")
    assert response.candidates[0].verification.status == "passed"
    assert len(response.candidates[0].verified_tree_oid) == 40
    assert response.evidence["verified_tree_oid"] == response.candidates[0].verified_tree_oid
    assert response.evidence["batch_manifest"]["head_sha"] == request_payload["head_sha"]
    # The API persists the candidate's own level and the finding view renders its limitations.
    candidate_evidence = response.candidates[0].preview["evidence"]
    assert candidate_evidence["verification_level"] == "independent_sandbox"
    assert candidate_evidence["limitations"] == response.evidence["limitations"]


@pytest.mark.asyncio
async def test_engine_abstains_without_complete_git_tree(request_payload):
    request_payload["tree_entries"] = []
    response = await RepairEngine().repair(RepairRequest.model_validate(request_payload))
    assert response.state == "unsupported"
    assert response.reason["code"] == "complete_git_tree_required"


@pytest.mark.asyncio
async def test_engine_abstains_for_unsupported_finding(request_payload):
    request_payload["findings"][0].update({"rule_id": "xss", "cwe_id": "CWE-79"})
    response = await RepairEngine().repair(RepairRequest.model_validate(request_payload))
    assert response.state == "unsupported"
    assert response.reason["code"] == "unsupported_rule_family"


@pytest.mark.asyncio
async def test_engine_abstains_for_shell_pipeline(request_payload):
    content = "exec(`git show ${ref} | head`);\n"
    import hashlib

    oid = hashlib.sha1(f"blob {len(content.encode())}\0".encode() + content.encode()).hexdigest()
    entry = GitTreeEntry(path="src/db.ts", mode="100644", type="blob", sha=oid)
    package = request_payload["tree_entries"][1]
    entries = [entry, GitTreeEntry.model_validate(package)]
    request_payload["files"][0] = {"path": "src/db.ts", "content": content, "sha": oid}
    request_payload["tree_entries"] = [value.model_dump() for value in entries]
    request_payload["head_tree_oid"] = compute_tree_oid(entries)
    request_payload["findings"][0].update({"rule_id": "command-injection", "cwe_id": "CWE-78", "line_start": 1, "line_end": 1})
    response = await RepairEngine().repair(RepairRequest.model_validate(request_payload))
    assert response.state == "unsupported"
    assert response.reason["code"] == "shell_pipeline_unsupported"


@pytest.mark.asyncio
async def test_agent_reserves_provider_budget_before_tool_execution(request_payload):
    request_payload["policy"]["max_total_tokens"] = 1_000
    request = RepairRequest.model_validate(request_payload)
    action = ProviderAction("abstain", {"reason_code": "x", "explanation": "x"}, input_tokens=1_001)
    agent = RepairAgent(ScriptedProvider([action]), Verifier(PassingBroker()))
    response = await RepairEngine(lambda ignored: agent).repair(request)
    assert response.state == "inconclusive"
    assert response.reason["code"] == "provider_budget_reservation_denied"


class DevelopmentBroker(PassingBroker):
    async def verify(self, payload, timeout_seconds):
        evidence = await super().verify(payload, timeout_seconds)
        evidence["verification_level"] = "development_unverified"
        evidence["runner"] = {"image_digest": None, "network": "unrestricted", "read_only_root": False, "runtime_class": "local-subprocess"}
        return evidence


async def _engine_with_broker(request_payload, source, broker):
    replacement = source.replace("db.query(`SELECT * FROM users WHERE id = ${id}`)", "db.query('SELECT * FROM users WHERE id = $1', [id])")
    actions = [
        ProviderAction(
            "propose_patch",
            {
                "hypothesis": "Untrusted id is interpolated into SQL.",
                "intended_behavior": "Load the same user by id.",
                "assumptions": ["pg positional parameters are available"],
                "citations": [{"path": "src/db.ts", "line_start": 1, "line_end": 3}],
                "changes": [whole_file_change("src/db.ts", source, replacement)],
                "regression_tests": [regression_test_spec()],
            },
        ),
        ProviderAction("request_verification", {}),
    ]
    agent = RepairAgent(ScriptedProvider(actions), Verifier(broker))
    return await RepairEngine(lambda request: agent).repair(RepairRequest.model_validate(request_payload))


@pytest.mark.asyncio
async def test_engine_reports_honest_limitations_for_checks_that_did_not_run(request_payload, source):
    response = await _ready_engine(request_payload, source)
    assert response.evidence["verification_level"] == "independent_sandbox"
    joined = " ".join(response.evidence["limitations"])
    assert "original test suite was not run" in joined
    assert "no type check or build was run" in joined
    assert "no scanner baseline/candidate finding comparison" in joined


@pytest.mark.asyncio
async def test_engine_refuses_development_evidence_under_the_default_policy(request_payload, source):
    response = await _engine_with_broker(request_payload, source, DevelopmentBroker())
    assert response.state == "unsupported"
    assert response.reason["code"] == "development_verification_not_permitted"
    assert response.candidates == []


@pytest.mark.asyncio
async def test_engine_labels_an_explicitly_allowed_development_candidate(request_payload, source):
    request_payload["policy"]["allow_development_verification"] = True
    response = await _engine_with_broker(request_payload, source, DevelopmentBroker())
    assert response.state == "ready"
    assert response.evidence["verification_level"] == "development_unverified"
    assert any("development local sandbox" in item for item in response.evidence["limitations"])
    candidate_evidence = response.candidates[0].preview["evidence"]
    assert candidate_evidence["verification_level"] == "development_unverified"
    assert any("development local sandbox" in item for item in candidate_evidence["limitations"])


SQL_SOURCE = "export function loadUser(db, id) {\n  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n}\n"
SQL_REPAIRED = "export function loadUser(db, id) {\n  return db.query('SELECT * FROM users WHERE id = $1', [id]);\n}\n"
CMD_SOURCE = "export function archive(exec, name) {\n  return exec(`tar -czf ${name}.tgz ${name}`);\n}\n"
CMD_REPAIRED = "export function archive(exec, name) {\n  return exec('tar', ['-czf', name + '.tgz', name]);\n}\n"
MANIFEST = '{"dependencies":{"pg":"8.13.0"}}\n'


def _two_file_payload(request_payload):
    """One job carrying an SQL finding in one file and a command finding in another."""
    from tests.conftest import git_blob

    entries = [
        GitTreeEntry(path="src/db.ts", mode="100644", type="blob", sha=git_blob(SQL_SOURCE)),
        GitTreeEntry(path="src/cmd.ts", mode="100644", type="blob", sha=git_blob(CMD_SOURCE)),
        GitTreeEntry(path="package.json", mode="100644", type="blob", sha=git_blob(MANIFEST)),
    ]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [
        {"path": "src/db.ts", "content": SQL_SOURCE, "sha": git_blob(SQL_SOURCE)},
        {"path": "src/cmd.ts", "content": CMD_SOURCE, "sha": git_blob(CMD_SOURCE)},
        {"path": "package.json", "content": MANIFEST, "sha": git_blob(MANIFEST)},
    ]
    payload["findings"] = [
        {"snapshot_id": "finding-sql", "rule_id": "js.sql-injection", "cwe_id": "CWE-89", "file_path": "src/db.ts", "line_start": 2, "line_end": 2},
        {"snapshot_id": "finding-cmd", "rule_id": "js.command-injection", "cwe_id": "CWE-78", "file_path": "src/cmd.ts", "line_start": 2, "line_end": 2},
    ]
    return payload


FINDING_BY_PATH = {"src/db.ts": "finding-sql", "src/cmd.ts": "finding-cmd"}


def _propose(path, original, replacement, hypothesis, finding_ids=None):
    """One proposal for `path` carrying one regression test per finding it claims."""
    claimed = finding_ids or [FINDING_BY_PATH[path]]
    return ProviderAction(
        "propose_patch",
        {
            "hypothesis": hypothesis,
            "intended_behavior": "Preserve the documented behavior for legitimate input.",
            "assumptions": ["the snapshot proves the required dependency"],
            "citations": [{"path": path, "line_start": 1, "line_end": 3}],
            "changes": [whole_file_change(path, original, replacement)],
            "regression_tests": [
                regression_test_spec(path=f".mitig8it/regression/{finding_id}.test.js", finding_id=finding_id)
                for finding_id in claimed
            ],
        },
    )


def _per_path_agent_factory(scripts):
    """A fresh agent per finding group, keyed by the group's first affected path."""

    def factory(prepared):
        return RepairAgent(ScriptedProvider(scripts[prepared.findings[0].affected_path]), Verifier(PassingBroker()))

    return factory


@pytest.mark.asyncio
async def test_two_findings_in_different_files_produce_two_candidates_and_one_combined_batch(request_payload):
    payload = _two_file_payload(request_payload)
    scripts = {
        "src/db.ts": [_propose("src/db.ts", SQL_SOURCE, SQL_REPAIRED, "Untrusted id is interpolated into SQL."), ProviderAction("request_verification", {})],
        "src/cmd.ts": [_propose("src/cmd.ts", CMD_SOURCE, CMD_REPAIRED, "Untrusted name is interpolated into a command."), ProviderAction("request_verification", {})],
    }
    response = await RepairEngine(_per_path_agent_factory(scripts)).repair(RepairRequest.model_validate(payload))
    assert response.state == "ready"
    assert [candidate.finding_ids for candidate in response.candidates] == [["finding-sql"], ["finding-cmd"]]
    assert {patch.path for candidate in response.candidates for patch in candidate.patch} == {"src/db.ts", "src/cmd.ts"}
    manifest = response.evidence["batch_manifest"]
    assert manifest["ordered_candidate_ids"] == [candidate.candidate_id for candidate in response.candidates]
    # The combined tree is verified in its own run, not inherited from either candidate.
    assert manifest["verified_tree_oid"] == response.evidence["verified_tree_oid"]
    assert manifest["verified_tree_oid"] not in {candidate.verified_tree_oid for candidate in response.candidates}
    assert manifest["combined_verification_evidence_digest"] not in {
        candidate.verification.evidence_digest for candidate in response.candidates
    }
    assert [group["state"] for group in response.evidence["groups"]] == ["ready", "ready"]


@pytest.mark.asyncio
async def test_two_findings_in_the_same_file_are_one_group_with_one_candidate(request_payload):
    payload = _two_file_payload(request_payload)
    payload["findings"][1] = {
        "snapshot_id": "finding-sql-2",
        "rule_id": "js.sql-injection",
        "cwe_id": "CWE-89",
        "file_path": "src/db.ts",
        "line_start": 2,
        "line_end": 2,
    }
    scripts = {
        "src/db.ts": [
            _propose("src/db.ts", SQL_SOURCE, SQL_REPAIRED, "Untrusted id is interpolated into SQL.", ["finding-sql", "finding-sql-2"]),
            ProviderAction("request_verification", {}),
        ],
    }
    calls: list[list[str]] = []

    def factory(prepared):
        calls.append([finding.stable_id for finding in prepared.findings])
        return RepairAgent(ScriptedProvider(scripts["src/db.ts"]), Verifier(PassingBroker()))

    response = await RepairEngine(factory).repair(RepairRequest.model_validate(payload))
    assert calls == [["finding-sql", "finding-sql-2"]]
    assert response.state == "ready"
    assert len(response.candidates) == 1
    assert response.candidates[0].finding_ids == ["finding-sql", "finding-sql-2"]
    assert response.skipped == []
    assert response.evidence["verified_tree_oid"] == response.candidates[0].verified_tree_oid


@pytest.mark.asyncio
async def test_a_finding_without_its_own_regression_test_is_dropped_from_the_candidate_and_reported(request_payload):
    """Two findings in one group, one reproducer: the candidate claims only the finding it proved."""
    payload = _two_file_payload(request_payload)
    payload["findings"][1] = {
        "snapshot_id": "finding-sql-2",
        "rule_id": "js.sql-injection",
        "cwe_id": "CWE-89",
        "file_path": "src/db.ts",
        "line_start": 2,
        "line_end": 2,
    }
    scripts = {
        "src/db.ts": [_propose("src/db.ts", SQL_SOURCE, SQL_REPAIRED, "Untrusted id is interpolated into SQL."), ProviderAction("request_verification", {})],
    }
    response = await RepairEngine(_per_path_agent_factory(scripts)).repair(RepairRequest.model_validate(payload))
    assert response.state == "ready"
    assert response.candidates[0].finding_ids == ["finding-sql"]
    assert response.skipped == [
        {
            "finding_id": "finding-sql-2",
            "code": "not_repaired",
            "message": "No regression test reproduced this finding, so the candidate does not claim it.",
        }
    ]
    group = response.evidence["groups"][0]
    assert group["finding_ids"] == ["finding-sql", "finding-sql-2"]
    assert group["repaired_finding_ids"] == ["finding-sql"]
    assert [item["finding_id"] for item in group["unproven_findings"]] == ["finding-sql-2"]


@pytest.mark.asyncio
async def test_a_group_below_the_budget_floor_is_not_launched_and_reports_budget_exhausted(request_payload):
    payload = _two_file_payload(request_payload)
    payload["policy"]["max_tool_calls"] = 5
    scripts = {
        "src/db.ts": [_propose("src/db.ts", SQL_SOURCE, SQL_REPAIRED, "Untrusted id is interpolated into SQL."), ProviderAction("request_verification", {})],
    }
    launched: list[str] = []

    def factory(prepared):
        launched.append(prepared.findings[0].affected_path)
        return RepairAgent(ScriptedProvider(scripts[prepared.findings[0].affected_path]), Verifier(PassingBroker()))

    response = await RepairEngine(factory).repair(RepairRequest.model_validate(payload))
    assert launched == ["src/db.ts"]
    assert response.state == "ready"
    assert [candidate.finding_ids for candidate in response.candidates] == [["finding-sql"]]
    second = response.evidence["groups"][1]
    assert second["finding_ids"] == ["finding-cmd"]
    assert second["state"] == "unsupported"
    assert second["reason"]["code"] == "budget_exhausted"


@pytest.mark.asyncio
async def test_a_later_group_that_edits_an_accepted_line_range_is_rejected_as_overlapping(request_payload):
    payload = _two_file_payload(request_payload)
    # Two disconnected groups whose agents both change the same line range of src/db.ts.
    other_repair = SQL_REPAIRED.replace("$1", "$1 /* audited */")
    scripts = {
        "src/db.ts": [_propose("src/db.ts", SQL_SOURCE, SQL_REPAIRED, "Untrusted id is interpolated into SQL."), ProviderAction("request_verification", {})],
        "src/cmd.ts": [
            _propose("src/db.ts", SQL_SOURCE, other_repair, "The same line is repaired differently.", ["finding-cmd"]),
            ProviderAction("request_verification", {}),
        ],
    }
    response = await RepairEngine(_per_path_agent_factory(scripts)).repair(RepairRequest.model_validate(payload))
    assert response.state == "ready"
    assert len(response.candidates) == 1
    second = response.evidence["groups"][1]
    assert second["state"] == "unsupported"
    assert second["reason"]["code"] == "overlapping_candidates"


@pytest.mark.asyncio
async def test_unsupported_findings_are_skipped_with_reasons_and_the_rest_are_repaired(request_payload):
    payload = _two_file_payload(request_payload)
    payload["findings"].append(
        {"snapshot_id": "finding-xss", "rule_id": "js.xss", "cwe_id": "CWE-79", "file_path": "src/db.ts", "line_start": 1, "line_end": 1}
    )
    scripts = {
        "src/db.ts": [_propose("src/db.ts", SQL_SOURCE, SQL_REPAIRED, "Untrusted id is interpolated into SQL."), ProviderAction("request_verification", {})],
        "src/cmd.ts": [_propose("src/cmd.ts", CMD_SOURCE, CMD_REPAIRED, "Untrusted name is interpolated into a command."), ProviderAction("request_verification", {})],
    }
    response = await RepairEngine(_per_path_agent_factory(scripts)).repair(RepairRequest.model_validate(payload))
    assert response.state == "ready"
    assert [candidate.finding_ids for candidate in response.candidates] == [["finding-sql"], ["finding-cmd"]]
    assert response.skipped == [
        {"finding_id": "finding-xss", "code": "unsupported_rule_family", "message": "This finding is outside the enabled repair families."}
    ]


@pytest.mark.asyncio
async def test_request_with_no_supported_finding_is_unsupported_and_lists_every_skip(request_payload):
    request_payload["findings"][0].update({"rule_id": "xss", "cwe_id": "CWE-79"})
    response = await RepairEngine().repair(RepairRequest.model_validate(request_payload))
    assert response.state == "unsupported"
    assert response.reason["code"] == "unsupported_rule_family"
    assert [entry["code"] for entry in response.skipped] == ["unsupported_rule_family"]
