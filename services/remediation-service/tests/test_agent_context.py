from __future__ import annotations

import json
from typing import Any

import pytest

from src.agent import ProviderAction, RepairAgent
from src.digests import content_sha256
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.patches import PatchPolicyError, apply_hunks, build_patch_bundle
from src.retrieval import Snapshot
from tests.conftest import git_blob, regression_test_spec, whole_file_change
from tests.test_agent_budget import DenseProvider, FailingVerifier, RecordingProvider, _abstain, _read


def _sixty_line_source() -> str:
    lines = ["'use strict';\n"]
    for index in range(2, 60):
        if index == 30:
            lines.append("  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n")
        else:
            lines.append(f"// line {index} of the module under repair\n")
    lines.append("module.exports = { loadUser };\n")
    return "".join(lines)


def _payload_with(request_payload: dict[str, Any], content: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    package = '{"dependencies":{"pg":"8.13.0"}}\n'
    entries = [
        GitTreeEntry(path="src/db.ts", mode="100644", type="blob", sha=git_blob(content)),
        GitTreeEntry(path="package.json", mode="100644", type="blob", sha=git_blob(package)),
    ]
    request_payload["files"] = [
        {"path": "src/db.ts", "content": content, "sha": git_blob(content)},
        {"path": "package.json", "content": package, "sha": git_blob(package)},
    ]
    request_payload["tree_entries"] = [entry.model_dump() for entry in entries]
    request_payload["head_tree_oid"] = compute_tree_oid(entries)
    request_payload["findings"] = findings
    return request_payload


def _finding(index: int, line: int) -> dict[str, Any]:
    return {
        "snapshot_id": f"finding-{index}",
        "rule_id": "js.sql-injection",
        "cwe_id": "CWE-89",
        "file_path": "src/db.ts",
        "line_start": line,
        "line_end": line,
    }


def _tool_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [message for message in messages if message.get("role") == "tool"]


@pytest.mark.asyncio
async def test_unscoped_read_returns_a_window_around_the_finding(request_payload):
    content = _sixty_line_source()
    request = RepairRequest.model_validate(_payload_with(request_payload, content, [_finding(1, 30)]))
    snapshot = Snapshot(request)
    provider = RecordingProvider([_read(None, None), _abstain()])
    await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    result = json.loads(_tool_messages(provider.last_messages)[0]["content"])
    assert result["line_start"] == 1  # 30 - 30 clamps to the first line
    assert result["line_end"] == 60
    assert result["lines"][0][0] == 1 and result["lines"][-1][0] == 60
    assert any("SELECT * FROM users" in text for _, text in result["lines"])


@pytest.mark.asyncio
async def test_a_window_read_returns_only_the_requested_lines(request_payload):
    content = _sixty_line_source()
    request = RepairRequest.model_validate(_payload_with(request_payload, content, [_finding(1, 30)]))
    snapshot = Snapshot(request)
    provider = RecordingProvider([_read(28, 32), _abstain()])
    await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    result = json.loads(_tool_messages(provider.last_messages)[0]["content"])
    assert (result["line_start"], result["line_end"]) == (28, 32)
    assert [number for number, _ in result["lines"]] == [28, 29, 30, 31, 32]
    assert all("line 2 of the module" not in text for _, text in result["lines"])


@pytest.mark.asyncio
async def test_one_tool_result_never_exceeds_the_per_result_character_cap(request_payload):
    content = _sixty_line_source() + "// padding line that makes the file long\n" * 400
    request = RepairRequest.model_validate(_payload_with(request_payload, content, [_finding(1, 30)]))
    request.policy.max_tool_result_chars = 1_000
    snapshot = Snapshot(request)
    provider = RecordingProvider([_read(1, 400), _abstain()])
    await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    result = json.loads(_tool_messages(provider.last_messages)[0]["content"])
    assert len(json.dumps(result["lines"])) <= 1_000
    assert result["truncated"] is True
    # Truncation drops whole lines, so the reported range still describes what came back.
    assert result["line_end"] - result["line_start"] + 1 == len(result["lines"])


@pytest.mark.asyncio
async def test_consumed_reads_are_stubbed_once_the_working_set_is_exceeded(request_payload):
    content = _sixty_line_source() + "// padding line that makes the file long\n" * 400
    request = RepairRequest.model_validate(_payload_with(request_payload, content, [_finding(1, 30)]))
    request.policy.max_tool_result_chars = 6_000
    request.policy.max_working_set_tokens = 3_000
    snapshot = Snapshot(request)
    provider = RecordingProvider([_read(1, 200), _read(201, 400), _read(1, 100), _abstain()])
    await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    results = [json.loads(message["content"]) for message in _tool_messages(provider.last_messages)]
    assert results[0].get("evicted_context") is True
    assert results[0]["read"][0]["path"] == "src/db.ts"
    assert results[0]["read"][0]["line_start"] == 1
    assert "content_digest" in results[0]["read"][0]
    assert "lines" not in results[0]
    # The most recent result is still the working set and keeps its content.
    assert results[-1].get("evicted_context") is not True
    assert "lines" in results[-1]


@pytest.mark.asyncio
async def test_eviction_never_removes_the_system_prompt_or_the_latest_verification(request_payload, source):
    replacement = source.replace(
        "db.query(`SELECT * FROM users WHERE id = ${id}`)", "db.query('SELECT * FROM users WHERE id = $1', [id])"
    )
    request = RepairRequest.model_validate(request_payload)
    request.policy.max_working_set_tokens = 2_000
    snapshot = Snapshot(request)

    class FailingOnceVerifier(FailingVerifier):
        async def verify(self, request, snapshot, bundle):
            from src.verification import VerificationResult

            return VerificationResult(
                status="failed",
                evidence={"checks": [{"check_id": "exploit", "status": "failed"}]},
                evidence_digest="sha256:" + "9" * 64,
                reason_code="regression_test_not_reproducing",
                verification_level="independent_sandbox",
                limitations=[],
            )

    proposal = ProviderAction(
        "propose_patch",
        {
            "hypothesis": "Untrusted id is interpolated into SQL.",
            "intended_behavior": "Load the same user by id.",
            "assumptions": ["pg positional parameters are available"],
            "citations": [{"path": "src/db.ts", "line_start": 1, "line_end": 3}],
            "changes": [whole_file_change("src/db.ts", source, replacement)],
            "regression_tests": [regression_test_spec()],
        },
        output_tokens=64,
    )
    actions = [_read(1, 3), _read(1, 3), proposal, ProviderAction("request_verification", {}, output_tokens=16)]
    provider = RecordingProvider(actions)
    result = await RepairAgent(provider, FailingOnceVerifier()).run(request, snapshot)

    messages = provider.last_messages
    assert messages[0]["role"] == "system"
    assert "bounded secure-code patch proposer" in messages[0]["content"]
    assert result.verification is not None and result.verification.status == "failed"


def test_a_hunk_with_a_stale_hash_is_rejected(request_payload, source):
    """A caller that still sends a digest is held to it, in prefixed or bare hexadecimal form."""
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    stale = {
        "path": "src/db.ts",
        "start_line": 2,
        "end_line": 2,
        "original_lines": [source.splitlines()[1]],
        "replaced_sha256": "sha256:" + "0" * 64,
        "replacement_lines": ["  return db.query('SELECT * FROM users WHERE id = $1', [id]);"],
    }
    with pytest.raises(PatchPolicyError, match="stale_hunk_digest"):
        build_patch_bundle(request, snapshot, [stale])

    bare = dict(stale) | {"replaced_sha256": content_sha256(source.splitlines()[1] + "\n").removeprefix("sha256:")}
    assert build_patch_bundle(request, snapshot, [bare], [regression_test_spec()]).changed_lines == 2


def test_a_hunk_patch_produces_the_same_tree_as_the_whole_file_replacement(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    replacement = source.replace(
        "db.query(`SELECT * FROM users WHERE id = ${id}`)", "db.query('SELECT * FROM users WHERE id = $1', [id])"
    )
    original_lines = source.splitlines()
    hunk = {
        "path": "src/db.ts",
        "start_line": 2,
        "end_line": 2,
        "original_lines": [original_lines[1]],
        "replacement_lines": [replacement.splitlines()[1]],
    }
    from_hunk = build_patch_bundle(request, snapshot, [hunk], [regression_test_spec()])
    from_whole_file = build_patch_bundle(
        request, snapshot, [whole_file_change("src/db.ts", source, replacement)], [regression_test_spec()]
    )
    assert from_hunk.patches[0].replacement_content == replacement
    assert from_hunk.patches[0].new_sha256 == from_whole_file.patches[0].new_sha256
    assert from_hunk.artifact_digest == from_whole_file.artifact_digest


def test_hunks_are_applied_bottom_up_and_must_not_overlap(request_payload):
    content = _sixty_line_source()
    request = RepairRequest.model_validate(_payload_with(request_payload, content, [_finding(1, 30)]))
    snapshot = Snapshot(request)
    lines = content.splitlines(keepends=True)
    first = {
        "path": "src/db.ts",
        "start_line": 2,
        "end_line": 3,
        "original_lines": [line.rstrip("\n") for line in lines[1:3]],
        "replacement_lines": ["// replaced first"],
    }
    second = {
        "path": "src/db.ts",
        "start_line": 40,
        "end_line": 41,
        "original_lines": [line.rstrip("\n") for line in lines[39:41]],
        "replacement_lines": ["// replaced second", "// and another"],
    }
    updated = apply_hunks(snapshot, [second, first])["src/db.ts"].splitlines()
    assert updated[1] == "// replaced first"
    assert updated[38:40] == ["// replaced second", "// and another"]
    assert len(updated) == len(content.splitlines()) - 1

    overlapping = dict(first) | {
        "start_line": 3,
        "end_line": 4,
        "original_lines": [line.rstrip("\n") for line in lines[2:4]],
    }
    with pytest.raises(PatchPolicyError, match="overlapping_hunks"):
        apply_hunks(snapshot, [first, overlapping])


@pytest.mark.asyncio
async def test_a_four_finding_job_on_a_sixty_line_file_stays_under_thirty_thousand_tokens(request_payload):
    content = _sixty_line_source()
    findings = [_finding(index, line) for index, line in enumerate([12, 30, 44, 58], start=1)]
    request = RepairRequest.model_validate(_payload_with(request_payload, content, findings))
    # A 60-line file needs a small working set: past reads become stubs instead of being re-sent.
    request.policy.max_working_set_tokens = 1_500
    snapshot = Snapshot(request)
    actions = [
        _read(None, None),
        ProviderAction("search_code", {"query": "db.query"}, output_tokens=48),
        _read(20, 40),
        ProviderAction("find_references", {"symbol": "loadUser"}, output_tokens=48),
        _read(None, None),
        ProviderAction("read_tests", {"source_path": "src/db.ts"}, output_tokens=32),
        _read(1, 60),
        _abstain(),
    ]
    provider = DenseProvider(actions)
    result = await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    assert provider.calls == len(actions)
    assert result.usage["input_tokens"] + result.usage["output_tokens"] < 30_000
