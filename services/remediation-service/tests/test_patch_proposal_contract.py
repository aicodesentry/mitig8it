"""The patch proposal contract a model can actually satisfy, and the loop that stops retrying.

A hunk quotes the lines it replaces and the service derives the digest, so a rejection names a
specific, correctable mistake instead of a hash the caller could never have computed.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from src.agent import ProviderAction, RepairAgent
from src.models import RepairRequest
from src.patches import PatchPolicyError, apply_hunks
from src.retrieval import Snapshot
from tests.conftest import git_blob, regression_test_spec
from tests.test_agent_budget import FailingVerifier, RecordingProvider, _abstain, _read

REPAIRED_LINE = "  return db.query('SELECT * FROM users WHERE id = $1', [id]);"


def _with_source(request_payload: dict[str, Any], content: str) -> dict[str, Any]:
    """The same request over a different `src/db.ts`, for cases the small fixture cannot express."""
    from src.git_tree import compute_tree_oid
    from src.models import GitTreeEntry

    entries = [
        GitTreeEntry(path=entry["path"], mode=entry["mode"], type=entry["type"], sha=git_blob(content))
        if entry["path"] == "src/db.ts"
        else GitTreeEntry.model_validate(entry)
        for entry in request_payload["tree_entries"]
    ]
    files = [
        file | {"content": content, "sha": git_blob(content)} if file["path"] == "src/db.ts" else file
        for file in request_payload["files"]
    ]
    return request_payload | {
        "tree_entries": [entry.model_dump() for entry in entries],
        "head_tree_oid": compute_tree_oid(entries),
        "files": files,
    }


def _hunk(source: str, **overrides: Any) -> dict[str, Any]:
    hunk = {
        "path": "src/db.ts",
        "start_line": 2,
        "original_lines": [source.splitlines()[1]],
        "replacement_lines": [REPAIRED_LINE],
    }
    hunk.update(overrides)
    return hunk


def _proposal(changes: list[dict[str, Any]]) -> ProviderAction:
    return ProviderAction(
        "propose_patch",
        {
            "hypothesis": "Untrusted id is interpolated into SQL.",
            "intended_behavior": "Load the same user by id.",
            "assumptions": ["pg positional parameters are available"],
            "citations": [{"path": "src/db.ts", "line_start": 1, "line_end": 3}],
            "changes": changes,
            "regression_tests": [regression_test_spec()],
        },
        output_tokens=64,
    )


def test_a_hunk_quoting_the_exact_lines_is_accepted(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    updated = apply_hunks(snapshot, [_hunk(source)])["src/db.ts"]
    assert updated == source.replace(source.splitlines()[1], REPAIRED_LINE)
    # The caller never supplies a digest, and the accepted hunk still binds to the exact snapshot.
    assert "replaced_sha256" not in _hunk(source)


def test_mismatched_original_lines_name_the_line_and_what_the_snapshot_holds(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    wrong = _hunk(source, original_lines=["  return db.query('SELECT * FROM users WHERE id = ' + id);"])
    with pytest.raises(PatchPolicyError) as raised:
        apply_hunks(snapshot, [wrong])
    assert raised.value.code == "original_lines_not_found:src/db.ts"
    guidance = raised.value.guidance or ""
    # The first line that differs, what the snapshot holds there, and what the hunk claimed.
    assert "Line 2 is" in guidance
    assert "SELECT * FROM users WHERE id = ${id}" in guidance
    assert "WHERE id = ' + id" in guidance
    assert "Copy the lines exactly as read_file returned them" in guidance


def test_an_off_by_one_start_line_still_lands_on_the_quoted_lines(request_payload, source):
    """The quoted text is the anchor, so a miscounted hint does not decide what is replaced."""
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    for hint in (1, 3, 90):
        updated = apply_hunks(snapshot, [_hunk(source, start_line=hint)])["src/db.ts"]
        assert updated.splitlines() == [source.splitlines()[0], REPAIRED_LINE, "}"]


def test_repeated_lines_are_disambiguated_by_the_hint_and_otherwise_named(request_payload, source):
    """A block that occurs twice is resolved by start_line, never guessed at."""
    first, query, closing = source.splitlines()
    duplicated = "\n".join([first, query, closing, first.replace("loadUser", "loadAdmin"), query, closing]) + "\n"
    request = RepairRequest.model_validate(_with_source(request_payload, duplicated))
    snapshot = Snapshot(request)
    repeated = duplicated.splitlines()[1]
    assert duplicated.splitlines().count(repeated) == 2

    ambiguous = dict(_hunk(duplicated), original_lines=[repeated])
    del ambiguous["start_line"]
    with pytest.raises(PatchPolicyError) as raised:
        apply_hunks(snapshot, [ambiguous])
    assert raised.value.code == "original_lines_ambiguous:src/db.ts"
    assert "at lines 2, 5" in (raised.value.guidance or "")

    # With the hint the service replaces exactly the occurrence the agent meant.
    updated = apply_hunks(snapshot, [dict(ambiguous, start_line=5)])["src/db.ts"].splitlines()
    assert updated[1] == repeated and updated[4] == REPAIRED_LINE


def test_the_quoted_lines_define_the_range_so_a_longer_quote_replaces_more(request_payload, source):
    """There is no end_line for the agent to miscount: two quoted lines replace two lines."""
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    two = source.splitlines()[1:3]
    updated = apply_hunks(snapshot, [_hunk(source, original_lines=two, replacement_lines=[REPAIRED_LINE, "}"])])
    assert updated["src/db.ts"].splitlines() == [source.splitlines()[0], REPAIRED_LINE, "}"]


def test_an_end_line_that_contradicts_the_quoted_lines_is_rejected(request_payload, source):
    """A caller that still sends end_line is held to it rather than silently overridden."""
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError) as raised:
        apply_hunks(snapshot, [_hunk(source, end_line=7)])
    assert raised.value.code == "hunk_line_range_inconsistent:src/db.ts@2-7"
    assert "end_line is 2" in (raised.value.guidance or "")


def test_a_hunk_quoting_no_lines_is_rejected(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    with pytest.raises(PatchPolicyError) as raised:
        apply_hunks(snapshot, [_hunk(source, original_lines=[])])
    assert raised.value.code == "original_lines_required"


def test_a_hunk_without_original_lines_is_rejected_with_the_required_shape(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    incomplete = _hunk(source)
    del incomplete["original_lines"]
    with pytest.raises(PatchPolicyError) as raised:
        apply_hunks(snapshot, [incomplete])
    assert raised.value.code == "change_schema_invalid"
    assert "original_lines" in (raised.value.guidance or "")


def test_a_quote_running_past_the_end_of_the_file_reports_its_length(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    too_long = _hunk(source, start_line=1, original_lines=[*source.splitlines(), "// not in the file"])
    with pytest.raises(PatchPolicyError) as raised:
        apply_hunks(snapshot, [too_long])
    assert raised.value.code == "original_lines_not_found:src/db.ts"
    assert f"past the end of the file, which has {len(source.splitlines())} lines" in (raised.value.guidance or "")


def test_a_read_of_an_absent_path_names_the_paths_the_snapshot_holds(request_payload):
    from src.retrieval import SnapshotError

    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    with pytest.raises(SnapshotError) as raised:
        snapshot.read("src/does-not-exist.ts")
    assert raised.value.code == "path_not_in_snapshot"
    assert "src/db.ts" in (raised.value.guidance or "")


@pytest.mark.asyncio
async def test_read_file_returns_numbered_lines_a_hunk_can_quote_back(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    provider = RecordingProvider([_read(1, 3), _abstain()])
    await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    result = json.loads([m for m in provider.last_messages if m.get("role") == "tool"][0]["content"])
    assert result["lines"] == [[index + 1, line] for index, line in enumerate(source.splitlines())]
    # Quoting the pair's text straight back into a hunk is accepted without any further work.
    number, text = result["lines"][1]
    apply_hunks(snapshot, [_hunk(source, start_line=number, original_lines=[text])])


@pytest.mark.asyncio
async def test_a_rejected_proposal_returns_the_reason_and_its_guidance_to_the_model(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    bad = _proposal([_hunk(source, original_lines=["not the line the snapshot holds"])])
    provider = RecordingProvider([bad, _abstain()])
    await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    result = json.loads([m for m in provider.last_messages if m.get("role") == "tool"][0]["content"])
    assert result["error"] == "PatchPolicyError"
    assert result["reason"] == "original_lines_not_found:src/db.ts"
    assert "Line 2 is" in result["guidance"]


@pytest.mark.asyncio
async def test_two_identical_rejections_abstain_instead_of_spending_the_budget(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    bad = _proposal([_hunk(source, original_lines=["not the line the snapshot holds"])])
    # The provider would repeat the same rejected call for the whole tool budget.
    provider = RecordingProvider([bad] * request.policy.max_tool_calls)
    result = await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    assert provider.calls == 2
    assert result.state == "unsupported"
    assert result.reason_code == "repeated_tool_rejection"
    assert "original_lines_not_found" in (result.explanation or "")


@pytest.mark.asyncio
async def test_a_corrected_second_attempt_is_not_treated_as_a_repeat(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    bad = _proposal([_hunk(source, original_lines=["not the line the snapshot holds"])])
    good = _proposal([_hunk(source)])
    provider = RecordingProvider([bad, good, _abstain()])
    result = await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    assert provider.calls == 3
    assert result.reason_code != "repeated_tool_rejection"
    outcomes = [(step["tool"], step["outcome"]) for step in result.trace]
    assert outcomes == [("propose_patch", "rejected"), ("propose_patch", "ok"), ("abstain", "abstained")]


@pytest.mark.asyncio
async def test_the_trace_records_each_outcome_without_any_file_contents(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    bad = _proposal([_hunk(source, original_lines=["not the line the snapshot holds"])])
    provider = RecordingProvider([_read(1, 3), bad, _abstain()])
    result = await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    read_step, rejected_step, abstain_step = result.trace
    assert read_step == {
        "sequence": 1,
        "tool": "read_file",
        "arguments_digest_only": {"keys": ["line_end", "line_start", "path"], "paths": []},
        "outcome": "ok",
        "reason": None,
        "result_bytes": read_step["result_bytes"],
    }
    assert read_step["result_bytes"] > 0
    assert rejected_step["outcome"] == "rejected"
    assert rejected_step["reason"] == "original_lines_not_found:src/db.ts"
    assert abstain_step["outcome"] == "abstained"
    assert abstain_step["reason"] == "no_repair"
    # No step ever carries repository text, patch text, or model prose.
    rendered = json.dumps(result.trace)
    assert "SELECT" not in rendered
    assert REPAIRED_LINE not in rendered
    assert "Untrusted id is interpolated" not in rendered


@pytest.mark.asyncio
async def test_a_trace_reason_is_redacted_to_a_bounded_code(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    shouting = ProviderAction(
        "abstain",
        {"reason_code": "a reason with spaces, newlines\nand $ymbols " + "x" * 300, "explanation": "no repair"},
        output_tokens=8,
    )
    result = await RepairAgent(RecordingProvider([shouting]), FailingVerifier()).run(request, snapshot)

    reason = result.trace[0]["reason"]
    assert len(reason) <= 120
    assert " " not in reason and "\n" not in reason and "$" not in reason
