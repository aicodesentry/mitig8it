from __future__ import annotations

import json
from typing import Any

import pytest

from src.agent import ProviderAction, RepairAgent
from src.agent.loop import estimate_history_tokens, estimate_tokens, output_reservation_tokens
from src.engine import RepairEngine
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.retrieval import Snapshot
from src.verification import Verifier
from tests.conftest import git_blob


PAD_LINE = "// padding to make this file large enough to matter for budgeting\n"


class RecordingProvider:
    """A provider that reports realistic `prompt_tokens` for the history it is handed."""

    def __init__(self, actions: list[ProviderAction], reported_input_tokens: int | None = None):
        self.actions = list(actions)
        self.calls = 0
        self.reported_input_tokens = reported_input_tokens
        self.histories: list[int] = []

    async def next_action(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ProviderAction:
        self.histories.append(len(json.dumps(messages, ensure_ascii=False).encode("utf-8")))
        action = self.actions[min(self.calls, len(self.actions) - 1)]
        self.calls += 1
        reported = self.reported_input_tokens
        if reported is None:
            reported = estimate_history_tokens(messages)
        return ProviderAction(
            action.name,
            action.arguments,
            call_id=f"call-{self.calls}",
            request_id=f"req-{self.calls}",
            input_tokens=reported,
            output_tokens=action.output_tokens,
        )


class FailingVerifier(Verifier):
    def __init__(self):  # pragma: no cover - never invoked in these tests
        pass


def _read(line_start: int, line_end: int, output_tokens: int = 64) -> ProviderAction:
    return ProviderAction(
        "read_file",
        {"path": "src/db.ts", "line_start": line_start, "line_end": line_end},
        output_tokens=output_tokens,
    )


def _abstain() -> ProviderAction:
    return ProviderAction("abstain", {"reason_code": "no_repair", "explanation": "done"}, output_tokens=32)


def _large_payload(request_payload: dict[str, Any], source: str, pad_lines: int) -> dict[str, Any]:
    content = source + PAD_LINE * pad_lines
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
    return request_payload


def test_output_reservation_tracks_the_largest_file_not_the_policy_cap(request_payload, source):
    request = RepairRequest.model_validate(_large_payload(request_payload, source, 640))
    snapshot = Snapshot(request)
    assert snapshot.largest_file_bytes >= 40_000
    request.policy.max_output_tokens_per_call = 16_000
    reservation = output_reservation_tokens(request.policy, snapshot)
    assert reservation == estimate_tokens("x" * snapshot.largest_file_bytes) + 512
    assert reservation < request.policy.max_output_tokens_per_call
    # The policy cap still bounds the reservation when the snapshot is larger than the cap allows.
    request.policy.max_output_tokens_per_call = 4_096
    assert output_reservation_tokens(request.policy, snapshot) == 4_096


def test_small_snapshots_still_reserve_a_floor(request_payload):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    assert output_reservation_tokens(request.policy, snapshot) == 1_024


@pytest.mark.asyncio
async def test_forty_kilobyte_snapshot_history_allows_at_least_eight_provider_calls(request_payload, source):
    """The live regression: the whole snapshot in the history used to deny call four.

    Reserving the history's byte length as tokens over-counts input roughly fourfold, so a 40 KB
    source file in context consumed a third of the 120k ceiling on every single call.
    """
    request = RepairRequest.model_validate(_large_payload(request_payload, source, 640))
    snapshot = Snapshot(request)
    actions = [_read(1, 320), _read(321, 640), _read(1, 48)] + [_read(1, 2) for _ in range(5)] + [_abstain()]
    provider = RecordingProvider(actions)
    result = await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    assert provider.calls >= 8
    assert result.reason_code == "no_repair"
    # The snapshot really was in the history, which is what the old byte-based estimate over-charged.
    assert max(provider.histories) > 40_000


@pytest.mark.asyncio
async def test_reported_usage_shrinks_the_next_reservation(request_payload, source):
    request = RepairRequest.model_validate(_large_payload(request_payload, source, 640))
    request.policy.max_total_tokens = 12_000
    request.policy.max_output_tokens_per_call = 4_096
    snapshot = Snapshot(request)
    # The first tool result puts about 20 KB in the history. A byte-length estimate would reserve
    # more than 20k tokens and deny the second call; the reported 100 prompt tokens do not.
    provider = RecordingProvider([_read(1, 320), _abstain()], reported_input_tokens=100)
    result = await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    assert provider.histories[1] > 20_000
    assert provider.calls == 2
    assert result.reason_code == "no_repair"


@pytest.mark.asyncio
async def test_denied_reservation_reports_the_numbers_as_evidence(request_payload, source):
    request = RepairRequest.model_validate(_large_payload(request_payload, source, 640))
    request.policy.max_total_tokens = 12_000
    request.policy.max_output_tokens_per_call = 4_096
    snapshot = Snapshot(request)
    # A large reported prompt makes the second reservation exceed what is left of the ceiling.
    provider = RecordingProvider([_read(1, 320), _abstain()], reported_input_tokens=7_000)
    result = await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    assert provider.calls == 1
    assert result.state == "inconclusive"
    assert result.reason_code == "provider_budget_reservation_denied"
    reservation = result.evidence["budget_reservation"]
    assert reservation["estimated_input_tokens"] >= 7_000
    assert reservation["reserved_output_tokens"] == 4_096
    assert reservation["estimated_total_tokens"] == reservation["estimated_input_tokens"] + 4_096
    assert reservation["remaining_tokens"] == 12_000 - reservation["spent_input_tokens"] - reservation["spent_output_tokens"]
    assert reservation["max_total_tokens"] == 12_000
    assert reservation["remaining_usd"] <= request.policy.max_spend_usd
    assert str(reservation["estimated_total_tokens"]) in (result.explanation or "")


@pytest.mark.asyncio
async def test_engine_response_carries_the_denied_reservation_numbers(request_payload):
    request_payload["policy"]["max_total_tokens"] = 1_000
    request = RepairRequest.model_validate(request_payload)
    provider = RecordingProvider([_abstain()], reported_input_tokens=10)
    agent = RepairAgent(provider, Verifier(_NullBroker()))
    response = await RepairEngine(lambda ignored: agent).repair(request)

    assert response.state == "inconclusive"
    assert response.reason["code"] == "provider_budget_reservation_denied"
    reservation = response.evidence["budget_reservation"]
    assert reservation["estimated_total_tokens"] > reservation["remaining_tokens"]
    assert reservation["remaining_tokens"] == 1_000
    assert response.evidence["groups"][0]["reason_evidence"]["budget_reservation"] == reservation


class _NullBroker:
    async def verify(self, payload, timeout_seconds):  # pragma: no cover - never invoked
        raise AssertionError("verification must not run when the budget denies the first call")
