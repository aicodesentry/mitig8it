from __future__ import annotations

import json
from typing import Any

import pytest

from src.agent import ProviderAction, RepairAgent
from src.agent.loop import estimate_history_tokens, estimate_tokens, output_reservation_tokens, with_headroom
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
        self.last_messages: list[dict[str, Any]] = []

    async def next_action(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ProviderAction:
        self.histories.append(len(json.dumps(messages, ensure_ascii=False).encode("utf-8")))
        self.last_messages = [dict(message) for message in messages]
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


class DenseProvider:
    """Reports usage the way a real provider does: the tool schemas count, and code is dense."""

    def __init__(self, actions: list[ProviderAction], bytes_per_token: float = 3.2):
        self.actions = list(actions)
        self.calls = 0
        self.bytes_per_token = bytes_per_token
        self.total_input = 0
        self.total_output = 0
        self.last_messages: list[dict[str, Any]] = []

    async def next_action(self, messages, tools):
        action = self.actions[min(self.calls, len(self.actions) - 1)]
        self.calls += 1
        self.last_messages = [dict(message) for message in messages]
        billed = len(json.dumps(messages, ensure_ascii=False).encode("utf-8")) + len(
            json.dumps(tools, ensure_ascii=False).encode("utf-8")
        )
        input_tokens = int(billed / self.bytes_per_token)
        self.total_input += input_tokens
        self.total_output += action.output_tokens
        return ProviderAction(
            action.name,
            action.arguments,
            call_id=f"call-{self.calls}",
            input_tokens=input_tokens,
            output_tokens=action.output_tokens,
        )


class SettlingCheckpointStore:
    """Encodes the durable store's rule: a reservation is an estimate, settled at the actual cost.

    `ExecutionCheckpointStore.save_provider_action` charges what the call really used and records
    the difference as an overage. An absent reservation is still a protocol violation and raises.
    """

    def __init__(self):
        self.reserved_tokens: int | None = None
        self.reserved_usd: float = 0.0
        self.settled: list[int] = []
        self.overages: list[dict[str, float]] = []

    async def load(self):
        return None

    async def reserve_provider_call(self, sequence: int, tokens: int, usd: float) -> bool:
        self.reserved_tokens = tokens
        self.reserved_usd = usd
        return True

    async def save_provider_action(self, state, action, actual_tokens: int, actual_usd: float) -> dict:
        from src.agent.checkpoint import CheckpointError
        from src.executions import _settlement

        if self.reserved_tokens is None:
            raise CheckpointError("provider reservation is absent")
        settlement = _settlement(self.reserved_tokens, self.reserved_usd, actual_tokens, actual_usd)
        self.settled.append(actual_tokens)
        if settlement["overage_tokens"] or settlement["overage_usd"]:
            self.overages.append(settlement)
        return settlement

    async def save_completed_step(self, state) -> None:
        return None


class FailingVerifier(Verifier):
    def __init__(self):  # pragma: no cover - never invoked in these tests
        pass


def _read(line_start: int | None, line_end: int | None, output_tokens: int = 64) -> ProviderAction:
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


def test_output_reservation_follows_the_change_size_not_the_policy_cap(request_payload, source):
    request = RepairRequest.model_validate(_large_payload(request_payload, source, 640))
    snapshot = Snapshot(request)
    assert snapshot.largest_file_bytes >= 40_000
    request.policy.max_output_tokens_per_call = 16_000
    request.policy.max_changed_lines = 200
    reservation = output_reservation_tokens(request.policy)
    # Bounded by the policy's own limit on a patch, not by the size of the file it edits.
    assert reservation == with_headroom(estimate_tokens("x" * (200 * 80))) + 1_024 + 512
    assert reservation < request.policy.max_output_tokens_per_call
    request.policy.max_output_tokens_per_call = 4_096
    assert output_reservation_tokens(request.policy) == 4_096


def test_small_change_budgets_still_reserve_a_floor(request_payload):
    request = RepairRequest.model_validate(request_payload)
    request.policy.max_changed_lines = 1
    assert output_reservation_tokens(request.policy) >= 1_024


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


@pytest.mark.asyncio
async def test_reported_usage_shrinks_the_next_reservation(request_payload, source):
    request = RepairRequest.model_validate(_large_payload(request_payload, source, 640))
    request.policy.max_total_tokens = 16_000
    request.policy.max_output_tokens_per_call = 4_096
    request.policy.max_tool_result_chars = 20_000
    request.policy.max_working_set_tokens = 400_000
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
    provider = RecordingProvider([_read(1, 320), _abstain()], reported_input_tokens=7_500)
    result = await RepairAgent(provider, FailingVerifier()).run(request, snapshot)

    assert provider.calls == 1
    assert result.state == "inconclusive"
    assert result.reason_code == "provider_budget_reservation_denied"
    reservation = result.evidence["budget_reservation"]
    assert reservation["estimated_input_tokens"] >= 7_500
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


@pytest.mark.asyncio
async def test_reservation_covers_the_tool_schemas_the_provider_bills_for(request_payload, source):
    """The live regression: the tool definitions are billed but are not in the message history."""
    request = RepairRequest.model_validate(_large_payload(request_payload, source, 16))
    snapshot = Snapshot(request)
    store = SettlingCheckpointStore()
    provider = DenseProvider([_read(1, 8), _read(1, 8), _abstain()])
    result = await RepairAgent(provider, FailingVerifier(), store).run(request, snapshot)

    assert result.reason_code == "no_repair"
    assert len(store.settled) == provider.calls
    # The reservation still has to cover what the provider bills, or every call overruns it.
    assert store.overages == []
    assert result.evidence["budget_reservation"]["overage_calls"] == 0


class _NullBroker:
    async def verify(self, payload, timeout_seconds):  # pragma: no cover - never invoked
        raise AssertionError("verification must not run when the budget denies the first call")


class CappedCheckpointStore(SettlingCheckpointStore):
    """Settles the first call, then refuses the next one because a hard cap was crossed."""

    def __init__(self, allowed_calls: int = 1):
        super().__init__()
        self.allowed_calls = allowed_calls

    async def save_provider_action(self, state, action, actual_tokens: int, actual_usd: float) -> dict:
        from src.agent.checkpoint import BudgetCapExceeded

        settlement = await super().save_provider_action(state, action, actual_tokens, actual_usd)
        if len(self.settled) > self.allowed_calls:
            raise BudgetCapExceeded(
                settlement
                | {
                    "cumulative_actual_tokens": sum(self.settled),
                    "cumulative_actual_usd": 0.75,
                    "max_total_tokens": 1_000,
                    "max_spend_usd": 0.5,
                }
            )
        return settlement


@pytest.mark.asyncio
async def test_crossing_the_hard_cap_reports_budget_cap_exceeded_not_a_durability_failure(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    store = CappedCheckpointStore(allowed_calls=1)
    provider = RecordingProvider([_read(1, 3), _read(1, 3), _abstain()])

    result = await RepairAgent(provider, FailingVerifier(), store).run(request, snapshot)

    assert result.reason_code == "budget_cap_exceeded"
    assert result.reason_code != "checkpoint_unavailable"
    assert "past the configured cap" in (result.explanation or "")
    # The settled calls, including the one that crossed the cap, are on the record.
    reservation = result.evidence["budget_reservation"]
    assert reservation["settled_calls"] == 2
    assert all({"reserved_tokens", "actual_tokens", "overage_tokens"} <= set(item) for item in reservation["settlements"])


@pytest.mark.asyncio
async def test_every_result_carries_what_the_run_actually_spent(request_payload, source):
    """Settlement evidence is not only for refused runs: a normal abstention carries it too."""
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    store = SettlingCheckpointStore()

    result = await RepairAgent(RecordingProvider([_read(1, 3), _abstain()]), FailingVerifier(), store).run(request, snapshot)

    reservation = result.evidence["budget_reservation"]
    assert reservation["settled_calls"] == 2
    assert reservation["overage_calls"] == 0
    assert [item["call_index"] for item in reservation["settlements"]] == [1, 2]
