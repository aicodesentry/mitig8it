from __future__ import annotations

from typing import Any, Protocol

from .provider import ProviderAction


class CheckpointError(RuntimeError):
    pass


class BudgetCapExceeded(CheckpointError):
    """Cumulative actual spend passed a hard cap, so the run stops with the spend recorded.

    A reservation is an estimate and may be overrun; `max_total_tokens` and `max_spend_usd` are
    the caps that actually bind. The settlement that crossed the cap is carried so the reason is
    reportable rather than only loggable.
    """

    def __init__(self, settlement: dict[str, Any]):
        super().__init__("cumulative provider spend exceeds the configured hard cap")
        self.settlement = settlement


class AgentCheckpointStore(Protocol):
    async def load(self) -> dict[str, Any] | None: ...

    async def reserve_provider_call(self, sequence: int, tokens: int, usd: float) -> bool: ...

    async def save_provider_action(
        self,
        state: dict[str, Any],
        action: ProviderAction,
        actual_tokens: int,
        actual_usd: float,
    ) -> dict[str, Any]: ...

    async def save_completed_step(self, state: dict[str, Any]) -> None: ...


class GroupScopedCheckpointStore:
    """Scopes one execution's durable checkpoint to the finding group currently running.

    A job with several connected finding groups runs one bounded agent loop per group against
    the same durable execution row. Each loop owns its own trajectory, so a checkpoint written
    by a different group is never resumed into this one.

    Spend reservations stay job-wide and are never reset, so a resumed multi-group job cannot
    exceed the job's token or USD budget. It can only consume more of that budget: a group that
    had already finished before a crash is run again, and the job ends with `budget_exhausted`
    for whatever the remaining budget can no longer cover.
    """

    def __init__(self, inner: AgentCheckpointStore, group_key: str):
        self.inner = inner
        self.group_key = group_key

    async def load(self) -> dict[str, Any] | None:
        state = await self.inner.load()
        if not state or state.get("group_key") != self.group_key:
            return None
        return state

    async def reserve_provider_call(self, sequence: int, tokens: int, usd: float) -> bool:
        return await self.inner.reserve_provider_call(sequence, tokens, usd)

    async def save_provider_action(
        self,
        state: dict[str, Any],
        action: ProviderAction,
        actual_tokens: int,
        actual_usd: float,
    ) -> dict[str, Any]:
        return await self.inner.save_provider_action({**state, "group_key": self.group_key}, action, actual_tokens, actual_usd)

    async def save_completed_step(self, state: dict[str, Any]) -> None:
        await self.inner.save_completed_step({**state, "group_key": self.group_key})
