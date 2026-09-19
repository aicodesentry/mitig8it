from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Protocol

import httpx


class ProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderAction:
    name: str
    arguments: dict[str, Any]
    call_id: str = "tool_call"
    request_id: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0


class LLMProvider(Protocol):
    async def next_action(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ProviderAction: ...


class OpenAICompatibleProvider:
    """Configurable production adapter for an OpenAI-compatible chat-completions API."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float = 90,
        max_output_tokens: int = 4096,
        client: httpx.AsyncClient | None = None,
    ):
        if not base_url.startswith("https://"):
            raise ProviderError("LLM provider URL must use HTTPS")
        if not api_key or not model:
            raise ProviderError("LLM provider API key and model are required")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.max_output_tokens = max_output_tokens
        self._client = client

    @classmethod
    def from_env(cls, expected_model: str | None = None) -> "OpenAICompatibleProvider":
        model = os.getenv("REPAIR_LLM_MODEL", "")
        if expected_model and model != expected_model:
            raise ProviderError("configured repair model does not match request version manifest")
        return cls(
            base_url=os.getenv("REPAIR_LLM_BASE_URL", "https://api.openai.com/v1"),
            api_key=os.getenv("REPAIR_LLM_API_KEY", ""),
            model=model,
            timeout_seconds=float(os.getenv("REPAIR_LLM_TIMEOUT_SECONDS", "90")),
            max_output_tokens=int(os.getenv("REPAIR_LLM_MAX_OUTPUT_TOKENS", "4096")),
        )

    async def next_action(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ProviderAction:
        client = self._client or httpx.AsyncClient()
        owns_client = self._client is None
        try:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={
                    "model": self.model,
                    "messages": messages,
                    "tools": tools,
                    "tool_choice": "required",
                    "temperature": 0,
                    "parallel_tool_calls": False,
                    "max_completion_tokens": self.max_output_tokens,
                },
                timeout=httpx.Timeout(self.timeout_seconds),
            )
            response.raise_for_status()
            data = response.json()
            message = data["choices"][0]["message"]
            calls = message.get("tool_calls") or []
            if len(calls) != 1 or calls[0].get("type") != "function":
                raise ProviderError("provider must return exactly one function tool call")
            function = calls[0]["function"]
            arguments = json.loads(function["arguments"])
            if not isinstance(arguments, dict):
                raise ProviderError("tool arguments must be an object")
            usage = data.get("usage")
            if not isinstance(usage, dict) or int(usage.get("prompt_tokens") or 0) <= 0:
                raise ProviderError("provider response must include token usage for budget enforcement")
            return ProviderAction(
                name=function["name"],
                arguments=arguments,
                call_id=str(calls[0]["id"]),
                request_id=data.get("id"),
                input_tokens=int(usage.get("prompt_tokens") or 0),
                output_tokens=int(usage.get("completion_tokens") or 0),
            )
        except ProviderError:
            raise
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ProviderError("LLM provider returned an invalid or unsuccessful response") from exc
        finally:
            if owns_client:
                await client.aclose()
