"""
Provider-neutral LLM client for Tier 3 triage.

The triage layer owns prompt construction and parsing. This module only adapts
provider-specific request/response shapes into one small internal response.
"""

import os
import re
from dataclasses import dataclass
from typing import Optional

import httpx

_REDACTED = "[REDACTED]"

# `key=...`, `api_key=...`, `access_token=...` in a URL query string or body.
_QUERY_SECRET_RE = re.compile(
    r"(?<![\w-])(api[_-]?key|key|access[_-]?token|token|password)=[^&\s\"'<>]+",
    re.IGNORECASE,
)
# `Authorization: Bearer ...` and provider API-key headers, however they are formatted.
_AUTH_VALUE_RE = re.compile(
    r"(?<![\w-])(authorization|x-goog-api-key|api-key|x-api-key)(\s*[:=]\s*)"
    r"(?:bearer\s+)?[^\s,;\"'}\]]+",
    re.IGNORECASE,
)
# Bare provider key material that leaked into a message without a label.
_BARE_KEY_RE = re.compile(r"(?<![\w-])(AIza[0-9A-Za-z_-]{10,}|sk-[A-Za-z0-9_-]{10,})")


def redact(value: object) -> str:
    """Strip API keys and Authorization values out of anything about to be logged.

    Applied to every log line and error message that can carry a request URL or a
    provider error body, so a misconfigured or failing provider call never prints
    credentials.
    """
    text = value if isinstance(value, str) else str(value)
    text = _QUERY_SECRET_RE.sub(lambda m: f"{m.group(1)}={_REDACTED}", text)
    text = _AUTH_VALUE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}", text)
    text = _BARE_KEY_RE.sub(_REDACTED, text)
    return text


# gemini-2.0-flash was retired and now returns 404 for every triage call.
# gemini-2.5-flash-lite is the cheapest generally available Gemini flash model
# that handles the structured JSON triage prompt.
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash-lite"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


@dataclass(frozen=True)
class LLMResponse:
    text: str
    input_tokens: int
    output_tokens: int
    provider: str
    model: str


def _normalized_provider() -> str:
    configured = (
        os.getenv("LLM_PROVIDER")
        or os.getenv("LLM_TRIAGE_PROVIDER")
        or ""
    ).strip().lower().replace("-", "_")
    if configured:
        return configured

    if os.getenv("GEMINI_API_KEY"):
        return "gemini"
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    if os.getenv("LLM_BASE_URL") and os.getenv("LLM_API_KEY"):
        return "openai_compatible"
    return "openai"


def _model_for(provider: str) -> str:
    configured = os.getenv("LLM_MODEL") or os.getenv("LLM_TRIAGE_MODEL")
    if configured:
        return configured
    if provider == "gemini":
        return DEFAULT_GEMINI_MODEL
    return DEFAULT_OPENAI_MODEL


def _api_key_for(provider: str) -> Optional[str]:
    generic_key = os.getenv("LLM_API_KEY")
    if generic_key:
        return generic_key
    if provider == "gemini":
        return os.getenv("GEMINI_API_KEY")
    if provider in {"openai", "openai_compatible"}:
        return os.getenv("OPENAI_API_KEY")
    return None


def is_llm_configured() -> bool:
    disabled_values = {"0", "false", "no", "off"}
    if os.getenv("LLM_TRIAGE_ENABLED", "true").strip().lower() in disabled_values:
        return False
    provider = _normalized_provider()
    if provider == "openai_compatible" and not os.getenv("LLM_BASE_URL"):
        return False
    return bool(_api_key_for(provider))


def call_llm(
    *,
    system_prompt: str,
    user_prompt: str,
    timeout_seconds: int,
    temperature: float = 0,
    max_output_tokens: int = 4096,
) -> LLMResponse:
    provider = _normalized_provider()
    model = _model_for(provider)
    api_key = _api_key_for(provider)
    if not api_key:
        raise RuntimeError(f"LLM API key is not configured for provider '{provider}'")

    if provider == "openai":
        return _call_openai(
            api_key=api_key,
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            timeout_seconds=timeout_seconds,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )
    if provider == "openai_compatible":
        return _call_openai(
            api_key=api_key,
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            timeout_seconds=timeout_seconds,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            base_url=os.getenv("LLM_BASE_URL"),
            provider="openai_compatible",
        )
    if provider == "gemini":
        return _call_gemini(
            api_key=api_key,
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            timeout_seconds=timeout_seconds,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )

    raise ValueError(f"Unsupported LLM_PROVIDER: {provider}")


def _call_openai(
    *,
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    timeout_seconds: int,
    temperature: float,
    max_output_tokens: int,
    base_url: Optional[str] = None,
    provider: str = "openai",
) -> LLMResponse:
    from openai import OpenAI

    client_kwargs = {"api_key": api_key, "timeout": timeout_seconds}
    if base_url:
        client_kwargs["base_url"] = base_url
    client = OpenAI(**client_kwargs)
    response = client.chat.completions.create(
        model=model,
        temperature=temperature,
        max_tokens=max_output_tokens,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )

    return LLMResponse(
        text=response.choices[0].message.content or "",
        input_tokens=response.usage.prompt_tokens if response.usage else 0,
        output_tokens=response.usage.completion_tokens if response.usage else 0,
        provider=provider,
        model=model,
    )


def _call_gemini(
    *,
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    timeout_seconds: int,
    temperature: float,
    max_output_tokens: int,
) -> LLMResponse:
    base_url = os.getenv(
        "GEMINI_BASE_URL",
        "https://generativelanguage.googleapis.com",
    ).rstrip("/")
    url = f"{base_url}/v1beta/models/{model}:generateContent"
    payload = {
        "systemInstruction": {
            "parts": [{"text": system_prompt}],
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": user_prompt}],
            }
        ],
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_output_tokens,
            "responseMimeType": "application/json",
        },
    }

    # The key travels in a header, never in the query string, so it cannot end up
    # in a URL that gets logged by httpx, by us, or by an intermediary.
    headers = {"x-goog-api-key": api_key}

    with httpx.Client(timeout=timeout_seconds) as client:
        response = client.post(url, headers=headers, json=payload)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                redact(f"Gemini request failed: {exc} body={response.text}")
            ) from None
        data = response.json()

    text = ""
    for candidate in data.get("candidates", []):
        for part in candidate.get("content", {}).get("parts", []):
            if part.get("text"):
                text += part["text"]

    usage = data.get("usageMetadata") or {}
    return LLMResponse(
        text=text,
        input_tokens=int(usage.get("promptTokenCount") or 0),
        output_tokens=int(usage.get("candidatesTokenCount") or 0),
        provider="gemini",
        model=model,
    )
