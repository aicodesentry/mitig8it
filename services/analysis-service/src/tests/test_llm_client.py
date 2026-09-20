"""Tests for provider-neutral LLM client wiring."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

import llm_client


def test_disabled_when_triage_flag_is_false():
    with patch.dict("os.environ", {"LLM_TRIAGE_ENABLED": "false", "LLM_PROVIDER": "gemini", "LLM_API_KEY": "key"}, clear=True):
        assert not llm_client.is_llm_configured()


def test_configured_with_generic_gemini_key():
    with patch.dict("os.environ", {"LLM_PROVIDER": "gemini", "LLM_API_KEY": "key"}, clear=True):
        assert llm_client.is_llm_configured()


def test_openai_compatible_requires_base_url():
    with patch.dict("os.environ", {"LLM_PROVIDER": "openai_compatible", "LLM_API_KEY": "key"}, clear=True):
        assert not llm_client.is_llm_configured()

    with patch.dict(
        "os.environ",
        {"LLM_PROVIDER": "openai_compatible", "LLM_API_KEY": "key", "LLM_BASE_URL": "http://localhost:11434/v1"},
        clear=True,
    ):
        assert llm_client.is_llm_configured()


@patch("openai.OpenAI")
def test_openai_call_uses_generic_key_and_model(mock_openai):
    completion = MagicMock()
    completion.choices = [MagicMock(message=MagicMock(content="[]"))]
    completion.usage = MagicMock(prompt_tokens=11, completion_tokens=7)
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = completion
    mock_openai.return_value = mock_client

    with patch.dict("os.environ", {"LLM_PROVIDER": "openai", "LLM_MODEL": "gpt-test", "LLM_API_KEY": "key"}, clear=True):
        response = llm_client.call_llm(
            system_prompt="system",
            user_prompt="user",
            timeout_seconds=10,
        )

    mock_openai.assert_called_once_with(api_key="key", timeout=10)
    mock_client.chat.completions.create.assert_called_once()
    kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert kwargs["model"] == "gpt-test"
    assert response.text == "[]"
    assert response.input_tokens == 11
    assert response.output_tokens == 7
    assert response.provider == "openai"


@patch("openai.OpenAI")
def test_openai_compatible_uses_base_url(mock_openai):
    completion = MagicMock()
    completion.choices = [MagicMock(message=MagicMock(content="[]"))]
    completion.usage = None
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = completion
    mock_openai.return_value = mock_client

    with patch.dict(
        "os.environ",
        {
            "LLM_PROVIDER": "openai_compatible",
            "LLM_MODEL": "local-model",
            "LLM_API_KEY": "key",
            "LLM_BASE_URL": "http://localhost:11434/v1",
        },
        clear=True,
    ):
        response = llm_client.call_llm(system_prompt="system", user_prompt="user", timeout_seconds=10)

    mock_openai.assert_called_once_with(api_key="key", timeout=10, base_url="http://localhost:11434/v1")
    assert response.provider == "openai_compatible"
    assert response.model == "local-model"


@patch("llm_client.httpx.Client")
def test_gemini_call_maps_response_shape(mock_client_cls):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": "[]"}]}}],
        "usageMetadata": {"promptTokenCount": 13, "candidatesTokenCount": 5},
    }
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value = mock_response
    mock_client_cls.return_value = mock_client

    with patch.dict("os.environ", {"LLM_PROVIDER": "gemini", "LLM_MODEL": "gemini-test", "LLM_API_KEY": "key"}, clear=True):
        response = llm_client.call_llm(system_prompt="system", user_prompt="user", timeout_seconds=10)

    mock_client.post.assert_called_once()
    url = mock_client.post.call_args.args[0]
    kwargs = mock_client.post.call_args.kwargs
    assert url.endswith("/v1beta/models/gemini-test:generateContent")
    assert "params" not in kwargs
    assert kwargs["headers"] == {"x-goog-api-key": "key"}
    assert "key" not in url
    assert kwargs["json"]["generationConfig"]["responseMimeType"] == "application/json"
    assert response.text == "[]"
    assert response.input_tokens == 13
    assert response.output_tokens == 5
    assert response.provider == "gemini"


def test_unsupported_provider_raises():
    with patch.dict("os.environ", {"LLM_PROVIDER": "unknown", "LLM_API_KEY": "key"}, clear=True):
        with pytest.raises(ValueError, match="Unsupported LLM_PROVIDER"):
            llm_client.call_llm(system_prompt="system", user_prompt="user", timeout_seconds=10)


def test_default_gemini_model_is_not_the_retired_one():
    with patch.dict("os.environ", {"LLM_PROVIDER": "gemini", "LLM_API_KEY": "key"}, clear=True):
        model = llm_client._model_for("gemini")
    assert model == "gemini-2.5-flash-lite"
    assert model != "gemini-2.0-flash"


def test_explicit_model_env_still_wins_over_default():
    with patch.dict(
        "os.environ",
        {"LLM_PROVIDER": "gemini", "LLM_API_KEY": "key", "LLM_MODEL": "gemini-custom"},
        clear=True,
    ):
        assert llm_client._model_for("gemini") == "gemini-custom"


@pytest.mark.parametrize(
    "raw",
    [
        "Client error '404 Not Found' for url 'https://x/v1beta/models/m:generateContent?key=AIzaSyFAKEKEYVALUE123456'",
        "GET https://x/v1?api_key=AIzaSyFAKEKEYVALUE123456&alt=json",
        "GET https://x/v1?access_token=AIzaSyFAKEKEYVALUE123456",
    ],
)
def test_redact_strips_key_query_values(raw):
    redacted = llm_client.redact(raw)
    assert "AIzaSyFAKEKEYVALUE123456" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_strips_authorization_and_bare_keys():
    redacted = llm_client.redact(
        "headers={'Authorization': 'Bearer sk-secretvalue123456', "
        "'x-goog-api-key': 'AIzaSyFAKEKEYVALUE123456'} raw=AIzaSyFAKEKEYVALUE123456"
    )
    assert "sk-secretvalue123456" not in redacted
    assert "AIzaSyFAKEKEYVALUE123456" not in redacted


def test_redact_keeps_non_secret_text_intact():
    assert llm_client.redact("LLM triage failed: connection timeout") == (
        "LLM triage failed: connection timeout"
    )
    assert "monkey=banana" in llm_client.redact("monkey=banana")


@patch("httpx.Client")
def test_gemini_http_error_is_logged_without_the_key(mock_client_cls):
    leaky_url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-test:generateContent?key=AIzaSyFAKEKEYVALUE123456"
    )
    request = httpx.Request("POST", leaky_url)
    mock_response = MagicMock()
    mock_response.text = '{"error": {"message": "check key=AIzaSyFAKEKEYVALUE123456"}}'
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        f"Client error '404 Not Found' for url '{leaky_url}'",
        request=request,
        response=MagicMock(),
    )
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value = mock_response
    mock_client_cls.return_value = mock_client

    env = {"LLM_PROVIDER": "gemini", "LLM_MODEL": "gemini-test", "LLM_API_KEY": "AIzaSyFAKEKEYVALUE123456"}
    with patch.dict("os.environ", env, clear=True):
        with pytest.raises(RuntimeError) as excinfo:
            llm_client.call_llm(system_prompt="system", user_prompt="user", timeout_seconds=10)

    message = str(excinfo.value)
    assert "AIzaSyFAKEKEYVALUE123456" not in message
    assert "404 Not Found" in message
    assert "[REDACTED]" in message
