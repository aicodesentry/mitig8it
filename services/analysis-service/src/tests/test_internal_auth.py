"""The internal secret is compared in constant time."""
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

import main

SECRET = "correct-horse-battery-staple"


def _request(header_value=None):
    headers = [] if header_value is None else [(b"x-internal-secret", header_value.encode("utf-8"))]
    return Request({"type": "http", "method": "GET", "path": "/metrics", "headers": headers, "query_string": b""})


@pytest.fixture(autouse=True)
def configured_secret(monkeypatch):
    monkeypatch.setenv("ANALYSIS_SERVICE_INTERNAL_SECRET", SECRET)
    monkeypatch.delenv("GITHUB_SERVICE_INTERNAL_SECRET", raising=False)


def test_the_matching_secret_is_accepted():
    assert main.require_internal_auth(_request(SECRET)) is None


@pytest.mark.parametrize("provided", [
    "",
    "wrong",
    SECRET[:-1],
    SECRET + "x",
    SECRET.upper(),
])
def test_a_differing_or_missing_secret_is_rejected(provided):
    with pytest.raises(HTTPException) as raised:
        main.require_internal_auth(_request(provided))
    assert raised.value.status_code == 401


def test_a_missing_header_is_rejected():
    with pytest.raises(HTTPException) as raised:
        main.require_internal_auth(_request(None))
    assert raised.value.status_code == 401


def test_an_unconfigured_secret_is_a_503_not_an_open_door(monkeypatch):
    monkeypatch.delenv("ANALYSIS_SERVICE_INTERNAL_SECRET")
    with pytest.raises(HTTPException) as raised:
        main.require_internal_auth(_request(""))
    assert raised.value.status_code == 503


def test_the_comparison_is_constant_time():
    with patch("main.hmac.compare_digest", wraps=main.hmac.compare_digest) as compare:
        main.require_internal_auth(_request(SECRET))
        with pytest.raises(HTTPException):
            main.require_internal_auth(_request("wrong"))
    assert compare.call_count == 2
    for call in compare.call_args_list:
        assert all(isinstance(argument, bytes) for argument in call.args)
