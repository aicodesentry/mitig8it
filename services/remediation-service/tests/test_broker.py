from __future__ import annotations

import hashlib
import hmac

import httpx
import pytest

from src.digests import canonical_json
from src.sandbox import BrokerEvidenceError, HttpSandboxBroker


def signed_evidence(request, *, signature_secret="attest-secret"):
    evidence = {
        "schema_version": "v1",
        "execution_id": request["execution_id"],
        "request_digest": request["request_digest"],
        "request_nonce": request["request_nonce"],
        "outcome": "passed",
    }
    evidence["attestation"] = {
        "algorithm": "HMAC-SHA256",
        "key_id": "key-1",
        "signature": hmac.new(signature_secret.encode(), canonical_json(evidence), hashlib.sha256).hexdigest(),
    }
    return evidence


@pytest.mark.asyncio
async def test_http_broker_requires_authenticated_digest_bound_evidence(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer transport-secret"
        payload = __import__("json").loads(request.content)
        return httpx.Response(200, json=signed_evidence(payload))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    broker = HttpSandboxBroker("https://broker.example", "transport-secret", "attest-secret", "key-1", client)
    request = {"execution_id": "exec", "request_digest": "digest", "request_nonce": "nonce"}
    assert (await broker.verify(request, 10))["outcome"] == "passed"
    await client.aclose()


@pytest.mark.asyncio
async def test_http_broker_rejects_tampered_attestation():
    async def handler(request: httpx.Request) -> httpx.Response:
        payload = __import__("json").loads(request.content)
        evidence = signed_evidence(payload)
        evidence["outcome"] = "failed"
        return httpx.Response(200, json=evidence)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    broker = HttpSandboxBroker("https://broker.example", "transport-secret", "attest-secret", "key-1", client)
    with pytest.raises(BrokerEvidenceError, match="invalid"):
        await broker.verify({"execution_id": "exec", "request_digest": "digest", "request_nonce": "nonce"}, 10)
    await client.aclose()


def test_broker_rejects_plain_http():
    with pytest.raises(Exception, match="HTTPS"):
        HttpSandboxBroker("http://broker.example", "a", "b", "c")


def _verification_request():
    return {"execution_id": "exec", "request_digest": "digest", "request_nonce": "nonce"}


@pytest.mark.asyncio
async def test_http_broker_waits_a_fixed_margin_beyond_the_sandbox_deadline():
    """The policy value is the broker's deadline; the transport must outlast it."""
    from src.sandbox.broker import CLIENT_TIMEOUT_MARGIN_SECONDS

    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["timeout"] = request.extensions["timeout"]
        return httpx.Response(200, json=signed_evidence(__import__("json").loads(request.content)))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    broker = HttpSandboxBroker("https://broker.example", "transport-secret", "attest-secret", "key-1", client)
    await broker.verify(_verification_request(), 600)
    await client.aclose()
    assert seen["timeout"]["read"] == 600 + CLIENT_TIMEOUT_MARGIN_SECONDS
    assert seen["timeout"]["connect"] == 600 + CLIENT_TIMEOUT_MARGIN_SECONDS


@pytest.mark.asyncio
async def test_http_broker_retries_a_client_timeout_once_under_the_same_idempotency_key():
    keys = []

    async def handler(request: httpx.Request) -> httpx.Response:
        keys.append(request.headers["idempotency-key"])
        if len(keys) == 1:
            raise httpx.ReadTimeout("read timed out", request=request)
        return httpx.Response(200, json=signed_evidence(__import__("json").loads(request.content)))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    broker = HttpSandboxBroker("https://broker.example", "transport-secret", "attest-secret", "key-1", client)
    assert (await broker.verify(_verification_request(), 10))["outcome"] == "passed"
    await client.aclose()
    # The repeat reads the execution the first request started; it never starts another.
    assert keys == ["digest", "digest"]


@pytest.mark.asyncio
async def test_http_broker_reports_a_second_client_timeout_as_transport_failure():
    from src.sandbox import BrokerTransportError

    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("read timed out", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    broker = HttpSandboxBroker("https://broker.example", "transport-secret", "attest-secret", "key-1", client)
    with pytest.raises(BrokerTransportError):
        await broker.verify(_verification_request(), 10)
    await client.aclose()
    assert calls == 2


@pytest.mark.asyncio
async def test_http_broker_does_not_retry_a_failed_response():
    """Only a client-side timeout is retried; a broker that answered is never asked twice."""
    from src.sandbox import BrokerTransportError

    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={"error": "unavailable"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    broker = HttpSandboxBroker("https://broker.example", "transport-secret", "attest-secret", "key-1", client)
    with pytest.raises(BrokerTransportError):
        await broker.verify(_verification_request(), 10)
    await client.aclose()
    assert calls == 1
