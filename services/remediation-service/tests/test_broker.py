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
