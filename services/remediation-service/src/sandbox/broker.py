from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx

from ..digests import canonical_json, digest_json


class BrokerConfigurationError(RuntimeError):
    pass


class BrokerTransportError(RuntimeError):
    pass


class BrokerEvidenceError(RuntimeError):
    pass


# The policy's `request_timeout_seconds` is the sandbox deadline: the budget the broker
# enforces across every baseline and candidate check. The transport must wait longer than
# that, otherwise a verification that the broker is still allowed to finish is abandoned
# client-side and reported as the broker being unavailable.
CLIENT_TIMEOUT_MARGIN_SECONDS = 30


def client_timeout_seconds(deadline_seconds: int) -> int:
    return int(deadline_seconds) + CLIENT_TIMEOUT_MARGIN_SECONDS


class SandboxBroker(Protocol):
    async def verify(self, payload: dict[str, Any], deadline_seconds: int) -> dict[str, Any]: ...


class HttpSandboxBroker:
    """Client for a trusted broker; this adapter never executes repository code locally."""

    def __init__(
        self,
        base_url: str,
        token: str,
        attestation_secret: str,
        attestation_key_id: str,
        client: httpx.AsyncClient | None = None,
    ):
        parsed = urlparse(base_url)
        allow_insecure = os.getenv("SANDBOX_BROKER_ALLOW_INSECURE_LOCALHOST", "").lower() == "true"
        local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.scheme != "https" and not (allow_insecure and local):
            raise BrokerConfigurationError("sandbox broker URL must use HTTPS")
        if not token or not attestation_secret or not attestation_key_id:
            raise BrokerConfigurationError("sandbox broker authentication and attestation settings are required")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.attestation_secret = attestation_secret.encode("utf-8")
        self.attestation_key_id = attestation_key_id
        self._client = client

    @classmethod
    def from_env(cls) -> "HttpSandboxBroker":
        values = {
            "base_url": os.getenv("SANDBOX_BROKER_URL", ""),
            "token": os.getenv("SANDBOX_BROKER_TOKEN", ""),
            "attestation_secret": os.getenv("SANDBOX_BROKER_ATTESTATION_SECRET", ""),
            "attestation_key_id": os.getenv("SANDBOX_BROKER_ATTESTATION_KEY_ID", ""),
        }
        if not all(values.values()):
            raise BrokerConfigurationError("sandbox broker is not fully configured")
        return cls(**values)

    async def verify(self, payload: dict[str, Any], deadline_seconds: int) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Idempotency-Key": payload["request_digest"],
        }
        client = self._client or httpx.AsyncClient()
        owns_client = self._client is None
        timeout = httpx.Timeout(client_timeout_seconds(deadline_seconds))
        try:
            data = await self._post_verification(client, payload, headers, timeout)
        except asyncio.CancelledError:
            try:
                await client.delete(
                    f"{self.base_url}/v1/verifications/{payload['request_digest']}",
                    headers={"Authorization": f"Bearer {self.token}"},
                    timeout=httpx.Timeout(10),
                )
            finally:
                raise
        except (httpx.HTTPError, ValueError) as exc:
            raise BrokerTransportError("sandbox broker request did not return a valid success response") from exc
        finally:
            if owns_client:
                await client.aclose()
        self._validate_attestation(data, payload)
        return data

    async def _post_verification(
        self, client: httpx.AsyncClient, payload: dict[str, Any], headers: dict[str, str], timeout: httpx.Timeout
    ) -> Any:
        # A client-side timeout is retried once with the same Idempotency-Key. The broker
        # owns the execution under that key: if it has finished, the repeat returns the
        # attested evidence; if it is still running, the repeat waits for it. The repeat
        # never starts a second execution. Any other transport failure is not retried.
        for attempt in (1, 2):
            try:
                response = await client.post(
                    f"{self.base_url}/v1/verifications",
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                )
            except httpx.TimeoutException:
                if attempt == 2:
                    raise
                continue
            response.raise_for_status()
            return response.json()
        raise AssertionError("unreachable")

    def _validate_attestation(self, data: Any, request: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise BrokerEvidenceError("broker evidence is not an object")
        attestation = data.get("attestation")
        if not isinstance(attestation, dict):
            raise BrokerEvidenceError("broker evidence has no attestation")
        if attestation.get("algorithm") != "HMAC-SHA256" or attestation.get("key_id") != self.attestation_key_id:
            raise BrokerEvidenceError("broker attestation identity is not trusted")
        signature = attestation.get("signature")
        if not isinstance(signature, str):
            raise BrokerEvidenceError("broker attestation signature is absent")
        signed = {key: value for key, value in data.items() if key != "attestation"}
        expected = hmac.new(self.attestation_secret, canonical_json(signed), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise BrokerEvidenceError("broker attestation signature is invalid")
        for key in ("execution_id", "request_digest", "request_nonce"):
            if data.get(key) != request.get(key):
                raise BrokerEvidenceError(f"broker evidence does not bind {key}")
        if data.get("schema_version") != "v1":
            raise BrokerEvidenceError("unsupported broker evidence schema")


def evidence_digest(evidence: dict[str, Any]) -> str:
    return digest_json(evidence)
