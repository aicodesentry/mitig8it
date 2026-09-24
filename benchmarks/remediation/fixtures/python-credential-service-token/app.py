"""Outbound notification client."""
import json
import urllib.request

NOTIFY_TOKEN = "ntfy-7c1f0b9a4d2e6853"


def _headers(extra=None):
    headers = {"Authorization": "Token " + NOTIFY_TOKEN}
    headers.update(extra or {})
    return headers


def build_request(url, payload):
    body = json.dumps(payload).encode("utf-8")
    return urllib.request.Request(url, data=body, headers=_headers({"Content-Type": "application/json"}))
