"""Outbound notification client."""
import json
import urllib.request
import os

NOTIFY_TOKEN = os.environ["NOTIFY_TOKEN"]


def _headers(extra=None):
    headers = {"Authorization": "Token " + NOTIFY_TOKEN}
    headers.update(extra or {})
    return headers


def build_request(url, payload):
    body = json.dumps(payload).encode("utf-8")
    return urllib.request.Request(url, data=body, headers=_headers({"Content-Type": "application/json"}))
