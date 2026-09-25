"""A GitHub API that answers from fixtures, for tests that must not touch the network.

It records every call so a test can assert what the action asked for, and it is deliberately
strict: an unrouted path raises rather than returning an empty result, so a test cannot pass
because the orchestrator quietly stopped making a request it used to make.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple


class FakeResponse:
    def __init__(self, payload: Any, status_code: int = 200, headers: Optional[Dict] = None):
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}
        self.text = json.dumps(payload) if not isinstance(payload, str) else payload

    def json(self) -> Any:
        return self._payload


class FakeGitHub:
    """Routes GET paths to canned payloads and remembers what was asked."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, Optional[Dict]]] = []
        self._routes: List[Tuple[re.Pattern, Callable[[re.Match, Optional[Dict]], Any]]] = []

    def route(self, pattern: str, handler) -> "FakeGitHub":
        compiled = re.compile(pattern)
        if callable(handler):
            self._routes.append((compiled, handler))
        else:
            self._routes.append((compiled, lambda _match, _params, value=handler: value))
        return self

    def reroute(self, pattern: str, handler) -> "FakeGitHub":
        """Replace an existing route, so a test can change one answer without rebuilding all."""
        self._routes = [route for route in self._routes if route[0].pattern != pattern]
        return self.route(pattern, handler)

    def get(self, url: str, headers=None, params=None) -> FakeResponse:  # noqa: ARG002
        path = url.split("https://api.github.com", 1)[-1]
        self.calls.append((path, dict(params) if params else None))
        for pattern, handler in self._routes:
            match = pattern.fullmatch(path)
            if match:
                payload = handler(match, params)
                if isinstance(payload, FakeResponse):
                    return payload
                return FakeResponse(payload)
        raise AssertionError(f"no fake route for GET {path} (params={params})")

    def paths(self) -> List[str]:
        return [path for path, _ in self.calls]

    def asked_for(self, fragment: str) -> bool:
        return any(fragment in path for path in self.paths())


def contents_payload(text: str) -> Dict[str, Any]:
    """What the contents endpoint returns for a text file."""
    return {
        "type": "file",
        "encoding": "base64",
        "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
    }


def repository(permissions: Dict[str, bool], full_name: str = "acme/widgets") -> Dict[str, Any]:
    return {"full_name": full_name, "id": 12345, "permissions": permissions}


def pull_request(number: int, head_sha: str, base_sha: str = "b" * 40) -> Dict[str, Any]:
    return {
        "number": number,
        "head": {"sha": head_sha, "ref": "feature"},
        "base": {"sha": base_sha, "ref": "main"},
    }


def paged(items: List[Any], page: Optional[str]) -> List[Any]:
    """Serve one page of a list the way the REST API does, 100 at a time."""
    index = int(page or 1)
    start = (index - 1) * 100
    return items[start : start + 100]
