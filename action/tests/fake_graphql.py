"""A GitHub GraphQL endpoint good enough to reconcile review threads against.

The publisher runs as a Node subprocess, so a fake that lives in the test process has to be
reachable over HTTP. This serves `POST /graphql` on localhost and answers the two operations the
publisher sends: the review-thread listing and `resolveReviewThread`.

`minimizeComment` is not one of them any more. A minimized thread is still an unresolved
conversation, so a repository that requires every conversation resolved stayed blocked by a
finding its author had fixed. The publisher deletes its own stale comment instead, through
github-service's `retireInlineComments`, which the publisher harness's stub answers.

It holds a mutable thread store, so a test can create threads in one run, let the publisher
resolve some of them, and then read back what actually happened rather than what was asked for.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional


class Thread:
    def __init__(self, thread_id: str, comment_id: str, body: str, login: str):
        self.id = thread_id
        self.comment_id = comment_id
        self.body = body
        # The login as REST spells it, which is how a caller naturally writes it and how the
        # publish request carries it. `graphql_login` is what this server actually serves.
        self.login = login
        self.is_resolved = False

    @property
    def graphql_login(self) -> str:
        """The login GraphQL returns, which is not the one REST returns.

        A review comment's `user.login` over REST is `github-actions[bot]`. The same account's
        `Bot.login` over GraphQL is `github-actions`, with no suffix: the suffix is a REST-only
        spelling. An author check that compared the two found zero threads on every run of the
        self-review, so the fake reproduces the difference rather than papering over it.
        """
        return self.login[: -len("[bot]")] if self.login.endswith("[bot]") else self.login

    def node(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "isResolved": self.is_resolved,
            "comments": {
                "nodes": [
                    {"id": self.comment_id, "body": self.body, "author": {"login": self.graphql_login}}
                ]
            },
        }


class FakeGraphQL:
    """The thread store plus a record of every mutation, with an optional forced failure."""

    def __init__(self, *, resolve_fails: bool = False):
        self.threads: List[Thread] = []
        self.calls: List[str] = []
        self.resolve_fails = resolve_fails
        self._next = 0
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # --- the store -----------------------------------------------------------------------

    def add_thread(self, body: str, login: str = "github-actions[bot]") -> Thread:
        self._next += 1
        thread = Thread(f"THREAD_{self._next}", f"COMMENT_{self._next}", body, login)
        self.threads.append(thread)
        return thread

    def resolved_bodies(self) -> List[str]:
        return [thread.body for thread in self.threads if thread.is_resolved]

    def open_bodies(self) -> List[str]:
        return [thread.body for thread in self.threads if not thread.is_resolved]

    # --- the protocol --------------------------------------------------------------------

    def execute(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        if "reviewThreads" in query:
            self.calls.append("list")
            return {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                            "nodes": [thread.node() for thread in self.threads],
                        }
                    }
                }
            }
        if "resolveReviewThread" in query:
            self.calls.append(f"resolve:{variables['id']}")
            if self.resolve_fails:
                raise ValueError("Resource not accessible by integration")
            for thread in self.threads:
                if thread.id == variables["id"]:
                    thread.is_resolved = True
                    return {"resolveReviewThread": {"thread": {"id": thread.id, "isResolved": True}}}
            raise ValueError("Could not resolve to a node")
        raise ValueError("unexpected GraphQL operation")

    # --- the server ----------------------------------------------------------------------

    def url(self) -> str:
        assert self._server is not None, "start() first"
        return f"http://127.0.0.1:{self._server.server_port}/graphql"

    def start(self) -> "FakeGraphQL":
        store = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - the BaseHTTPRequestHandler spelling.
                length = int(self.headers.get("Content-Length") or 0)
                document = json.loads(self.rfile.read(length) or b"{}")
                try:
                    payload = {"data": store.execute(document.get("query") or "", document.get("variables") or {})}
                except ValueError as error:
                    payload = {"errors": [{"message": str(error)}]}
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
