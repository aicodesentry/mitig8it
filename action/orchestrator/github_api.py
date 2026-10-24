"""The GitHub REST calls the action makes, with the workflow's own token.

Everything here runs against `${{ github.token }}` inside the customer's runner. There is no App
JWT, no installation token exchange, and no credential of ours anywhere in the process. The only
host contacted is the API base the runner itself was given.

Reads are retried on the statuses GitHub uses for throttling and transient faults, matching
`GitHubReader` in the github-service. Writes live in the Node publisher, which reuses the
service's own write path, so this module reads only.
"""
from __future__ import annotations

import base64
import logging
import random
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

import httpx

from . import pr_scope

RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_ATTEMPTS = 4
BASE_DELAY_SECONDS = 1.0
MAX_DELAY_SECONDS = 60.0
REQUEST_TIMEOUT_SECONDS = 30.0
PAGE_SIZE = 100
# Above this the contents API returns metadata with no inline content.
CONTENTS_API_INLINE_LIMIT_BYTES = 1_000_000
# The analysis service's own spelling, so every surface renders the kind the same way.
LIMITATION_NOT_ANALYZED = "not_analyzed"


def _int_or_zero(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _size_limitation(path: str, size: int) -> Dict[str, Any]:
    described = f"{size} bytes" if size else "too large for the contents API"
    return {
        "kind": LIMITATION_NOT_ANALYZED,
        "path": path,
        "reason": "size",
        "message": (
            f"not analysed whole ({described}, above the {pr_scope.MAX_FILE_CONTENT_BYTES}-byte "
            "limit for full-file analysis); only its patch was read"
        ),
    }


class GitHubError(Exception):
    """A GitHub request failed in a way the run cannot continue past."""


class HeadMovedError(GitHubError):
    """The pull request head moved while the file list was being read.

    Production raises the same condition as a 409 and abandons the run. A review that mixes two
    commits reports findings against lines that no longer exist, so the run is abandoned rather
    than published against a head it did not read.
    """


class PermissionError_(GitHubError):
    """The workflow granted a permission the action refuses to hold."""


class GitHubReader:
    def __init__(
        self,
        token: str,
        repository: str,
        api_url: str = "https://api.github.com",
        client: Optional[httpx.Client] = None,
        sleep=time.sleep,
        random_source=random.random,
    ) -> None:
        if not token:
            raise GitHubError("a GitHub token is required")
        if "/" not in repository:
            raise GitHubError(f"repository must be owner/name, got {repository!r}")
        self.token = token
        self.repository = repository
        self.owner, self.repo = repository.split("/", 1)
        self.api_url = api_url.rstrip("/")
        self._sleep = sleep
        self._random = random_source
        self._client = client or httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> httpx.Response:
        """One GET, retried with full jitter on throttling and transient faults."""
        url = path if path.startswith("http") else f"{self.api_url}{path}"
        last_error: Optional[Exception] = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = self._client.get(url, headers=self._headers(), params=params)
            except httpx.HTTPError as error:
                last_error = error
                if attempt == MAX_ATTEMPTS:
                    raise GitHubError(f"GET {path} failed: {error}") from error
                self._back_off(attempt, None)
                continue
            if response.status_code < 400:
                return response
            if response.status_code not in RETRYABLE_STATUSES or attempt == MAX_ATTEMPTS:
                raise GitHubError(
                    f"GET {path} failed with status {response.status_code}: "
                    f"{response.text[:400]}"
                )
            self._back_off(attempt, response.headers.get("retry-after"))
        raise GitHubError(f"GET {path} failed: {last_error}")

    def _back_off(self, attempt: int, retry_after: Optional[str]) -> None:
        if retry_after:
            try:
                self._sleep(min(float(retry_after), MAX_DELAY_SECONDS))
                return
            except ValueError:
                pass
        ceiling = min(BASE_DELAY_SECONDS * (2 ** (attempt - 1)), MAX_DELAY_SECONDS)
        self._sleep(ceiling * self._random())

    def _paginate(self, path: str, params: Optional[Dict[str, Any]] = None) -> Iterable[Any]:
        page = 1
        while True:
            merged = dict(params or {})
            merged.update({"per_page": PAGE_SIZE, "page": page})
            payload = self.get(path, merged).json()
            if not isinstance(payload, list):
                raise GitHubError(f"expected a list from {path}")
            yield from payload
            if len(payload) < PAGE_SIZE:
                return
            page += 1

    # --- the calls the orchestrator makes -------------------------------------------------

    def repository_permissions(self) -> Dict[str, bool]:
        """The permissions this token holds on the repository.

        GitHub reports an Actions token's granted scopes through the repository object, so this
        is how the action learns whether the workflow handed it `contents: write` when it asked
        for none. `push` is the flag that corresponds to write access to file contents.
        """
        payload = self.get(f"/repos/{self.owner}/{self.repo}").json()
        permissions = payload.get("permissions")
        if not isinstance(permissions, dict):
            raise PermissionError_(
                "The repository response carried no permissions object, so the action could "
                "not confirm that it holds no write access to contents. Refusing to run rather "
                "than assume. Report this with the API base the workflow used."
            )
        return {key: bool(value) for key, value in permissions.items()}

    def pull_request(self, number: int) -> Dict[str, Any]:
        return self.get(f"/repos/{self.owner}/{self.repo}/pulls/{number}").json()

    def assert_head(self, number: int, head_sha: str) -> None:
        pull = self.pull_request(number)
        actual = (pull.get("head") or {}).get("sha")
        if actual != head_sha:
            raise HeadMovedError(
                f"Analysis run superseded by another PR head ({actual} is not {head_sha})"
            )

    def list_pull_request_files(self, number: int, head_sha: str) -> List[Dict[str, Any]]:
        """Every changed file on the pull request, read at a head that did not move.

        The head is asserted before and after the listing, exactly as `fetchPullRequestFiles`
        does, because a push between the first and last page would otherwise produce a file list
        that belongs to no single commit.
        """
        self.assert_head(number, head_sha)
        files = list(self._paginate(f"/repos/{self.owner}/{self.repo}/pulls/{number}/files"))
        self.assert_head(number, head_sha)
        return files

    def file_contents(self, paths: Iterable[str], ref: str) -> Dict[str, str]:
        """Head-revision text for each path, without the files that could not be read whole."""
        return self.file_contents_with_limitations(paths, ref)[0]

    def file_contents_with_limitations(
        self, paths: Iterable[str], ref: str
    ) -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
        """Head-revision text for each path, and a `not_analyzed` limitation for each skipped one.

        A skipped file is absent from the contents and named in the limitations, never present
        as an empty or truncated string: the scanner would report a clean result for text it
        never saw. Two cases are skipped for size. Text over the byte cap is dropped rather than
        cut. Over 1 MB the contents API returns no content at all (`encoding: "none"`, or an
        empty `content` beside a large `size`), and that used to be stored as an empty file.
        """
        contents: Dict[str, str] = {}
        limitations: List[Dict[str, Any]] = []
        for path in list(paths)[: pr_scope.MAX_CHANGED_FILES]:
            if not path or not isinstance(path, str):
                continue
            # Each segment is encoded on its own so the separators survive, matching the
            # `path.split('/').map(encodeURIComponent).join('/')` the github-service uses.
            encoded = "/".join(quote(part, safe="") for part in path.split("/"))
            response = self.get(
                f"/repos/{self.owner}/{self.repo}/contents/{encoded}", {"ref": ref}
            )
            payload = response.json()
            if isinstance(payload, str):
                text = payload
            else:
                raw = payload.get("content") or ""
                size = _int_or_zero(payload.get("size"))
                withheld = str(payload.get("encoding") or "").lower() == "none" or (
                    not raw and size > CONTENTS_API_INLINE_LIMIT_BYTES
                )
                if withheld:
                    limitations.append(_size_limitation(path, size))
                    continue
                try:
                    text = base64.b64decode(raw).decode("utf-8", errors="replace")
                except (ValueError, TypeError):
                    limitations.append(
                        {
                            "kind": LIMITATION_NOT_ANALYZED,
                            "path": path,
                            "reason": "unreadable",
                            "message": "not analysed whole: GitHub returned content that "
                            "could not be decoded; only its patch was read",
                        }
                    )
                    continue
            byte_size = len(text.encode("utf-8"))
            if byte_size > pr_scope.MAX_FILE_CONTENT_BYTES:
                limitations.append(_size_limitation(path, byte_size))
                continue
            contents[path] = text
        return contents, limitations

    def git_tree(self, head_sha: str) -> Dict[str, Any]:
        """The complete recursive tree at the head commit.

        The repair engine verifies that every file it was handed hashes to its entry in this
        tree, which is what stops a repair being built against content the commit does not
        contain. A truncated tree cannot support that check, so the caller treats it as a reason
        to skip repairs rather than to guess.
        """
        response = self.get(
            f"/repos/{self.owner}/{self.repo}/git/trees/{head_sha}", {"recursive": "1"}
        )
        return response.json()

    def viewer_login(self) -> str:
        """The login the token posts as, used to recognise the action's own comments.

        The App resolves `<slug>[bot]`. A workflow token posts as `github-actions[bot]`, which
        `GET /user` does not answer for, so the login is read from the token's own identity when
        that call works and falls back to the Actions bot otherwise.

        The 403 is the expected answer, not a fault, and it was the only status code in the whole
        run log: `HTTP Request: GET https://api.github.com/user "HTTP/1.1 403 Forbidden"` on every
        one of the trial's 26 runs, at INFO, in a log a reader is scanning for exactly that shape.
        httpx logs every request it makes, so the one call whose failure is the normal case is
        made with that logger quiet. Nothing else the action does is hidden this way.
        """
        transport_log = logging.getLogger("httpx")
        previous = transport_log.level
        transport_log.setLevel(max(previous, logging.WARNING))
        try:
            payload = self.get("/user").json()
        except GitHubError:
            return "github-actions[bot]"
        finally:
            transport_log.setLevel(previous)
        login = payload.get("login")
        return str(login) if login else "github-actions[bot]"
