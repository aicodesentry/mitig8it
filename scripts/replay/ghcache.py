"""Disk-cached, read-only GitHub reads through the authenticated `gh` CLI.

Every response is stored under the cache directory keyed by the request path, so a
rerun of the same replay costs no API calls. Nothing here writes to GitHub: the only
verb used is `gh api --method GET`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any

GH_TIMEOUT_SECONDS = 120
MAX_ATTEMPTS = 3


class GitHubError(RuntimeError):
    pass


class GitHubReader:
    def __init__(self, cache_dir: Path, refresh: bool = False):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.refresh = refresh
        self.calls = 0
        self.cache_hits = 0

    def _cache_path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.cache_dir / digest[:2] / f"{digest}.json"

    def get(self, path: str, paginate: bool = False) -> Any:
        key = f"{'paginate:' if paginate else ''}{path}"
        cache_path = self._cache_path(key)
        if cache_path.exists() and not self.refresh:
            self.cache_hits += 1
            return json.loads(cache_path.read_text(encoding="utf-8"))["body"]

        argv = ["gh", "api", "--method", "GET", path]
        if paginate:
            argv.append("--paginate")
            # --paginate on a JSON array endpoint concatenates arrays when --slurp is off;
            # gh emits one array per page, so the slurp keeps the result parseable.
            argv.append("--slurp")

        last_error = ""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self.calls += 1
            try:
                result = subprocess.run(argv, capture_output=True, text=True, timeout=GH_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                last_error = "gh api timed out"
                time.sleep(2 * attempt)
                continue
            if result.returncode == 0:
                break
            last_error = (result.stderr or result.stdout or "").strip()[:500]
            if "rate limit" in last_error.lower() or "abuse" in last_error.lower():
                time.sleep(20 * attempt)
                continue
            if "404" in last_error or "Not Found" in last_error:
                raise GitHubError(f"not found: {path}")
            time.sleep(2 * attempt)
        else:
            raise GitHubError(f"gh api failed for {path}: {last_error}")

        try:
            body = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise GitHubError(f"gh api returned non-JSON for {path}") from exc

        if paginate and isinstance(body, list):
            flattened: list[Any] = []
            for page in body:
                if isinstance(page, list):
                    flattened.extend(page)
                else:
                    flattened.append(page)
            body = flattened

        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps({"path": path, "body": body}), encoding="utf-8")
        return body

    def merged_pull_requests(self, repo: str, count: int) -> list[dict[str, Any]]:
        pulls: list[dict[str, Any]] = []
        page = 1
        while len(pulls) < count and page <= 10:
            batch = self.get(
                f"repos/{repo}/pulls?state=closed&sort=updated&direction=desc&per_page=100&page={page}"
            )
            if not isinstance(batch, list) or not batch:
                break
            pulls.extend(item for item in batch if item.get("merged_at"))
            page += 1
        pulls.sort(key=lambda item: item.get("merged_at") or "", reverse=True)
        return pulls[:count]

    def pull_request_files(self, repo: str, number: int) -> list[dict[str, Any]]:
        files = self.get(f"repos/{repo}/pulls/{number}/files?per_page=100", paginate=True)
        return files if isinstance(files, list) else []

    def file_content(self, repo: str, ref: str, path: str) -> dict[str, Any]:
        """The head-sha blob for one path, decoded the way the github-service decodes it.

        Returns {"content": str} on success, or {"skipped": reason} for anything the
        production path would drop (missing blob, oversized file, non-UTF-8 bytes).
        """
        encoded = "/".join(_percent_encode(part) for part in path.split("/"))
        try:
            body = self.get(f"repos/{repo}/contents/{encoded}?ref={ref}")
        except GitHubError as exc:
            return {"skipped": f"content_unavailable:{exc}"[:200]}
        if isinstance(body, list):
            return {"skipped": "content_is_directory"}
        if not isinstance(body, dict):
            return {"skipped": "content_unexpected_shape"}
        if body.get("encoding") != "base64" or not isinstance(body.get("content"), str):
            return {"skipped": "content_not_base64"}
        raw = base64.b64decode(body["content"])
        # The github-service drops anything over 500 kB after decoding.
        if len(raw) > 500_000:
            return {"skipped": "content_over_500kb"}
        try:
            return {"content": raw.decode("utf-8")}
        except UnicodeDecodeError:
            # Node's Buffer.toString('utf8') replaces invalid bytes instead of failing, so
            # production really does hand this text to the analysis service.
            return {"content": raw.decode("utf-8", errors="replace"), "non_utf8": True}


def _percent_encode(part: str) -> str:
    from urllib.parse import quote

    return quote(part, safe="")
