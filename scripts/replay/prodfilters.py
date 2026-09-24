"""The production payload rules, mirrored so a replay is faithful.

Each function here has one counterpart in the services:

* ``scoped_files``            -> githubInternalOperations.js ``fetchPullRequestFiles``
* ``PR_FILE_CAP``            -> the 200-file limit in the same function
* ``should_fetch_content``   -> prAnalysisOrchestrator.js ``shouldFetchFullFileContent``
* ``reviewable_line_spans``  -> suggestedFixValidator.js ``extractReviewableLineSpans``
* ``CONTENT_BYTE_CAP``       -> the 500 kB drop in ``fetchFileContents``

If one of those changes in a service, change it here in the same commit or the replay
stops describing production.
"""
from __future__ import annotations

import re
from typing import Any

PR_FILE_CAP = 200
CONTENT_PATH_CAP = 200
CONTENT_BYTE_CAP = 500_000
ANALYSIS_FILE_CAP = 300

SCOPED_STATUSES = {"added", "modified", "renamed"}

TIER2_SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".c", ".cpp", ".h", ".hpp", ".rs", ".swift", ".kt",
}

HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def scoped_files(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The changed files production forwards: added/modified/renamed, not dist/ or node_modules."""
    return [
        item
        for item in files
        if item.get("status") in SCOPED_STATUSES
        and not str(item.get("filename", "")).startswith("dist/")
        and "node_modules" not in str(item.get("filename", ""))
    ]


def file_extension(path: str) -> str:
    match = re.search(r"(\.[^./]+)$", str(path or "").lower())
    return match.group(1) if match else ""


def should_fetch_content(path: str) -> bool:
    path = str(path or "")
    if file_extension(path) not in TIER2_SUPPORTED_EXTENSIONS:
        return False
    if path.startswith("dist/") or "node_modules/" in path:
        return False
    if path.endswith(".min.js") or path.endswith(".min.css"):
        return False
    return True


def reviewable_line_spans(patch: str) -> list[dict[str, int]]:
    """New-side line spans of the added lines, exactly as the api-service derives them."""
    spans: list[dict[str, int]] = []
    if not patch:
        return spans

    new_line = 0
    span_start: int | None = None
    span_end: int | None = None

    def flush() -> None:
        nonlocal span_start, span_end
        if span_start is None or span_end is None:
            return
        spans.append({"start": span_start, "end": span_end})
        span_start = None
        span_end = None

    for raw in str(patch).split("\n"):
        if raw.startswith("@@"):
            flush()
            match = HUNK_HEADER.match(raw)
            if match:
                new_line = int(match.group(1))
            continue
        if raw.startswith("+++ ") or raw.startswith("--- "):
            continue
        if raw.startswith("+"):
            line_number = new_line or 1
            if span_start is None:
                span_start = line_number
                span_end = line_number
            elif line_number == span_end + 1:
                span_end = line_number
            else:
                flush()
                span_start = line_number
                span_end = line_number
            new_line += 1
            continue
        flush()
        if not raw.startswith("-"):
            new_line += 1

    flush()
    return spans
