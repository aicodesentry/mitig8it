"""Which changed files a review looks at, and how much of each one it reads.

Production splits these rules across two Node services. `fetchPullRequestFiles` in
services/github-service/src/services/githubInternalOperations.js decides which entries of the
pull request file list are in scope at all and caps the count. `shouldFetchFullFileContent` and
`buildTier2FilePayload` in services/api-service/src/services/prAnalysisOrchestrator.js decide
which of those files get their full head-revision content attached, and
`extractReviewableLineSpans` in services/api-service/src/services/suggestedFixValidator.js turns
a patch into the added-line spans that ride along on the payload.

The action has no Node orchestrator to ask, so the rules are ported here rather than re-derived.
tests/test_node_parity.py reads the three Node sources and asserts every literal below still
matches the one production uses, so a change on either side fails the build instead of silently
giving the action a different scope from the app.

The rules that already exist in Python are imported, not copied: test-code classification and the
scanner-asset exclusion come from the analysis service's own test_code_scope module.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

# githubInternalOperations.js: .filter((f) => ['added', 'modified', 'renamed'].includes(f.status))
REVIEWABLE_FILE_STATUSES = ("added", "modified", "renamed")

# githubInternalOperations.js: !f.filename.startsWith('dist/') && !f.filename.includes('node_modules')
VENDOR_PATH_PREFIXES = ("dist/",)
VENDOR_PATH_SUBSTRINGS = ("node_modules",)

# prAnalysisOrchestrator.js: path.startsWith('dist/') || path.includes('node_modules/')
# The content fetch tests for the directory, the listing filter for the bare name. The
# difference is unobservable in the pipeline, because the listing filter runs first and is the
# broader of the two, but both are kept verbatim so the parity test compares like with like.
CONTENT_VENDOR_PATH_SUBSTRINGS = ("node_modules/",)

# githubInternalOperations.js: const FILE_CAP = 200, and the run reviews the first
# FILE_CAP in path order rather than refusing the pull request.
MAX_CHANGED_FILES = 200

# githubInternalOperations.js: if (Buffer.byteLength(content || '', 'utf8') > 500000) continue;
MAX_FILE_CONTENT_BYTES = 500000

# prAnalysisOrchestrator.js: TIER2_CODE_EXTENSIONS and TIER2_TEMPLATE_EXTENSIONS, unioned
# into TIER2_SUPPORTED_EXTENSIONS. The template half is what lets the scanner reach the
# cross-site scripting that lives in `.ejs`, `.pug` and friends.
TIER2_CODE_EXTENSIONS = frozenset(
    {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
        ".cs", ".c", ".cpp", ".h", ".hpp", ".rs", ".swift", ".kt",
    }
)

TIER2_TEMPLATE_EXTENSIONS = frozenset(
    {
        ".html", ".htm", ".ejs", ".erb", ".hbs", ".handlebars", ".mustache",
        ".dust", ".njk", ".jinja", ".jinja2", ".j2", ".twig", ".vue", ".svelte", ".pug",
    }
)

TIER2_SUPPORTED_EXTENSIONS = TIER2_CODE_EXTENSIONS | TIER2_TEMPLATE_EXTENSIONS

# prAnalysisOrchestrator.js: const INLINE_COMMENT_CAP = 40;
INLINE_COMMENT_CAP = 40

# prAnalysisOrchestrator.js: path.endsWith('.min.js') || path.endsWith('.min.css')
MINIFIED_SUFFIXES = (".min.js", ".min.css")

_EXTENSION_RE = re.compile(r"(\.[^./]+)$")
_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class ChangedFileLimitError(Exception):
    """Kept for callers that still catch it; the scope function no longer raises it.

    `fetchPullRequestFiles` used to refuse an oversized pull request with a 422. It now
    reviews the first `MAX_CHANGED_FILES` in path order and reports a `file_cap` limitation,
    because a partial review of a large change is worth more than no review at all. The port
    follows, so nothing raises this any more.
    """


def file_extension(path: str) -> str:
    """The lowercased final extension of a path, or "" when it has none."""
    match = _EXTENSION_RE.search(str(path or "").lower())
    return match.group(1) if match else ""


def is_vendor_path(path: str) -> bool:
    """True for build output and vendored dependencies, which are never reviewed."""
    name = str(path or "")
    if any(name.startswith(prefix) for prefix in VENDOR_PATH_PREFIXES):
        return True
    return any(fragment in name for fragment in VENDOR_PATH_SUBSTRINGS)


def scope_changed_files(files: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Reduce a GitHub pull request file listing to the entries a review reads.

    Deleted files carry no reviewable content and removed code cannot be exploited, so only
    added, modified and renamed entries survive. Build output and vendored dependencies are
    dropped because a finding there is not the author's to fix.
    """
    scoped = [
        entry
        for entry in files
        if str(entry.get("status") or "") in REVIEWABLE_FILE_STATUSES
        and not is_vendor_path(str(entry.get("filename") or entry.get("path") or ""))
    ]
    # Sorted by path first so the same pull request always yields the same selection,
    # whatever order the API returned the pages in, then truncated to the cap. The caller
    # reads `changed_file_limitation` to say how many of how many were reviewed.
    ordered = sorted(
        scoped, key=lambda entry: str(entry.get("filename") or entry.get("path") or "")
    )
    return [
        {
            "path": str(entry.get("filename") or entry.get("path") or ""),
            "patch": entry.get("patch") or "",
            "additions": int(entry.get("additions") or 0),
            "deletions": int(entry.get("deletions") or 0),
            "status": str(entry.get("status") or ""),
            "raw_url": entry.get("raw_url") or "",
        }
        for entry in ordered[:MAX_CHANGED_FILES]
    ]


def changed_file_limitation(files: List[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    """The `file_cap` limitation for a pull request over the cap, or None.

    Mirrors the limitation `fetchPullRequestFiles` returns, so the action states the same
    partial-review fact the hosted product states.
    """
    scoped = [
        entry
        for entry in files
        if str(entry.get("status") or "") in REVIEWABLE_FILE_STATUSES
        and not is_vendor_path(str(entry.get("filename") or entry.get("path") or ""))
    ]
    if len(scoped) <= MAX_CHANGED_FILES:
        return None
    return {
        "kind": "file_cap",
        "message": f"Reviewed {MAX_CHANGED_FILES} of {len(scoped)} changed files",
    }


def should_fetch_full_file_content(file_entry: Dict[str, Any]) -> bool:
    """True when the semgrep tier gets more from the whole file than from the patch alone.

    A taint rule needs the source and the sink, and a patch usually holds only one of them. The
    extension allowlist keeps the fetch to languages the scanner has rules for, and the minified
    suffixes keep a single-line bundle out of a scan that would find nothing useful in it.
    """
    path = str(file_entry.get("path") or "")
    if file_extension(path) not in TIER2_SUPPORTED_EXTENSIONS:
        return False
    if path.startswith(VENDOR_PATH_PREFIXES) or any(
        fragment in path for fragment in CONTENT_VENDOR_PATH_SUBSTRINGS
    ):
        return False
    return not path.endswith(MINIFIED_SUFFIXES)


def extract_reviewable_line_spans(patch: str) -> List[Dict[str, int]]:
    """The contiguous runs of added lines in a patch, as inclusive new-file line numbers.

    A review may only anchor a comment to a line the author actually touched, so the spans are
    built from `+` lines alone. Context lines advance the new-file counter and break the current
    run; removed lines break it without advancing, because they occupy no line in the new file.

    Ported line for line from `extractReviewableLineSpans`; the quirks are deliberate. A file
    header is skipped without advancing the counter, a hunk header that does not parse leaves the
    counter where it was, and a `+` line seen before any hunk header lands on line 1.
    """
    spans: List[Dict[str, int]] = []
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

    for raw_line in str(patch).split("\n"):
        if raw_line.startswith("@@"):
            flush()
            match = _HUNK_HEADER_RE.match(raw_line)
            if match:
                new_line = int(match.group(1))
            continue
        if raw_line.startswith("+++ ") or raw_line.startswith("--- "):
            continue
        if raw_line.startswith("+"):
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
        if not raw_line.startswith("-"):
            new_line += 1

    flush()
    return spans


def reviewable_lines(patch: str) -> set[int]:
    """Every new-file line number a comment may anchor to, flattened from the spans."""
    lines: set[int] = set()
    for span in extract_reviewable_line_spans(patch):
        lines.update(range(span["start"], span["end"] + 1))
    return lines


def build_analysis_files(
    scoped_files: Sequence[Dict[str, Any]],
    content_by_path: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Attach head-revision content and added-line spans to the scoped file list.

    A file whose content was not fetched keeps `content: ""` rather than being dropped: the
    regex tier still reads its patch. Mirrors `buildTier2FilePayload`.
    """
    payload: List[Dict[str, Any]] = []
    for entry in scoped_files:
        content = content_by_path.get(entry["path"])
        payload.append(
            {
                **entry,
                "content": content if isinstance(content, str) else "",
                "reviewable_line_spans": extract_reviewable_line_spans(entry.get("patch") or ""),
            }
        )
    return payload
