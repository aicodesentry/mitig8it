"""The ported scope rules must still match the Node sources they were ported from.

pr_scope.py restates rules that production keeps in two Node services. A copy drifts silently:
someone widens the extension allowlist in the api-service, the app starts reading a new language
and the action quietly does not. These tests read the Node sources and compare the literals, so
the drift fails a build instead of becoming a difference nobody notices.

They parse text rather than execute Node, so they run in the plain pytest job with no toolchain.
Every assertion names the file and the construct it came from, so a failure says what to change.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from orchestrator import pr_scope

REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_OPERATIONS = (
    REPO_ROOT / "services/github-service/src/services/githubInternalOperations.js"
)
API_ORCHESTRATOR = (
    REPO_ROOT / "services/api-service/src/services/prAnalysisOrchestrator.js"
)
FIX_VALIDATOR = REPO_ROOT / "services/api-service/src/services/suggestedFixValidator.js"


def read(path: Path) -> str:
    assert path.is_file(), f"expected the Node source at {path}"
    return path.read_text(encoding="utf-8")


def test_reviewable_statuses_match_fetch_pull_request_files():
    source = read(GITHUB_OPERATIONS)
    match = re.search(
        r"\.filter\(\(f\) => \[([^\]]+)\]\.includes\(f\.status\)\)", source
    )
    assert match, "fetchPullRequestFiles no longer filters on a status array"
    statuses = tuple(re.findall(r"'([^']+)'", match.group(1)))
    assert statuses == pr_scope.REVIEWABLE_FILE_STATUSES


def test_vendor_filter_matches_fetch_pull_request_files():
    source = read(GITHUB_OPERATIONS)
    match = re.search(
        r"!f\.filename\.startsWith\('([^']+)'\) && !f\.filename\.includes\('([^']+)'\)",
        source,
    )
    assert match, "fetchPullRequestFiles no longer filters vendor paths the same way"
    assert (match.group(1),) == pr_scope.VENDOR_PATH_PREFIXES
    assert (match.group(2),) == pr_scope.VENDOR_PATH_SUBSTRINGS


def test_changed_file_cap_matches_fetch_pull_request_files():
    source = read(GITHUB_OPERATIONS)
    match = re.search(r"if \(scoped\.length > (\d+)\)", source)
    assert match, "fetchPullRequestFiles no longer caps the scoped file count"
    assert int(match.group(1)) == pr_scope.MAX_CHANGED_FILES
    assert f"{pr_scope.MAX_CHANGED_FILES}-file analysis limit" in source


def test_file_content_byte_cap_matches_fetch_file_contents():
    source = read(GITHUB_OPERATIONS)
    match = re.search(
        r"if \(Buffer\.byteLength\(content \|\| '', 'utf8'\) > (\d+)\) continue;", source
    )
    assert match, "fetchFileContents no longer skips oversized files by byte length"
    assert int(match.group(1)) == pr_scope.MAX_FILE_CONTENT_BYTES


def test_tier2_extensions_match_the_api_service_constant():
    source = read(API_ORCHESTRATOR)
    match = re.search(
        r"const TIER2_SUPPORTED_EXTENSIONS = new Set\(\[(.*?)\]\);", source, re.DOTALL
    )
    assert match, "TIER2_SUPPORTED_EXTENSIONS is no longer a Set literal"
    extensions = frozenset(re.findall(r"'([^']+)'", match.group(1)))
    assert extensions == pr_scope.TIER2_SUPPORTED_EXTENSIONS


def test_inline_comment_cap_matches_the_api_service_constant():
    source = read(API_ORCHESTRATOR)
    match = re.search(r"const INLINE_COMMENT_CAP = (\d+);", source)
    assert match, "INLINE_COMMENT_CAP is no longer a numeric constant"
    assert int(match.group(1)) == pr_scope.INLINE_COMMENT_CAP


def test_content_fetch_filter_matches_should_fetch_full_file_content():
    source = read(API_ORCHESTRATOR)
    body = re.search(
        r"function shouldFetchFullFileContent\(file\) \{(.*?)\n\}", source, re.DOTALL
    )
    assert body, "shouldFetchFullFileContent is no longer a plain function"
    vendor = re.search(
        r"path\.startsWith\('([^']+)'\) \|\| path\.includes\('([^']+)'\)", body.group(1)
    )
    assert vendor, "the vendor guard changed shape"
    assert (vendor.group(1),) == pr_scope.VENDOR_PATH_PREFIXES
    assert (vendor.group(2),) == pr_scope.CONTENT_VENDOR_PATH_SUBSTRINGS

    minified = tuple(
        re.findall(r"path\.endsWith\('([^']+)'\)", body.group(1))
    )
    assert minified == pr_scope.MINIFIED_SUFFIXES


def test_scanner_extension_set_matches_the_analysis_service():
    """The two allowlists are separate declarations in two languages and must agree.

    The api-service decides what content to fetch; the analysis service decides what semgrep
    scans. If they diverge, the action fetches bytes nothing reads, or starves a scan that has
    rules for the language.
    """
    opengrep = REPO_ROOT / "services/analysis-service/src/opengrep_runner.py"
    source = read(opengrep)
    match = re.search(r"SUPPORTED_EXTENSIONS = \{(.*?)\}", source, re.DOTALL)
    assert match, "SUPPORTED_EXTENSIONS is no longer a set literal"
    extensions = frozenset(re.findall(r'"([^"]+)"', match.group(1)))
    assert extensions == pr_scope.TIER2_SUPPORTED_EXTENSIONS


# The patches below are run through the Node implementation and the Python port in
# test_reviewable_line_spans_match_node, which is skipped when Node is unavailable. They are
# also asserted directly, so the port is pinned even without a toolchain.
SPAN_FIXTURES = {
    "single added run": (
        "@@ -1,3 +1,5 @@\n context\n+added one\n+added two\n context\n",
        [{"start": 2, "end": 3}],
    ),
    "two runs split by context": (
        "@@ -1,6 +1,8 @@\n a\n+one\n b\n+two\n",
        [{"start": 2, "end": 2}, {"start": 4, "end": 4}],
    ),
    "removed lines do not advance the counter": (
        "@@ -1,4 +1,3 @@\n a\n-gone\n-also gone\n+new\n",
        [{"start": 2, "end": 2}],
    ),
    "file headers are skipped": (
        "--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,3 @@\n a\n+new\n",
        [{"start": 2, "end": 2}],
    ),
    "added line before any hunk header lands on line one": (
        "+orphan\n",
        [{"start": 1, "end": 1}],
    ),
    "multiple hunks": (
        "@@ -1,2 +1,3 @@\n a\n+one\n@@ -10,2 +12,3 @@\n b\n+two\n",
        [{"start": 2, "end": 2}, {"start": 13, "end": 13}],
    ),
    "empty patch": ("", []),
}


@pytest.mark.parametrize("name", sorted(SPAN_FIXTURES))
def test_reviewable_line_spans_fixtures(name):
    patch, expected = SPAN_FIXTURES[name]
    assert pr_scope.extract_reviewable_line_spans(patch) == expected


def test_reviewable_line_spans_match_node():
    """Run both implementations over the fixtures and compare, when Node is on PATH.

    Parsing cannot prove an algorithm matches, only a constant. The container has Node, so the
    action's own build runs the real comparison; a developer without it still gets the fixtures.
    """
    import json
    import shutil
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH")
    assert FIX_VALIDATOR.is_file(), f"expected the Node source at {FIX_VALIDATOR}"

    script = (
        f"const v = require({json.dumps(str(FIX_VALIDATOR))});"
        "const f = (v.__private && v.__private.extractReviewableLineSpans)"
        " || v.extractReviewableLineSpans;"
        "if (typeof f !== 'function') { throw new Error('extractReviewableLineSpans not exported'); }"
        "const patches = JSON.parse(process.argv[1]);"
        "console.log(JSON.stringify(patches.map(f)));"
    )
    patches = [patch for patch, _ in (SPAN_FIXTURES[name] for name in sorted(SPAN_FIXTURES))]
    result = subprocess.run(
        [node, "-e", script, json.dumps(patches)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, f"node failed: {result.stderr}"
    from_node = json.loads(result.stdout)
    from_python = [pr_scope.extract_reviewable_line_spans(patch) for patch in patches]
    assert from_node == from_python
