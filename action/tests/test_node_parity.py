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

from orchestrator import analysis, pr_scope, run

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
    """The cap selects rather than refuses, and the port has to select the same way.

    `fetchPullRequestFiles` sorts by path and takes the first FILE_CAP, reporting a
    `file_cap` limitation. A port that still raised, or that truncated an unsorted list,
    would review a different set of files than the hosted product does.
    """
    source = read(GITHUB_OPERATIONS)
    match = re.search(r"const FILE_CAP = (\d+);", source)
    assert match, "fetchPullRequestFiles no longer declares a FILE_CAP"
    assert int(match.group(1)) == pr_scope.MAX_CHANGED_FILES
    assert "ordered.slice(0, FILE_CAP)" in source, "the cap no longer selects by slice"
    assert "kind: 'file_cap'" in source, "the cap no longer reports a limitation"


def test_file_content_byte_cap_matches_fetch_file_contents():
    source = read(GITHUB_OPERATIONS)
    match = re.search(
        r"if \(Buffer\.byteLength\(content \|\| '', 'utf8'\) > (\d+)\) continue;", source
    )
    assert match, "fetchFileContents no longer skips oversized files by byte length"
    assert int(match.group(1)) == pr_scope.MAX_FILE_CONTENT_BYTES


def test_tier2_extensions_match_the_api_service_constant():
    source = read(API_ORCHESTRATOR)
    code = re.search(r"const TIER2_CODE_EXTENSIONS = \[(.*?)\];", source, re.DOTALL)
    template = re.search(r"const TIER2_TEMPLATE_EXTENSIONS = \[(.*?)\];", source, re.DOTALL)
    assert code, "TIER2_CODE_EXTENSIONS is no longer an array literal"
    assert template, "TIER2_TEMPLATE_EXTENSIONS is no longer an array literal"
    assert frozenset(re.findall(r"'([^']+)'", code.group(1))) == pr_scope.TIER2_CODE_EXTENSIONS
    assert (
        frozenset(re.findall(r"'([^']+)'", template.group(1)))
        == pr_scope.TIER2_TEMPLATE_EXTENSIONS
    )


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
    # The sets moved to test_code_scope.py, which owns "what do we scan"; opengrep_runner
    # re-exports them.
    scope = REPO_ROOT / "services/analysis-service/src/test_code_scope.py"
    source = read(scope)
    code = re.search(r"CODE_EXTENSIONS = \{(.*?)\}", source, re.DOTALL)
    template = re.search(r"TEMPLATE_EXTENSIONS = \{(.*?)\}", source, re.DOTALL)
    assert code, "CODE_EXTENSIONS is no longer a set literal"
    assert template, "TEMPLATE_EXTENSIONS is no longer a set literal"
    assert frozenset(re.findall(r'"([^"]+)"', code.group(1))) == pr_scope.TIER2_CODE_EXTENSIONS
    assert (
        frozenset(re.findall(r'"([^"]+)"', template.group(1)))
        == pr_scope.TIER2_TEMPLATE_EXTENSIONS
    )


def test_the_test_code_policy_is_the_same_in_all_three_copies():
    """`TEST_CODE_PATH_PATTERNS` is written out three times and nothing compared them.

    The analysis service downgrades a finding in test code to `info`, the App decides how to
    render and cap it, and the action decides whether it blocks. All three carry their own copy
    of the path patterns, and `prAnalysisOrchestrator.js` says "Mirrors
    services/analysis-service/src/test_code_scope.py" in a comment that nothing enforced. A
    drift here means a file is test code to one of them and runtime source to another, which is
    the difference between a blocking finding and an informational one.
    """
    scope = read(REPO_ROOT / "services/analysis-service/src/test_code_scope.py")
    python_patterns = re.search(r"TEST_CODE_PATH_PATTERNS = \[(.*?)\]", scope, re.DOTALL)
    assert python_patterns, "TEST_CODE_PATH_PATTERNS is no longer a list literal"
    expected = re.findall(r're\.compile\(r"(.*?)"\)', python_patterns.group(1))
    assert len(expected) == 4, expected

    orchestrator = read(API_ORCHESTRATOR)
    js_patterns = re.search(r"TEST_CODE_PATH_PATTERNS = \[(.*?)\];", orchestrator, re.DOTALL)
    assert js_patterns, "the App no longer declares TEST_CODE_PATH_PATTERNS as an array"
    # A JS regex literal must escape a forward slash; a Python raw string must not. That is the
    # one difference the two spellings are allowed to have.
    found = [pattern.replace("\\/", "/") for pattern in re.findall(r"/(.*?)/,", js_patterns.group(1))]
    assert found == expected, f"the App's patterns {found} differ from the service's {expected}"

    # The informational severity itself, which is what the action reads off a finding.
    assert re.search(r'INFORMATIONAL_SEVERITY = "info"', scope)
    assert re.search(r"INFORMATIONAL_SEVERITY = 'info'", orchestrator)
    assert analysis.is_informational({"severity": "info"}) is True
    assert analysis.is_informational({"severity": "high"}) is False
    assert analysis.is_informational({"severity": "high", "in_test_code": True}) is True
    assert analysis.is_informational(
        {"severity": "high", "evidence_details": {"extra": {"in_test_code": True}}}
    ) is True


def test_the_action_states_the_informational_case_the_way_the_app_does():
    """The renderer labels an informational finding the way the App labels it.

    Nothing posts one any more, in either product: both leave informational findings out of the
    inline set entirely. The rendering is pinned anyway, because a renderer that dressed a
    test-code finding up as a blocking one would be a worse thing to leave lying around than an
    unused branch. The App keeps its branch for the same reason.
    """
    body = run.render_finding_comment(
        {
            "fingerprint": "fp",
            "severity": "info",
            "title": "SQL injection",
            "file_path": "services/api-service/tests/a.test.js",
            "original_severity": "high",
        }
    )
    assert "INFORMATIONAL - TEST CODE" in body
    assert "does not block this pull request" in body
    assert "scanner severity high" in body

    runtime = run.render_finding_comment(
        {"fingerprint": "fp", "severity": "high", "title": "SQL injection", "file_path": "src/a.js"}
    )
    assert "INFORMATIONAL" not in runtime
    assert "does not block" not in runtime


def test_the_action_reads_the_app_s_rule_for_which_findings_are_informational():
    """`isInfoFinding` in the App and `is_informational` in the action are one rule, twice.

    Read out of the App rather than restated here, so widening the App's predicate fails this
    test instead of quietly leaving the action treating a finding as runtime that the App treats
    as informational. Which side of that line a finding falls on decides whether it blocks the
    check, whether a fix is generated for it, and whether it is annotated on the diff.
    """
    source = read(API_ORCHESTRATOR)
    constant = re.search(r"const INFORMATIONAL_SEVERITY = '([^']+)';", source)
    assert constant, "INFORMATIONAL_SEVERITY is no longer a string constant"
    predicate = re.search(r"function isInfoFinding\(finding\) \{(.*?)\n\}", source, re.DOTALL)
    assert predicate, "isInfoFinding is no longer a plain function"
    body = predicate.group(1)
    assert "=== INFORMATIONAL_SEVERITY" in body, "the severity clause of isInfoFinding changed shape"
    assert "extra.in_test_code" in body, "the scanner-marker clause of isInfoFinding changed shape"

    severity = constant.group(1)
    assert analysis.is_informational({"severity": severity}) is True
    assert analysis.is_informational(
        {"severity": "critical", "evidence_details": {"extra": {"in_test_code": True}}}
    ) is True
    assert analysis.is_informational({"severity": "critical"}) is False


def test_neither_product_annotates_an_informational_finding():
    """Both products refuse an informational finding inline, and this reads both refusals.

    One self-review put eighteen `INFORMATIONAL - TEST CODE` comments across `services/*/tests`
    on a pull request whose point was three runtime findings, and they were the noise a reader
    had to dig through to reach them. A comment on test code with no fix behind it is noise in
    either product, so neither posts one: they are reported as a count in the check summary and
    the review body, which say the findings were not posted.

    The App's refusal is read out of `explainInlineCommentDecision` rather than restated here,
    so the App putting them back on the diff fails this test rather than becoming a difference
    nobody notices. The action's refusal is exercised directly.
    """
    source = read(API_ORCHESTRATOR)
    gate = re.search(
        r"function explainInlineCommentDecision\(finding\) \{(.*?)\n\}", source, re.DOTALL
    )
    assert gate, "explainInlineCommentDecision is no longer a plain function"
    assert "isInfoFinding(finding)" in gate.group(1), (
        "the App's inline gate no longer consults isInfoFinding"
    )
    assert "informational_test_code" in gate.group(1), (
        "the App's inline gate no longer refuses an informational finding"
    )

    patch = "@@ -1,1 +1,80 @@\n" + "".join(f"+line {i}\n" for i in range(1, 80))
    runtime = [
        {"fingerprint": f"fp-runtime-{i}", "file_path": "src/a.py", "line_start": i + 1,
         "severity": "medium"}
        for i in range(pr_scope.INLINE_COMMENT_CAP)
    ]
    informational = [
        {"fingerprint": f"fp-info-{i}", "file_path": "src/a.py", "line_start": i + 1,
         "severity": "critical", "evidence_details": {"extra": {"in_test_code": True}}}
        for i in range(10)
    ]

    comments = run.build_inline_comments(informational + runtime, {"src/a.py": patch})

    # An informational finding takes no slot, so the cap is spent entirely on runtime findings.
    assert len(comments) == pr_scope.INLINE_COMMENT_CAP
    assert {comment["fingerprint"] for comment in comments} == {f["fingerprint"] for f in runtime}
    assert run.build_inline_comments(informational, {"src/a.py": patch}) == []


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
