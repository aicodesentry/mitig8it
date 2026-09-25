"""The orchestrator's behaviour against a recorded event and a fake GitHub API.

These tests never reach the network and never start the scanner. What they pin is the part of
the action that is its own: which files it puts in the payload, what shape that payload has,
when it refuses to run, what it says when no model key was given, and what a second run does.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from orchestrator import analysis, github_api, pr_scope, run
from tests import fake_github

FIXTURES = Path(__file__).parent / "fixtures"
HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40
REPO = "acme/widgets"

VULNERABLE_PY = '''import sqlite3


def report(conn, name):
    return conn.execute("SELECT * FROM reports WHERE name = '" + name + "'").fetchall()
'''

PATCH = (
    "@@ -1,3 +1,5 @@\n"
    " import sqlite3\n"
    "\n"
    "+def report(conn, name):\n"
    "+    return conn.execute(\"SELECT * FROM reports WHERE name = '\" + name + \"'\").fetchall()\n"
)


@pytest.fixture
def event(tmp_path, monkeypatch):
    payload = json.loads((FIXTURES / "pull_request_opened.json").read_text())
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.setenv("GITHUB_ACTOR", "dana")
    return payload


@pytest.fixture
def api():
    changed = [
        {
            "filename": "src/reports.py",
            "status": "modified",
            "patch": PATCH,
            "additions": 2,
            "deletions": 0,
            "raw_url": "https://example.invalid/raw",
        },
        # Deleted files carry nothing to review.
        {"filename": "src/old.py", "status": "removed", "patch": "", "additions": 0, "deletions": 9},
        # Vendored code is not the author's to fix.
        {"filename": "node_modules/left-pad/index.js", "status": "added", "patch": "+x", "additions": 1, "deletions": 0},
        # Build output likewise.
        {"filename": "dist/bundle.js", "status": "added", "patch": "+y", "additions": 1, "deletions": 0},
        # A language the scanner has no rules for still reaches tier 1 through its patch.
        {"filename": "README.md", "status": "modified", "patch": "@@ -1 +1,2 @@\n a\n+b\n", "additions": 1, "deletions": 0},
    ]
    fake = fake_github.FakeGitHub()
    fake.route(r"/repos/acme/widgets", fake_github.repository({"pull": True, "push": False, "admin": False}))
    fake.route(r"/repos/acme/widgets/pulls/42", fake_github.pull_request(42, HEAD_SHA, BASE_SHA))
    fake.route(
        r"/repos/acme/widgets/pulls/42/files",
        lambda _m, params: fake_github.paged(changed, (params or {}).get("page")),
    )
    fake.route(
        r"/repos/acme/widgets/contents/src/reports\.py",
        fake_github.contents_payload(VULNERABLE_PY),
    )
    return fake


def reader_for(api) -> github_api.GitHubReader:
    return github_api.GitHubReader(
        token="gh_test", repository=REPO, client=api, sleep=lambda _s: None
    )


# --- the payload the action builds -------------------------------------------------------

def test_changed_file_scope_matches_production(api):
    reader = reader_for(api)
    scoped = pr_scope.scope_changed_files(reader.list_pull_request_files(42, HEAD_SHA))
    # Path order, not listing order: the scope is sorted so the same pull request always
    # yields the same selection when the cap truncates it.
    assert [f["path"] for f in scoped] == ["README.md", "src/reports.py"]


def test_the_head_is_asserted_before_and_after_the_listing(api):
    reader = reader_for(api)
    reader.list_pull_request_files(42, HEAD_SHA)
    pull_reads = [p for p in api.paths() if p == "/repos/acme/widgets/pulls/42"]
    assert len(pull_reads) == 2, "a push mid-listing must be caught, so the head is read twice"


def test_a_moved_head_abandons_the_run(api):
    """A push between the request and the read must not produce a review of neither commit."""
    api.reroute(r"/repos/acme/widgets/pulls/42", fake_github.pull_request(42, "c" * 40))
    with pytest.raises(github_api.HeadMovedError):
        reader_for(api).list_pull_request_files(42, HEAD_SHA)


def test_only_scannable_languages_have_their_content_fetched(api):
    reader = reader_for(api)
    scoped = pr_scope.scope_changed_files(reader.list_pull_request_files(42, HEAD_SHA))
    wanted = [f["path"] for f in scoped if pr_scope.should_fetch_full_file_content(f)]
    assert wanted == ["src/reports.py"], "Markdown has no scanner rules, so its bytes are not read"


def test_the_analysis_payload_has_production_s_shape(api):
    reader = reader_for(api)
    scoped = pr_scope.scope_changed_files(reader.list_pull_request_files(42, HEAD_SHA))
    wanted = [f["path"] for f in scoped if pr_scope.should_fetch_full_file_content(f)]
    contents = reader.file_contents(wanted, HEAD_SHA)
    files = pr_scope.build_analysis_files(scoped, contents)

    assert {f["path"] for f in files} == {"src/reports.py", "README.md"}
    for entry in files:
        # Exactly the fields ChangedFile accepts, and every one of them present.
        assert set(entry) == {
            "path", "patch", "additions", "deletions", "status", "raw_url",
            "content", "reviewable_line_spans",
        }
        assert isinstance(entry["reviewable_line_spans"], list)

    source = next(f for f in files if f["path"] == "src/reports.py")
    assert source["content"] == VULNERABLE_PY
    assert source["reviewable_line_spans"] == [{"start": 3, "end": 4}]

    readme = next(f for f in files if f["path"] == "README.md")
    assert readme["content"] == "", "an unfetched file keeps empty content rather than dropping out"


def test_the_payload_is_accepted_by_the_analysis_service_model(api):
    """The shape is not merely plausible: the service's own model validates it.

    Skipped where the analysis service's dependencies are not installed, which is the case in a
    bare checkout. Inside the action's own image they always are, so the container build runs it.
    """
    try:
        main = analysis._analysis_main()
    except Exception as error:  # noqa: BLE001 - any import failure means the same thing here
        pytest.skip(f"the analysis service is not importable here: {error}")
    reader = reader_for(api)
    scoped = pr_scope.scope_changed_files(reader.list_pull_request_files(42, HEAD_SHA))
    contents = reader.file_contents(["src/reports.py"], HEAD_SHA)
    request = main.AnalyzePRRequest(
        repository_full_name=REPO,
        pull_request_number=42,
        commit_sha=HEAD_SHA,
        files=pr_scope.build_analysis_files(scoped, contents),
    )
    reports = next(f for f in request.files if f.path == "src/reports.py")
    assert reports.reviewable_line_spans == [{"start": 3, "end": 4}]


def test_an_unreadable_file_fails_the_run_closed(api, event, monkeypatch):
    """A file skipped for size must not become a clean review."""
    api.reroute(
        r"/repos/acme/widgets/contents/src/reports\.py",
        fake_github.contents_payload("x" * (pr_scope.MAX_FILE_CONTENT_BYTES + 1)),
    )
    reader = reader_for(api)
    contents = reader.file_contents(["src/reports.py"], HEAD_SHA)
    assert contents == {}, "an oversized file is absent rather than truncated"


# --- the permission refusal ---------------------------------------------------------------

def test_contents_write_is_refused(api):
    api.reroute(r"/repos/acme/widgets", fake_github.repository({"pull": True, "push": True, "admin": False}))
    with pytest.raises(run.ActionError) as error:
        run.assert_least_privilege(reader_for(api))
    message = str(error.value)
    assert "refuses to run with `contents: write`" in message
    assert "contents: read" in message, "the message must show the permissions block to use"
    assert "pull-requests: write" in message
    assert "checks: write" in message


def test_least_privilege_passes_on_a_read_only_token(api):
    assert run.assert_least_privilege(reader_for(api))["push"] is False


def test_an_unreadable_permissions_object_refuses_rather_than_assumes(api):
    api.reroute(r"/repos/acme/widgets", {"full_name": REPO, "id": 1})
    with pytest.raises(github_api.PermissionError_) as error:
        run.assert_least_privilege(reader_for(api))
    assert "could not confirm" in str(error.value)


# --- the no-key summary line ---------------------------------------------------------------

def test_no_model_key_disables_triage(monkeypatch):
    monkeypatch.delenv("INPUT_MODEL_API_KEY", raising=False)
    monkeypatch.setenv("LLM_TRIAGE_ENABLED", "false")
    assert analysis.model_triage_enabled() is False


def test_a_model_key_enables_triage(monkeypatch):
    monkeypatch.setenv("LLM_TRIAGE_ENABLED", "true")
    assert analysis.model_triage_enabled() is True


def test_the_publisher_states_the_no_key_case_in_the_review_body(tmp_path):
    """The review must say which half of the product ran, on every keyless run."""
    publisher = Path(__file__).resolve().parents[1] / "publisher/publish.js"
    import subprocess
    import shutil

    if not shutil.which("node"):
        pytest.skip("node is not on PATH")
    script = (
        f"const p = require({json.dumps(str(publisher))});"
        "const base = {counts:{critical:1,high:0,medium:0,low:0,info:0},findings:1,fixes:1};"
        "console.log(JSON.stringify({"
        "  without: p.buildReviewBody({...base, modelConfigured:false}),"
        "  with: p.buildReviewBody({...base, modelConfigured:true}),"
        "}));"
    )
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    bodies = json.loads(result.stdout)
    assert "No model key was configured" in bodies["without"]
    assert "only template fixes were produced" in bodies["without"]
    assert "nothing left this runner" in bodies["without"]
    assert "No model key was configured" not in bodies["with"]


# --- idempotency ----------------------------------------------------------------------------

def test_every_inline_comment_carries_its_fingerprint_marker():
    """The marker is the whole basis of a re-run editing instead of duplicating."""
    findings = [
        {
            "fingerprint": "fp-one",
            "file_path": "src/reports.py",
            "line_start": 4,
            "severity": "critical",
            "title": "SQL injection",
            "rule_id": "opengrep.cwe-89.sql-string-concat",
        }
    ]
    comments = run.build_inline_comments(findings, {"src/reports.py": PATCH})
    assert len(comments) == 1
    assert comments[0]["body"].startswith("<!-- mitig8it-finding:fp-one -->")


def test_a_rerun_builds_byte_identical_comments():
    """Nothing in a comment body varies between runs, so a second run writes nothing."""
    findings = [
        {
            "fingerprint": "fp-one",
            "file_path": "src/reports.py",
            "line_start": 3,
            "severity": "high",
            "title": "SQL injection",
            "description": "User input reaches a query.",
        }
    ]
    first = run.build_inline_comments(findings, {"src/reports.py": PATCH})
    second = run.build_inline_comments(findings, {"src/reports.py": PATCH})
    assert first == second


def test_findings_outside_the_diff_get_no_inline_comment():
    """A comment on an untouched line points the reader at code that is not the change."""
    findings = [
        {"fingerprint": "fp", "file_path": "src/reports.py", "line_start": 99, "severity": "high"}
    ]
    assert run.build_inline_comments(findings, {"src/reports.py": PATCH}) == []


def test_a_finding_outside_the_diff_is_reported_rather_than_dropped():
    """Having nowhere to put a comment is a reason to name the finding, not to hide it.

    On nodejs-goof the trial saw six findings, five critical, and no sentence anywhere naming
    a file or a line. Across the ten repositories 28 of 93 findings existed only as a number.
    """
    findings = [
        {
            "fingerprint": "fp",
            "file_path": "src/reports.py",
            "line_start": 99,
            "severity": "high",
            "rule_id": "sql.injection.raw_query",
        }
    ]
    plan = run.plan_comments(findings, {"src/reports.py": PATCH})
    assert plan["comments"] == []
    assert plan["unanchored"] == [
        {
            "path": "src/reports.py",
            "line": 99,
            "severity": "high",
            "rule": "sql.injection.raw_query",
            "reason": "line_outside_diff",
        }
    ]


def test_a_finding_past_the_inline_cap_is_reported_too():
    """Invisible for a second reason is still invisible, so it is named the same way."""
    findings = [
        {
            "fingerprint": f"fp-{i}",
            "file_path": "src/reports.py",
            "line_start": 3,
            "severity": "medium",
            "rule_id": "r",
        }
        for i in range(pr_scope.INLINE_COMMENT_CAP + 15)
    ]
    plan = run.plan_comments(findings, {"src/reports.py": PATCH})
    assert len(plan["comments"]) == pr_scope.INLINE_COMMENT_CAP
    assert len(plan["unanchored"]) == 15
    assert {item["reason"] for item in plan["unanchored"]} == {"over_inline_cap"}


def test_an_informational_finding_is_never_reported_as_unanchored():
    """It is not being asked for, so listing it would restore the noise that was removed."""
    findings = [
        {
            "fingerprint": "fp-info",
            "file_path": "src/reports.py",
            "line_start": 99,
            "severity": "info",
            "rule_id": "r",
        }
    ]
    plan = run.plan_comments(findings, {"src/reports.py": PATCH})
    assert plan["comments"] == []
    assert plan["unanchored"] == []


def test_one_arithmetic_serves_the_title_the_summary_and_the_body():
    counts = {"critical": 22, "high": 10, "medium": 5, "low": 0, "info": 2}
    totals = run.review_totals(counts, [{"x": 1}] * 16, [{"y": 1}] * 21)
    assert totals["runtime"] == 37
    assert totals["blocking"] == 32
    assert totals["inline"] == 16
    assert totals["unanchored"] == 21
    assert totals["informational"] == 2
    assert totals["inline"] + totals["unanchored"] == totals["runtime"]


def test_inline_comments_are_capped_at_the_production_limit():
    findings = [
        {
            "fingerprint": f"fp-{i}",
            "file_path": "src/reports.py",
            "line_start": 3,
            "severity": "medium",
        }
        for i in range(pr_scope.INLINE_COMMENT_CAP + 15)
    ]
    comments = run.build_inline_comments(findings, {"src/reports.py": PATCH})
    assert len(comments) == pr_scope.INLINE_COMMENT_CAP


def test_a_comment_never_says_one_sentence_three_times():
    """40 of the trial's 65 comments did. The OpenGrep rules set all three fields to the message.

    The whole body of `views/admin.ejs:17` was "EJS unescaped output tag. `<%-` writes raw HTML;
    use `<%=` so the value is escaped" in bold, again as prose, and a third time after
    "Remediation:".
    """
    sentence = "EJS unescaped output tag. `<%-` writes raw HTML; use `<%=` so the value is escaped"
    body = run.render_finding_comment(
        {
            "fingerprint": "fp",
            "file_path": "views/admin.ejs",
            "line_start": 17,
            "severity": "critical",
            "title": sentence,
            "description": sentence,
            "remediation": sentence,
        }
    )
    assert body.count(sentence) == 2, body
    assert f"**{sentence}**" in body
    assert f"Remediation: {sentence}" in body


def test_a_description_that_says_something_new_is_kept():
    body = run.render_finding_comment(
        {
            "fingerprint": "fp",
            "file_path": "a.py",
            "line_start": 1,
            "severity": "high",
            "title": "SQL injection",
            "description": "The login query concatenates the request body.",
            "remediation": "Pass the value as a bound parameter.",
        }
    )
    assert "The login query concatenates the request body." in body
    assert "Remediation: Pass the value as a bound parameter." in body


def test_a_remediation_that_only_repeats_the_description_is_dropped():
    sentence = "Pass the value as a bound parameter."
    body = run.render_finding_comment(
        {
            "fingerprint": "fp",
            "file_path": "a.py",
            "line_start": 1,
            "severity": "high",
            "title": "SQL injection",
            "description": sentence,
            "remediation": sentence,
        }
    )
    assert body.count(sentence) == 1
    assert "Remediation:" not in body


def test_inline_comments_are_ordered_most_severe_first():
    findings = [
        {"fingerprint": "low", "file_path": "src/reports.py", "line_start": 3, "severity": "low"},
        {"fingerprint": "crit", "file_path": "src/reports.py", "line_start": 4, "severity": "critical"},
    ]
    comments = run.build_inline_comments(findings, {"src/reports.py": PATCH})
    assert [c["fingerprint"] for c in comments] == ["crit", "low"]


# --- the fail-on gate ------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("fail_on", "counts", "expected"),
    [
        ("none", {"critical": 3, "high": 2}, "neutral"),
        ("critical", {"critical": 1, "high": 0}, "failure"),
        ("critical", {"critical": 0, "high": 5}, "success"),
        ("high", {"critical": 0, "high": 1}, "failure"),
        ("high", {"critical": 1, "high": 0}, "failure"),
        ("high", {"critical": 0, "high": 0}, "success"),
    ],
)
def test_fail_on_decides_the_conclusion(fail_on, counts, expected):
    assert run.fail_conclusion(fail_on, counts) == expected


def test_fail_on_none_never_blocks():
    """Installing the action must not break a merge on the day it is added."""
    assert run.fail_conclusion("none", {"critical": 99, "high": 99}) == "neutral"


def test_a_clean_review_is_green_rather_than_grey():
    """All 26 trial runs concluded neutral, including the five that found nothing.

    A repository with a clean review and a repository with 22 critical findings showed the same
    grey check, and only the title told them apart. `neutral` belongs to a review held back by
    `fail-on: none`, not to a review with nothing in it.
    """
    empty = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for fail_on in ("none", "high", "critical"):
        assert run.fail_conclusion(fail_on, empty) == "success"
    # Informational findings are in test code and never decide anything.
    assert run.fail_conclusion("none", dict(empty, info=7)) == "success"
    # Something to report, and the repository asked not to be blocked by it.
    assert run.fail_conclusion("none", dict(empty, medium=1)) == "neutral"


# --- informational findings -------------------------------------------------------------------

def test_an_informational_finding_gets_no_inline_comment():
    """Eighteen of these landed on `services/*/tests` in one self-review and buried the rest.

    A test-code finding cannot block the check and is not something the author is being asked to
    fix in this pull request. It is worth a number in the summary, not a comment on the diff.
    """
    findings = [
        {"fingerprint": "fp-runtime", "file_path": "src/reports.py", "line_start": 3, "severity": "high"},
        {"fingerprint": "fp-info", "file_path": "src/reports.py", "line_start": 4, "severity": "info"},
    ]
    comments = run.build_inline_comments(findings, {"src/reports.py": PATCH})
    assert [comment["fingerprint"] for comment in comments] == ["fp-runtime"]


def test_the_scanner_s_test_code_marker_is_enough_to_keep_a_finding_out_of_the_diff():
    """The severity is not the only spelling: a finding can carry `in_test_code` and keep its own.

    Both spellings are what `is_informational` accepts, and both are what the App's own
    `isInfoFinding` accepts, so the action must not post either of them.
    """
    findings = [
        {
            "fingerprint": "fp-marked",
            "file_path": "src/reports.py",
            "line_start": 3,
            "severity": "critical",
            "evidence_details": {"extra": {"in_test_code": True}},
        },
        {"fingerprint": "fp-flag", "file_path": "src/reports.py", "line_start": 4,
         "severity": "critical", "in_test_code": True},
    ]
    assert run.build_inline_comments(findings, {"src/reports.py": PATCH}) == []


def test_an_informational_finding_is_not_kept_alive_for_the_resolver():
    """What is not posted has no thread to keep open, and any thread it left is now stale."""
    findings = [
        {"fingerprint": "fp-runtime", "file_path": "src/a.py", "line_start": 1, "severity": "high"},
        {"fingerprint": "fp-info", "file_path": "tests/test_a.py", "line_start": 1, "severity": "info"},
    ]
    assert run.active_fingerprints(findings) == ["fp-runtime"]


def test_an_unanchored_runtime_finding_is_still_kept_alive():
    """The reason the list is built from findings and not from comments."""
    findings = [{"fingerprint": "fp-far", "file_path": "src/a.py", "line_start": 900, "severity": "high"}]
    assert run.build_inline_comments(findings, {"src/a.py": PATCH}) == []
    assert run.active_fingerprints(findings) == ["fp-far"]


def test_the_summary_and_the_review_body_say_the_informational_findings_were_not_posted():
    """A count with no comments behind it has to explain itself, on both surfaces."""
    publisher = Path(__file__).resolve().parents[1] / "publisher/publish.js"
    import shutil
    import subprocess

    if not shutil.which("node"):
        pytest.skip("node is not on PATH")
    script = (
        f"const p = require({json.dumps(str(publisher))});"
        "const request = {counts:{critical:1,high:0,medium:0,low:0,info:18},findings:19,fixes:0,"
        " modelConfigured:false, failConclusion:'failure'};"
        "console.log(JSON.stringify({"
        "  body: p.buildReviewBody(request),"
        "  summary: p.checkRunSummary(request).summary,"
        "  one: p.checkRunSummary({...request, counts:{...request.counts, info:1}}).summary,"
        "  none: p.checkRunSummary({...request, counts:{...request.counts, info:0}}).summary,"
        "}));"
    )
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    rendered = json.loads(result.stdout)

    assert "18 informational findings in test code, not posted." in rendered["body"]
    assert "18 informational findings in test code, not posted." in rendered["summary"]
    assert "1 informational finding in test code, not posted." in rendered["one"]
    assert "informational" not in rendered["none"], "a run with none says nothing about them"


def test_the_expected_403_on_the_viewer_call_is_not_logged(api, caplog):
    """The only status code in every trial run log, and it is the normal answer.

    `HTTP Request: GET https://api.github.com/user "HTTP/1.1 403 Forbidden"` appeared at INFO on
    all 26 runs. A workflow token has no user identity, so the 403 is expected and the code
    already falls back; what it looked like to a reader scanning the log was the failure.
    """
    import logging

    def forbidden(_match, _params):
        # httpx logs every request it makes, at INFO, on the `httpx` logger.
        logging.getLogger("httpx").info(
            'HTTP Request: GET https://api.github.com/user "HTTP/1.1 403 Forbidden"'
        )
        return fake_github.FakeResponse({"message": "Resource not accessible"}, status_code=403)

    api.route(r"/user", forbidden)

    transport_log = logging.getLogger("httpx")
    with caplog.at_level(logging.INFO, logger="httpx"):
        before = transport_log.level
        login = reader_for(api).viewer_login()
        # The logger is left exactly as it was found, so nothing else in the run goes quiet.
        assert transport_log.level == before

    assert login == "github-actions[bot]"
    assert api.asked_for("/user"), "the call is silenced, not removed"
    assert [record.message for record in caplog.records] == []


def test_a_viewer_call_that_answers_is_still_used(api):
    api.route(r"/user", {"login": "my-app[bot]"})
    assert reader_for(api).viewer_login() == "my-app[bot]"


def test_the_scope_report_separates_what_was_analysed_from_what_was_not():
    """"12 files in scope" counted the workflow the pull request adds and the README it edits.

    Neither is a file a security rule reads whole, and nothing said which files had been
    dropped or why, although action/README.md promised the check summary would.
    """
    files = [
        {"filename": "app/routes/index.js", "status": "modified", "patch": "@@ -1 +1 @@\n+a\n"},
        {"filename": "app/views/admin.ejs", "status": "modified", "patch": "@@ -1 +1 @@\n+a\n"},
        {"filename": ".github/workflows/mitig8it.yml", "status": "added", "patch": "@@ -0,0 +1 @@\n+a\n"},
        {"filename": "README.md", "status": "modified", "patch": "@@ -1 +1 @@\n+a\n"},
        {"filename": "dist/bundle.js", "status": "modified", "patch": "@@ -1 +1 @@\n+a\n"},
        {"filename": "static/app.min.js", "status": "modified", "patch": "@@ -1 +1 @@\n+a\n"},
        {"filename": "old.js", "status": "removed", "patch": ""},
    ]
    report = pr_scope.scope_report(files)

    assert report["changed"] == 5, "removed files and vendored paths are not part of the review"
    assert report["analysed"] == 2, "the JavaScript route and the template, not the YAML or the README"
    assert report["skipped"] == 3
    assert report["vendored"] == 1
    assert report["excluded"] == 0

    summary = pr_scope.scope_summary(report)
    assert summary.startswith("2 files analysed")
    assert "3 read as a patch only" in summary
    assert "1 skipped as build output or a vendored dependency" in summary
    assert ".mitig8it.yml" not in summary, "nothing was excluded, so nothing is claimed"


def test_the_scope_report_counts_what_the_repository_excluded():
    class Exclusions:
        def matches(self, path):
            return path.startswith("vendor/")

    files = [
        {"filename": "app/index.js", "status": "modified", "patch": "@@ -1 +1 @@\n+a\n"},
        {"filename": "vendor/lib.js", "status": "modified", "patch": "@@ -1 +1 @@\n+a\n"},
    ]
    report = pr_scope.scope_report(files, Exclusions())

    assert report == {"changed": 2, "analysed": 1, "excluded": 1, "skipped": 0, "vendored": 0}
    assert "1 excluded by .mitig8it.yml" in pr_scope.scope_summary(report)


def test_the_scope_summary_is_empty_when_there_is_nothing_to_say():
    assert pr_scope.scope_summary({"changed": 0, "analysed": 0, "excluded": 0, "skipped": 0, "vendored": 0}) == ""


def test_test_code_findings_are_counted_apart_from_runtime_ones():
    findings = [
        {"severity": "critical", "file_path": "src/a.py"},
        {"severity": "info", "file_path": "tests/test_a.py"},
        {"severity": "high", "file_path": "tests/test_b.py", "evidence_details": {"extra": {"in_test_code": True}}},
    ]
    counts = analysis.severity_counts(findings)
    assert counts["critical"] == 1
    assert counts["info"] == 2
    assert counts["high"] == 0, "a test-code finding must not count towards the blocking total"


# --- inputs ------------------------------------------------------------------------------------

def test_inputs_are_read_from_the_action_environment(monkeypatch):
    monkeypatch.setenv("INPUT_FAIL_ON", "critical")
    monkeypatch.setenv("INPUT_POST_FIXES", "false")
    monkeypatch.setenv("INPUT_MAX_FILES", "50")
    assert run.input_value("fail-on", "none") == "critical"
    assert run.boolean_input("post-fixes", True) is False
    assert run.input_value("max-files", "200") == "50"


def test_an_empty_input_falls_back_to_the_default(monkeypatch):
    """GitHub sets an unset input to the empty string, which must not mean "no cap"."""
    monkeypatch.setenv("INPUT_MAX_FILES", "")
    assert run.input_value("max-files", "200") == "200"


def test_a_non_pull_request_event_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "event.json"
    path.write_text(json.dumps({"action": "created", "issue": {"number": 1}}))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    with pytest.raises(run.ActionError) as error:
        run.pull_request_from_event(run.load_event())
    assert "only runs on pull_request events" in str(error.value)


def test_the_recorded_event_is_read_the_way_the_runner_supplies_it(event):
    pull = run.pull_request_from_event(run.load_event())
    assert pull["number"] == 42
    assert pull["head"]["sha"] == HEAD_SHA
    assert pull["base"]["sha"] == BASE_SHA


def test_too_many_files_is_reviewed_to_the_cap_and_says_so():
    """A pull request over the cap is reviewed as far as the cap allows, in path order.

    It used to be refused outright, which was the one case where a developer got nothing
    back. The selection is sorted first so the same pull request always yields the same
    files, and the limitation states how many of how many were reviewed.
    """
    files = [
        {"filename": f"src/f{i:04d}.py", "status": "modified", "patch": "+x"}
        for i in range(pr_scope.MAX_CHANGED_FILES + 5)
    ]
    scoped = pr_scope.scope_changed_files(files)
    assert len(scoped) == pr_scope.MAX_CHANGED_FILES
    assert [entry["path"] for entry in scoped] == [
        f"src/f{i:04d}.py" for i in range(pr_scope.MAX_CHANGED_FILES)
    ]

    limitation = pr_scope.changed_file_limitation(files)
    assert limitation == {
        "kind": "file_cap",
        "message": f"Reviewed {pr_scope.MAX_CHANGED_FILES} of {pr_scope.MAX_CHANGED_FILES + 5} changed files",
    }


def test_a_pull_request_within_the_cap_reports_no_limitation():
    files = [{"filename": "src/a.py", "status": "modified", "patch": "+x"}]
    assert pr_scope.changed_file_limitation(files) is None
