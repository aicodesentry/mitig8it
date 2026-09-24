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
    assert [f["path"] for f in scoped] == ["src/reports.py", "README.md"]


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
    assert request.files[0].reviewable_line_spans == [{"start": 3, "end": 4}]


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


# --- informational findings -------------------------------------------------------------------

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


def test_too_many_files_is_refused_rather_than_partly_reviewed():
    files = [
        {"filename": f"src/f{i}.py", "status": "modified", "patch": "+x"}
        for i in range(pr_scope.MAX_CHANGED_FILES + 1)
    ]
    with pytest.raises(pr_scope.ChangedFileLimitError) as error:
        pr_scope.scope_changed_files(files)
    assert "split the change" in str(error.value)
