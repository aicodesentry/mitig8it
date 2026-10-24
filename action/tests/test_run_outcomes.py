"""What a whole run does on a repository it has never seen, from event to exit code.

These drive `run.main()` end to end: the recorded event, the fake GitHub for every read, the
analysis replaced by canned findings, and the real Node publisher against the harness stub for
every write. What they pin is the promise the README makes to someone adding the action to a
legacy repository: `fail-on: none` never turns the job red because of us, code the pull request
did not write never blocks it, and a partial review never reads as a clean one.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orchestrator import analysis, github_api, run
from tests import fake_github, fake_graphql, publisher_harness

FIXTURES = Path(__file__).parent / "fixtures"
HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40
REPO = "acme/widgets"

SOURCE = "import os\n\n\ndef handler(request):\n    return eval(request.args['x'])\n"
PATCH = (
    "@@ -1,3 +1,5 @@\n"
    " import os\n"
    "\n"
    "+def handler(request):\n"
    "+    return eval(request.args['x'])\n"
)

pytestmark = pytest.mark.skipif(
    not publisher_harness.node_available(), reason="node is not on PATH"
)


def finding(line: int, severity: str = "critical", fingerprint: str | None = None) -> dict:
    return {
        "fingerprint": fingerprint or f"fp-{line}",
        "file_path": "src/app.py",
        "line_start": line,
        "severity": severity,
        "title": "Code injection",
        "rule_id": "cwe-95.eval-injection",
    }


class Harness:
    """One run's worth of environment, fakes and recorded output."""

    def __init__(self, tmp_path: Path, monkeypatch, capsys):
        self.tmp_path = tmp_path
        self.monkeypatch = monkeypatch
        self.capsys = capsys
        self.event = json.loads((FIXTURES / "pull_request_opened.json").read_text())
        self.findings: list = []
        self.limitations: list = []
        self.analysis_error: Exception | None = None
        self.api = fake_github.FakeGitHub()
        self.api.route(r"/repos/acme/widgets", fake_github.repository({"pull": True, "push": False}))
        self.api.route(r"/repos/acme/widgets/pulls/42", fake_github.pull_request(42, HEAD_SHA, BASE_SHA))
        self.files = [
            {"filename": "src/app.py", "status": "modified", "patch": PATCH,
             "additions": 2, "deletions": 0},
        ]
        self.api.route(
            r"/repos/acme/widgets/pulls/42/files",
            lambda _m, params: fake_github.paged(self.files, (params or {}).get("page")),
        )
        self.api.route(r"/repos/acme/widgets/contents/src/app\.py", fake_github.contents_payload(SOURCE))
        self.api.route(
            r"/user",
            lambda _m, _p: fake_github.FakeResponse({"message": "Resource not accessible"}, 403),
        )
        self.graphql = fake_graphql.FakeGraphQL().start()
        self.publisher = publisher_harness.Publisher(tmp_path / "publisher", graphql_url=self.graphql.url())
        self.summary_path = tmp_path / "summary.md"
        self.output_path = tmp_path / "output.txt"
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        env = {
            "GITHUB_REPOSITORY": REPO,
            "GITHUB_ACTOR": "dana",
            "INPUT_GITHUB_TOKEN": "ghs_test",
            "GITHUB_STEP_SUMMARY": str(self.summary_path),
            "GITHUB_OUTPUT": str(self.output_path),
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_GRAPHQL_URL": self.graphql.url(),
            "MITIG8IT_GITHUB_SERVICE_ROOT": str(self.publisher.root / "github-service"),
            "MITIG8IT_STUB_STATE": str(self.publisher.state_path),
        }
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        for key in ("GITHUB_API_URL", "INPUT_FAIL_ON", "INPUT_MAX_FILES", "INPUT_MODEL_API_KEY"):
            monkeypatch.delenv(key, raising=False)

        real_reader = github_api.GitHubReader
        api = self.api

        def reader(**kwargs):
            return real_reader(client=api, sleep=lambda _s: None, **kwargs)

        monkeypatch.setattr(github_api, "GitHubReader", reader)
        monkeypatch.setattr(analysis, "analyze", self._analyze)

    def _analyze(self, _repository, _number, _sha, _files):
        if self.analysis_error is not None:
            raise self.analysis_error
        return list(self.findings), list(self.limitations)

    def stop(self) -> None:
        self.graphql.stop()

    def write_event(self) -> None:
        path = self.tmp_path / "event.json"
        path.write_text(json.dumps(self.event))
        self.monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))

    def main(self, **inputs) -> int:
        for name, value in inputs.items():
            self.monkeypatch.setenv(f"INPUT_{name.upper()}", value)
        self.write_event()
        code = run.main()
        captured = self.capsys.readouterr()
        self.stdout = captured.out
        self.stderr = captured.err
        return code

    def annotations(self, level: str) -> list:
        prefix = f"::{level}"
        return [line for line in self.stdout.splitlines() if line.startswith(prefix)]

    def calls(self, name: str) -> list:
        return [call for call in self.publisher.calls() if call["name"] == name]

    def summary(self) -> str:
        return self.summary_path.read_text() if self.summary_path.exists() else ""


@pytest.fixture
def harness(tmp_path, monkeypatch, capsys):
    instance = Harness(tmp_path, monkeypatch, capsys)
    yield instance
    instance.stop()


def test_a_clean_run_publishes_and_exits_zero(harness):
    harness.findings = [finding(4)]
    assert harness.main() == 0
    assert len(harness.calls("review")) == 1
    assert harness.calls("check")[0]["conclusion"] == "neutral"


# --- every failure has a defined outcome -------------------------------------------------------

def test_a_scanner_failure_under_fail_on_none_is_neutral_and_exits_zero(harness):
    harness.analysis_error = RuntimeError("Tier 2 analysis failed: semgrep timed out")
    assert harness.main() == 0
    errors = harness.annotations("error")
    assert errors and "RuntimeError" in errors[0]
    check = harness.calls("check")
    assert len(check) == 1
    assert check[0]["conclusion"] == "neutral"
    assert "RuntimeError" in check[0]["summary"]
    assert "not a clean review" in check[0]["summary"]
    assert harness.calls("review") == [], "nothing was reviewed, so no review is posted"
    assert "did not complete" in harness.summary()


def test_a_scanner_failure_under_fail_on_high_still_fails_the_job(harness):
    harness.analysis_error = RuntimeError("Tier 2 analysis failed")
    assert harness.main(fail_on="high") == 1
    assert harness.calls("check")[0]["conclusion"] == "neutral"


def test_a_head_that_moved_is_reported_not_raised(harness):
    harness.api.reroute(r"/repos/acme/widgets/pulls/42", fake_github.pull_request(42, "c" * 40))
    assert harness.main() == 0
    assert any("superseded" in line for line in harness.annotations("error"))
    assert "HeadMovedError" in harness.calls("check")[0]["summary"]


def test_a_max_files_that_is_not_a_number_falls_back_with_a_warning(harness):
    harness.findings = [finding(4)]
    assert harness.main(max_files="two hundred") == 0
    assert any("max-files must be a whole number" in line for line in harness.annotations("warning"))
    assert len(harness.calls("review")) == 1, "the run carried on with the default"


def test_one_inline_edit_failing_is_a_warning_not_a_failure(harness):
    """Without GraphQL every comment is written through `postInlineComment`, one by one."""
    harness.monkeypatch.setenv("GITHUB_GRAPHQL_URL", "http://127.0.0.1:9/graphql")
    harness.publisher.fail("inline", 500, "Server Error")
    harness.findings = [finding(4, severity="medium")]
    assert harness.main(fail_on="high") == 0
    assert any("publish: inline src/app.py:4" in line for line in harness.annotations("warning"))
    assert harness.annotations("error") == []
    assert harness.calls("check")[0]["conclusion"] == "success"


def test_a_review_that_could_not_be_posted_follows_fail_on(harness):
    harness.publisher.fail("review", 500, "Server Error")
    harness.findings = [finding(4, severity="medium")]
    assert harness.main() == 0
    assert any("publishing failed: review" in line for line in harness.annotations("error"))
    checks = harness.calls("check")
    assert checks[-1]["conclusion"] == "neutral"
    assert "PublishError" in checks[-1]["summary"]


def test_a_review_that_could_not_be_posted_fails_under_fail_on_high(harness):
    harness.publisher.fail("review", 500, "Server Error")
    assert harness.main(fail_on="high") == 1


def test_a_publisher_that_crashed_is_reported_not_raised(harness, tmp_path):
    crashing = tmp_path / "crash.js"
    crashing.write_text("process.stderr.write('boom\\n'); process.exit(3);\n")
    harness.monkeypatch.setenv("MITIG8IT_PUBLISHER", str(crashing))
    harness.findings = [finding(4)]
    assert harness.main() == 0
    assert any("publishing failed: boom" in line for line in harness.annotations("error")), harness.stdout


def test_contents_write_is_refused_whatever_fail_on_says(harness):
    """A refusal the workflow author has to fix must not read as a review that ran."""
    harness.api.reroute(r"/repos/acme/widgets", fake_github.repository({"pull": True, "push": True}))
    assert harness.main() == 1
    assert any("refuses to run with `contents: write`" in line for line in harness.annotations("error"))
    assert harness.calls("check") == []


# --- GitHub Enterprise Server ----------------------------------------------------------------

def test_an_enterprise_server_api_is_refused_before_the_token_goes_anywhere(harness):
    """The publisher's write path is hard-wired to api.github.com, so a GHES token would be sent
    to the wrong host. The run stops before any request instead."""
    harness.monkeypatch.setenv("GITHUB_API_URL", "https://ghe.example.com/api/v3")
    assert harness.main() == 0
    errors = harness.annotations("error")
    assert errors and "GitHub Enterprise Server" in errors[0]
    assert "https://ghe.example.com/api/v3" in errors[0]
    assert harness.api.calls == [], "nothing was read with the token"
    assert harness.publisher.calls() == [], "nothing was written with the token"
    assert harness.main(fail_on="high") == 1


def test_the_public_api_url_with_a_trailing_slash_is_accepted(harness):
    harness.monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com/")
    harness.findings = [finding(4)]
    assert harness.main() == 0
    assert len(harness.calls("review")) == 1


# --- limitations reach the output --------------------------------------------------------------

def test_the_scanner_s_limitations_reach_the_check_the_review_and_the_job_summary(harness):
    harness.limitations = [
        {"path": "src/app.py", "kind": "partial_parse", "type": "Syntax error",
         "message": "Syntax error at line 3", "line": 3},
        {"kind": "budget", "path": "", "message": "Tier 1 stopped after 0 of 1 files (20 s budget)"},
    ]
    assert harness.main() == 0
    check = harness.calls("check")[0]
    body = harness.calls("review")[0]["body"]
    for text in (check["summary"], body, harness.summary()):
        assert "Not fully analysed" in text
        assert "Syntax error at line 3" in text
        assert "Tier 1 stopped after 0 of 1 files" in text
    assert any("Not fully analysed" in line for line in harness.annotations("warning"))


# --- large files ----------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "payload",
    [
        fake_github.contents_payload("x = 1\n" * 100_000),  # 600 kB: over the 500 kB cap
        {"type": "file", "encoding": "none", "content": "", "size": 2_400_000},  # over 1 MB
    ],
    ids=["600kB", "2MB"],
)
def test_a_large_file_is_reported_not_analysed_and_the_run_continues(harness, payload):
    harness.api.reroute(r"/repos/acme/widgets/contents/src/app\.py", payload)
    seen = {}

    def analyze(_repository, _number, _sha, files):
        seen["files"] = files
        return [finding(4)], []

    harness.monkeypatch.setattr(analysis, "analyze", analyze)
    assert harness.main() == 0
    assert seen["files"][0]["content"] == "", "the patch is still scanned"
    check = harness.calls("check")[0]
    assert "Not fully analysed" in check["summary"]
    assert "src/app.py" in check["summary"]
    assert "(partial review)" in check["title"]
    assert len(harness.calls("review")) == 1


# --- pre-existing code in a touched file -------------------------------------------------------

def test_a_finding_on_an_unchanged_line_does_not_fail_fail_on_high(harness):
    """Touching a legacy file must not block the pull request for code its author did not write."""
    harness.findings = [finding(1, severity="critical", fingerprint="fp-old")]
    assert harness.main(fail_on="high") == 0
    check = harness.calls("check")[0]
    assert check["conclusion"] == "success"
    assert "0 critical or high" in check["title"]
    assert "1 pre-existing" in check["title"]
    assert "pre-existing in a touched file, not counted" in check["summary"]
    body = harness.calls("review")[0]["body"]
    assert "src/app.py:1" in body, "the author still sees it"
    assert "pre-existing in a touched file, not counted" in body
    outputs = harness.output_path.read_text()
    assert "critical=0" in outputs
    assert "conclusion=success" in outputs


def test_a_finding_on_an_added_line_fails_fail_on_high(harness):
    harness.findings = [finding(4, severity="critical", fingerprint="fp-new")]
    assert harness.main(fail_on="high") == 1
    check = harness.calls("check")[0]
    assert check["conclusion"] == "failure"
    assert "1 critical or high" in check["title"]
    assert "pre-existing" not in check["title"]


def test_only_the_added_line_counts_when_both_are_present(harness):
    harness.findings = [
        finding(1, severity="critical", fingerprint="fp-old"),
        finding(4, severity="high", fingerprint="fp-new"),
    ]
    assert harness.main(fail_on="critical") == 0, "the only critical is pre-existing"
    assert harness.calls("check")[0]["conclusion"] == "success"
