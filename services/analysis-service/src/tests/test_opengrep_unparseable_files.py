"""A file the scanner cannot parse is a coverage gap, not a failed security scan.

Real pull requests carry files the scanner's parser rejects: a syntax error the pull
request is about to fix, a language dialect the parser does not know yet, a generated
or vendored blob. The scanner reports those at warning level against the one file and
still scans the rest of the batch. Before this, any such warning failed tier 2 closed,
which failed the whole analysis run and reported no findings at all for the pull request.

The classification that decides which scanner errors are tolerable lives in
`_classify_scanner_errors` and is unit tested against canned scanner JSON in
`test_scanner_error_classification.py`. What is tested here is the end to end
behaviour with the real scanner: an unparseable file beside a real vulnerability
still reports the vulnerability, and the unparseable file comes back as a recorded
limitation rather than sinking the batch.
"""

import shutil
import subprocess

import pytest

import opengrep_runner
from opengrep_runner import run_opengrep, run_opengrep_with_limitations


def _can_run_opengrep() -> bool:
    opengrep_path = shutil.which("semgrep")
    if not opengrep_path:
        return False
    try:
        result = subprocess.run([opengrep_path, "--help"], capture_output=True, text=True, timeout=30)
        return result.returncode == 0
    except Exception:
        return False


skip_no_opengrep = pytest.mark.skipif(not _can_run_opengrep(), reason="OpenGrep/Semgrep executable is unavailable")

UNPARSEABLE_PYTHON = "def broken(:\n    this is not python at all ][\n"
VULNERABLE_PYTHON = 'import subprocess\n\n\ndef run(name):\n    subprocess.run("ls " + name, shell=True)\n'


class TestUnparseableFileDoesNotSinkTheBatch:
    def test_the_other_files_are_still_reported(self, monkeypatch):
        def fake_run_semgrep(target_dir):
            return {
                "results": [],
                "errors": [{
                    "level": "warn",
                    "type": ["PartialParsing", []],
                    "path": f"{target_dir}/svc/broken.py",
                    "message": "Syntax error",
                }],
                "analysis_limitations": [{
                    "path": f"{target_dir}/svc/broken.py",
                    "kind": opengrep_runner.LIMITATION_PARTIAL_PARSE,
                    "type": "Partial parsing",
                    "message": "Syntax error",
                    "line": None,
                }],
            }

        monkeypatch.setattr(opengrep_runner, "_run_semgrep", fake_run_semgrep)
        findings, limitations = run_opengrep_with_limitations(
            [{"path": "svc/broken.py", "patch": "", "content": UNPARSEABLE_PYTHON}]
        )
        assert findings == []
        assert [limitation["path"] for limitation in limitations] == ["svc/broken.py"]
        assert limitations[0]["kind"] == opengrep_runner.LIMITATION_PARTIAL_PARSE

    @skip_no_opengrep
    def test_a_real_syntax_error_beside_a_real_vulnerability(self):
        findings, limitations = run_opengrep_with_limitations(
            [
                {"path": "svc/broken.py", "patch": "", "content": UNPARSEABLE_PYTHON},
                {"path": "svc/runner.py", "patch": "", "content": VULNERABLE_PYTHON},
            ]
        )

        # The claim is which files were covered, not how many rules matched inside one: the
        # tier 2 coverage set gives a shell-injection line more than one matching rule.
        assert findings, "the parseable file produced no finding"
        assert {finding["file_path"] for finding in findings} == {"svc/runner.py"}
        assert [limitation["path"] for limitation in limitations] == ["svc/broken.py"]
        assert limitations[0]["kind"] == opengrep_runner.LIMITATION_PARTIAL_PARSE

    @skip_no_opengrep
    def test_run_opengrep_discards_the_limitations_and_still_returns_findings(self):
        findings = run_opengrep(
            [
                {"path": "svc/broken.py", "patch": "", "content": UNPARSEABLE_PYTHON},
                {"path": "svc/runner.py", "patch": "", "content": VULNERABLE_PYTHON},
            ]
        )

        # The claim is which files were covered, not how many rules matched inside one: the
        # tier 2 coverage set gives a shell-injection line more than one matching rule.
        assert findings, "the parseable file produced no finding"
        assert {finding["file_path"] for finding in findings} == {"svc/runner.py"}
