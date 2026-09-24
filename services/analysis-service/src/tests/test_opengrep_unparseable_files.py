"""A file the scanner cannot parse is a coverage gap, not a failed security scan.

Real pull requests carry files the scanner's parser rejects: a syntax error the pull
request is about to fix, a language dialect the parser does not know yet, a generated
or vendored blob. The scanner reports those at warning level against the one file and
still scans the rest of the batch. Before this, any such warning failed tier 2 closed,
which failed the whole analysis run and reported no findings at all for the pull request.
"""

import shutil
import subprocess

import pytest

import opengrep_runner
from opengrep_runner import partition_scan_errors, run_opengrep


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


class TestErrorPartition:
    def test_a_parse_warning_on_a_scanned_file_is_a_coverage_gap(self):
        errors = [{
            "level": "warn",
            "type": ["PartialParsing", []],
            "path": "/tmp/scan/svc/broken.py",
            "message": "Syntax error at line /tmp/scan/svc/broken.py:2",
        }]
        unscanned, fatal = partition_scan_errors(errors, "/tmp/scan")
        assert fatal == []
        assert unscanned == [{
            "path": "svc/broken.py",
            "code": "PartialParsing",
            "detail": "Syntax error at line /tmp/scan/svc/broken.py:2",
        }]

    def test_a_per_file_timeout_is_a_coverage_gap(self):
        errors = [{"level": "warn", "type": "Timeout", "path": "/tmp/scan/big.ts", "message": "timed out"}]
        unscanned, fatal = partition_scan_errors(errors, "/tmp/scan")
        assert fatal == []
        assert [gap["code"] for gap in unscanned] == ["Timeout"]

    def test_a_rule_configuration_failure_still_fails_closed(self):
        errors = [{"level": "error", "type": "InvalidRuleSchemaError", "message": "bad rule"}]
        unscanned, fatal = partition_scan_errors(errors, "/tmp/scan")
        assert unscanned == []
        assert len(fatal) == 1

    def test_an_error_outside_the_scan_directory_still_fails_closed(self):
        errors = [{"level": "warn", "type": "PartialParsing", "path": "/etc/passwd", "message": "x"}]
        unscanned, fatal = partition_scan_errors(errors, "/tmp/scan")
        assert unscanned == []
        assert len(fatal) == 1

    def test_a_malformed_error_entry_still_fails_closed(self):
        unscanned, fatal = partition_scan_errors(["not a dict"], "/tmp/scan")
        assert unscanned == []
        assert fatal == ["not a dict"]


class TestUnparseableFileDoesNotSinkTheBatch:
    def test_the_other_files_are_still_reported(self, monkeypatch):
        def fake_run_semgrep(target_dir):
            return (
                {
                    "results": [],
                    "errors": [{
                        "level": "warn",
                        "type": ["PartialParsing", []],
                        "path": f"{target_dir}/svc/broken.py",
                        "message": "Syntax error",
                    }],
                },
                [],
            )

        monkeypatch.setattr(opengrep_runner, "_run_semgrep", fake_run_semgrep)
        gaps = []
        findings = run_opengrep(
            [{"path": "svc/broken.py", "patch": "", "content": UNPARSEABLE_PYTHON}], gaps
        )
        assert findings == []

    @skip_no_opengrep
    def test_a_real_syntax_error_beside_a_real_vulnerability(self):
        gaps = []
        findings = run_opengrep(
            [
                {"path": "svc/broken.py", "patch": "", "content": UNPARSEABLE_PYTHON},
                {"path": "svc/runner.py", "patch": "", "content": VULNERABLE_PYTHON},
            ],
            gaps,
        )

        # The claim is which files were covered, not how many rules matched inside one: the
        # tier 2 coverage set gives a shell-injection line more than one matching rule.
        assert findings, "the parseable file produced no finding"
        assert {finding["file_path"] for finding in findings} == {"svc/runner.py"}
        assert [gap["path"] for gap in gaps] == ["svc/broken.py"]
        assert gaps[0]["code"] == "PartialParsing"

    @skip_no_opengrep
    def test_the_gap_list_is_optional(self):
        findings = run_opengrep([{"path": "svc/broken.py", "patch": "", "content": UNPARSEABLE_PYTHON}])
        assert findings == []
