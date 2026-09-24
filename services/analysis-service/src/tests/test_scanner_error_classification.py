"""One unparsable file must not delete the findings from every other file.

A pull request with a single lexical error in one file used to lose the whole
tier 2 scan: `_run_semgrep` raised on any non-empty `errors` list and the
orchestrator failed the check run closed with zero findings. These tests pin
the classification that replaced it, using canned semgrep JSON in the
`cli_error` shape (code, level, type, message, path, spans).
"""
import json
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

import opengrep_runner
from opengrep_runner import (
    LIMITATION_NOT_ANALYZED,
    LIMITATION_PARTIAL_PARSE,
    run_opengrep_with_limitations,
)

FILES = [
    {"path": "svc/cwe-vul.py", "patch": "+import os\n+os.system(cmd)\n"},
    {"path": "svc/other.py", "patch": "+import os\n+os.system(other)\n"},
]


def _semgrep_output(results=None, errors=None):
    return json.dumps({"results": results or [], "errors": errors or [], "paths": {"scanned": []}})


def _finding_match(path_suffix="svc/cwe-vul.py", line=3):
    return {
        "check_id": "command-injection",
        "path": path_suffix,
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 20},
        "extra": {
            "message": "Command injection",
            "severity": "ERROR",
            "lines": "os.system(cmd)",
            "metadata": {"category": "security", "cwe": "CWE-78"},
        },
    }


def _run_with_semgrep_output(monkeypatch, output_json, stderr=""):
    """Drive the real batching path with a canned scanner process result."""
    monkeypatch.setattr(
        opengrep_runner.subprocess,
        "run",
        lambda *args, **kwargs: CompletedProcess(args[0] if args else [], 0, stdout=output_json, stderr=stderr),
    )
    return run_opengrep_with_limitations(FILES)


class TestWarningLevelParseErrors:
    def test_lexical_error_keeps_results_and_records_a_limitation(self, monkeypatch):
        errors = [{
            "code": 3,
            "level": "warn",
            "type": "Lexical error",
            "path": "svc/cwe-vul.py",
            "message": "Lexical error at line svc/cwe-vul.py:127:\n unrecognized symbol in string",
        }]
        findings, limitations = _run_with_semgrep_output(
            monkeypatch,
            _semgrep_output(results=[_finding_match()], errors=errors),
        )

        assert len(findings) == 1, "the batch results survive a per-file parse error"
        assert len(limitations) == 1
        assert limitations[0]["path"] == "svc/cwe-vul.py"
        assert limitations[0]["kind"] == LIMITATION_PARTIAL_PARSE
        assert limitations[0]["type"] == "Lexical error"
        assert limitations[0]["line"] == 127
        assert "unrecognized symbol" in limitations[0]["message"]

    @pytest.mark.parametrize(
        "error_type",
        ["Lexical error", "Syntax error", "Other syntax error", "Partial parsing", "Parsing error"],
    )
    def test_every_warning_level_parse_type_is_tolerated(self, monkeypatch, error_type):
        errors = [{"code": 3, "level": "warn", "type": error_type, "path": "svc/other.py", "message": "broken"}]
        findings, limitations = _run_with_semgrep_output(
            monkeypatch,
            _semgrep_output(results=[_finding_match()], errors=errors),
        )
        assert len(findings) == 1
        assert [limitation["kind"] for limitation in limitations] == [LIMITATION_PARTIAL_PARSE]

    def test_partial_parsing_carries_its_line_from_the_parameterised_type(self, monkeypatch):
        errors = [{
            "code": 3,
            "level": "warn",
            "type": ["PartialParsing", [{"path": "svc/other.py", "start": {"line": 42, "col": 1}, "end": {"line": 44, "col": 1}}]],
            "path": "svc/other.py",
            "message": "Partial parsing",
        }]
        _, limitations = _run_with_semgrep_output(
            monkeypatch,
            _semgrep_output(results=[], errors=errors),
        )
        assert limitations[0]["type"] == "Partial parsing", "the constructor tag is made readable"
        assert limitations[0]["line"] == 42

    def test_the_scan_temp_directory_never_reaches_the_limitation(self, monkeypatch):
        """The path and message are published; neither may carry the scratch path."""
        captured = {}

        def fake_run(args, **kwargs):
            captured["tmpdir"] = args[-1]
            errors = [{
                "code": 3,
                "level": "warn",
                "type": ["PartialParsing", []],
                "path": f"{args[-1]}/svc/cwe-vul.py",
                "message": f"Syntax error at line {args[-1]}/svc/cwe-vul.py:2:\n bad token",
            }]
            return CompletedProcess(args, 0, stdout=_semgrep_output(errors=errors), stderr="")

        monkeypatch.setattr(opengrep_runner.subprocess, "run", fake_run)
        _, limitations = run_opengrep_with_limitations(FILES)

        assert limitations[0]["path"] == "svc/cwe-vul.py"
        assert captured["tmpdir"] not in limitations[0]["message"]
        assert limitations[0]["message"].startswith("Syntax error at line svc/cwe-vul.py:2:")

    def test_spans_win_over_the_message_for_the_line(self, monkeypatch):
        errors = [{
            "code": 3,
            "level": "warn",
            "type": "Syntax error",
            "path": "svc/other.py",
            "message": "Syntax error at line svc/other.py:9:\n bad token",
            "spans": [{"file": "svc/other.py", "start": {"line": 77, "col": 2}, "end": {"line": 77, "col": 8}}],
        }]
        _, limitations = _run_with_semgrep_output(monkeypatch, _semgrep_output(errors=errors))
        assert limitations[0]["line"] == 77


class TestResourceLimits:
    @pytest.mark.parametrize("error_type", ["Timeout", "Out of memory", "Too many matches"])
    def test_per_file_resource_limit_records_a_limitation(self, monkeypatch, error_type):
        errors = [{
            "code": 3,
            "level": "warn",
            "type": error_type,
            "path": "svc/other.py",
            "message": f"{error_type} when running rules on svc/other.py",
        }]
        findings, limitations = _run_with_semgrep_output(
            monkeypatch,
            _semgrep_output(results=[_finding_match()], errors=errors),
        )

        assert len(findings) == 1, "findings from the other files are kept"
        assert limitations[0]["kind"] == LIMITATION_NOT_ANALYZED
        assert limitations[0]["type"] == error_type
        assert limitations[0]["path"] == "svc/other.py"

    def test_error_level_timeout_with_a_path_is_still_only_a_limitation(self, monkeypatch):
        errors = [{"code": 3, "level": "error", "type": "Timeout", "path": "svc/other.py", "message": "timed out"}]
        findings, limitations = _run_with_semgrep_output(
            monkeypatch,
            _semgrep_output(results=[_finding_match()], errors=errors),
        )
        assert len(findings) == 1
        assert limitations[0]["kind"] == LIMITATION_NOT_ANALYZED


class TestFatalErrors:
    def test_config_failure_fails_closed_with_the_details_in_the_message(self, monkeypatch):
        errors = [{
            "code": 2,
            "level": "error",
            "type": "Invalid YAML",
            "message": "invalid configuration file found: rules/bad.yml is not valid YAML",
        }]
        with pytest.raises(RuntimeError) as excinfo:
            _run_with_semgrep_output(
                monkeypatch,
                _semgrep_output(results=[_finding_match()], errors=errors),
                stderr="semgrep: fatal: could not load rules\n",
            )

        message = str(excinfo.value)
        assert "Invalid YAML" in message
        assert "not valid YAML" in message
        assert "level=error" in message
        assert "could not load rules" in message, "the stderr tail reaches the logs"

    def test_fatal_error_without_a_path_fails_closed(self, monkeypatch):
        errors = [{"code": 2, "level": "error", "type": "Fatal error", "message": "engine crashed"}]
        with pytest.raises(RuntimeError, match="Fatal error"):
            _run_with_semgrep_output(monkeypatch, _semgrep_output(errors=errors))

    def test_error_level_parse_failure_still_fails_closed(self, monkeypatch):
        """Parse problems are tolerated at warn level; `--strict` style errors are not."""
        errors = [{"code": 3, "level": "error", "type": "Lexical error", "path": "svc/other.py", "message": "bad"}]
        with pytest.raises(RuntimeError, match="Lexical error"):
            _run_with_semgrep_output(monkeypatch, _semgrep_output(errors=errors))

    def test_long_messages_are_truncated_in_the_raised_error(self, monkeypatch):
        errors = [{"code": 2, "level": "error", "type": "Fatal error", "message": "x" * 1000}]
        with pytest.raises(RuntimeError) as excinfo:
            _run_with_semgrep_output(monkeypatch, _semgrep_output(errors=errors))
        assert "x" * 200 in str(excinfo.value)
        assert "x" * 201 not in str(excinfo.value)


class TestLogging:
    def test_every_scanner_error_is_logged_with_type_level_path_and_message(self, monkeypatch, capsys):
        errors = [
            {"code": 3, "level": "warn", "type": "Lexical error", "path": "svc/cwe-vul.py", "message": "unrecognized symbol"},
            {"code": 3, "level": "warn", "type": "Timeout", "path": "svc/other.py", "message": "rule timed out"},
        ]
        _run_with_semgrep_output(monkeypatch, _semgrep_output(errors=errors))

        logged = capsys.readouterr().out
        assert "OpenGrep scanner error: type=Lexical error level=warn path=svc/cwe-vul.py message=unrecognized symbol" in logged
        assert "OpenGrep scanner error: type=Timeout level=warn path=svc/other.py message=rule timed out" in logged

    def test_a_fatal_error_is_logged_before_it_is_raised(self, monkeypatch, capsys):
        errors = [{"code": 2, "level": "error", "type": "Fatal error", "message": "engine crashed"}]
        with pytest.raises(RuntimeError):
            _run_with_semgrep_output(monkeypatch, _semgrep_output(errors=errors))
        assert "OpenGrep scanner error: type=Fatal error level=error" in capsys.readouterr().out


class TestLimitationsReachThePayload:
    def test_tier2_payload_carries_the_limitations(self):
        from main import AnalyzePRRequest, analyze_tier2_payload

        request = AnalyzePRRequest(
            repository_full_name="owner/repo",
            pull_request_number=1,
            commit_sha="a" * 40,
            files=[{"path": "svc/cwe-vul.py", "patch": "+eval(user_input)"}],
        )
        limitation = {
            "path": "svc/cwe-vul.py",
            "kind": LIMITATION_PARTIAL_PARSE,
            "type": "Lexical error",
            "message": "unrecognized symbol in string",
            "line": 127,
        }
        with patch("main.run_opengrep_with_limitations", return_value=([], [limitation])):
            payload = analyze_tier2_payload(request)

        assert payload["analysis_limitations"] == [limitation]

    def test_combined_payload_carries_the_limitations(self):
        from main import AnalyzePRRequest, analyze_pull_request_payload

        request = AnalyzePRRequest(
            repository_full_name="owner/repo",
            pull_request_number=1,
            commit_sha="a" * 40,
            files=[{"path": "svc/cwe-vul.py", "patch": "+eval(user_input)"}],
        )
        limitation = {
            "path": "svc/cwe-vul.py",
            "kind": LIMITATION_NOT_ANALYZED,
            "type": "Timeout",
            "message": "timed out",
            "line": None,
        }
        with patch("main.run_opengrep_with_limitations", return_value=([], [limitation])):
            payload = analyze_pull_request_payload(request)

        assert payload["analysis_limitations"] == [limitation]

    def test_a_clean_scan_reports_no_limitations(self, monkeypatch):
        findings, limitations = _run_with_semgrep_output(
            monkeypatch,
            _semgrep_output(results=[_finding_match()], errors=[]),
        )
        assert len(findings) == 1
        assert limitations == []
