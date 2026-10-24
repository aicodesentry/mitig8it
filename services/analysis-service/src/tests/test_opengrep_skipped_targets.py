"""A file the scanner skips is a limitation, never a silent empty result.

`_run_semgrep` passes `--max-target-bytes`, and the scanner skips any file over it without an
error: with `--quiet` its JSON does not even list the file under `paths.skipped`. A 508 kB file
with thousands of `eval(req.query...)` sinks used to return zero findings and zero limitations,
which reads exactly like a clean file. The upstream 500 kB content cap hides this today, so this
is the second line of defence for the day that cap moves.
"""

import shutil
import subprocess

import pytest

import opengrep_runner
from opengrep_runner import SCANNER_MAX_TARGET_BYTES, run_opengrep_with_limitations


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


def _oversized_js() -> str:
    lines = []
    size = 0
    index = 0
    while size <= 508_000:
        line = f"eval(req.query.a{index});\n"
        lines.append(line)
        size += len(line)
        index += 1
    return "".join(lines)


SMALL_FILE = {"path": "src/small.js", "content": "const x = eval(req.query.code);\n"}


@skip_no_opengrep
class TestTheRealScannerSkipsAnOversizedFile:
    def test_a_508_kb_file_yields_one_size_limitation_and_the_other_file_is_still_scanned(self):
        big = {"path": "src/big.js", "content": _oversized_js()}
        assert len(big["content"].encode("utf-8")) > SCANNER_MAX_TARGET_BYTES

        findings, limitations = run_opengrep_with_limitations([big, SMALL_FILE])

        assert [(item["path"], item["kind"], item["reason"]) for item in limitations] == [
            ("src/big.js", "not_analyzed", "size"),
        ]
        assert "500000" in limitations[0]["message"]
        assert {finding["file_path"] for finding in findings} == {"src/small.js"}


class TestSkippedPathsInTheScannerOutput:
    def _fake(self, monkeypatch, paths):
        def fake_run_semgrep(target_dir):
            return {
                "results": [],
                "errors": [],
                "paths": {
                    "scanned": [],
                    "skipped": [{**entry, "path": f"{target_dir}/{entry['path']}"} for entry in paths],
                },
            }

        monkeypatch.setattr(opengrep_runner, "_run_semgrep", fake_run_semgrep)

    def test_a_listed_skip_becomes_a_limitation_with_its_reason(self, monkeypatch):
        self._fake(monkeypatch, [{"path": "src/a.py", "reason": "too_many_matches"}])

        _findings, limitations = run_opengrep_with_limitations([{"path": "src/a.py", "content": "x = 1\n"}])

        assert [(item["path"], item["kind"], item["reason"]) for item in limitations] == [
            ("src/a.py", "not_analyzed", "too_many_matches"),
        ]

    def test_a_listed_size_skip_is_reported_once(self, monkeypatch):
        self._fake(monkeypatch, [{"path": "src/big.py", "reason": "exceeded_size_limit"}])
        big = {"path": "src/big.py", "content": "x = 1\n" * 100_000}

        _findings, limitations = run_opengrep_with_limitations([big])

        assert [(item["path"], item["reason"]) for item in limitations] == [("src/big.py", "size")]

    def test_a_file_under_the_limit_that_is_not_listed_adds_nothing(self, monkeypatch):
        self._fake(monkeypatch, [])

        _findings, limitations = run_opengrep_with_limitations([{"path": "src/a.py", "content": "x = 1\n"}])

        assert limitations == []
