"""A file scanned from its patch alone must report the file's own line numbers.

A tier 2 scan falls back to rebuilding the new side of a file from its unified diff
whenever the head content is unavailable, which is what happens to a file over the
500 kB content cap and to a `.min.js` the orchestrator never fetches. The rebuild used
to concatenate the hunks and keep the diff's leading marker on context lines, so:

* a finding at line 501 of the file was reported at line 3 of the reconstruction, and
  the inline review comment went to an unrelated line, and
* every context line sat one column right of the added lines around it, which makes a
  Python patch unparseable and, with the old error handling, failed the whole tier.
"""

import shutil
import subprocess

import pytest

from opengrep_runner import _extract_file_content, _extract_scan_content, run_opengrep


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

PYTHON_PATCH = "\n".join([
    "@@ -498,4 +498,6 @@ def handler(request):",
    " def handler(request):",
    "     name = request.args.get('name')",
    "+    import subprocess",
    "+    subprocess.run('ls ' + name, shell=True)",
    "     return name",
    "",
])


class TestReconstruction:
    def test_a_hunk_lands_at_its_new_side_line_number(self):
        lines = _extract_file_content(PYTHON_PATCH).split("\n")
        assert lines[497] == "def handler(request):"
        assert lines[500] == "    subprocess.run('ls ' + name, shell=True)"
        assert lines[:497] == [""] * 497

    def test_a_context_line_loses_the_diff_marker_and_keeps_its_indentation(self):
        lines = _extract_file_content(PYTHON_PATCH).split("\n")
        # The context line and the added line below it are both indented four spaces,
        # exactly as the file has them.
        assert lines[498] == "    name = request.args.get('name')"
        assert lines[499] == "    import subprocess"

    def test_separate_hunks_keep_their_own_offsets(self):
        patch = "\n".join([
            "@@ -1,1 +1,1 @@",
            "+first = 1",
            "@@ -40,1 +40,1 @@",
            "+fortieth = 40",
        ])
        lines = _extract_file_content(patch).split("\n")
        assert lines[0] == "first = 1"
        assert lines[39] == "fortieth = 40"
        assert lines[1:39] == [""] * 38

    def test_removed_lines_and_diff_prose_are_not_content(self):
        patch = "\n".join([
            "@@ -1,2 +1,2 @@",
            "-old = 1",
            "+new = 1",
            "\\ No newline at end of file",
        ])
        content = _extract_file_content(patch)
        assert content == "new = 1"

    def test_a_missing_hunk_header_still_starts_at_line_one(self):
        assert _extract_file_content("+only = 1") == "only = 1"

    def test_full_content_is_still_preferred(self):
        file_info = {"path": "handler.py", "patch": PYTHON_PATCH, "content": "value = 1\n"}
        assert _extract_scan_content(file_info) == "value = 1\n"


@skip_no_opengrep
class TestScannerReportsTheFilesLineNumbers:
    def test_a_patch_only_python_file_parses_and_reports_the_real_line(self):
        gaps: list[dict] = []
        findings = run_opengrep([{"path": "svc/handler.py", "patch": PYTHON_PATCH}], gaps)

        assert gaps == [], gaps
        assert [finding["line_start"] for finding in findings] == [501]
        assert findings[0]["code_snippet"] == "subprocess.run('ls ' + name, shell=True)"
