"""Tests for bounded multi-file batching in the native scanner tier."""

import shutil
import subprocess

import pytest

import opengrep_runner
from opengrep_runner import build_scan_batches, run_opengrep


def _can_run_opengrep() -> bool:
    opengrep_path = shutil.which("semgrep")
    if not opengrep_path:
        return False
    try:
        result = subprocess.run(
            [opengrep_path, "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False


skip_no_opengrep = pytest.mark.skipif(
    not _can_run_opengrep(),
    reason="OpenGrep/Semgrep executable is unavailable",
)


def _entry(path: str, size: int) -> dict:
    return {"path": path, "content": "x" * size, "size": size}


class TestBuildScanBatches:
    def test_splits_on_file_count(self):
        batches = build_scan_batches(
            [_entry(f"f{i}.py", 10) for i in range(10)],
            max_files=4,
            max_bytes=1_000_000,
        )

        assert [len(batch) for batch in batches] == [4, 4, 2]

    def test_splits_on_total_bytes(self):
        batches = build_scan_batches(
            [_entry(f"f{i}.py", 400) for i in range(5)],
            max_files=100,
            max_bytes=1000,
        )

        assert [len(batch) for batch in batches] == [2, 2, 1]

    def test_single_oversized_file_still_gets_scanned(self):
        batches = build_scan_batches(
            [_entry("huge.py", 5000), _entry("small.py", 10)],
            max_files=100,
            max_bytes=1000,
        )

        assert [entry["path"] for batch in batches for entry in batch] == ["huge.py", "small.py"]
        assert len(batches) == 2

    def test_empty_input_produces_no_batches(self):
        assert build_scan_batches([]) == []

    def test_defaults_come_from_environment(self, monkeypatch):
        monkeypatch.setenv("OPENGREP_BATCH_MAX_FILES", "3")
        monkeypatch.setenv("OPENGREP_BATCH_MAX_BYTES", "1048576")

        batches = build_scan_batches([_entry(f"f{i}.py", 10) for i in range(7)])

        assert [len(batch) for batch in batches] == [3, 3, 1]

    def test_invalid_environment_values_fall_back_to_defaults(self, monkeypatch):
        monkeypatch.setenv("OPENGREP_BATCH_MAX_FILES", "not-a-number")
        monkeypatch.delenv("OPENGREP_BATCH_MAX_BYTES", raising=False)

        assert opengrep_runner.batch_max_files() == opengrep_runner.DEFAULT_BATCH_MAX_FILES
        assert opengrep_runner.batch_max_bytes() == opengrep_runner.DEFAULT_BATCH_MAX_BYTES


class TestBatchFailureFailsClosed:
    def test_a_failing_batch_aborts_the_whole_tier(self, monkeypatch):
        monkeypatch.setenv("OPENGREP_BATCH_MAX_FILES", "2")
        calls = {"count": 0}

        def fake_run_semgrep(target_dir):
            calls["count"] += 1
            if calls["count"] == 2:
                raise RuntimeError("OpenGrep failed with exit code 2")
            return {"results": [], "errors": []}, []

        monkeypatch.setattr(opengrep_runner, "_run_semgrep", fake_run_semgrep)

        files = [
            {"path": f"svc/file{i}.py", "patch": "+import os\n+os.system(cmd)\n"}
            for i in range(6)
        ]

        with pytest.raises(RuntimeError, match="OpenGrep failed with exit code 2"):
            run_opengrep(files)

        # It stopped at the failing batch rather than reporting partial results.
        assert calls["count"] == 2

    def test_scanner_errors_in_one_batch_fail_closed(self, monkeypatch):
        monkeypatch.setattr(
            opengrep_runner,
            "_run_semgrep",
            lambda target_dir: (_ for _ in ()).throw(RuntimeError("OpenGrep reported incomplete analysis")),
        )

        with pytest.raises(RuntimeError, match="incomplete analysis"):
            run_opengrep([{"path": "svc/file.py", "patch": "+import os\n+os.system(cmd)\n"}])


LANGUAGE_SAMPLES = [
    (".py", "+import pickle\n+data = pickle.loads(user_input)\n"),
    (".js", "+const result = eval(req.body.code)\n"),
    (".go", "+data, _ := os.ReadFile(filepath.Join(baseDir, r.URL.Query().Get(\"file\")))\n"),
]


@skip_no_opengrep
class TestManyFilesAreAllScanned:
    def test_sixty_files_across_languages_are_batched_and_all_reported(self, monkeypatch):
        monkeypatch.setenv("OPENGREP_BATCH_MAX_FILES", "25")
        monkeypatch.setenv("OPENGREP_BATCH_MAX_BYTES", str(1024 * 1024))

        real_run_semgrep = opengrep_runner._run_semgrep
        batch_dirs = []

        def counting_run_semgrep(target_dir):
            batch_dirs.append(target_dir)
            return real_run_semgrep(target_dir)

        monkeypatch.setattr(opengrep_runner, "_run_semgrep", counting_run_semgrep)

        files = []
        for index in range(60):
            extension, patch = LANGUAGE_SAMPLES[index % len(LANGUAGE_SAMPLES)]
            files.append({
                "path": f"svc/module{index}{extension}",
                "patch": patch,
            })

        findings = run_opengrep(files)

        # 60 files at 25 per batch means three scanner processes.
        assert len(batch_dirs) == 3
        assert len(set(batch_dirs)) == 3

        found_paths = {finding["file_path"] for finding in findings}
        expected_paths = {file["path"] for file in files}
        assert found_paths == expected_paths, sorted(expected_paths - found_paths)
        assert all(finding["in_test_code"] is False for finding in findings)
