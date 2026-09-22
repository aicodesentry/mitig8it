"""Request-supplied file paths must stay inside the OpenGrep scan directory.

`Path(tmpdir) / path` discards the directory for an absolute path and `..` climbs
out of it, so a crafted PR file name could have written request content anywhere
the service user can write.
"""
import os
from pathlib import Path

import pytest

from opengrep_runner import ScanPathError, contained_scan_path, run_opengrep


@pytest.fixture
def root(tmp_path):
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    return scan_root


@pytest.mark.parametrize("path", [
    "src/app.py",
    "deep/nested/dir/handler.js",
    "./relative.py",
    "a/../b.py",
])
def test_paths_inside_the_root_are_accepted(root, path):
    target = contained_scan_path(root, path)
    assert target.resolve().is_relative_to(root.resolve())


@pytest.mark.parametrize("path", [
    "../x.py",
    "../../etc/cron.d/job",
    "src/../../x.py",
    "..",
])
def test_parent_traversal_is_rejected(root, path):
    with pytest.raises(ScanPathError, match="outside the scan directory"):
        contained_scan_path(root, path)


@pytest.mark.parametrize("path", ["/etc/passwd", "/usr/local/lib/x.py", ""])
def test_absolute_and_empty_paths_are_rejected(root, path):
    with pytest.raises(ScanPathError, match="outside the scan directory"):
        contained_scan_path(root, path)


def test_a_symlink_escaping_the_root_is_rejected(root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, root / "link")
    with pytest.raises(ScanPathError, match="outside the scan directory"):
        contained_scan_path(root, "link/x.py")
    assert not (outside / "x.py").exists()


def test_a_symlink_staying_inside_the_root_is_accepted(root):
    (root / "real").mkdir()
    os.symlink(root / "real", root / "alias")
    assert contained_scan_path(root, "alias/x.py") == root / "alias" / "x.py"


def test_the_tier_fails_closed_on_an_escaping_path():
    with pytest.raises(ScanPathError, match="'../evil.py'"):
        run_opengrep([{"path": "../evil.py", "patch": "+eval(user_input)"}])


def test_the_scan_path_error_is_a_runtime_error():
    # run_opengrep callers treat RuntimeError as the detector failing closed.
    assert issubclass(ScanPathError, RuntimeError)
