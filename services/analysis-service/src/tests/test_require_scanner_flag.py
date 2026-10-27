"""`MITIG8IT_REQUIRE_SCANNER=1` turns a missing-scanner skip into a failure, and nothing else."""

from pathlib import Path

import pytest

pytest_plugins = ["pytester"]

CONFTEST = Path(__file__).with_name("conftest.py")

INNER_TESTS = '''
import pytest

missing = pytest.mark.skipif(True, reason="OpenGrep/Semgrep executable is unavailable")


@missing
def test_marker_skip():
    pass


def test_runtime_skip():
    pytest.skip("tier 2 scanner is unavailable in this environment")


def test_unrelated_skip():
    pytest.skip("this case declares no parameterised counterpart")


@pytest.mark.xfail(reason="the scanner is expected to miss this", strict=True)
def test_expected_failure():
    assert False
'''


@pytest.fixture
def inner(pytester):
    pytester.makeconftest(CONFTEST.read_text())
    pytester.makepyfile(test_inner=INNER_TESTS)
    return pytester


def test_without_the_flag_scanner_skips_stay_skips(inner, monkeypatch):
    monkeypatch.delenv("MITIG8IT_REQUIRE_SCANNER", raising=False)
    inner.runpytest("-p", "no:cacheprovider").assert_outcomes(skipped=3, xfailed=1)


def test_with_the_flag_scanner_skips_fail_and_other_skips_do_not(inner, monkeypatch):
    monkeypatch.setenv("MITIG8IT_REQUIRE_SCANNER", "1")
    result = inner.runpytest("-p", "no:cacheprovider")
    # A marker skip happens at setup, so pytest reports its failure as an error; either one
    # fails the job.
    result.assert_outcomes(failed=1, errors=1, skipped=1, xfailed=1)
    result.stdout.fnmatch_lines(["*MITIG8IT_REQUIRE_SCANNER=1 requires the tier 2 scanner*"])
