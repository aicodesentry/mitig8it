"""Suite-wide settings for the analysis-service tests.

Several files skip their tier 2 tests when the scanner is not installed, which is the right
call on a laptop and the wrong one in CI: a broken scanner install would turn the whole tier 2
suite green by skipping it. With `MITIG8IT_REQUIRE_SCANNER=1` (set in the analysis-tests CI
job) any skip whose reason names the scanner is reported as a failure instead. This is the one
place the rule lives, so the per-file `skipif` markers stay as they are.
"""

import os
import re

import pytest

REQUIRE_SCANNER_ENV = "MITIG8IT_REQUIRE_SCANNER"
SCANNER_SKIP_REASON = re.compile(r"opengrep|semgrep|scanner", re.IGNORECASE)


def _scanner_required() -> bool:
    return os.getenv(REQUIRE_SCANNER_ENV, "").strip() == "1"


def _skip_reason(report) -> str:
    longrepr = report.longrepr
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        return str(longrepr[2])
    return str(longrepr or "")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if not report.skipped or not _scanner_required() or hasattr(report, "wasxfail"):
        return
    reason = _skip_reason(report)
    if not SCANNER_SKIP_REASON.search(reason):
        return
    report.outcome = "failed"
    report.longrepr = (
        f"{REQUIRE_SCANNER_ENV}=1 requires the tier 2 scanner, but this test skipped: {reason}"
    )
