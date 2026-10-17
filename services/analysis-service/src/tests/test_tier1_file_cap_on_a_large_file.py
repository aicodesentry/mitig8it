"""Tier 1 finishes a large file inside its per-file cap, so what it reports does not depend on load.

The September 2026 action trial lost pygoat `introduction/views.py:963` (SSRF), deleted the
`views.py:291` comment on a README-only commit, and saw `auth.weak_password_hash` leave the
supporting detections of `views.py:1026` between two runs over the same file. All three are
the production per-file cap (`TIER1_FILE_BUDGET_SECONDS`, 2 s): every rule rebuilt the file's
reviewable entries, which runs the comment stripper over the whole 48 kB head file, so tier 1
took 8 to 26 s on it and the cap stopped it after 6 to 9 of 35 rules, a different number each
run. The SSRF rule is 26th in `SECURITY_RULES` and the cookie rule 23rd.

The file here is the corpus file itself, committed under its MIT licence in
`benchmarks/vulnerable-corpus/fixture-subset/`, and the pull request is the trial's: one
trailing comment on each labelled line, head content supplied. No budget is lifted.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import finding_quality
import main

REPO_ROOT = Path(__file__).resolve().parents[4]
VIEWS = (
    REPO_ROOT / "benchmarks" / "vulnerable-corpus" / "fixture-subset" / "trees"
    / "adeyosemanputra__pygoat" / "introduction" / "views.py"
)
TRIAL_LINES = [158, 214, 291, 460, 496, 560, 864, 963, 1026]


def _trial_shaped_file() -> main.ChangedFile:
    lines = VIEWS.read_text(encoding="utf-8").splitlines()
    head = list(lines)
    hunks = []
    for number in TRIAL_LINES:
        head[number - 1] = lines[number - 1] + "  # reviewed"
        hunks.append(f"@@ -{number},1 +{number},1 @@\n-{lines[number - 1]}\n+{head[number - 1]}\n")
    return main.ChangedFile(
        path="introduction/views.py",
        patch="".join(hunks),
        content="\n".join(head) + "\n",
        reviewable_line_spans=[{"start": number, "end": number} for number in TRIAL_LINES],
    )


@pytest.fixture
def production_budgets(monkeypatch):
    monkeypatch.delenv("TIER1_BUDGET_SECONDS", raising=False)
    monkeypatch.delenv("TIER1_FILE_BUDGET_SECONDS", raising=False)
    finding_quality._parse_patch_entries_cached.cache_clear()


def test_every_rule_runs_on_the_trial_file_under_the_production_cap(production_budgets):
    limitations: list = []
    findings = main.pattern_findings([_trial_shaped_file()], limitations)

    assert limitations == [], "the per-file cap stopped tier 1 on the trial file"
    reported = {(finding["line_start"], finding["rule_id"]) for finding in findings}
    assert (963, "ssrf.untrusted_url_fetch") in reported
    assert (291, "session.insecure_cookie") in reported
    assert (1026, "auth.weak_password_hash") in reported
    assert (1026, "crypto.weak.hash") in reported


def test_the_file_is_stripped_once_however_many_rules_read_it(production_budgets, monkeypatch):
    calls = {"count": 0}
    real = finding_quality.strip_lines

    def counting(*args, **kwargs):
        calls["count"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(finding_quality, "strip_lines", counting)
    changed = _trial_shaped_file()
    for _ in range(10):
        finding_quality.parse_patch_entries(changed.patch, changed.path, changed.content)

    once = calls["count"]
    finding_quality._parse_patch_entries_cached.cache_clear()
    finding_quality.parse_patch_entries(changed.patch, changed.path, changed.content)
    assert calls["count"] == 2 * once


def test_each_caller_gets_its_own_entries():
    patch = "@@ -1,1 +1,2 @@\n x = 1\n+y = 2\n"
    first = finding_quality.parse_patch_entries(patch, "a.py", "x = 1\ny = 2\n")
    first[0]["scan_text"] = "changed by a caller"
    second = finding_quality.parse_patch_entries(patch, "a.py", "x = 1\ny = 2\n")
    assert second[0]["scan_text"] == "x = 1"
