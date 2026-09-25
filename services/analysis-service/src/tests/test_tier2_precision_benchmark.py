"""The tier 2 precision benchmark: every posting rule fires on its own fixture, and the
lines a rule was narrowed away from stay silent.

A rule that posts is a claim about real code, and the claim decays. A pattern edited to
remove a false positive can remove the true positive with it, and nothing else in the suite
would notice: the replay is not run in CI and a rule that has stopped matching produces no
failure, only silence. `benchmarks/tier2-precision/cases.json` turns that silence into a
failing test.

Every fixture is scanned in one scanner pass, because a pass costs a second and there are
ninety of them.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from opengrep_runner import RULES_DIR, load_rule_metadata, quarantined_rule_ids, run_opengrep

CASES_PATH = Path(__file__).resolve().parents[4] / "benchmarks" / "tier2-precision" / "cases.json"

# The coverage files. They are the rule set the benchmark is responsible for.
COVERAGE_FILES = ("javascript_coverage.yml", "python_coverage.yml", "template_coverage.yml")


def _coverage_rule_ids() -> list[str]:
    ids: list[str] = []
    for name in COVERAGE_FILES:
        document = yaml.safe_load((RULES_DIR / name).read_text(encoding="utf-8"))
        ids.extend(str(rule["id"]) for rule in document["rules"])
    return ids


COVERAGE_RULE_IDS = _coverage_rule_ids()


def _cases() -> list[dict]:
    document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    return list(document["cases"])


@pytest.fixture(scope="module")
def scan() -> dict[str, set[str]]:
    """Rule ids that fired, keyed by fixture path."""
    files = [
        {"path": case["path"], "content": case["code"], "patch": "", "reviewable_line_spans": []}
        for case in _cases()
    ]
    hits: dict[str, set[str]] = {case["path"]: set() for case in _cases()}
    for finding in run_opengrep(files):
        hits.setdefault(finding["file_path"], set()).add(finding["rule_id"])
    return hits


class TestCaseFile:
    def test_every_case_names_a_rule_that_exists(self):
        known = load_rule_metadata()
        for case in _cases():
            for rule in case.get("rules") or [case["rule"]]:
                assert f"opengrep.{rule}" in known, f"{case['id']} names an unknown rule"

    def test_every_posting_coverage_rule_has_a_true_positive_fixture(self):
        """A coverage rule that posts and that no fixture proves is a gap in the benchmark.

        The pre-existing rules in javascript.yml and python.yml are out of scope: they were
        in the tree before the coverage set, and their measurement is the replay.
        """
        covered = {case["rule"] for case in _cases() if case["expect"] == "finding"}
        quarantined = quarantined_rule_ids()
        missing = sorted(
            rule
            for rule in COVERAGE_RULE_IDS
            if f"opengrep.{rule}" not in quarantined and rule not in covered
        )
        assert not missing, f"posting rules with no true-positive fixture: {missing}"


class TestTruePositives:
    @pytest.mark.parametrize("case", [c for c in _cases() if c["expect"] == "finding"], ids=lambda c: c["id"])
    def test_rule_fires_on_its_fixture(self, case, scan):
        fired = scan[case["path"]]
        assert f"opengrep.{case['rule']}" in fired, (
            f"{case['rule']} did not fire on its own fixture; it fired: {sorted(fired) or 'nothing'}"
        )


class TestNoFindingLines:
    @pytest.mark.parametrize("case", [c for c in _cases() if c["expect"] == "no-finding"], ids=lambda c: c["id"])
    def test_narrowed_rule_stays_silent(self, case, scan):
        """A line the September 2026 replay raised a false positive on.

        The rule named here was narrowed because of this exact line. If it fires again the
        narrowing has been undone, and the rule's measured precision no longer describes it.
        """
        fired = scan[case["path"]]
        unwanted = sorted(f"opengrep.{rule}" for rule in case["rules"] if f"opengrep.{rule}" in fired)
        assert not unwanted, f"{case['id']}: {unwanted} fired on a line they were narrowed away from"
