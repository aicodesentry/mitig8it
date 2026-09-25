"""The tier 1 precision gate.

`benchmarks/tier1-precision/cases.json` holds every line the September 2026
real-repository replay read by hand and judged wrong, plus one true positive per rule
family drawn from `tests/test_security_rules.py`. A rule change that makes a false
positive post again, or that stops a true positive being found, fails here.
"""

import json
from pathlib import Path

import pytest

from main import (
    AnalyzePRRequest,
    QUARANTINED_RULE_IDS,
    analyze_tier1_payload,
    rule_scan_options,
)
from finding_quality import pattern_matches_reviewable_content
from security_rules import SECURITY_RULES

BENCHMARK_DIR = Path(__file__).resolve().parents[4] / "benchmarks" / "tier1-precision"
CASES = json.loads((BENCHMARK_DIR / "cases.json").read_text())

FALSE_POSITIVES = CASES["false_positives"]
TRUE_POSITIVES = CASES["true_positives"]


def _patch(snippet):
    return "@@ -1,%d +1,%d @@\n" % (len(snippet), len(snippet)) + "".join(
        f"+{line}\n" for line in snippet
    )


def _tier1(case):
    payload = AnalyzePRRequest(
        repository_full_name="acme/app",
        pull_request_number=1,
        commit_sha="a" * 40,
        files=[{"path": case["path"], "patch": _patch(case["snippet"])}],
    )
    return analyze_tier1_payload(payload)


def _rule(rule_id):
    return next(rule for rule in SECURITY_RULES if rule.rule_id == rule_id)


def _rule_still_matches(case):
    rule = _rule(case["rule_id"])
    return pattern_matches_reviewable_content(
        _patch(case["snippet"]), rule.pattern, **rule_scan_options(rule, case["path"])
    )


def _ids(cases):
    return [case["id"] for case in cases]


class TestSetIntegrity:
    def test_the_set_is_the_size_the_report_supports(self):
        assert len(FALSE_POSITIVES) == 18
        assert len(TRUE_POSITIVES) == 20

    def test_every_case_is_well_formed(self):
        for case in FALSE_POSITIVES + TRUE_POSITIVES:
            assert case["expected"] in ("no_finding", "finding"), case["id"]
            assert case["language"] and case["path"] and case["snippet"]
            assert any(rule.rule_id == case["rule_id"] for rule in SECURITY_RULES), case["rule_id"]

    def test_case_ids_are_unique(self):
        ids = _ids(FALSE_POSITIVES + TRUE_POSITIVES)
        assert len(ids) == len(set(ids))

    def test_every_false_positive_names_what_suppresses_it(self):
        allowed = set(CASES["suppressed_by_values"])
        for case in FALSE_POSITIVES:
            if "known_gap" in case:
                continue
            assert case["suppressed_by"] in allowed, case["id"]


class TestNoQuarantinedRulePosts:
    @pytest.mark.parametrize("case", FALSE_POSITIVES + TRUE_POSITIVES, ids=_ids(FALSE_POSITIVES + TRUE_POSITIVES))
    def test_no_posted_finding_comes_from_a_quarantined_rule(self, case):
        posted = {finding["rule_id"] for finding in _tier1(case)["findings"]}
        assert not (posted & QUARANTINED_RULE_IDS), sorted(posted & QUARANTINED_RULE_IDS)


class TestFalsePositivesDoNotPost:
    @pytest.mark.parametrize(
        "case",
        [case for case in FALSE_POSITIVES if "known_gap" not in case],
        ids=_ids([case for case in FALSE_POSITIVES if "known_gap" not in case]),
    )
    def test_the_case_produces_no_posted_finding_for_its_rule(self, case):
        posted = [finding["rule_id"] for finding in _tier1(case)["findings"]]
        assert case["rule_id"] not in posted

    @pytest.mark.parametrize(
        "case",
        [case for case in FALSE_POSITIVES if case.get("suppressed_by") in ("word_boundary", "exclusion", "comment_stripping")],
        ids=_ids([case for case in FALSE_POSITIVES if case.get("suppressed_by") in ("word_boundary", "exclusion", "comment_stripping")]),
    )
    def test_the_rule_itself_no_longer_matches(self, case):
        """Proof for the mechanically fixed rules: the quarantine is not what saves these."""
        assert not _rule_still_matches(case), case["id"]


class TestKnownGaps:
    @pytest.mark.parametrize(
        "case",
        [case for case in FALSE_POSITIVES if "known_gap" in case],
        ids=_ids([case for case in FALSE_POSITIVES if "known_gap" in case]),
    )
    def test_a_known_gap_is_still_open(self, case):
        """A recorded gap must stay recorded until it closes, then lose its marker.

        This asserts the failure, so the day the gap closes this test fails and the
        `known_gap` key has to come out of the case.
        """
        posted = [finding["rule_id"] for finding in _tier1(case)["findings"]]
        assert case["rule_id"] in posted, (
            f"{case['id']} no longer reproduces: remove its `known_gap` key"
        )


class TestTruePositivesStillFire:
    @pytest.mark.parametrize("case", TRUE_POSITIVES, ids=_ids(TRUE_POSITIVES))
    def test_the_case_still_produces_its_finding(self, case):
        """The rule still recognizes its true positive.

        A quarantined rule is withheld, not removed: its finding is counted rather than
        posted. Asserting the count for those keeps the evidence that the rule still works,
        which is what would justify re-enabling it, without asserting a posting the policy
        has deliberately taken away.
        """
        result = _tier1(case)
        if case["rule_id"] in QUARANTINED_RULE_IDS:
            assert result["quarantined_findings"].get(case["rule_id"], 0) >= 1, (
                f"{case['id']} no longer fires at all, so the quarantine measurement "
                "has stopped describing the rule"
            )
            return
        posted = [finding["rule_id"] for finding in result["findings"]]
        assert case["rule_id"] in posted, posted

    def test_the_true_positive_set_covers_every_posting_rule_family(self):
        covered = {case["rule_id"] for case in TRUE_POSITIVES}
        posting = {rule.rule_id for rule in SECURITY_RULES if rule.posting == "post"}
        uncovered = posting - covered
        # Rules with no true-positive case here are the ones no replay evidence touched.
        # Keep the list explicit so adding a rule forces a decision about its case.
        assert uncovered == {
            "deserialize.untrusted_data",
            "llm.prompt.injection",
            "logging.sensitive_data",
            "memory.buffer_overflow",
            "memory.format_string",
            "race.toctou",
            "redirect.open",
            "session.insecure_cookie",
            "ssrf.untrusted_url_fetch",
            "xxe.xml_parsing",
        }, sorted(uncovered)
