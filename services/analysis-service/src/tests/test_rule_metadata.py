"""Rule metadata and the shape check that keeps a broken exclusion from coming back.

A negative lookahead placed after an unbounded greedy quantifier excludes nothing: the
engine satisfies it by letting the quantifier run to the end of the line. The repository
found this once, in `auth.bypass.missing_check`, and four sibling rules kept the shape.
`find_ineffective_lookaheads` is the static check that stops it happening a third time.
"""

import re

import pytest

from security_rules import (
    POSTING_POST,
    POSTING_QUARANTINE,
    PRECISION_MEASURED,
    PRECISION_UNMEASURED,
    SECURITY_RULES,
    SecurityRule,
    find_ineffective_lookaheads,
    tier1_patterns,
)

EXPECTED_QUARANTINE = {
    "null.pointer.deref",
    "integer.overflow",
    "rate_limit.missing",
    "authz.missing_function_level",
    "concurrency.shared_state",
}


def _find(rule_id):
    return next(rule for rule in SECURITY_RULES if rule.rule_id == rule_id)


def _quarantined():
    return {rule.rule_id for rule in SECURITY_RULES if rule.posting == POSTING_QUARANTINE}


class TestRuleMetadata:
    def test_every_rule_declares_a_known_precision_and_posting(self):
        for rule in SECURITY_RULES:
            assert rule.precision in (PRECISION_MEASURED, PRECISION_UNMEASURED), rule.rule_id
            assert rule.posting in (POSTING_POST, POSTING_QUARANTINE), rule.rule_id

    def test_quarantine_is_exactly_the_measured_set(self):
        assert _quarantined() == EXPECTED_QUARANTINE

    def test_every_quarantined_rule_cites_its_evidence(self):
        for rule_id in EXPECTED_QUARANTINE:
            rule = _find(rule_id)
            assert rule.precision == PRECISION_MEASURED
            assert len(rule.precision_evidence) > 60, rule_id

    def test_a_posting_rule_never_claims_evidence_it_does_not_have(self):
        for rule in SECURITY_RULES:
            if rule.posting == POSTING_POST and rule.precision == PRECISION_UNMEASURED:
                assert rule.precision_evidence == "", rule.rule_id

    def test_the_credential_rule_keeps_reading_string_literals(self):
        # Secrets live in strings, so this rule must never have their bodies blanked.
        assert _find("secret.hardcoded.credential").reads_string_literals is True


class TestIneffectiveLookaheadCheck:
    def test_no_tier1_pattern_carries_the_shape_any_more(self):
        assert find_ineffective_lookaheads() == []

    def test_the_check_covers_every_pattern_tier1_runs(self):
        ids = {rule_id for rule_id, _pattern in tier1_patterns()}
        assert {rule.rule_id for rule in SECURITY_RULES} <= ids
        assert any(rule_id.startswith("dependency.risk.version[") for rule_id in ids)
        assert any(rule_id.endswith(".exclusion") for rule_id in ids)

    @pytest.mark.parametrize("source", [
        # The four shapes the replay found, as they stood before this change.
        r"(\.destroy\(|\.remove\().*(?!@login_required|@auth)",
        r"(parseInt|int\().*(?!isNaN|isFinite)",
        r"\.\w+\s*\(.*\)\s*\.\w+\s*(?!\?\.|&&)",
        r"(global\s+\w+|threading\.Thread).*(?!lock|mutex)",
        # And the shape hiding one group deeper.
        r"(?:a.*(?!b))c",
    ])
    def test_the_shape_is_detected_wherever_it_reappears(self, source):
        assert find_ineffective_lookaheads([_synthetic(source)]), source

    @pytest.mark.parametrize("source", [
        # The repaired shape: the lookahead is anchored at the start of the line.
        r"^(?!.*(?:auth|jwt))\.destroy\(",
        # A required token between the greedy quantifier and the lookahead anchors it.
        r"lodash.*4\.17\.(?:1\d|20|[0-9])(?!\d)",
        # A lazy quantifier cannot give characters back to satisfy the lookahead.
        r"(int\().*?(?!isNaN)",
        # No quantifier at all.
        r"(?<![.\w$])exec\s*\((?!\s*[`])",
    ])
    def test_anchored_lookaheads_are_not_flagged(self, source):
        assert find_ineffective_lookaheads([_synthetic(source)]) == []

    def test_every_rule_with_the_shape_would_be_quarantined(self):
        flagged = {rule_id for rule_id, _ in find_ineffective_lookaheads()}
        assert flagged <= _quarantined()


class TestRelocatedExclusions:
    """The exclusion pass does what the lookahead was written to do and could not."""

    @pytest.mark.parametrize("rule_id, line", [
        ("null.pointer.deref", "if (encoding === undefined || encoding.toLowerCase().replace('-', '') === 'utf8') {"),
        ("null.pointer.deref", "const name = user?.profile.getName().trim();"),
        ("integer.overflow", "const n = parseInt(raw, 10); if (isNaN(n)) return;"),
        ("rate_limit.missing", "app.post('/login', rateLimiter, handleLogin)"),
        ("authz.missing_function_level", "@login_required\ndef delete_user(request):"),
        ("concurrency.shared_state", "with lock: global counter"),
    ])
    def test_the_excluded_line_is_dropped(self, rule_id, line):
        rule = _find(rule_id)
        assert rule.exclusion is not None
        assert rule.pattern.search(line), "the pattern is expected to match before exclusion"
        assert rule.exclusion.search(line), line

    @pytest.mark.parametrize("rule_id, line", [
        ("integer.overflow", "        models.UniqueConstraint(fields=['category'], name='unique_slug')"),
        ("integer.overflow", "function fingerprint(snapshot: Snapshot): string {"),
    ])
    def test_the_word_boundary_stops_the_pattern_itself(self, rule_id, line):
        assert not _find(rule_id).pattern.search(line), line


def _synthetic(source):
    return SecurityRule(
        rule_id="synthetic",
        title="synthetic",
        category="synthetic",
        cwe_id="CWE-1",
        owasp_category="A01:2021",
        severity="medium",
        confidence=0.5,
        exploitability="low",
        pattern=re.compile(source),
        description="",
        remediation="",
    )
