"""Per-rule precision: the corpus prior, the live outcomes, and the confidence a finding carries.

docs/validation/fix-placement-and-calibration-2026-10.md states the formula and works one
example by hand; the numbers asserted here are that example.
"""
import pytest

import rule_precision
from analysis_grpc_server import _triage_request_from_proto, analysis_pb2
from google.protobuf import struct_pb2
from llm_triage import _build_finding_context, _evidence_strength
from main import TriageRequest, triage_findings_payload
from rule_precision import (
    BASIS_MEASURED,
    BASIS_STATIC_PRIOR,
    MINIMUM_OUTCOMES,
    apply_rule_stats,
    calibrate,
    parse_precision_evidence,
    wilson_lower_bound,
)

CONFIG_KEY = "opengrep.cwe-798.js-credential-config-key"


class TestWilsonLowerBound:
    def test_the_worked_example(self):
        assert wilson_lower_bound(21, 25) == pytest.approx(0.6535, abs=1e-4)

    def test_values_shared_with_the_api_service(self):
        # services/api-service/tests/qualityMetrics.test.js asserts the same four values.
        assert wilson_lower_bound(20, 20) == pytest.approx(0.8389, abs=1e-4)
        assert wilson_lower_bound(0, 20) == 0
        assert wilson_lower_bound(3, 3) == pytest.approx(0.4385, abs=1e-4)

    def test_no_trials_is_no_answer(self):
        assert wilson_lower_bound(0, 0) is None


class TestParsePrecisionEvidence:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("86 findings over 23 repositories, 7 adjudicated, 3 true and 4 false, precision 0.43.", (3, 7)),
            ("7 findings over 3 repositories, 3 adjudicated by label, all true (NodeGoat), precision 1.00.", (3, 3)),
            ("2 findings over 2 repositories, both adjudicated by label and true, precision 1.00.", (2, 2)),
            ("1 finding, adjudicated by label and true (dvna's `secure: false` session cookie), precision 1.00.", (1, 1)),
            ("3 findings in pygoat, 1 hand-read and true, precision 1.00.", (1, 1)),
            ("8 findings, all 8 hand-read. 4 true (dvna's two listings) and 4 false, every false one a partial.", (4, 8)),
            ("46 findings, a seeded random 10 read by hand, 10 true and 0 false.", (10, 10)),
        ],
    )
    def test_the_phrasings_the_rule_files_use(self, text, expected):
        assert parse_precision_evidence(text) == expected

    @pytest.mark.parametrize(
        "text",
        [
            "",
            None,
            "Sept 2026 replay: 85 of 134 findings (63%), and all 19 sampled by hand were wrong.",
            "zero findings over 240 workflow files from 27 repositories.",
            "Sept 2026 replay: 2 findings, both wrong.",
        ],
    )
    def test_a_line_without_a_count_is_not_guessed_at(self, text):
        assert parse_precision_evidence(text) is None

    def test_every_rule_file_is_read_and_the_quarantined_rule_keeps_its_measurement(self):
        priors = rule_precision.rule_priors()
        assert priors["path.traversal.user_path"]["evidence"] == (3, 7)
        assert priors[CONFIG_KEY]["evidence"] == (3, 3)
        assert priors[CONFIG_KEY]["static_confidence"] == pytest.approx(0.8)


class TestCalibrate:
    def test_below_the_minimum_the_static_constant_stays_and_says_it_is_a_prior(self):
        result = calibrate(CONFIG_KEY, 0.8, {"positive": 15, "negative": 4})
        assert result["basis"] == BASIS_STATIC_PRIOR
        assert result["precision"] == 0.8
        assert result["outcomes"] == 19
        assert result["minimum_outcomes"] == MINIMUM_OUTCOMES == 20

    def test_the_worked_example_pools_the_corpus_with_the_outcomes(self):
        # 3 of 3 in the corpus, 18 positive and 4 negative live: 21 of 25, lower bound 0.65.
        result = calibrate(CONFIG_KEY, 0.8, {"positive": 18, "negative": 4})
        assert result["basis"] == BASIS_MEASURED
        assert (result["prior_true"], result["prior_adjudicated"]) == (3, 3)
        assert result["precision"] == 0.65

    def test_a_rule_with_no_corpus_count_is_measured_on_outcomes_alone(self):
        result = calibrate("opengrep.not-a-rule", 0.9, {"positive": 20, "negative": 0})
        assert (result["prior_true"], result["prior_adjudicated"]) == (0, 0)
        assert result["precision"] == 0.84

    def test_counts_that_arrive_as_struct_floats_or_garbage_are_read_safely(self):
        assert calibrate(CONFIG_KEY, 0.8, {"positive": 18.0, "negative": "4"})["outcomes"] == 22
        assert calibrate(CONFIG_KEY, 0.8, {"positive": -3, "negative": "x"})["outcomes"] == 0
        assert calibrate(CONFIG_KEY, 0.8, None)["basis"] == BASIS_STATIC_PRIOR


def _finding(rule_id=CONFIG_KEY, confidence=0.8, scope="ast-pattern"):
    return {
        "rule_id": rule_id,
        "confidence": confidence,
        "analysis_scope": scope,
        "evidence_details": {"analysis_scope": scope, "extra": {"workflow": "kept"}},
        "fingerprint": "fp",
        "file_path": "config.js",
        "line_start": 3,
        "severity": "high",
        "category": "hardcoded secrets",
    }


class TestApplyRuleStats:
    def test_without_a_rules_key_nothing_is_touched(self):
        findings = [_finding()]
        assert apply_rule_stats(findings, {}) is findings
        assert apply_rule_stats(findings, {"minimum_outcomes": 20}) is findings

    def test_a_measured_rule_records_its_precision_and_keeps_the_existing_extra(self):
        [finding] = apply_rule_stats(
            [_finding()], {"minimum_outcomes": 20, "rules": {CONFIG_KEY: {"positive": 18, "negative": 4}}}
        )
        extra = finding["evidence_details"]["extra"]
        assert extra["workflow"] == "kept"
        assert extra["rule_precision"]["basis"] == BASIS_MEASURED
        assert extra["rule_precision"]["precision"] == 0.65

    def test_confidence_is_left_for_the_inline_gate(self):
        """A perfect record of 20 bounds at 0.84, under the 0.85 AST gate: replacing confidence
        would silence a rule for being new, not for being wrong."""
        [finding] = apply_rule_stats(
            [_finding(rule_id="opengrep.not-a-rule", confidence=0.88)],
            {"minimum_outcomes": 20, "rules": {"opengrep.not-a-rule": {"positive": 20, "negative": 0}}},
        )
        assert finding["confidence"] == 0.88
        assert finding["evidence_details"]["extra"]["rule_precision"]["precision"] == 0.84

    def test_a_rule_on_its_prior_keeps_its_confidence_and_says_so(self):
        [finding] = apply_rule_stats([_finding()], {"minimum_outcomes": 20, "rules": {}})
        assert finding["confidence"] == 0.8
        assert finding["evidence_details"]["extra"]["rule_precision"]["basis"] == BASIS_STATIC_PRIOR


class TestEvidenceStrength:
    def _with(self, precision, scope="ast-pattern"):
        finding = _finding(scope=scope)
        finding["evidence_details"]["extra"]["rule_precision"] = precision
        return finding

    def test_a_static_prior_does_not_move_it(self):
        assert _evidence_strength(self._with({"basis": BASIS_STATIC_PRIOR, "precision": 0.99})) == "medium"

    def test_a_measured_precision_of_at_least_080_raises_it_one_step(self):
        assert _evidence_strength(self._with({"basis": BASIS_MEASURED, "precision": 0.84})) == "strong"
        assert _evidence_strength(self._with({"basis": BASIS_MEASURED, "precision": 0.84}, "pattern")) == "medium"
        assert _evidence_strength(self._with({"basis": BASIS_MEASURED, "precision": 0.9}, "taint-intraprocedural")) == "strong"

    def test_a_measured_precision_below_050_makes_it_light_whatever_the_scope(self):
        assert _evidence_strength(self._with({"basis": BASIS_MEASURED, "precision": 0.43}, "taint-intraprocedural")) == "light"

    def test_between_the_two_thresholds_the_scope_decides(self):
        assert _evidence_strength(self._with({"basis": BASIS_MEASURED, "precision": 0.65})) == "medium"

    def test_triage_sees_the_basis_beside_the_confidence(self):
        finding = self._with({"basis": BASIS_MEASURED, "precision": 0.65, "outcomes": 22})
        context = _build_finding_context(finding, {})
        assert context["rule_precision"]["outcomes"] == 22
        assert context["evidence_strength"] == "medium"


class TestThroughTheService:
    def test_the_triage_endpoint_calibrates_without_a_model(self, monkeypatch):
        import llm_triage

        monkeypatch.setattr(llm_triage, "is_llm_triage_enabled", lambda: False)
        payload = TriageRequest(
            repository_full_name="acme/app",
            pull_request_number=1,
            commit_sha="a" * 40,
            findings=[_finding()],
            rule_stats={"minimum_outcomes": 20, "rules": {CONFIG_KEY: {"positive": 18, "negative": 4}}},
        )
        [finding] = triage_findings_payload(payload)["findings"]
        assert finding["confidence"] == 0.8
        assert finding["evidence_details"]["extra"]["rule_precision"]["basis"] == BASIS_MEASURED
        assert finding["evidence_details"]["extra"]["rule_precision"]["precision"] == 0.65

    def test_rule_stats_survive_the_grpc_request(self):
        stats = struct_pb2.Struct()
        stats.update({"minimum_outcomes": 20, "rules": {CONFIG_KEY: {"positive": 18, "negative": 4}}})
        request = analysis_pb2.TriageFindingsRequest(
            repository_full_name="acme/app", pull_request_number=1, commit_sha="a" * 40, rule_stats=stats
        )
        decoded = analysis_pb2.TriageFindingsRequest.FromString(request.SerializeToString())
        parsed = _triage_request_from_proto(decoded)
        assert parsed.rule_stats["rules"][CONFIG_KEY] == {"positive": 18.0, "negative": 4.0}

    def test_a_request_without_rule_stats_carries_none(self):
        request = analysis_pb2.TriageFindingsRequest(
            repository_full_name="acme/app", pull_request_number=1, commit_sha="a" * 40
        )
        decoded = analysis_pb2.TriageFindingsRequest.FromString(request.SerializeToString())
        assert _triage_request_from_proto(decoded).rule_stats == {}
