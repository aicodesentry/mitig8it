"""Promotion decisions exercise sample size, statistical uncertainty, and evidence identity."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import benchmarks.rule_quality_gate as rule_gate_module
from benchmarks.quality_gate import precision_gate, wilson_interval
from benchmarks.rule_quality_gate import evaluate_evidence, evaluate_rules, load_rules
from benchmarks.remediation.evaluate import CaseResult, release_gate, summarize
from benchmarks.test_analysis_attestation import SyntheticAuthority, synthetic_evidence


ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64
EMPTY = {"schema_version": "v1", "rules": {}}
_AUTHORITY = None


@pytest.fixture(autouse=True)
def synthetic_review_trust_store(monkeypatch, tmp_path):
    authority = SyntheticAuthority(tmp_path / "analysis-trusted-reviewers.json")
    monkeypatch.setattr(sys.modules[__name__], "_AUTHORITY", authority)
    monkeypatch.setattr(rule_gate_module, "TRUST_STORE", authority.path)


def reviewed_evidence(total=100, false=0):
    return _AUTHORITY.sign({
        "rule_id": "new", "collection_provenance": synthetic_evidence()["collection_provenance"],
        "rule_digest": DIGEST, "corpus": "pinned-independent-replay-v1", "split": "holdout",
        "sampling_plan": "Frozen random PR sample; one finding per independent PR.",
        "observations": [{"id": f"finding-{number}", "sampling_unit": f"repository/pr/{number}",
                          "reviewer": "independent-reviewer", "source": f"pinned-source:{number}",
                          "verdict": "false" if number < false else "true"}
                         for number in range(total)],
    })


@pytest.mark.parametrize("successes,total,passed", [(0, 0, False), (20, 20, False), (99, 99, False),
                                                   (100, 100, True), (99, 100, False),
                                                   (190, 200, False), (199, 200, True)])
def test_precision_uses_sample_floor_and_confidence_bound(successes, total, passed):
    result = precision_gate(successes, total)
    assert result["passed"] is passed
    if total:
        assert result["precision"] == successes / total


def test_wilson_bound_matches_reference_value_without_rounding():
    assert wilson_interval(100, 100)[0] == pytest.approx(0.9630065017930143)
    assert wilson_interval(99, 100)[0] == pytest.approx(0.9455138038212947)
    assert wilson_interval(0, 0) == (None, None)


@pytest.mark.parametrize("successes,total", [(True, 100), (101, 100), (-1, 100), (1, 1.5), (0, -1)])
def test_invalid_counts_cannot_enter_statistical_gate(successes, total):
    with pytest.raises(ValueError):
        precision_gate(successes, total)


@pytest.mark.parametrize("kwargs", [{"minimum_samples": 99}, {"minimum_samples": True},
                                    {"precision_floor": 0.94}, {"precision_floor": float("nan")},
                                    {"precision_floor": float("inf")}, {"unresolved": -1}])
def test_callers_cannot_weaken_policy_or_pass_nonfinite_thresholds(kwargs):
    with pytest.raises(ValueError):
        precision_gate(100, 100, **kwargs)


def test_unresolved_judgments_block_otherwise_perfect_results():
    result = precision_gate(100, 100, unresolved=1)
    assert not result["passed"]
    assert "unresolved_adjudications:1" in result["reasons"]


def test_reviewed_holdout_evidence_can_promote_a_rule():
    assert evaluate_evidence(reviewed_evidence(), DIGEST)["passed"]


@pytest.mark.parametrize("field,value,reason", [
    ("rule_digest", "b" * 64, "different_rule_revision"), ("split", "train", "must_be_holdout"),
    ("split", "validation", "must_be_holdout"), ("corpus", "", "missing_corpus"),
    ("sampling_plan", "", "missing_sampling_plan"), ("observations", None, "missing_observations"),
])
def test_evidence_is_bound_to_frozen_holdout_and_exact_rule(field, value, reason):
    evidence = reviewed_evidence()
    evidence[field] = value
    with pytest.raises(ValueError, match=reason):
        evaluate_evidence(evidence, DIGEST)


@pytest.mark.parametrize("field", ["id", "sampling_unit"])
def test_repeated_findings_or_correlated_sampling_units_cannot_inflate_sample_size(field):
    evidence = reviewed_evidence()
    evidence["observations"][1][field] = evidence["observations"][0][field]
    with pytest.raises(ValueError, match="duplicate"):
        evaluate_evidence(evidence, DIGEST)


@pytest.mark.parametrize("field", ["id", "sampling_unit", "reviewer", "source", "verdict"])
def test_incomplete_observations_cannot_be_silently_discarded(field):
    evidence = reviewed_evidence()
    evidence["observations"][0].pop(field)
    with pytest.raises(ValueError):
        evaluate_evidence(evidence, DIGEST)


def test_uncertain_observations_are_reported_and_block_promotion():
    evidence = reviewed_evidence(101)
    evidence["observations"][0]["verdict"] = "uncertain"
    evidence = _AUTHORITY.sign(evidence)
    result = evaluate_evidence(evidence, DIGEST)
    assert result["reviewed_predictions"] == 100
    assert result["unresolved_predictions"] == 1
    assert not result["passed"]


def test_legacy_policy_preserves_behavior_without_claiming_validation():
    report = evaluate_rules({"legacy": {"posting": "post", "rule_digest": DIGEST}},
                            {"schema_version": "v1", "rules": {"legacy": DIGEST}}, EMPTY)
    assert report["passed"]
    assert report["rules"]["legacy"]["status"] == "legacy_unvalidated"
    assert report["counts"]["validated"] == 0


def test_new_changed_or_reenabled_rules_fail_closed_without_evidence():
    rules = {name: {"posting": "post", "rule_digest": DIGEST} for name in ("new", "changed", "reenabled")}
    legacy = {"schema_version": "v1", "rules": {"changed": "b" * 64}}
    report = evaluate_rules(rules, legacy, EMPTY)
    assert not report["passed"]
    assert report["counts"]["blocked"] == 3


def test_quarantine_remains_available_without_any_precision_claim():
    report = evaluate_rules({"new": {"posting": "quarantine", "rule_digest": DIGEST}}, EMPTY, EMPTY)
    assert report["passed"]
    assert report["rules"]["new"]["status"] == "quarantined"


def test_quarantining_or_changing_a_legacy_rule_retires_its_exception():
    legacy = {"schema_version": "v1", "rules": {"legacy": DIGEST}}
    rules = {"legacy": {"posting": "quarantine", "rule_digest": DIGEST}}
    report = evaluate_rules(rules, legacy, EMPTY)
    assert not report["passed"]
    assert "retire_stale_legacy_exception:legacy" in report["reasons"]
    assert evaluate_rules(rules, EMPTY, EMPTY)["passed"]
    rules["legacy"]["posting"] = "post"
    assert not evaluate_rules(rules, EMPTY, EMPTY)["passed"], "Re-enabling now requires evidence"


@pytest.mark.parametrize("document", [[], None, {}, {"schema_version": "v1", "rules": []}])
def test_malformed_policy_inputs_are_rejected_explicitly(document):
    with pytest.raises(ValueError):
        evaluate_rules({}, document, EMPTY)
    with pytest.raises(ValueError):
        evaluate_rules({}, EMPTY, document)


def test_missing_posting_policy_cannot_publish():
    assert not evaluate_rules({"new": {"rule_digest": DIGEST}}, EMPTY, EMPTY)["passed"]
    assert not evaluate_rules({}, EMPTY, EMPTY)["passed"]


def test_passing_evidence_is_actually_used_by_publication_check():
    evidence = {"schema_version": "v1", "rules": {"new": reviewed_evidence()}}
    rules = {"new": {"posting": "post", "rule_digest": DIGEST}}
    assert evaluate_rules(rules, EMPTY, evidence)["counts"]["validated"] == 1
    evidence["rules"]["new"]["observations"][0]["verdict"] = "false"
    assert not evaluate_rules(rules, EMPTY, evidence)["passed"]


@pytest.mark.parametrize("change", ["unsigned", "false_identity", "false_population", "missing_identity", "missing_population"])
def test_statistically_perfect_unauthenticated_candidates_cannot_be_validated(change):
    evidence = reviewed_evidence()
    if change == "unsigned": evidence.pop("attestation")
    elif change == "false_identity": evidence["collection_provenance"]["review_identity_authenticated"] = False
    elif change == "false_population": evidence["collection_provenance"]["population_sampling_verified"] = False
    elif change == "missing_identity": evidence["collection_provenance"].pop("review_identity_authenticated")
    elif change == "missing_population": evidence["collection_provenance"].pop("population_sampling_verified")
    report = evaluate_rules({"new": {"posting": "post", "rule_digest": DIGEST}}, EMPTY,
                            {"schema_version": "v1", "rules": {"new": evidence}})
    assert not report["passed"]
    assert report["counts"]["validated"] == 0
    assert report["rules"]["new"]["status"] == "blocked"


def test_current_inventory_runs_offline_and_marks_legacy_exceptions_explicitly():
    completed = subprocess.run([sys.executable, "-m", "benchmarks.rule_quality_gate"], cwd=ROOT,
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr + completed.stdout
    report = json.loads(completed.stdout)
    assert report["counts"]["legacy_unvalidated"] > 0
    assert report["counts"]["validated"] == 0
    assert report["counts"]["quarantined"] > 0
    assert set(report["rules"]) == set(load_rules())


def test_cli_exits_nonzero_for_a_new_postable_rule_without_evidence(monkeypatch, capsys):
    monkeypatch.setattr(rule_gate_module, "load_rules", lambda: {
        "unreviewed.new.rule": {"posting": "post", "rule_digest": DIGEST},
    })
    monkeypatch.setattr(sys, "argv", ["rule_quality_gate"])
    assert rule_gate_module.main() == 2
    report = json.loads(capsys.readouterr().out)
    assert not report["passed"]
    assert report["rules"]["unreviewed.new.rule"]["status"] == "blocked"


def test_cli_fails_closed_with_machine_readable_reason_on_invalid_inputs(monkeypatch, capsys):
    def invalid_rules():
        raise ValueError("invalid rule file")
    monkeypatch.setattr(rule_gate_module, "load_rules", invalid_rules)
    monkeypatch.setattr(sys, "argv", ["rule_quality_gate"])
    assert rule_gate_module.main() == 2
    assert "invalid_quality_inputs:invalid rule file" in json.loads(capsys.readouterr().out)["reasons"]


def case(number, *, kind="supported", state="ready", outcome="passed", split="holdout"):
    return CaseResult(f"case-{number}", f"repo-{number}", split, "sql_parameterization", kind,
                      "ready" if kind == "supported" else "unsupported", state, outcome,
                      None, None, {}, 0)


def test_unsafe_ready_negative_counts_against_precision():
    results = [case(1), case(2, kind="negative", outcome="failed")]
    assert summarize(results)["precision"] == 0.5
    report = release_gate([], results)
    assert report["precision_gate"]["precision"] == 0.5


def test_release_does_not_use_train_or_validation_to_meet_holdout_sample_minimum():
    results = [case(number, split="train") for number in range(100)]
    report = release_gate([], results)
    assert report["precision_gate"]["reviewed_predictions"] == 0
    assert not report["precision_gate"]["passed"]


def test_release_requires_complete_unique_results_even_when_precision_passes():
    results = [case(number) for number in range(100)]
    fixtures = [(ROOT, {"id": result.fixture_id, "kind": result.kind, "family": result.family,
                        "repository_id": result.repository_id, "split": result.split})
                for result in results]
    assert release_gate(fixtures, results)["precision_gate"]["passed"]
    duplicate = results + [copy.copy(results[0])]
    assert "fixture_results_missing_duplicate_or_unexpected" in release_gate(fixtures, duplicate)["reasons"]
    assert "fixture_results_missing_duplicate_or_unexpected" in release_gate(fixtures, results[:-1])["reasons"]
    assert not release_gate(fixtures, results)["passed"], "The external review/isolation gate stays closed"


def test_release_and_ci_execute_quality_gate_before_publication():
    release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    steps = release["jobs"]["release"]["steps"]
    gate = next(index for index, step in enumerate(steps) if "python3 -m benchmarks.rule_quality_gate" in step.get("run", ""))
    push = next(index for index, step in enumerate(steps) if step.get("name") == "Push the image and record its digest")
    assert gate < push
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert any("-m benchmarks.rule_quality_gate" in step.get("run", "")
               for job in ci["jobs"].values() for step in job["steps"])
