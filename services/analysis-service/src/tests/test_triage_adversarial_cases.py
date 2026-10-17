"""The adversarial triage cases in `benchmarks/model-selection/triage/adversarial`.

Six authored files on which a rule fires but no input reaches the sink, and six hand-read true
corpus findings. The live question, whether a model confirms the first six, needs a provider
and is measured with `run_eval.py` (see docs/validation/triage-adversarial-2026-10.md). What
is checked here without one:

* the manifest is internally consistent, so `run_eval.py` accepts it;
* the real tiers still produce exactly the frozen finding for each authored file, so the
  cases keep testing what they say;
* a model that confirms every authored finding without an exploit payload, which is the
  failure the cases were written for, leaves none of the high or critical ones confirmed.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

import llm_triage
from llm_client import LLMResponse

CASES_DIR = Path(__file__).resolve().parents[4] / "benchmarks" / "model-selection" / "triage" / "adversarial"
MANIFEST = json.loads((CASES_DIR / "cases.json").read_text(encoding="utf-8"))
ADJUDICATIONS = Path(__file__).resolve().parents[4] / "benchmarks" / "vulnerable-corpus" / "adjudications.json"


def _builder():
    spec = importlib.util.spec_from_file_location("adversarial_build_inputs", CASES_DIR / "build_inputs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _authored_records():
    return [r for r in MANIFEST["findings"] if r["source"] == "adversarial-authored"]


def test_manifest_is_consistent():
    records = MANIFEST["findings"]
    assert MANIFEST["counts"] == {"findings": 12, "real": 6, "not_real": 6, "pull_requests": 12}
    assert len({r["pr_id"] for r in records}) == 12, "one finding per request"
    blob = json.dumps(
        [[r["id"], r["label"], r["input_sha256"]] for r in sorted(records, key=lambda r: r["id"])]
    ).encode("utf-8")
    assert MANIFEST["dataset_sha256"] == hashlib.sha256(blob).hexdigest()


def test_corpus_cases_are_hand_read_true():
    verdicts = {a["fingerprint"]: a["verdict"] for a in json.loads(ADJUDICATIONS.read_text())["adjudications"]}
    corpus = [r for r in MANIFEST["findings"] if r["source"] == "adversarial-corpus"]
    assert len(corpus) == 6
    for record in corpus:
        assert record["label"] == "real"
        assert verdicts.get(record["fingerprint"]) == "true", record["id"]


@pytest.fixture(scope="module")
def authored_inputs():
    builder = _builder()
    pull_requests = {}
    records = builder.build_authored(pull_requests)
    return records, pull_requests


def test_tiers_still_produce_the_frozen_authored_findings(authored_inputs):
    built, _ = authored_inputs
    frozen = {r["id"]: r for r in _authored_records()}
    assert {r["id"] for r in built} == set(frozen)
    for record in built:
        assert record["input_sha256"] == frozen[record["id"]]["input_sha256"], record["id"]


def _confirm_everything_without_payload(**kwargs):
    if "## Findings to triage" not in kwargs["user_prompt"]:
        return LLMResponse(text='{"counterexample": null, "behavior_risk": "none"}', input_tokens=1,
                           output_tokens=1, provider="fake", model="fake")
    contexts = json.loads(kwargs["user_prompt"].split("## Findings to triage\n\n", 1)[1])
    answer = [
        {
            "fingerprint": c["fingerprint"],
            "reachability": "The flagged call is a dangerous function.",
            "exploit_payload": {"entrypoint": "attacker input", "input": "malicious input", "expected_effect": "code runs"},
            "verdict": "true_positive",
            "reasoning": "Dangerous function.",
            "adjusted_severity": None,
            "adjusted_confidence": None,
            "exploit_scenario": None,
            "remediation": None,
            "fixed_code": None,
        }
        for c in contexts
    ]
    return LLMResponse(text=json.dumps(answer), input_tokens=10, output_tokens=10, provider="fake", model="fake")


def test_confirming_without_a_payload_confirms_no_high_or_critical_authored_case(authored_inputs):
    _, pull_requests = authored_inputs
    outcomes = {}
    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False), \
            patch.object(llm_triage, "call_llm", side_effect=_confirm_everything_without_payload):
        for pr_id, pr in pull_requests.items():
            [finding] = llm_triage.triage_findings(pr["findings"], pr["file_patches"])
            outcomes[pr_id] = (finding["severity"], finding["llm_triage"]["verdict"], finding["llm_triage"].get("downgrade"))

    for pr_id, (severity, verdict, downgrade) in outcomes.items():
        if severity in {"high", "critical"}:
            assert verdict == "uncertain", pr_id
            assert downgrade["reason"] == "no_concrete_payload", pr_id
        else:
            # The two redirect cases are medium, below the payload rule. They stay confirmed;
            # the write-up names this as the gap the live run has to size.
            assert severity == "medium" and verdict == "true_positive", pr_id
    assert sum(1 for severity, _, _ in outcomes.values() if severity in {"high", "critical"}) == 4
