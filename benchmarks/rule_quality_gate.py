"""Offline release check for new, changed, or re-enabled analysis rules.

The legacy snapshot preserves existing posting behavior, without asserting its
quality. Anything outside that exact snapshot must carry reviewed holdout evidence.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from benchmarks.quality_gate import precision_gate
from benchmarks.analysis_attestation import TRUST_STORE, read_json, verify_attestation


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "benchmarks" / "rule-quality"
SOURCE = ROOT / "services" / "analysis-service" / "src"
RUNTIME_POLICY = SOURCE / "publication-policy.json"
sys.path.insert(0, str(SOURCE))
try:
    from rule_publication import current_rules as load_rules, digest
finally:
    sys.path.remove(str(SOURCE))


def evaluate_precision_evidence(evidence: Any, rule_digest: str) -> dict[str, Any]:
    """Structural/statistical diagnostic only; cannot authorize publication."""
    if not isinstance(evidence, dict) or evidence.get("rule_digest") != rule_digest:
        raise ValueError("evidence_missing_or_for_different_rule_revision")
    for field in ("corpus", "sampling_plan"):
        if not isinstance(evidence.get(field), str) or not evidence[field].strip():
            raise ValueError(f"evidence_missing_{field}")
    if evidence.get("split") != "holdout":
        raise ValueError("evidence_must_be_holdout")
    observations = evidence.get("observations")
    if not isinstance(observations, list):
        raise ValueError("evidence_missing_observations")
    seen_ids, seen_units = set(), set()
    successes = failures = unresolved = 0
    for observation in observations:
        if not isinstance(observation, dict):
            raise ValueError("invalid_observation")
        for field in ("id", "sampling_unit", "reviewer", "source"):
            if not isinstance(observation.get(field), str) or not observation[field].strip():
                raise ValueError(f"observation_missing_{field}")
        if observation["id"] in seen_ids or observation["sampling_unit"] in seen_units:
            raise ValueError("duplicate_observation_or_sampling_unit")
        seen_ids.add(observation["id"])
        seen_units.add(observation["sampling_unit"])
        verdict = observation.get("verdict")
        if verdict == "true":
            successes += 1
        elif verdict == "false":
            failures += 1
        elif verdict == "uncertain":
            unresolved += 1
        else:
            raise ValueError("invalid_observation_verdict")
    return precision_gate(successes, successes + failures, unresolved=unresolved)


def evaluate_evidence(evidence: Any, rule_digest: str, *, rule_id: str | None = None,
                      trust_store_path: Path | None = None) -> dict[str, Any]:
    statistics = evaluate_precision_evidence(evidence, rule_digest)
    # Neither caller-supplied true flags nor a reviewer string establish trust.
    # Authenticate the entire candidate against the local purpose-specific store.
    authentication = verify_attestation(evidence, rule_id or evidence.get("rule_id"), rule_digest,
                                        trust_store_path=trust_store_path or TRUST_STORE)
    return {**statistics, "authentication": authentication}


def evaluate_rules(rules: dict, legacy: dict, evidence: dict) -> dict[str, Any]:
    if not isinstance(legacy, dict) or legacy.get("schema_version") != "v1" or not isinstance(legacy.get("rules"), dict):
        raise ValueError("invalid_legacy_inventory")
    if not isinstance(evidence, dict) or evidence.get("schema_version") != "v1" or not isinstance(evidence.get("rules"), dict):
        raise ValueError("invalid_evidence_document")
    # Retire an exception as soon as its rule changes or is quarantined. Otherwise
    # restoring the old ID/definition later could bypass the promotion requirement.
    retired = sorted(rule_id for rule_id, fingerprint in legacy["rules"].items()
                     if rules.get(rule_id, {}).get("posting") != "post"
                     or rules[rule_id].get("rule_digest") != fingerprint)
    reasons = [f"retire_stale_legacy_exception:{rule_id}" for rule_id in retired]
    results = {}
    for rule_id, rule in sorted(rules.items()):
        if rule.get("posting") == "quarantine":
            results[rule_id] = {"status": "quarantined", "passed": True}
        elif rule.get("posting") != "post":
            results[rule_id] = {"status": "blocked", "passed": False, "reasons": ["invalid_posting_policy"]}
        elif legacy["rules"].get(rule_id) == rule["rule_digest"]:
            results[rule_id] = {"status": "legacy_unvalidated", "passed": True}
        else:
            try:
                result = evaluate_evidence(evidence["rules"].get(rule_id), rule["rule_digest"], rule_id=rule_id)
                results[rule_id] = {"status": "validated" if result["passed"] else "blocked", **result}
            except ValueError as error:
                results[rule_id] = {"status": "blocked", "passed": False, "reasons": [str(error)]}
    return {"passed": not reasons and all(rule["passed"] for rule in results.values()) and bool(results),
            "reasons": reasons,
            "counts": {status: sum(item["status"] == status for item in results.values())
                       for status in ("quarantined", "legacy_unvalidated", "validated", "blocked")},
            "rules": results}


def runtime_policy(rules: dict, report: dict) -> dict:
    return {"schema_version": "v1", "remediation_release_verified": False, "rules": {
        rule_id: {"rule_digest": rules[rule_id]["rule_digest"], "status": result["status"]}
        for rule_id, result in report["rules"].items()
        if result["passed"] and result["status"] in {"validated", "legacy_unvalidated"}
    }}


def run_gate(*, check_runtime_policy: bool = True) -> dict:
    rules = load_rules()
    report = evaluate_rules(rules, read_json(POLICY / "legacy-posting.json"), read_json(POLICY / "evidence.json"))
    if check_runtime_policy:
        try:
            matches = json.loads(RUNTIME_POLICY.read_text()) == runtime_policy(rules, report)
        except (OSError, ValueError):
            matches = False
        if not matches:
            report["passed"] = False
            report["reasons"].append("packaged_runtime_publication_policy_missing_or_stale")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--refresh-runtime-policy", action="store_true",
                        help="Regenerate the packaged allowlist only after promotion evidence passes")
    args = parser.parse_args()
    try:
        report = run_gate(check_runtime_policy=not args.refresh_runtime_policy)
        if args.refresh_runtime_policy and report["passed"]:
            RUNTIME_POLICY.write_text(json.dumps(runtime_policy(load_rules(), report), indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as error:
        report = {"passed": False, "reasons": [f"invalid_quality_inputs:{error}"]}
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
