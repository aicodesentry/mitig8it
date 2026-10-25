"""Offline production readiness. Reporting compatibility never establishes readiness."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import yaml

from benchmarks.rule_quality_gate import ROOT, run_gate
from benchmarks.remediation import release_evidence


RELEASE_ARTIFACT = {
    "schema_version": "v1",
    "remediation_release_verified": False,
    "reason": "trusted_external_review_evidence_missing",
}
RELEASE_ARTIFACT_PATHS = (
    ROOT / "services/github-service/src/quality-release.json",
    ROOT / "services/api-service/src/quality-release.json",
)


def assess_readiness(rule_report: dict, *, component: str = "all", artifacts_match: bool = True,
                     remediation_report: dict | None = None) -> dict:
    counts = rule_report.get("counts", {})
    analysis_reasons = list(rule_report.get("reasons", []))
    if not rule_report.get("passed"):
        analysis_reasons.append("rule_promotion_gate_failed")
    if counts.get("legacy_unvalidated", 0):
        analysis_reasons.append(f"legacy_rule_evidence_missing:{counts['legacy_unvalidated']}")
    if not counts.get("validated", 0):
        analysis_reasons.append("no_statistically_validated_posting_rules")
    remediation_report = remediation_report or {"passed": False, "reasons": ["independent_production_release_evidence_missing"]}
    remediation_reasons = list(remediation_report.get("reasons", []))
    if not remediation_report.get("passed") and not remediation_reasons:
        remediation_reasons.append("independent_production_release_evidence_missing")
    if not artifacts_match:
        remediation_reasons.append("packaged_release_evidence_artifact_missing_or_tampered")
    analysis = {"production_ready": not analysis_reasons, "reasons": analysis_reasons, "counts": counts}
    remediation = {"production_ready": not remediation_reasons, "reasons": remediation_reasons}
    if remediation_report.get("passed"):
        remediation["artifact"] = remediation_report["artifact"]
    required = [analysis, remediation] if component == "all" else [analysis if component == "analysis" else remediation]
    return {
        "schema_version": "v1", "component": component,
        "scope": "analysis_rule_and_remediation_quality",
        "production_ready": all(item["production_ready"] for item in required),
        "compatibility_admission_passed": bool(rule_report.get("passed")) and artifacts_match,
        "analysis": analysis, "remediation": remediation,
    }


def build_report(component: str = "all", *, evidence_bundle: Path | None = None,
                 refresh_release_artifacts: bool = False, now=None) -> dict:
    try:
        rule_report = run_gate()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, yaml.YAMLError) as error:
        rule_report = {"passed": False, "reasons": [f"invalid_rule_evidence:{error}"]}
    try:
        admission = release_evidence.load_release_admission(evidence_bundle or release_evidence.RELEASE_BUNDLE, now=now)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError):
        admission = {"passed": False, "reasons": ["independent_production_release_evidence_missing_or_invalid"]}
    expected_artifact = admission["artifact"] if admission["passed"] else RELEASE_ARTIFACT
    # Generation is not a boolean override: every invocation reauthenticates the
    # exact current source/identity/corpus/results and recomputes statistical floors.
    # An invalid bundle never writes an artifact, including the blocked sentinel.
    if refresh_release_artifacts and admission["passed"] and component != "analysis":
        for path in RELEASE_ARTIFACT_PATHS:
            path.write_text(json.dumps(expected_artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    artifacts_match = True
    for path in RELEASE_ARTIFACT_PATHS:
        try:
            artifacts_match = artifacts_match and release_evidence.canonical_json(release_evidence.read_json(path)) == release_evidence.canonical_json(expected_artifact)
        except (OSError, ValueError):
            artifacts_match = False
    return assess_readiness(rule_report, component=component, artifacts_match=artifacts_match, remediation_report=admission)


def deployment_preflight(driver: str, *, evidence_bundle: Path | None = None) -> dict:
    """Read-only admission before API migrations: binary identity is not topology."""
    reasons = []
    levels = {"local": "development_unverified", "cloud_run_job": "isolated_job"}
    provided = levels.get(driver)
    if provided is None:
        reasons.append("unsupported_deployment_topology")
    if provided != "independent_sandbox":
        reasons.append(f"deployment_isolation_level_mismatch:{driver}:{provided or 'unknown'}:independent_sandbox")
    try:
        admission = release_evidence.load_release_admission(evidence_bundle or release_evidence.RELEASE_BUNDLE)
        if admission["artifact"]["sandbox"]["verification_level"] != provided:
            reasons.append("reviewed_execution_topology_does_not_match_deployment")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError):
        reasons.append("independent_production_release_evidence_missing_or_invalid")
    return {"schema_version": "v1", "scope": "ordered_production_release_preflight",
            "passed": not reasons, "driver": driver, "provided_verification_level": provided, "reasons": reasons}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=["all", "analysis", "remediation"], default="all")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report-only", action="store_true", help="Emit readiness without enforcing it; never use for shipping")
    parser.add_argument("--compatibility", action="store_true", help="Staging admission; explicitly allows documented legacy exceptions")
    parser.add_argument("--release-evidence", type=Path, help="Complete signed release bundle; expected identity/trust remain checked-in")
    parser.add_argument("--refresh-release-artifacts", action="store_true", help="Generate packaged artifacts only from fully verified current release evidence")
    parser.add_argument("--assert-sandbox-image", help="Also require this exact digest to match authenticated sandbox identity")
    parser.add_argument("--assert-service-image", help="Also require the exact authenticated remediation service binary")
    parser.add_argument("--preflight-deployment-driver", help="Read-only ordered release topology and signed identity preflight")
    args = parser.parse_args()
    if args.refresh_release_artifacts and (args.compatibility or args.report_only):
        parser.error("Artifact generation cannot use compatibility or reporting admission")
    if (args.assert_sandbox_image or args.assert_service_image) and (args.compatibility or args.report_only):
        parser.error("Sandbox identity assertion requires strict production admission")
    if args.preflight_deployment_driver:
        if args.compatibility or args.report_only or args.refresh_release_artifacts:
            parser.error("Deployment preflight is strictly read-only and cannot use nonproduction admission")
        preflight = deployment_preflight(args.preflight_deployment_driver, evidence_bundle=args.release_evidence)
        print(json.dumps(preflight, indent=2, sort_keys=True))
        return 0 if preflight["passed"] else 2
    report = build_report(args.component, evidence_bundle=args.release_evidence,
                          refresh_release_artifacts=args.refresh_release_artifacts)
    if args.assert_sandbox_image and (not report["remediation"]["production_ready"]
            or report["remediation"].get("artifact", {}).get("sandbox", {}).get("image_digest") != args.assert_sandbox_image):
        report["production_ready"] = False
        report["remediation"]["production_ready"] = False
        report["remediation"]["reasons"].append("deployment_sandbox_image_identity_mismatch")
    if args.assert_service_image and (not report["remediation"]["production_ready"]
            or report["remediation"].get("artifact", {}).get("service", {}).get("image_digest") != args.assert_service_image):
        report["production_ready"] = False
        report["remediation"]["production_ready"] = False
        report["remediation"]["reasons"].append("deployment_service_image_identity_mismatch")
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if args.report_only:
        return 0
    passed = report["compatibility_admission_passed"] if args.compatibility else report["production_ready"]
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
