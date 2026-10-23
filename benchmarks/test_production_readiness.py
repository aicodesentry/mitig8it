import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import benchmarks.production_readiness as readiness
import benchmarks.rule_quality_gate as gate


ROOT = Path(__file__).resolve().parents[1]


def test_legacy_compatibility_is_never_reported_as_production_readiness():
    report = readiness.build_report()
    assert report["compatibility_admission_passed"]
    assert not report["production_ready"]
    legacy = json.loads((ROOT / "benchmarks/rule-quality/legacy-posting.json").read_text())
    assert report["analysis"]["counts"]["legacy_unvalidated"] == len(legacy["rules"])
    assert report["analysis"]["counts"]["validated"] == 0
    assert "no_statistically_validated_posting_rules" in report["analysis"]["reasons"]
    assert not report["remediation"]["production_ready"]


@pytest.mark.parametrize("counts", [{"quarantined": 10}, {"legacy_unvalidated": 10},
                                    {"quarantined": 10, "legacy_unvalidated": 10},
                                    {"validated": 1, "legacy_unvalidated": 1}])
def test_missing_or_partial_rule_evidence_cannot_establish_readiness(counts):
    report = readiness.assess_readiness({"passed": True, "counts": counts}, component="analysis")
    assert not report["production_ready"]


def test_validated_analysis_does_not_imply_remediation_is_ready():
    rules = {"passed": True, "counts": {"validated": 5, "legacy_unvalidated": 0, "quarantined": 10}}
    assert readiness.assess_readiness(rules, component="analysis")["production_ready"]
    assert not readiness.assess_readiness(rules)["production_ready"]
    assert not readiness.assess_readiness(rules, component="remediation")["production_ready"]


@pytest.mark.parametrize("args,exit_code", [([], 2), (["--component", "analysis"], 2),
                                         (["--component", "remediation"], 2),
                                         (["--compatibility"], 0), (["--report-only"], 0)])
def test_readiness_cli_enforces_production_unless_reporting_or_staging_is_explicit(args, exit_code):
    result = subprocess.run([sys.executable, "-m", "benchmarks.production_readiness", *args],
                            cwd=ROOT, text=True, capture_output=True, check=False)
    assert result.returncode == exit_code, result.stderr
    assert json.loads(result.stdout)["production_ready"] is False


@pytest.mark.parametrize("mode", ["--compatibility", "--report-only"])
@pytest.mark.parametrize("assertion", ["--refresh-release-artifacts", "--assert-sandbox-image=registry/runner@sha256:" + "a" * 64])
def test_generation_and_deployment_identity_assertions_cannot_use_nonstrict_modes(mode, assertion):
    result = subprocess.run([sys.executable, "-m", "benchmarks.production_readiness", mode, assertion],
                            cwd=ROOT, text=True, capture_output=True, check=False)
    assert result.returncode == 2


def test_manual_release_artifact_edits_cannot_open_either_gate(monkeypatch, tmp_path):
    path = tmp_path / "quality-release.json"
    path.write_text(json.dumps({**readiness.RELEASE_ARTIFACT, "remediation_release_verified": True}))
    monkeypatch.setattr(readiness, "RELEASE_ARTIFACT_PATHS", [path])
    report = readiness.build_report()
    assert not report["production_ready"]
    assert not report["compatibility_admission_passed"]
    assert "packaged_release_evidence_artifact_missing_or_tampered" in report["remediation"]["reasons"]


def test_compiled_allowlist_must_match_the_canonical_evidence(monkeypatch, tmp_path):
    path = tmp_path / "publication-policy.json"
    path.write_text(json.dumps({"schema_version": "v1", "rules": {}}))
    monkeypatch.setattr(gate, "RUNTIME_POLICY", path)
    report = gate.run_gate()
    assert not report["passed"]
    assert "packaged_runtime_publication_policy_missing_or_stale" in report["reasons"]


def test_packaged_release_admission_is_identical_in_all_node_services():
    for path in readiness.RELEASE_ARTIFACT_PATHS:
        assert json.loads(path.read_text()) == readiness.RELEASE_ARTIFACT


def test_every_external_shipping_job_checks_local_readiness_first():
    shipping_pattern = re.compile(r"docker push|gcloud run deploy|firebase-tools@\S+ deploy|gh release create|kubectl apply|helm (?:upgrade|install)")
    found = []
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        workflow = yaml.safe_load(path.read_text())
        for job_name, job in workflow.get("jobs", {}).items():
            steps = job.get("steps", [])
            writes = [index for index, step in enumerate(steps) if shipping_pattern.search(step.get("run", ""))]
            if not writes:
                continue
            found.append((path.name, job_name))
            gates = [index for index, step in enumerate(steps)
                     if step.get("uses") == "./.github/actions/quality-readiness"
                     or ("-m benchmarks.production_readiness" in step.get("run", "")
                         and "--report-only" not in step["run"] and "--compatibility" not in step["run"])]
            assert gates and min(gates) < min(writes), f"{path.name}/{job_name} can ship without evidence"
    assert len(found) >= 6


def test_composite_has_no_production_compatibility_fallback():
    path = ROOT / ".github/actions/quality-readiness/action.yml"
    action = yaml.safe_load(path.read_text())
    commands = "\n".join(step.get("run", "") for step in action["runs"]["steps"])
    assert 'python -m benchmarks.production_readiness --component "$QUALITY_COMPONENT" --release-evidence "$evidence_path" --refresh-release-artifacts' in commands
    assert 'python -m benchmarks.production_readiness --component "$QUALITY_COMPONENT" --release-evidence "$evidence_path"\n' in commands
    assert 'staging) python -m benchmarks.production_readiness --component "$QUALITY_COMPONENT" --compatibility ;;' in commands
    assert "--report-only" not in commands
    assert "|| true" not in commands
    assert "--proto '=https' --proto-redir '=https'" in commands
    assert "--max-redirs 3" in commands and "--max-time 30" in commands
    assert "--max-filesize 20971520" in commands
    assert "url.username or url.password or url.query or url.fragment" in commands
    assert "benchmarks/requirements-quality.txt" in commands


def test_production_sandbox_promotes_the_authenticated_digest_before_any_push_or_job_mutation():
    workflow = yaml.safe_load((ROOT / ".github/workflows/deploy-remediation-cloudrun.yml").read_text())
    steps = workflow["jobs"]["deploy"]["steps"]
    admission = next(i for i, step in enumerate(steps) if step.get("name") == "Resolve the authenticated production sandbox digest before any push")
    writes = [i for i, step in enumerate(steps) if re.search(r"docker push|gcloud run jobs update|gcloud run deploy", step.get("run", ""))]
    assert admission < min(writes)
    assert "--assert-sandbox-image" in steps[admission]["run"]
    assert steps[admission]["if"] == "env.ENVIRONMENT == 'production'"
    assert "cloud_run_job) PROVIDED_LEVEL='isolated_job'" in steps[admission]["run"]
    assert "local) PROVIDED_LEVEL='development_unverified'" in steps[admission]["run"]
    assert 'if [ "$LEVEL" != "$PROVIDED_LEVEL" ]; then' in steps[admission]["run"]
    assert "not just its image digest" in steps[admission]["run"]
    assert steps[admission]["run"].index("exit 1") < steps[admission]["run"].index("gcloud artifacts docker images describe")
    assert 'echo "JOB_IMAGE=$APPROVED"' in steps[admission]["run"]
    build = next(step for step in steps if step.get("name") == "Build and push the sandbox job image")
    assert "env.ENVIRONMENT != 'production'" in build["if"]
    update = next(step for step in steps if step.get("name") == "Point the sandbox job at the new digest")["run"]
    assert update.index("--assert-sandbox-image") < update.index("gcloud run jobs update")
    metadata = next(step["run"] for step in steps if step.get("name") == "Set release metadata")
    assert '["service"]["image_digest"]' in metadata
    assert 'echo "IMAGE=$SERVICE_IMAGE"' in metadata
    for name in ("Build repair image", "Push repair image"):
        assert next(step["if"] for step in steps if step.get("name") == name) == "env.ENVIRONMENT != 'production'"
    assert "--assert-service-image" in steps[admission]["run"]


def test_ordered_release_preflight_precedes_api_and_cannot_mutate_cloud():
    workflow = yaml.safe_load((ROOT / ".github/workflows/deploy-production.yml").read_text())
    preflight = workflow["jobs"]["preflight"]
    assert preflight["needs"] == "verify-ci"
    assert workflow["jobs"]["api-service"]["needs"] == "preflight"
    assert preflight["permissions"] == {"contents": "read"}
    admission = next(step for step in preflight["steps"] if step.get("uses") == "./.github/actions/quality-readiness")
    assert admission["with"]["deployment-driver"] == workflow["jobs"]["remediation-service"]["with"]["sandbox_driver"]
    assert not any("google-github-actions/" in step.get("uses", "") for step in preflight["steps"])
    assert not any(re.search(r"gcloud|docker push|db:migrate", step.get("run", "")) for step in preflight["steps"])


def test_required_ci_installs_pinned_quality_dependencies_and_runs_evidence_and_intake_tests():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    job = workflow["jobs"]["analysis-tests"]
    assert "if" not in job
    assert "analysis-tests" in workflow["jobs"]["ci-required"]["needs"]
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "pip install -r ../../../benchmarks/requirements-quality.txt" in commands
    for suite in ("test_release_evidence.py", "test_corpus_intake.py", "test_production_intake.py"):
        assert "benchmarks/remediation/tests/" + suite in commands


def test_requested_remediation_release_check_consumes_authenticated_bundle():
    workflow = yaml.safe_load((ROOT / ".github/workflows/remediation.yml").read_text())
    steps = workflow["jobs"]["remediation-benchmark-gate"]["steps"] if "remediation-benchmark-gate" in workflow["jobs"] else next(
        job["steps"] for job in workflow["jobs"].values() if any(step.get("name") == "Evaluate release evidence without deploying" for step in job.get("steps", [])))
    command = next(step["run"] for step in steps if step.get("name") == "Evaluate release evidence without deploying")
    assert '--release-evidence "$REMEDIATION_RELEASE_EVIDENCE_PATH"' in command
    assert 'test "$evaluation_exit_code" -eq 2' in command
    assert any(step.get("uses") == "./.github/actions/quality-readiness" and "inputs.release_gate" in step.get("if", "") for step in steps)


@pytest.mark.parametrize("filename", ["deploy-production.yml", "deploy-staging.yml"])
def test_ordered_deployment_callers_allow_the_permissions_requested_by_reusable_jobs(filename):
    caller = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
    checked = 0
    for name, job in caller["jobs"].items():
        reusable = job.get("uses", "")
        if not reusable.startswith("./.github/workflows/"):
            continue
        called = yaml.safe_load((ROOT / reusable).read_text())
        allowed = job.get("permissions", caller.get("permissions", {}))
        for called_job in called["jobs"].values():
            requested = called_job.get("permissions", called.get("permissions", {}))
            if requested.get("id-token") == "write":
                checked += 1
                assert allowed.get("id-token") == "write", (
                    f"{filename}/{name} cannot delegate the id-token: write permission requested by {reusable}"
                )
    assert checked >= 5, "API, analysis, GitHub, remediation, and dependency smoke must be checked"
    assert {scope for scope, access in caller["permissions"].items() if access == "write"} == {"id-token"}


@pytest.mark.parametrize("filename,job", [
    ("deploy-production.yml", "verify-ci"),
    ("deploy-production.yml", "preflight"),
    ("deploy-staging.yml", "authorize"),
])
def test_deployment_preflight_jobs_do_not_receive_oidc_or_write_permissions(filename, job):
    caller = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
    permissions = caller["jobs"][job].get("permissions", caller["permissions"])
    assert permissions.get("id-token", "none") == "none"
    assert all(access in {"read", "none"} for access in permissions.values())
