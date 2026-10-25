"""Real Ed25519 signatures with ephemeral keys; no production approvals or keys."""
import base64
import copy
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from benchmarks.remediation import release_evidence as evidence


NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)


def timestamp(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def signed(tmp_path):
    # Never serialize a private key; every test generates a new key in memory.
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    store = {"schema_version": "v1", "minimum_reviewers": 1, "max_receipt_age_seconds": 3600,
             "keys": [{"key_id": "test-key", "reviewer_id": "independent-test-reviewer", "algorithm": "ed25519",
                       "status": "active", "public_key_base64": base64.b64encode(public).decode()}]}
    trust = tmp_path / "trusted-keys.json"
    corpus = tmp_path / "fixtures"
    corpus.mkdir()
    fixture_dir = corpus / "one"
    fixture_dir.mkdir()
    metadata = {"schema_version": "v1", "id": "one", "repository_id": "external/repo", "split": "holdout",
                "family": "sql_parameterization", "kind": "supported", "expected_state": "ready"}
    (fixture_dir / "fixture.json").write_text(json.dumps(metadata))
    (fixture_dir / "original.js").write_text("unsafe(input);\n")
    (fixture_dir / "repaired.js").write_text("safe(input);\n")
    (fixture_dir / "verify.js").write_text("// independently audited regression check\n")
    inputs = {"source_revision": "a" * 40,
              "manifest": {"schema_version": "v1", "minimum_cases": 120},
              "fixtures": evidence.fixture_inventory(corpus),
              "results": [{"fixture_id": "one", "repository_id": "external/repo", "split": "holdout",
                           "family": "sql_parameterization", "kind": "supported", "observed_state": "ready",
                           "outcome": "passed", "verification_level": "independent_sandbox",
                           "evidence": {"checks": [{"baseline": "failed", "candidate": "passed"}]},
                           "usage": {"input_tokens": 10}, "limitations": []}],
              "provider_id": "provider.example", "model_id": "immutable-model-2026-10-23",
              "configuration": {"temperature": 0, "prompt_digest": "sha256:" + "b" * 64, "budget": 10},
              "sandbox_image_digest": "registry.example/runner@sha256:" + "c" * 64,
              "service_image_digest": "registry.example/remediation@sha256:" + "f" * 64}
    payload = {"schema_version": "v1", "purpose": evidence.PURPOSE,
               **evidence.expected_bindings(**inputs),
               "issued_at": timestamp(NOW - timedelta(minutes=5)), "expires_at": timestamp(NOW + timedelta(minutes=5)),
               "reviews": [{"fixture_id": "one", "reviewer_id": "independent-test-reviewer", "verdict": "approved",
                            "fixture_digest": evidence.digest(inputs["fixtures"]["one"]),
                            "result_digest": evidence.digest(inputs["results"][0])}]}
    receipt = {"schema_version": "v1", "payload": payload, "signatures": []}

    def resign():
        receipt["signatures"] = [{"key_id": "test-key", "reviewer_id": "independent-test-reviewer", "algorithm": "ed25519",
                                  "signature": base64.b64encode(private.sign(evidence.signing_bytes(payload))).decode()}]

    def verify():
        trust.write_text(json.dumps(store))
        return evidence.verify_release_evidence(receipt, **inputs, trust_store_path=trust, now=NOW)

    resign()
    return {"receipt": receipt, "payload": payload, "store": store, "private": private, "inputs": inputs,
            "resign": resign, "verify": verify, "corpus": corpus, "fixture_dir": fixture_dir}


def test_real_signature_authenticates_complete_current_inputs_but_is_not_readiness(signed):
    result = signed["verify"]()
    assert result["authenticated_reviewers"] == ["independent-test-reviewer"]
    assert result["reviewed_fixtures"] == 1
    assert result["source_revision"] == signed["inputs"]["source_revision"]
    assert result["receipt_digest"] == evidence.digest(signed["receipt"])
    assert result["scope"] == "external_review_authentication_only"
    assert "production_ready" not in result and "passed" not in result


def test_key_order_does_not_change_canonical_signature_bytes(signed):
    before = evidence.signing_bytes(signed["payload"])
    signed["receipt"]["payload"] = dict(reversed(list(signed["payload"].items())))
    assert evidence.signing_bytes(signed["receipt"]["payload"]) == before
    signed["verify"]()


@pytest.mark.parametrize("field", ["source_revision", "manifest_digest", "fixtures_digest", "results_digest", "provider", "sandbox", "service"])
def test_every_current_binding_is_checked_even_with_a_valid_new_signature(signed, field):
    value = signed["payload"][field]
    signed["payload"][field] = {"changed": True} if isinstance(value, dict) else "changed"
    signed["resign"]()
    with pytest.raises(evidence.ReleaseEvidenceError, match=f"binding_mismatch:{field}"):
        signed["verify"]()


@pytest.mark.parametrize("filename", ["original.js", "repaired.js", "verify.js", "fixture.json"])
def test_current_fixture_source_reference_checks_and_metadata_are_all_bound(signed, filename):
    path = signed["fixture_dir"] / filename
    if filename.endswith(".json"):
        metadata = json.loads(path.read_text())
        metadata["new_verification_rule"] = "changed"
        path.write_text(json.dumps(metadata))
    else:
        path.write_text(path.read_text() + "// changed\n")
    signed["inputs"]["fixtures"] = evidence.fixture_inventory(signed["corpus"])
    with pytest.raises(evidence.ReleaseEvidenceError, match="binding_mismatch:fixtures_digest"):
        signed["verify"]()


@pytest.mark.parametrize("change", ["results", "configuration", "provider_id", "model_id", "sandbox_image_digest", "service_image_digest", "source_revision", "manifest"])
def test_changed_evaluation_or_deployment_identity_cannot_reuse_receipt(signed, change):
    inputs = signed["inputs"]
    if change == "results":
        inputs[change][0]["evidence"]["checks"][0]["candidate"] = "changed"
    elif change in {"configuration", "manifest"}:
        inputs[change]["new_option"] = True
    elif change == "source_revision":
        inputs[change] = "d" * 40
    elif change in {"sandbox_image_digest", "service_image_digest"}:
        inputs[change] = "registry.example/runner@sha256:" + "d" * 64
    else:
        inputs[change] += "-changed"
    with pytest.raises(evidence.ReleaseEvidenceError, match="binding_mismatch"):
        signed["verify"]()


@pytest.mark.parametrize("mutation,reason", [
    (lambda s: s["store"]["keys"].clear(), "no_trusted_review_keys"),
    (lambda s: s["store"]["keys"][0].update(status="revoked"), "revoked_review_key"),
    (lambda s: s["receipt"]["signatures"][0].update(key_id="unknown"), "unknown_review_key"),
    (lambda s: s["receipt"]["signatures"][0].update(reviewer_id="impersonator"), "reviewer_key_identity_mismatch"),
    (lambda s: s["receipt"]["signatures"][0].update(algorithm="none"), "invalid_signature_record"),
    (lambda s: s["receipt"]["signatures"].clear(), "missing_review_signatures"),
    (lambda s: s["receipt"]["signatures"].append(copy.deepcopy(s["receipt"]["signatures"][0])), "duplicate_review_signature"),
    (lambda s: s["store"]["keys"].append(copy.deepcopy(s["store"]["keys"][0])), "duplicate_trusted_key"),
    (lambda s: s["store"].update(minimum_reviewers=2), "insufficient_independent_reviewers"),
    (lambda s: s["store"].update(minimum_reviewers=0), "invalid_reviewer_threshold"),
    (lambda s: s["store"].update(max_receipt_age_seconds=99999999), "invalid_receipt_age_policy"),
    (lambda s: s["receipt"].update(public_key="untrusted-embedded-key"), "invalid_release_receipt"),
])
def test_untrusted_revoked_duplicate_or_malformed_key_and_signature_records_fail_closed(signed, mutation, reason):
    mutation(signed)
    with pytest.raises(evidence.ReleaseEvidenceError, match=reason):
        signed["verify"]()


@pytest.mark.parametrize("encoded", ["not base64!!", "", "YQ==", "A" * 88, "_" * 86 + "==", " A" * 44])
def test_signature_requires_canonical_base64_of_exactly_64_bytes(signed, encoded):
    signed["receipt"]["signatures"][0]["signature"] = encoded
    with pytest.raises(evidence.ReleaseEvidenceError, match="invalid_signature_base64"):
        signed["verify"]()


def test_wrong_key_and_wrong_domain_signatures_cannot_verify(signed):
    other = Ed25519PrivateKey.generate()
    signed["receipt"]["signatures"][0]["signature"] = base64.b64encode(other.sign(evidence.signing_bytes(signed["payload"]))).decode()
    with pytest.raises(evidence.ReleaseEvidenceError, match="invalid_review_signature"):
        signed["verify"]()
    signed["receipt"]["signatures"][0]["signature"] = base64.b64encode(signed["private"].sign(evidence.canonical_json(signed["payload"]))).decode()
    with pytest.raises(evidence.ReleaseEvidenceError, match="invalid_review_signature"):
        signed["verify"]()


def test_authenticated_signer_cannot_be_replaced_by_unsigned_review_owner(signed):
    signed["payload"]["reviews"][0]["reviewer_id"] = "not-the-signer"
    signed["resign"]()
    with pytest.raises(evidence.ReleaseEvidenceError, match="fixture_reviewer_not_authenticated"):
        signed["verify"]()


@pytest.mark.parametrize("mutation,reason", [
    (lambda p: p.update(reviews=[]), "missing_fixture_reviews"),
    (lambda p: p["reviews"].append(copy.deepcopy(p["reviews"][0])), "duplicate_or_unknown_fixture_review"),
    (lambda p: p["reviews"][0].update(fixture_id="unknown"), "duplicate_or_unknown_fixture_review"),
    (lambda p: p["reviews"][0].update(verdict="uncertain"), "fixture_review_not_approved"),
    (lambda p: p["reviews"][0].update(verdict="rejected"), "fixture_review_not_approved"),
    (lambda p: p["reviews"][0].update(fixture_digest="sha256:" + "0" * 64), "fixture_review_binding_mismatch"),
    (lambda p: p["reviews"][0].update(result_digest="sha256:" + "0" * 64), "fixture_review_binding_mismatch"),
    (lambda p: p.update(unrecognized_flag=True), "invalid_release_payload"),
])
def test_authentication_does_not_excuse_incomplete_or_invalid_reviews(signed, mutation, reason):
    mutation(signed["payload"])
    signed["resign"]()
    with pytest.raises(evidence.ReleaseEvidenceError, match=reason):
        signed["verify"]()


@pytest.mark.parametrize("issued,expires", [
    (NOW - timedelta(hours=2), NOW - timedelta(hours=1)),
    (NOW + timedelta(minutes=1), NOW + timedelta(minutes=2)),
    (NOW - timedelta(minutes=5), NOW),
    (NOW - timedelta(minutes=5), NOW + timedelta(days=5)),
    (NOW, NOW),
])
def test_expired_future_or_excessively_long_receipts_are_rejected_even_when_signed(signed, issued, expires):
    signed["payload"].update(issued_at=timestamp(issued), expires_at=timestamp(expires))
    signed["resign"]()
    with pytest.raises(evidence.ReleaseEvidenceError, match="stale_or_future_release_receipt"):
        signed["verify"]()


@pytest.mark.parametrize("value", ["2026-13-01T00:00:00Z", "2026-10-23", "2026-10-23T12:00:00+00:00", None])
def test_timestamp_format_is_strict_and_timezone_explicit(signed, value):
    signed["payload"]["issued_at"] = value
    signed["resign"]()
    with pytest.raises(evidence.ReleaseEvidenceError, match="invalid_receipt_timestamp"):
        signed["verify"]()


@pytest.mark.parametrize("level", ["isolated_job", "development_unverified", "static_assertion", "none", None])
def test_nonproduction_verification_never_authenticates_a_production_release(signed, level):
    signed["inputs"]["results"][0]["verification_level"] = level
    with pytest.raises(evidence.ReleaseEvidenceError, match="production_sandbox_evidence_required"):
        signed["verify"]()


@pytest.mark.parametrize("mutation,reason", [
    (lambda i: i["results"].append(copy.deepcopy(i["results"][0])), "duplicate_result_id"),
    (lambda i: i.update(results=[]), "empty_evaluation_results"),
    (lambda i: i["results"][0].update(fixture_id="unknown"), "missing_complete_fixture"),
    (lambda i: i["results"][0].update(outcome="inconclusive"), "evaluation_result_not_passed"),
    (lambda i: i["results"][0].update(outcome="failed"), "evaluation_result_not_passed"),
    (lambda i: i["results"][0].update(split="train"), "result_fixture_metadata_mismatch"),
    (lambda i: i["results"][0].update(observed_state="unsupported"), "evaluation_state_mismatch"),
    (lambda i: i["fixtures"].update(missing=copy.deepcopy(i["fixtures"]["one"])), "fixture_results_missing_or_unexpected"),
    (lambda i: i.update(sandbox_image_digest="registry.example/runner:latest"), "sandbox_image_must_be_digest_pinned"),
    (lambda i: i.update(service_image_digest="registry.example/service:latest"), "service_image_must_be_digest_pinned"),
    (lambda i: i.update(configuration={}), "missing_provider_configuration"),
])
def test_duplicate_missing_failed_or_inconclusive_results_and_unpinned_identity_fail_closed(signed, mutation, reason):
    mutation(signed["inputs"])
    with pytest.raises(evidence.ReleaseEvidenceError, match=reason):
        signed["verify"]()


def test_complete_review_coverage_is_required_not_only_at_least_one_signed_fixture(signed):
    inputs = signed["inputs"]
    second = copy.deepcopy(inputs["fixtures"]["one"])
    second["metadata"]["id"] = "two"
    inputs["fixtures"]["two"] = second
    inputs["results"].append({**copy.deepcopy(inputs["results"][0]), "fixture_id": "two"})
    signed["payload"].update(evidence.expected_bindings(**inputs))
    signed["resign"]()
    with pytest.raises(evidence.ReleaseEvidenceError, match="fixture_review_coverage_incomplete"):
        signed["verify"]()


def test_a_trusted_key_cannot_be_repeated_under_another_id_to_amplify_threshold(signed):
    signed["store"]["keys"].append({**signed["store"]["keys"][0], "key_id": "alias", "reviewer_id": "other"})
    with pytest.raises(evidence.ReleaseEvidenceError, match="duplicate_trusted_key"):
        signed["verify"]()


def test_two_independent_reviewers_can_authenticate_the_complete_receipt(signed):
    second_private = Ed25519PrivateKey.generate()
    second_public = second_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    signed["store"]["minimum_reviewers"] = 2
    signed["store"]["keys"].append({"key_id": "second-key", "reviewer_id": "second-reviewer", "status": "active",
                                    "algorithm": "ed25519", "public_key_base64": base64.b64encode(second_public).decode()})
    inputs = signed["inputs"]
    second = copy.deepcopy(inputs["fixtures"]["one"])
    second["metadata"]["id"] = "two"
    second["metadata"]["repository_id"] = "another/repo"
    inputs["fixtures"]["two"] = second
    result = {**copy.deepcopy(inputs["results"][0]), "fixture_id": "two", "repository_id": "another/repo"}
    inputs["results"].append(result)
    signed["payload"].update(evidence.expected_bindings(**inputs))
    signed["payload"]["reviews"].append({"fixture_id": "two", "reviewer_id": "second-reviewer", "verdict": "approved",
                                        "fixture_digest": evidence.digest(second), "result_digest": evidence.digest(result)})
    signed["resign"]()
    signed["receipt"]["signatures"].append({"key_id": "second-key", "reviewer_id": "second-reviewer", "algorithm": "ed25519",
        "signature": base64.b64encode(second_private.sign(evidence.signing_bytes(signed["payload"]))).decode()})
    assert signed["verify"]()["authenticated_reviewers"] == ["independent-test-reviewer", "second-reviewer"]


@pytest.mark.parametrize("value", [None, "not an object", [], {}, {"schema_version": "v1", "keys": []}])
def test_malformed_trust_stores_are_refused(signed, value):
    trust = signed["corpus"].parent / "malformed-trust.json"
    trust.write_text(json.dumps(value))
    with pytest.raises(evidence.ReleaseEvidenceError, match="invalid_trust_store"):
        evidence.verify_release_evidence(signed["receipt"], **signed["inputs"], trust_store_path=trust, now=NOW)


def test_malformed_trusted_key_status_is_a_clean_refusal(signed):
    signed["store"]["keys"][0]["status"] = {"active": True}
    with pytest.raises(evidence.ReleaseEvidenceError, match="invalid_trusted_key"):
        signed["verify"]()


def test_production_store_is_empty_and_cannot_accept_the_ephemeral_test_receipt(signed):
    # Future, independently approved production keys must still reject this
    # ephemeral key. Do not require the production trust store to stay empty.
    with pytest.raises(evidence.ReleaseEvidenceError, match="no_trusted_review_keys|unknown_review_key"):
        evidence.verify_release_evidence(signed["receipt"], **signed["inputs"], now=NOW)


def test_duplicate_json_fields_are_not_silently_overwritten(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"keys": [], "keys": ["attacker"]}')
    with pytest.raises(evidence.ReleaseEvidenceError, match="duplicate_json_key"):
        evidence.read_json(path)


@pytest.mark.parametrize("value", [{1: "coerced-key"}, {"number": float("nan")}, {"number": float("inf")}, ("tuple",)])
def test_canonical_encoding_rejects_ambiguous_or_non_json_values(value):
    with pytest.raises(evidence.ReleaseEvidenceError):
        evidence.canonical_json(value)


def test_fixture_inventory_rejects_links_and_duplicate_ids(signed):
    (signed["fixture_dir"] / "outside.js").symlink_to(signed["fixture_dir"] / "original.js")
    with pytest.raises(evidence.ReleaseEvidenceError, match="fixture_symlink_not_allowed"):
        evidence.fixture_inventory(signed["corpus"])
    (signed["fixture_dir"] / "outside.js").unlink()
    duplicate = signed["corpus"] / "duplicate"
    duplicate.mkdir()
    (duplicate / "fixture.json").write_text((signed["fixture_dir"] / "fixture.json").read_text())
    with pytest.raises(evidence.ReleaseEvidenceError, match="duplicate_fixture_id"):
        evidence.fixture_inventory(signed["corpus"])


def test_cli_refuses_dirty_implementation_without_logging_caller_documents(signed, monkeypatch, capsys, tmp_path):
    # A signing key is never a CLI argument or environment override. The source
    # revision is resolved from the repository, not accepted from the receipt.
    monkeypatch.setattr(evidence, "ROOT", tmp_path)
    trust = tmp_path / "trusted-keys.json"
    trust.write_text(json.dumps(signed["store"]))
    monkeypatch.setattr(evidence, "TRUST_STORE", trust)
    calls = []

    def git(argv, **_kwargs):
        calls.append(argv)
        if "diff" in argv:
            raise subprocess.CalledProcessError(1, argv)
        return subprocess.CompletedProcess(argv, 0, stdout="")

    monkeypatch.setattr(evidence.subprocess, "run", git)
    monkeypatch.setattr(sys, "argv", ["verify", "--receipt", "secret-receipt-value", "--evaluation", "evaluation", "--identity", "identity"])
    assert evidence.main() == 2
    output = capsys.readouterr().out
    assert "refused" in output and "secret-receipt-value" not in output
    assert any("ls-files" in argv for argv in calls)


def test_cli_refuses_untracked_engine_implementation(signed, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(evidence, "ROOT", tmp_path)
    trust = tmp_path / "trusted-keys.json"
    trust.write_text(json.dumps(signed["store"]))
    monkeypatch.setattr(evidence, "TRUST_STORE", trust)

    def git(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout="new-engine-file.py\n" if "--others" in argv else "")

    monkeypatch.setattr(evidence.subprocess, "run", git)
    monkeypatch.setattr(sys, "argv", ["verify", "--receipt", "receipt", "--evaluation", "evaluation", "--identity", "identity"])
    assert evidence.main() == 2
    assert "refused" in capsys.readouterr().out


@pytest.fixture
def release_bundle(tmp_path, monkeypatch):
    """A statistically sufficient *test-only* corpus with real ephemeral signatures."""
    from benchmarks.remediation.evaluate import SUPPORTED_FAMILIES
    current_root = evidence.ROOT
    root = tmp_path / "repository"
    corpus = root / "benchmarks/remediation/fixtures"
    release = root / "benchmarks/remediation/release"
    corpus.mkdir(parents=True)
    release.mkdir()
    manifest = evidence.read_json(current_root / "benchmarks/remediation/release-manifest.json")
    # This future-qualifying synthetic population contains no static regression
    # demonstrations. Removing abstention exceptions makes its policy stricter.
    manifest["release_abstentions"] = {}
    manifest_path = root / "benchmarks/remediation/release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    trust = release / "trusted-keys.json"
    trust.write_text(json.dumps({"schema_version": "v1", "minimum_reviewers": 1, "max_receipt_age_seconds": 3600,
        "keys": [{"key_id": "ephemeral-bundle-key", "reviewer_id": "external-test-reviewer", "algorithm": "ed25519",
                  "status": "active", "public_key_base64": base64.b64encode(public).decode()}]}))
    identity = {"provider_id": "provider.example", "model_id": "immutable-model-version",
                "configuration": {"temperature": 0, "prompt_digest": "sha256:" + "d" * 64},
                "sandbox_image_digest": "registry.example/sandbox@sha256:" + "e" * 64,
                "service_image_digest": "registry.example/remediation@sha256:" + "f" * 64}
    identity_path = release / "evaluation-identity.json"
    identity_path.write_text(json.dumps(identity))
    results = []
    specs = [(family, "supported") for family in sorted(SUPPORTED_FAMILIES) for _ in range(20)]
    specs += [("sql_parameterization", kind) for kind in ("negative", "adversarial") for _ in range(30)]
    for index, (family, kind) in enumerate(specs):
        fixture_id = f"reviewed-{index:03}"
        path = corpus / fixture_id
        path.mkdir()
        state = "ready" if kind == "supported" else "unsupported"
        metadata = {"schema_version": "v1", "id": fixture_id, "repository_id": f"independent/repository-{index}",
                    "split": "holdout", "family": family, "kind": kind, "expected_state": state}
        (path / "fixture.json").write_text(json.dumps(metadata))
        (path / "original.js").write_text("unsafe(input);\n")
        (path / "repaired.js").write_text("safe(input);\n")
        (path / "verify.js").write_text("// independently reviewed check\n")
        results.append({"fixture_id": fixture_id, **{key: metadata[key] for key in ("repository_id", "split", "family", "kind")},
                        "expected_state": state, "observed_state": state, "outcome": "passed", "reason": None,
                        "fixture_tests": {"passed": True}, "usage": {}, "elapsed_ms": 1,
                        "verification_level": "independent_sandbox" if state == "ready" else None, "limitations": [],
                        "repair_evidence": {"candidates": [{"path": "original.js", "replacement_content": "safe(input);\n"}] if state == "ready" else [],
                            "request_versions": {"repair_model": identity["model_id"], "repair_service_image": identity["service_image_digest"]},
                            "requested_sandbox_image_digest": identity["sandbox_image_digest"],
                            "evidence": {"verification_level": "independent_sandbox", "baseline": "failed", "candidate": "passed"}}})
    evaluation = {"schema_version": "v1", "suite": "release", "adapter": "engine", "provider_kind": "live-provider",
                  "results_kind": "repair_quality", "source_revision": "a" * 40,
                  "evaluation_identity": identity, "results": results}
    bundle = {"schema_version": "v1", "evaluation": evaluation, "receipt": {}}
    from benchmarks.remediation import corpus_intake
    # The Git/preregistration chain is independently covered by test_production_intake.
    # Isolate the statistical and image-identity protocol in this synthetic corpus.
    intake_binding = {"schema_version": "v1", "test_ledger_digest": "sha256:" + "1" * 64}
    monkeypatch.setattr(corpus_intake, "validate_release_intake", lambda **_: intake_binding)
    path = release / "evidence.json"
    now = datetime.now(timezone.utc)

    def resign():
        inventory = evidence.fixture_inventory(corpus)
        payload = {"schema_version": "v1", "purpose": evidence.PURPOSE,
            **evidence.expected_bindings(source_revision="a" * 40, manifest=evidence.read_json(manifest_path), fixtures=inventory,
                                        results=results, intake_bindings=intake_binding, **identity),
            "issued_at": timestamp(now - timedelta(minutes=1)), "expires_at": timestamp(now + timedelta(minutes=5)),
            "reviews": [{"fixture_id": item["fixture_id"], "reviewer_id": "external-test-reviewer", "verdict": "approved",
                         "fixture_digest": evidence.digest(inventory[item["fixture_id"]]), "result_digest": evidence.digest(item)}
                        for item in results]}
        bundle["receipt"] = {"schema_version": "v1", "payload": payload, "signatures": [{"algorithm": "ed25519",
            "key_id": "ephemeral-bundle-key", "reviewer_id": "external-test-reviewer",
            "signature": base64.b64encode(private.sign(evidence.signing_bytes(payload))).decode()}]}
        save()

    def save():
        path.write_text(json.dumps(bundle))

    monkeypatch.setattr(evidence, "ROOT", root)
    monkeypatch.setattr(evidence, "TRUST_STORE", trust)
    monkeypatch.setattr(evidence, "EVALUATION_IDENTITY", identity_path)
    monkeypatch.setattr(evidence, "clean_checkout_revision", lambda: "a" * 40)
    resign()
    return {"bundle": bundle, "path": path, "root": root, "corpus": corpus, "now": now,
            "identity": identity, "identity_path": identity_path, "manifest_path": manifest_path,
            "results": results, "resign": resign, "save": save}


def test_full_release_admission_authenticates_and_recomputes_statistics(release_bundle):
    admission = evidence.load_release_admission(release_bundle["path"], now=release_bundle["now"])
    assert admission["passed"] and admission["statistics"]["precision_gate"]["reviewed_predictions"] == 140
    assert admission["artifact"]["source_revision"] == "a" * 40
    assert admission["artifact"]["sandbox"]["image_digest"] == release_bundle["identity"]["sandbox_image_digest"]
    assert admission["artifact"]["service"]["image_digest"] == release_bundle["identity"]["service_image_digest"]


@pytest.mark.parametrize("driver", ["local", "cloud_run_job", "caller_asserted_independent_sandbox"])
def test_even_verified_release_cannot_use_an_unreviewed_execution_topology_or_write_artifacts(release_bundle, driver, monkeypatch, tmp_path):
    from benchmarks import production_readiness as readiness
    artifacts = [tmp_path / "api-artifact.json", tmp_path / "github-artifact.json"]
    for path in artifacts:
        path.write_text(json.dumps(readiness.RELEASE_ARTIFACT))
    before = [path.read_bytes() for path in artifacts]
    monkeypatch.setattr(readiness, "RELEASE_ARTIFACT_PATHS", artifacts)
    result = readiness.deployment_preflight(driver, evidence_bundle=release_bundle["path"])
    assert not result["passed"]
    assert any("deployment_isolation_level_mismatch" in reason for reason in result["reasons"])
    assert [path.read_bytes() for path in artifacts] == before


@pytest.mark.parametrize("stratum", ["sql_parameterization", "negative", "adversarial"])
def test_aggregate_holdout_accuracy_cannot_replace_each_required_holdout_stratum(release_bundle, stratum):
    for result in release_bundle["results"]:
        matches = result["kind"] == stratum or (result["kind"] == "supported" and result["family"] == stratum)
        if matches:
            result["split"] = "train"
            path = release_bundle["corpus"] / result["fixture_id"] / "fixture.json"
            metadata = json.loads(path.read_text())
            metadata["split"] = "train"
            path.write_text(json.dumps(metadata))
    release_bundle["resign"]()
    with pytest.raises(evidence.ReleaseEvidenceError, match="minimum_holdout_(?:family|negative|adversarial)_cases_not_met"):
        evidence.load_release_admission(release_bundle["path"], now=release_bundle["now"])


def test_static_regression_cases_have_explicit_bound_abstention_policy_not_false_positive_repairs():
    from benchmarks.remediation.evaluate import release_statistics
    from types import SimpleNamespace
    raw = evidence.fixture_inventory(evidence.ROOT / "benchmarks/remediation/fixtures")
    manifest = evidence.read_json(evidence.ROOT / "benchmarks/remediation/release-manifest.json")
    effective = evidence.release_fixture_inventory(raw, manifest)
    abstentions = [key for key, item in effective.items() if item["metadata"].get("release_abstention")]
    assert len(abstentions) == 5
    assert len(effective) == len(raw) == 81
    assert all(raw[key]["metadata"]["expected_state"] == "ready" and effective[key]["metadata"]["kind"] == "supported"
               and effective[key]["metadata"]["expected_state"] == "unsupported" for key in abstentions)
    rows = [SimpleNamespace(fixture_id=key, **{field: item["metadata"][field] for field in ("repository_id", "split", "kind", "family")},
             observed_state=item["metadata"]["expected_state"], outcome="passed") for key, item in effective.items()]
    stats = release_statistics([(evidence.ROOT, item["metadata"]) for item in effective.values()], rows, manifest)
    holdout = [row for row in rows if row.split == "holdout" and row.kind == "supported"]
    assert stats["holdout_coverage"] == sum(row.observed_state == "ready" for row in holdout) / len(holdout)
    assert not stats["passed"]  # Authored seed is still too small/unqualified.
    changed = copy.deepcopy(raw)
    changed[abstentions[0]]["files"]["changed.js"] = "sha256:" + "0" * 64
    with pytest.raises(evidence.ReleaseEvidenceError, match="release_abstention_fixture_binding_mismatch"):
        evidence.release_fixture_inventory(changed, manifest)


@pytest.mark.parametrize("field,value,reason", [
    ("adapter", "reference", "live_production_evaluation_required"),
    ("adapter", "engine-local", "live_production_evaluation_required"),
    ("provider_kind", "scripted-provider", "live_production_evaluation_required"),
    ("results_kind", "pipeline_integrity", "live_production_evaluation_required"),
    ("source_revision", "b" * 40, "evaluation_source_revision_mismatch"),
])
def test_pipeline_self_assessment_and_wrong_source_cannot_promote(release_bundle, field, value, reason):
    release_bundle["bundle"]["evaluation"][field] = value
    release_bundle["bundle"]["evaluation"]["passed"] = True
    release_bundle["save"]()
    with pytest.raises(evidence.ReleaseEvidenceError, match=reason):
        evidence.load_release_admission(release_bundle["path"], now=release_bundle["now"])


@pytest.mark.parametrize("field", ["provider_id", "model_id", "configuration", "sandbox_image_digest", "service_image_digest"])
def test_signed_provider_identity_is_compared_with_independent_current_policy(release_bundle, field):
    identity = copy.deepcopy(release_bundle["identity"])
    identity[field] = {"changed": True} if field == "configuration" else "changed"
    release_bundle["identity_path"].write_text(json.dumps(identity))
    with pytest.raises(evidence.ReleaseEvidenceError, match="evaluation_identity_mismatch"):
        evidence.load_release_admission(release_bundle["path"], now=release_bundle["now"])


def test_ready_result_without_complete_replacement_and_evidence_cannot_promote(release_bundle):
    release_bundle["results"][0].pop("repair_evidence")
    release_bundle["resign"]()
    with pytest.raises(evidence.ReleaseEvidenceError, match="complete_repair_evidence_missing"):
        evidence.load_release_admission(release_bundle["path"], now=release_bundle["now"])


def test_cryptographically_approved_but_statistically_insufficient_holdout_cannot_promote(release_bundle):
    for result in release_bundle["results"][:41]:
        result["split"] = "train"
        path = release_bundle["corpus"] / result["fixture_id"] / "fixture.json"
        metadata = json.loads(path.read_text())
        metadata["split"] = "train"
        path.write_text(json.dumps(metadata))
    release_bundle["resign"]()
    with pytest.raises(evidence.ReleaseEvidenceError, match="minimum_precision_samples_not_met:99/100"):
        evidence.load_release_admission(release_bundle["path"], now=release_bundle["now"])


def test_reduced_release_policy_floors_are_not_an_override(release_bundle):
    manifest = json.loads(release_bundle["manifest_path"].read_text())
    manifest["minimum_supported_cases_per_family"] = 1
    release_bundle["manifest_path"].write_text(json.dumps(manifest))
    release_bundle["resign"]()
    with pytest.raises(ValueError, match="release_policy_below_floor"):
        evidence.load_release_admission(release_bundle["path"], now=release_bundle["now"])


def test_only_full_verified_current_admission_generates_packaged_artifacts(release_bundle, monkeypatch, tmp_path):
    from benchmarks import production_readiness as readiness
    artifacts = [tmp_path / "api-quality-release.json", tmp_path / "github-quality-release.json"]
    for path in artifacts:
        path.write_text(json.dumps(readiness.RELEASE_ARTIFACT))
    monkeypatch.setattr(readiness, "RELEASE_ARTIFACT_PATHS", artifacts)
    monkeypatch.setattr(readiness, "run_gate", lambda: {"passed": True, "counts": {"validated": 1}})
    kwargs = {"evidence_bundle": release_bundle["path"], "now": release_bundle["now"]}
    assert not readiness.build_report(**kwargs)["production_ready"]
    report = readiness.build_report(**kwargs, refresh_release_artifacts=True)
    assert report["production_ready"]
    assert json.loads(artifacts[0].read_text()) == json.loads(artifacts[1].read_text()) == report["remediation"]["artifact"]
    assert readiness.build_report(**kwargs)["production_ready"]
    edited = json.loads(artifacts[0].read_text())
    edited["remediation_release_verified"] = 1
    artifacts[0].write_text(json.dumps(edited))
    assert not readiness.build_report(**kwargs)["production_ready"]
    # A hand-edited boolean/source identity is not a release receipt.
    edited = json.loads(artifacts[0].read_text())
    edited["remediation_release_verified"] = True
    edited["source_revision"] = "b" * 40
    artifacts[0].write_text(json.dumps(edited))
    assert not readiness.build_report(**kwargs)["production_ready"]
    # Expiry invalidates already packaged artifacts. A stale refresh never writes.
    before = [path.read_bytes() for path in artifacts]
    stale = readiness.build_report(evidence_bundle=release_bundle["path"], now=release_bundle["now"] + timedelta(days=1), refresh_release_artifacts=True)
    assert not stale["production_ready"]
    assert [path.read_bytes() for path in artifacts] == before


def test_release_evaluator_cli_uses_the_same_authenticated_statistical_decision(release_bundle, monkeypatch, capsys):
    from benchmarks.remediation import evaluate
    monkeypatch.setattr(sys, "argv", ["evaluate", "--suite", "release", "--release-evidence", str(release_bundle["path"])])
    assert evaluate.main() == 0
    assert json.loads(capsys.readouterr().out)["release_gate"]["passed"]
    release_bundle["bundle"]["receipt"]["signatures"][0]["signature"] = "invalid"
    release_bundle["save"]()
    assert evaluate.main() == 2
    assert not json.loads(capsys.readouterr().out)["release_gate"]["passed"]
