"""Ephemeral synthetic keys/claims test the verifier, never release evidence."""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from benchmarks import analysis_attestation as auth
from benchmarks import rule_quality_gate as gate


RULE = "test.synthetic.rule"
DIGEST = "a" * 64


class SyntheticAuthority:
    """Test-only signer: never installed in the repository trust store."""
    def __init__(self, path):
        self.path = path
        self.keys = {}

    def sign(self, evidence, rule_id=None, *, domain=auth.DOMAIN):
        rule_id = rule_id or evidence["rule_id"]
        candidate = auth.authenticated_candidate(evidence, {})
        current = datetime.now(timezone.utc).replace(microsecond=0)
        payload = auth.prepare_payload(candidate, rule_id,
                                       issued_at=(current - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                       expires_at=(current + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                       auditor_id="synthetic-sampling-auditor", audit_reference="synthetic-test-only-audit")
        reviewers = payload["reviewer_ids"]
        signers = sorted(set(reviewers) | {payload["sampling_audit"]["auditor_id"]})
        entries, signatures = [], []
        for reviewer in signers:
            private = self.keys.setdefault(reviewer, Ed25519PrivateKey.generate())
            public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            key_id = "synthetic-" + hashlib.sha256(reviewer.encode()).hexdigest()[:12]
            roles = ([auth.REVIEW_ROLE] if reviewer in reviewers else []) + ([auth.AUDIT_ROLE] if reviewer == payload["sampling_audit"]["auditor_id"] else [])
            entries.append({"key_id": key_id, "reviewer_id": reviewer, "algorithm": "ed25519", "status": "active",
                            "public_key_base64": base64.b64encode(public).decode(), "roles": roles})
            signatures.append({"key_id": key_id, "reviewer_id": reviewer, "algorithm": "ed25519",
                               "signature": base64.b64encode(private.sign(domain + auth.canonical_json(payload))).decode()})
        self.path.write_text(json.dumps({"schema_version": "v1", "minimum_reviewers": 1,
                                        "max_receipt_age_seconds": auth.MAX_AGE_SECONDS, "keys": entries}))
        return auth.authenticated_candidate(candidate, {"schema_version": "v1", "payload": payload, "signatures": signatures})

    def resign_payload(self, evidence):
        for signature in evidence["attestation"]["signatures"]:
            signature["signature"] = base64.b64encode(self.keys[signature["reviewer_id"]].sign(
                auth.signing_bytes(evidence["attestation"]["payload"]))).decode()


def synthetic_evidence():
    return {"rule_id": RULE, "rule_digest": DIGEST, "corpus": "synthetic-test-only", "split": "holdout",
            "sampling_plan": "Synthetic independent units, not a real population frame.",
            "observations": [{"id": f"test-{i}", "sampling_unit": f"synthetic-repo-{i}", "reviewer": "synthetic-reviewer",
                              "source": f"synthetic-pinned-source-{i}", "verdict": "true"} for i in range(100)],
            "collection_provenance": {"plan_id": "b" * 64, "collection_id": "c" * 64, "reviews_sha256": "d" * 64,
                                      "registration": {"plan_id": "b" * 64, "commit": "e" * 40, "path": "synthetic-plan.json"},
                                      "system": {"execution_sha256": "f" * 64}, "population": "synthetic-test-only",
                                      "registered_by": "synthetic-registrant", "review_identity_authenticated": False,
                                      "population_sampling_verified": False}}


@pytest.fixture
def signed(tmp_path):
    authority = SyntheticAuthority(tmp_path / "trusted.json")
    return authority, authority.sign(synthetic_evidence())


def verify(authority, evidence, **kwargs):
    return auth.verify_attestation(evidence, RULE, DIGEST, trust_store_path=authority.path, **kwargs)


def test_real_ed25519_signature_and_both_trust_roles_authenticate(signed):
    authority, evidence = signed
    result = verify(authority, evidence)
    assert result["review_identity_authenticated"] is result["population_sampling_verified"] is True
    assert result["population_verification"] == "trusted_human_audit"
    assert gate.evaluate_evidence(evidence, DIGEST, rule_id=RULE, trust_store_path=authority.path)["passed"]


def test_sampling_auditor_cannot_audit_their_own_observation_reviews():
    evidence = auth.authenticated_candidate(synthetic_evidence(), {})
    current = datetime.now(timezone.utc).replace(microsecond=0)
    with pytest.raises(ValueError, match="independent_of_observation_reviewers"):
        auth.prepare_payload(evidence, RULE,
                             issued_at=(current - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                             expires_at=(current + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                             auditor_id="synthetic-reviewer", audit_reference="self-audit")


@pytest.mark.parametrize("field", ["review_identity_authenticated", "population_sampling_verified"])
@pytest.mark.parametrize("value", [None, False, "true", 1])
def test_missing_false_or_coerced_trust_flags_cannot_validate(signed, field, value):
    authority, evidence = signed
    if value is None:
        evidence["collection_provenance"].pop(field)
    else:
        evidence["collection_provenance"][field] = value
    with pytest.raises(ValueError, match="not_authenticated|not_verified"):
        gate.evaluate_evidence(evidence, DIGEST, rule_id=RULE, trust_store_path=authority.path)


def test_true_flags_without_receipt_cannot_validate(signed):
    authority, evidence = signed
    evidence.pop("attestation")
    with pytest.raises(ValueError, match="missing_or_invalid_analysis_attestation"):
        verify(authority, evidence)


def test_empty_checked_in_store_rejects_even_a_cryptographically_valid_receipt(signed):
    _, evidence = signed
    assert auth.read_json(auth.TRUST_STORE)["keys"] == []
    with pytest.raises(ValueError, match="no_trusted_analysis_review_keys"):
        auth.verify_attestation(evidence, RULE, DIGEST)


@pytest.mark.parametrize("change", ["verdict", "source", "unit", "system", "population", "plan", "rule_id", "rule_digest"])
def test_complete_evidence_and_rule_identity_are_signed(signed, change):
    authority, evidence = signed
    if change in {"verdict", "source", "unit"}:
        evidence["observations"][0][{"unit": "sampling_unit"}.get(change, change)] = "false" if change == "verdict" else "changed"
    elif change == "system": evidence["collection_provenance"]["system"]["execution_sha256"] = "0" * 64
    elif change == "population": evidence["collection_provenance"]["population"] = "other"
    elif change == "plan": evidence["collection_provenance"]["plan_id"] = "0" * 64
    else: evidence[change] = "other" if change == "rule_id" else "0" * 64
    with pytest.raises(ValueError, match="mismatch|registration"):
        verify(authority, evidence)


def test_other_protocol_signature_cannot_be_replayed(signed):
    authority, _ = signed
    evidence = authority.sign(synthetic_evidence(), domain=b"mitig8it/remediation-release-evidence/v1\x00")
    with pytest.raises(ValueError, match="invalid_analysis_review_signature"):
        verify(authority, evidence)


@pytest.mark.parametrize("change,reason", [
    ("signature", "invalid_analysis_review_signature"), ("unknown_key", "unknown_or_revoked"),
    ("identity", "identity_mismatch"), ("duplicate_signature", "duplicate_analysis_review_signature"),
    ("missing_reviewer", "every_observation_reviewer"), ("missing_auditor", "sampling_auditor"),
    ("purpose", "invalid_analysis_attestation_payload"), ("unreviewed_author", "binding_mismatch"),
    ("audit_assertion", "missing_or_invalid_sampling_audit"), ("no_audit_reference", "missing_or_invalid_sampling_audit"),
])
def test_signature_coverage_and_explicit_sampling_audit_are_required(signed, change, reason):
    authority, evidence = signed
    receipt = evidence["attestation"]
    reviewer = next(s for s in receipt["signatures"] if s["reviewer_id"] == "synthetic-reviewer")
    if change == "signature": reviewer["signature"] = base64.b64encode(b"x" * 64).decode()
    elif change == "unknown_key": reviewer["key_id"] = "untrusted"
    elif change == "identity": reviewer["reviewer_id"] = "another-identity"
    elif change == "duplicate_signature": receipt["signatures"].append(deepcopy(reviewer))
    elif change == "missing_reviewer": receipt["signatures"].remove(reviewer)
    elif change == "missing_auditor": receipt["signatures"] = [reviewer]
    elif change == "purpose": receipt["payload"]["purpose"] = "mitig8it/remediation-release-evidence"
    elif change == "unreviewed_author": evidence["observations"][0]["reviewer"] = "unauthenticated-author"
    elif change == "audit_assertion":
        receipt["payload"]["sampling_audit"]["assertions"]["independent_sampling_units"] = False
        authority.resign_payload(evidence)
    elif change == "no_audit_reference":
        receipt["payload"]["sampling_audit"]["reference"] = ""
        authority.resign_payload(evidence)
    with pytest.raises(ValueError, match=reason):
        verify(authority, evidence)


@pytest.mark.parametrize("change,reason", [
    ("revoked", "unknown_or_revoked"), ("review_role", "every_observation_reviewer"),
    ("audit_role", "sampling_auditor"), ("duplicate_key", "duplicate_analysis_trusted_key"),
    ("minimum", "every_observation_reviewer"), ("age", "invalid_analysis_trust_policy"),
])
def test_trust_store_controls_roles_revocation_threshold_and_key_material(signed, change, reason):
    authority, evidence = signed
    store = json.loads(authority.path.read_text())
    reviewer = next(k for k in store["keys"] if k["reviewer_id"] == "synthetic-reviewer")
    auditor = next(k for k in store["keys"] if k["reviewer_id"] == "synthetic-sampling-auditor")
    if change == "revoked": reviewer["status"] = "revoked"
    elif change == "review_role": reviewer["roles"] = [auth.AUDIT_ROLE]
    elif change == "audit_role": auditor["roles"] = [auth.REVIEW_ROLE]
    elif change == "duplicate_key": store["keys"].append(deepcopy(reviewer))
    elif change == "minimum": store["minimum_reviewers"] = 2
    elif change == "age": store["max_receipt_age_seconds"] = auth.MAX_AGE_SECONDS + 1
    authority.path.write_text(json.dumps(store))
    with pytest.raises(ValueError, match=reason):
        verify(authority, evidence)


@pytest.mark.parametrize("offset", [-timedelta(days=1), timedelta(days=8)])
def test_future_or_expired_receipts_fail_closed(signed, offset):
    authority, evidence = signed
    with pytest.raises(ValueError, match="stale_or_future"):
        verify(authority, evidence, now=datetime.now(timezone.utc) + offset)


def test_signed_bad_statistics_still_fail(signed):
    authority, evidence = signed
    evidence["observations"][0]["verdict"] = "false"
    evidence = authority.sign(evidence)
    decision = gate.evaluate_evidence(evidence, DIGEST, rule_id=RULE, trust_store_path=authority.path)
    assert not decision["passed"]
    assert "precision_lower_bound_below_floor" in decision["reasons"]


def test_duplicate_json_keys_and_untrusted_embedded_key_are_rejected(signed):
    authority, evidence = signed
    authority.path.write_text('{"schema_version":"v1","schema_version":"v1"}')
    with pytest.raises(ValueError, match="duplicate_json_key"):
        verify(authority, evidence)
    evidence["attestation"]["public_key_base64"] = "untrusted-receipt-key"
    with pytest.raises(ValueError, match="missing_or_invalid_analysis_attestation"):
        verify(authority, evidence)


def test_signing_request_is_unsigned_and_cannot_overwrite(signed, tmp_path, capsys):
    _, evidence = signed
    evidence.pop("attestation")
    path, output = tmp_path / "candidate.json", tmp_path / "payload.json"
    path.write_text(json.dumps({"schema_version": "v1", "rules": {RULE: evidence}}))
    current = datetime.now(timezone.utc).replace(microsecond=0)
    args = ["--evidence", str(path), "--rule-id", RULE, "--issued-at", current.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "--expires-at", (current + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "--auditor-id", "synthetic-sampling-auditor", "--audit-reference", "synthetic-test-only", "--output", str(output)]
    assert auth.main(args) == 0
    assert json.loads(capsys.readouterr().out)["authenticated"] is False
    assert output.stat().st_mode & 0o777 == 0o600
    assert auth.main(args) == 2
