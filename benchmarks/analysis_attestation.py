"""Authenticate analysis observation reviews and a declared-population sampling audit.

An attestation authenticates accountable human assertions, not mathematical proof
of representativeness or independence. It never replaces the statistical gate.
Keys are enrolled only in the checked-in purpose-specific trust store; receipts
cannot enroll keys. No command reads private keys or signs on a reviewer's behalf.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any


TRUST_STORE = Path(__file__).resolve().parent / "rule-quality/trusted-reviewers.json"
DOMAIN = b"mitig8it/analysis-rule-publication/v1\x00"
PURPOSE = "mitig8it/analysis-rule-publication"
MAX_AGE_SECONDS = 30 * 24 * 60 * 60
REVIEW_ROLE = "analysis-observation-review"
AUDIT_ROLE = "analysis-sampling-audit"
AUDIT_ASSERTIONS = {
    "frame_matches_declared_population", "independent_sampling_units",
    "holdout_not_used_for_tuning", "sampling_plan_followed_without_outcome_selection",
    "registrant_identity_and_reviewer_independence_audited",
}
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:/@+-]{0,255}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")


class AttestationError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise AttestationError(reason)


def canonical_json(value: Any) -> bytes:
    def validate(item):
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is float:
            require(math.isfinite(item), "non_finite_json_number")
        elif type(item) is list:
            for child in item:
                validate(child)
        elif type(item) is dict:
            require(all(type(key) is str for key in item), "non_string_json_key")
            for child in item.values():
                validate(child)
        else:
            raise AttestationError("non_json_value")
    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def signing_bytes(payload: dict) -> bytes:
    return DOMAIN + canonical_json(payload)


def read_json(path: Path) -> Any:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(AttestationError("non_finite_json_number")))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise AttestationError("unreadable_attestation_document") from error


def _identifier(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def _timestamp(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None,
            "invalid_attestation_timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise AttestationError("invalid_attestation_timestamp") from error


def _base64(value, length, reason):
    require(isinstance(value, str), reason)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise AttestationError(reason) from error
    require(len(raw) == length and base64.b64encode(raw).decode("ascii") == value, reason)
    return raw


def authenticated_candidate(evidence: dict, receipt: dict) -> dict:
    """Prepare a candidate for verification; flags alone never authorize admission."""
    require(isinstance(evidence, dict) and isinstance(evidence.get("collection_provenance"), dict),
            "missing_collection_provenance")
    result = deepcopy(evidence)
    result["collection_provenance"].update(review_identity_authenticated=True, population_sampling_verified=True)
    result["attestation"] = deepcopy(receipt)
    return result


def bindings(evidence: dict, rule_id: str, rule_digest: str) -> dict:
    require(isinstance(evidence, dict) and _identifier(rule_id) and evidence.get("rule_id") == rule_id,
            "attestation_rule_identity_mismatch")
    require(isinstance(rule_digest, str) and HASH.fullmatch(rule_digest) is not None
            and evidence.get("rule_digest") == rule_digest, "attestation_rule_revision_mismatch")
    provenance = evidence.get("collection_provenance")
    require(isinstance(provenance, dict), "missing_collection_provenance")
    require(provenance.get("review_identity_authenticated") is True, "review_identity_not_authenticated")
    require(provenance.get("population_sampling_verified") is True, "population_sampling_not_verified")
    for field in ("plan_id", "collection_id", "reviews_sha256"):
        require(isinstance(provenance.get(field), str) and HASH.fullmatch(provenance[field]) is not None,
                f"missing_attested_{field}")
    registration, system = provenance.get("registration"), provenance.get("system")
    require(isinstance(registration, dict) and registration.get("plan_id") == provenance["plan_id"]
            and isinstance(registration.get("commit"), str) and re.fullmatch(r"[0-9a-f]{40}", registration["commit"]) is not None
            and isinstance(registration.get("path"), str) and bool(registration["path"]), "missing_attested_registration")
    require(isinstance(system, dict) and isinstance(system.get("execution_sha256"), str)
            and HASH.fullmatch(system["execution_sha256"]) is not None, "missing_attested_system")
    require(isinstance(provenance.get("population"), str) and bool(provenance["population"].strip())
            and _identifier(provenance.get("registered_by")), "missing_attested_population_or_registrant")
    rows = evidence.get("observations")
    require(isinstance(rows, list) and bool(rows) and all(isinstance(row, dict) for row in rows), "missing_attested_observations")
    reviewers = sorted({row.get("reviewer") for row in rows if _identifier(row.get("reviewer"))})
    require(bool(reviewers) and all(row.get("reviewer") in reviewers for row in rows), "invalid_attested_reviewer")
    require(len(reviewers) == len({reviewer.casefold() for reviewer in reviewers}), "ambiguous_attested_reviewer_identity")
    require(all(reviewer.casefold() != provenance["registered_by"].casefold() for reviewer in reviewers),
            "registrant_cannot_review_own_study")
    return {"rule_id": rule_id, "rule_digest": rule_digest,
            "evidence_digest": digest({key: value for key, value in evidence.items() if key != "attestation"}),
            "reviewer_ids": reviewers}


def prepare_payload(evidence: dict, rule_id: str, *, issued_at: str, expires_at: str,
                    auditor_id: str, audit_reference: str) -> dict:
    """Produce an unsigned signing request; it authenticates nothing by itself."""
    candidate = authenticated_candidate(evidence, {})
    expected = bindings(candidate, rule_id, candidate.get("rule_digest"))
    require(_identifier(auditor_id) and auditor_id.casefold() != candidate["collection_provenance"]["registered_by"].casefold(),
            "invalid_sampling_auditor")
    require(auditor_id.casefold() not in {reviewer.casefold() for reviewer in expected["reviewer_ids"]},
            "sampling_auditor_must_be_independent_of_observation_reviewers")
    require(isinstance(audit_reference, str) and bool(audit_reference.strip()), "missing_sampling_audit_reference")
    issued, expires = _timestamp(issued_at), _timestamp(expires_at)
    require(0 < (expires - issued).total_seconds() <= MAX_AGE_SECONDS, "invalid_attestation_lifetime")
    return {"schema_version": "v1", "purpose": PURPOSE, **expected, "issued_at": issued_at, "expires_at": expires_at,
            "sampling_audit": {"auditor_id": auditor_id, "reference": audit_reference,
                              "assertions": {assertion: True for assertion in sorted(AUDIT_ASSERTIONS)}}}


def verify_attestation(evidence: dict, rule_id: str, rule_digest: str, *,
                       trust_store_path: Path = TRUST_STORE, now: datetime | None = None) -> dict:
    expected = bindings(evidence, rule_id, rule_digest)
    receipt = evidence.get("attestation")
    require(isinstance(receipt, dict) and set(receipt) == {"schema_version", "payload", "signatures"}
            and receipt["schema_version"] == "v1", "missing_or_invalid_analysis_attestation")
    payload = receipt["payload"]
    require(isinstance(payload, dict) and set(payload) == {"schema_version", "purpose", "issued_at", "expires_at", "sampling_audit", *expected}
            and payload["schema_version"] == "v1" and payload["purpose"] == PURPOSE, "invalid_analysis_attestation_payload")
    for key, value in expected.items():
        require(canonical_json(payload[key]) == canonical_json(value), f"analysis_attestation_binding_mismatch:{key}")
    store = read_json(trust_store_path)
    require(isinstance(store, dict) and set(store) == {"schema_version", "minimum_reviewers", "max_receipt_age_seconds", "keys"}
            and store["schema_version"] == "v1", "invalid_analysis_trust_store")
    minimum, age = store["minimum_reviewers"], store["max_receipt_age_seconds"]
    require(type(minimum) is int and minimum >= 1 and type(age) is int and 1 <= age <= MAX_AGE_SECONDS,
            "invalid_analysis_trust_policy")
    require(isinstance(store["keys"], list) and bool(store["keys"]), "no_trusted_analysis_review_keys")
    keys, materials = {}, set()
    for key in store["keys"]:
        require(isinstance(key, dict) and set(key) == {"key_id", "reviewer_id", "algorithm", "status", "public_key_base64", "roles"},
                "invalid_analysis_trusted_key")
        require(_identifier(key["key_id"]) and _identifier(key["reviewer_id"]) and key["algorithm"] == "ed25519"
                and isinstance(key["status"], str) and key["status"] in {"active", "revoked"}, "invalid_analysis_trusted_key")
        require(isinstance(key["roles"], list) and bool(key["roles"]) and all(isinstance(role, str) for role in key["roles"])
                and len(key["roles"]) == len(set(key["roles"])) and set(key["roles"]) <= {REVIEW_ROLE, AUDIT_ROLE},
                "invalid_analysis_key_roles")
        material = _base64(key["public_key_base64"], 32, "invalid_analysis_public_key")
        require(key["key_id"] not in keys and material not in materials, "duplicate_analysis_trusted_key")
        keys[key["key_id"]] = key
        materials.add(material)
    issued, expires = _timestamp(payload["issued_at"]), _timestamp(payload["expires_at"])
    current = now or datetime.now(timezone.utc)
    require(isinstance(current, datetime) and current.tzinfo is not None, "verification_time_must_be_timezone_aware")
    require(issued <= current < expires and 0 < (expires - issued).total_seconds() <= age
            and (current - issued).total_seconds() <= age, "stale_or_future_analysis_attestation")
    audit = payload["sampling_audit"]
    require(isinstance(audit, dict) and set(audit) == {"auditor_id", "reference", "assertions"}
            and _identifier(audit["auditor_id"]) and isinstance(audit["reference"], str) and bool(audit["reference"].strip())
            and isinstance(audit["assertions"], dict) and set(audit["assertions"]) == AUDIT_ASSERTIONS
            and all(value is True for value in audit["assertions"].values()), "missing_or_invalid_sampling_audit")
    require(audit["auditor_id"].casefold() != evidence["collection_provenance"]["registered_by"].casefold(),
            "registrant_cannot_audit_own_study")
    require(audit["auditor_id"].casefold() not in {reviewer.casefold() for reviewer in expected["reviewer_ids"]},
            "sampling_auditor_must_be_independent_of_observation_reviewers")
    signatures = receipt["signatures"]
    require(isinstance(signatures, list) and bool(signatures), "missing_analysis_review_signatures")
    # Lazy import keeps ordinary compatibility checks usable without installing
    # release-only crypto dependencies. Authenticated promotion requires them.
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise AttestationError("analysis_attestation_dependency_missing") from error
    signed_keys, signers = set(), {}
    for signature in signatures:
        require(isinstance(signature, dict) and set(signature) == {"algorithm", "key_id", "reviewer_id", "signature"}
                and signature["algorithm"] == "ed25519" and _identifier(signature["key_id"])
                and _identifier(signature["reviewer_id"]), "invalid_analysis_signature_record")
        key_id, reviewer = signature["key_id"], signature["reviewer_id"]
        require(key_id not in signed_keys and reviewer not in signers, "duplicate_analysis_review_signature")
        key = keys.get(key_id)
        require(key is not None and key["status"] == "active", "unknown_or_revoked_analysis_review_key")
        require(key["reviewer_id"] == reviewer, "analysis_reviewer_key_identity_mismatch")
        try:
            Ed25519PublicKey.from_public_bytes(_base64(key["public_key_base64"], 32, "invalid_analysis_public_key")).verify(
                _base64(signature["signature"], 64, "invalid_analysis_signature_base64"), signing_bytes(payload))
        except InvalidSignature as error:
            raise AttestationError("invalid_analysis_review_signature") from error
        signed_keys.add(key_id)
        signers[reviewer] = set(key["roles"])
    reviewers = expected["reviewer_ids"]
    require(len(reviewers) >= minimum and all(REVIEW_ROLE in signers.get(reviewer, set()) for reviewer in reviewers),
            "every_observation_reviewer_must_authenticate")
    require(AUDIT_ROLE in signers.get(audit["auditor_id"], set()), "sampling_auditor_must_authenticate")
    require(set(signers) == set(reviewers) | {audit["auditor_id"]}, "unexpected_analysis_signer")
    return {"review_identity_authenticated": True, "population_sampling_verified": True,
            "attestation_digest": digest(receipt), "reviewers": reviewers, "sampling_auditor": audit["auditor_id"],
            "expires_at": payload["expires_at"], "population_verification": "trusted_human_audit"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True, help="Unsigned evidence-candidate document")
    parser.add_argument("--rule-id", required=True)
    parser.add_argument("--issued-at", required=True, help="UTC YYYY-MM-DDTHH:MM:SSZ")
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--auditor-id", required=True)
    parser.add_argument("--audit-reference", required=True, help="Durable independent sampling-audit review reference")
    parser.add_argument("--output", type=Path, required=True, help="New unsigned signing-payload file")
    args = parser.parse_args(argv)
    try:
        document = read_json(args.evidence)
        require(isinstance(document, dict) and document.get("schema_version") == "v1"
                and isinstance(document.get("rules"), dict), "invalid_evidence_document")
        payload = prepare_payload(document["rules"][args.rule_id], args.rule_id, issued_at=args.issued_at,
                                  expires_at=args.expires_at, auditor_id=args.auditor_id, audit_reference=args.audit_reference)
        # Source/review material is sensitive; never overwrite a prior request.
        import os
        with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            output.write(canonical_json(payload) + b"\n")
        print(json.dumps({"authenticated": False, "production_ready": False, "output": str(args.output)}))
        return 0
    except (ValueError, TypeError, KeyError, OSError) as error:
        print(json.dumps({"authenticated": False, "production_ready": False, "reason": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
