"""Synthetic-only workflow tests. No observation here is release evidence."""
from copy import deepcopy
import base64
from datetime import datetime, timedelta, timezone
import difflib
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from benchmarks import analysis_evidence as evidence
from benchmarks import rule_quality_gate
from benchmarks.test_analysis_attestation import SyntheticAuthority


RULE = evidence.EXAMPLE_RULE
PATH = ".github/workflows/check.yml"
BASE = "name: check\non: push\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
HEAD = BASE + "      - uses: codecov/codecov-action@v5\n"
PATCH = "\n".join(list(difflib.unified_diff(BASE.splitlines(), HEAD.splitlines(), lineterm=""))[2:])
SYSTEM = {"source_revision": "c" * 40, "execution_sha256": "d" * 64,
          "configuration": {"triage": "not_called"}, "scanner": {"version": "synthetic"}}


def blob(content):
    raw = content.encode()
    return {"type": "file", "path": PATH, "encoding": "base64", "content": base64.b64encode(raw).decode(),
            "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def specification(size=100, frame_size=None):
    return {"rule_id": RULE, "corpus": "synthetic-test-only", "population": "synthetic unit test frame, not real evidence",
            "sampling_plan": "Synthetic tests of fixed one-repository/one-prediction selection; not a production sample.",
            "registered_by": "synthetic-registrant", "selection_seed": "synthetic-seed", "sample_size": size,
            "frame": [{"repo": f"example/project-{i}", "pr": i + 1, "head_sha": "a" * 40,
                       "base_sha": "b" * 40, "independence_group": f"synthetic-group-{i}"}
                      for i in range(frame_size or size)]}


def finding(**overrides):
    return {"rule_id": RULE, "fingerprint": "synthetic-fingerprint", "file_path": PATH,
            "line_start": 8, "line_end": 8, "code_snippet": HEAD.splitlines()[7],
            "internal_type": "unpinned_workflow_action", **overrides}


class Reader:
    def __init__(self, frame):
        self.frame = {unit["repo"]: unit for unit in frame}
        self.calls = []
        self.change = None

    def get(self, endpoint, paginate=False):
        self.calls.append((endpoint, paginate))
        parts = endpoint.split("/")
        repo = "/".join(parts[1:3])
        unit = self.frame[repo]
        if endpoint.endswith("/files?per_page=100"):
            result = [{"filename": PATH, "status": "modified", "sha": blob(HEAD)["sha"],
                       "patch": PATCH, "additions": 1, "deletions": 0}]
        elif "/pulls/" in endpoint:
            result = {"number": unit["pr"], "merged_at": "2026-01-01T00:00:00Z", "changed_files": 1,
                      "head": {"sha": unit["head_sha"]},
                      "base": {"sha": unit["base_sha"], "repo": {"full_name": repo}}}
        else:
            assert "/contents/" in endpoint
            result = blob(HEAD if endpoint.endswith("a" * 40) else BASE)
        if self.change:
            result = self.change(endpoint, deepcopy(result))
        return result


@pytest.fixture
def harness(monkeypatch):
    monkeypatch.setattr(evidence, "current_system", lambda: deepcopy(SYSTEM))
    monkeypatch.setattr(evidence, "_workflow_rule", lambda rule: "e" * 64)
    monkeypatch.setattr(evidence, "registered_plan", lambda _path, plan: {
        "path": "benchmarks/rule-quality/test-frame.json", "commit": "f" * 40, "plan_id": plan["plan_id"]})
    scanner = Mock(return_value=([finding()], []))
    monkeypatch.setattr(evidence, "scan", scanner)
    plan = evidence.preregister(specification())
    reader = Reader(plan["frame"])
    registration = evidence.registered_plan(Path("unused"), plan)
    collected = evidence.collect(plan, registration, reader)
    return SimpleNamespace(plan=plan, reader=reader, collected=collected, scanner=scanner)


def seal(document, field):
    return evidence.sealed({key: value for key, value in document.items() if key != field}, field)


def reviewed(harness):
    queue = evidence.review_queue(harness.plan, harness.collected)
    for row in queue["observations"]:
        row.update(verdict="true", reviewer="synthetic-other-reviewer", reviewed_at=evidence.now(),
                   review_note="Synthetic test assertion, not an actual independent review.")
    return queue


def test_preregistered_exact_frame_collects_pinned_source_and_real_unjudged_queue(harness):
    h = harness
    assert len(h.collected["units"]) == len(h.collected["selection"]) == 100
    assert h.collected["selection_complete"]
    queue = evidence.review_queue(h.plan, h.collected)
    assert all(row["verdict"] is row["reviewer"] is row["reviewed_at"] is None for row in queue["observations"])
    assert len({row["sampling_unit"] for row in queue["observations"]}) == 100
    source = h.collected["units"][0]["sources"][0]
    assert source["head"]["content"] == HEAD and source["base"]["content"] == BASE
    assert source["head"]["sha256"] == hashlib.sha256(HEAD.encode()).hexdigest()
    assert any(endpoint.endswith("?ref=" + "a" * 40) for endpoint, _ in h.reader.calls)
    assert any(endpoint.endswith("?ref=" + "b" * 40) for endpoint, _ in h.reader.calls)


def test_successful_import_is_deterministic_and_does_not_mutate_destination(harness):
    reviews = reviewed(harness)
    existing = {"schema_version": "v1", "rules": {"unrelated": {"kept": True}}}
    before = deepcopy(existing)
    result, decision = evidence.import_reviews(harness.plan, harness.collected, reviews, existing)
    assert not decision["passed"] and decision["precision_gate"]["reviewed_predictions"] == 100
    assert decision["precision_gate"]["precision_wilson_95"][0] > 0.95
    with pytest.raises(ValueError, match="review_identity_not_authenticated"):
        rule_quality_gate.evaluate_evidence(result["rules"][RULE], harness.plan["rule_digest"], rule_id=RULE)
    assert existing == before
    reviews["observations"].reverse()
    again, _ = evidence.import_reviews(harness.plan, harness.collected, reviews, existing)
    assert result == again
    idempotent, _ = evidence.import_reviews(harness.plan, harness.collected, reviews, result)
    assert idempotent == result
    provenance = result["rules"][RULE]["collection_provenance"]
    assert provenance["review_identity_authenticated"] is provenance["population_sampling_verified"] is False
    assert provenance["reviews_sha256"] and provenance["limitations"]


def test_import_revalidates_source_then_authenticates_exact_signed_candidate(harness, tmp_path, monkeypatch):
    reviews = reviewed(harness)
    existing = {"schema_version": "v1", "rules": {}}
    unsigned, _ = evidence.import_reviews(harness.plan, harness.collected, reviews, existing)
    authority = SyntheticAuthority(tmp_path / "trusted-analysis.json")
    signed = authority.sign(unsigned["rules"][RULE])
    monkeypatch.setattr(rule_quality_gate, "TRUST_STORE", authority.path)
    result, decision = evidence.import_reviews(harness.plan, harness.collected, reviews, existing,
                                              attestation=signed["attestation"])
    assert decision["passed"]
    assert result["rules"][RULE] == signed
    assert decision["authentication"]["population_verification"] == "trusted_human_audit"
    # Correct signatures never allow a modified review or collection to import.
    reviews["observations"][0]["review_note"] += " modified"
    with pytest.raises(ValueError, match="binding_mismatch:evidence_digest"):
        evidence.import_reviews(harness.plan, harness.collected, reviews, existing, attestation=signed["attestation"])


def test_import_rejects_receipt_from_unenrolled_reviewers(harness, tmp_path):
    reviews = reviewed(harness)
    existing = {"schema_version": "v1", "rules": {}}
    unsigned, _ = evidence.import_reviews(harness.plan, harness.collected, reviews, existing)
    authority = SyntheticAuthority(tmp_path / "untrusted-analysis.json")
    signed = authority.sign(unsigned["rules"][RULE])
    with pytest.raises(ValueError, match="no_trusted_analysis_review_keys"):
        evidence.import_reviews(harness.plan, harness.collected, reviews, existing, attestation=signed["attestation"])


def test_99_of_100_cannot_pass_unmodified_wilson_floor(harness):
    reviews = reviewed(harness)
    reviews["observations"][0]["verdict"] = "false"
    with pytest.raises(evidence.EvidenceError, match="precision_gate_failed:precision_lower_bound_below_floor"):
        evidence.import_reviews(harness.plan, harness.collected, reviews, {"schema_version": "v1", "rules": {}})


@pytest.mark.parametrize("change,reason", [
    ("missing", "missing_or_duplicate_review_rows"), ("duplicate", "duplicate_or_invalid_review_id"),
    ("uncertain", "unresolved_review_judgment"), ("null", "unresolved_review_judgment"),
    ("stale_digest", "stale_review_document"), ("binding", "modified_or_stale_review_binding"),
    ("registrant", "reviewer_must_differ"), ("no_note", "reviewer_must_differ"),
    ("old_time", "invalid_review_time"), ("future_time", "invalid_review_time"),
])
def test_review_rows_fail_closed_without_omitting_bad_judgments(harness, change, reason):
    reviews = reviewed(harness)
    if change == "missing": reviews["observations"].pop()
    elif change == "duplicate": reviews["observations"][1] = deepcopy(reviews["observations"][0])
    elif change == "uncertain": reviews["observations"][0]["verdict"] = "uncertain"
    elif change == "null": reviews["observations"][0]["verdict"] = None
    elif change == "stale_digest": reviews["collection_id"] = "0" * 64
    elif change == "binding": reviews["observations"][0]["head_sha"] = "0" * 40
    elif change == "registrant": reviews["observations"][0]["reviewer"] = "SYNTHETIC-REGISTRANT"
    elif change == "no_note": reviews["observations"][0]["review_note"] = ""
    elif change == "old_time": reviews["observations"][0]["reviewed_at"] = "2020-01-01T00:00:00Z"
    elif change == "future_time": reviews["observations"][0]["reviewed_at"] = "2999-01-01T00:00:00Z"
    with pytest.raises(evidence.EvidenceError, match=reason):
        evidence.import_reviews(harness.plan, harness.collected, reviews, {"schema_version": "v1", "rules": {}})


@pytest.mark.parametrize("change", ["missing", "duplicate", "reordered", "source", "patch", "selection", "registration", "system_metadata"])
def test_resealed_modified_or_incomplete_collections_are_still_rejected(harness, change):
    collected = deepcopy(harness.collected)
    if change == "missing": collected["units"].pop()
    elif change == "duplicate": collected["units"][1] = deepcopy(collected["units"][0])
    elif change == "reordered": collected["units"].reverse()
    elif change == "source": collected["units"][0]["sources"][0]["head"]["content"] += "# changed\n"
    elif change == "patch": collected["units"][0]["sources"][0]["patch"] += "+# changed"
    elif change == "selection": collected["selection"][0] = deepcopy(collected["selection"][1])
    elif change == "registration": collected["registration"]["commit"] = "0" * 40
    elif change == "system_metadata": collected["system"]["configuration"]["triage"] = "invented"
    with pytest.raises(evidence.EvidenceError):
        evidence.review_queue(harness.plan, seal(collected, "collection_id"))


def test_import_reexecutes_scanner_and_refuses_invented_observations(harness):
    harness.scanner.return_value = ([], [])
    with pytest.raises(evidence.EvidenceError, match="stale_or_invented_scanner_observations"):
        evidence.import_reviews(harness.plan, harness.collected, reviewed(harness), {"schema_version": "v1", "rules": {}})


def test_any_partial_failed_or_missing_scan_blocks_collection(harness):
    harness.scanner.return_value = ([finding()], [{"kind": "partial_parse", "path": PATH}])
    with pytest.raises(evidence.EvidenceError, match="incomplete_scanner_coverage"):
        evidence.collect(harness.plan, harness.collected["registration"], harness.reader)


def test_zero_predictions_preserve_all_units_but_cannot_generate_a_complete_review_queue(harness):
    harness.scanner.return_value = ([], [])
    collected = evidence.collect(harness.plan, harness.collected["registration"], harness.reader)
    assert len(collected["units"]) == 100 and not collected["selection_complete"]
    with pytest.raises(evidence.EvidenceError, match="prediction_selection"):
        evidence.review_queue(harness.plan, collected)


def test_duplicate_alerts_cannot_inflate_independent_sample_count(harness):
    harness.scanner.return_value = ([finding(), finding()], [])
    with pytest.raises(evidence.EvidenceError, match="duplicate_finding_identity"):
        evidence.collect(harness.plan, harness.collected["registration"], harness.reader)


@pytest.mark.parametrize("change", ["duplicate_repo", "duplicate_lineage", "wrong_ref", "minimum", "smaller_frame", "case_alias"])
def test_invalid_frame_or_sample_size_cannot_be_preregistered(harness, change):
    spec = specification()
    if change == "duplicate_repo": spec["frame"][1]["repo"] = spec["frame"][0]["repo"]
    elif change == "duplicate_lineage": spec["frame"][1]["independence_group"] = spec["frame"][0]["independence_group"]
    elif change == "wrong_ref": spec["frame"][0]["head_sha"] = "main"
    elif change == "minimum": spec["sample_size"] = 99
    elif change == "smaller_frame": spec["frame"].pop()
    elif change == "case_alias": spec["frame"][0]["repo"] = "Example/project-0"
    with pytest.raises(evidence.EvidenceError):
        evidence.preregister(spec)


def test_seeded_selection_is_stable_one_alert_per_repo_and_not_population_sampling_proof(harness):
    units = deepcopy(harness.collected["units"])
    for unit in units:
        unit["findings"].append(finding(fingerprint="second-fingerprint"))
    first = evidence.selection(harness.plan, units)
    for unit in units: unit["findings"].reverse()
    assert evidence.selection(harness.plan, list(reversed(units))) == first
    assert len(first) == len({row["sampling_unit"] for row in first}) == 100


def test_fixed_sample_keeps_all_frame_units_and_selects_only_the_preregistered_number(harness):
    plan = evidence.preregister(specification(frame_size=110))
    harness.scanner.reset_mock()
    collected = evidence.collect(plan, evidence.registered_plan(Path("unused"), plan), Reader(plan["frame"]))
    assert harness.scanner.call_count == len(collected["units"]) == 110
    assert len(collected["selection"]) == 100
    assert len({row["sampling_unit"] for row in collected["selection"]}) == 100
    assert evidence.review_queue(plan, collected)["collection_id"] == collected["collection_id"]


def test_missing_pr_stale_ref_truncated_files_and_corrupt_blob_cannot_be_skipped(harness):
    frame = harness.plan["frame"][0]
    mutations = [
        lambda endpoint, value: {**value, "head": {"sha": "0" * 40}} if "/pulls/" in endpoint and isinstance(value, dict) else value,
        lambda endpoint, value: [] if "/files?" in endpoint else value,
        lambda endpoint, value: {**value, "sha": "0" * 40} if "/contents/" in endpoint else value,
    ]
    for mutation in mutations:
        harness.reader.change = mutation
        with pytest.raises(evidence.EvidenceError):
            evidence.fetch_unit(harness.reader, frame)
    harness.reader.change = lambda _endpoint, _value: None
    with pytest.raises(Exception, match="requested PR"):
        evidence.fetch_unit(harness.reader, frame)


@pytest.mark.parametrize("change", ["head", "base", "truncated", "counts"])
def test_diff_must_match_both_exact_source_versions_and_all_change_counts(change):
    patch, before, after, added = PATCH, BASE, HEAD, 1
    if change == "head": after = HEAD.replace("codecov", "changed")
    elif change == "base": before = BASE.replace("checkout", "changed")
    elif change == "truncated": patch = PATCH.rsplit("\n", 1)[0]
    elif change == "counts": added = 2
    with pytest.raises(evidence.EvidenceError):
        evidence.verify_patch(patch, before, after, added, 0)
    evidence.verify_patch(PATCH + "\n", BASE, HEAD, 1, 0)


def test_configuration_or_rule_changes_invalidate_collection_and_reviews(harness, monkeypatch):
    monkeypatch.setattr(evidence, "current_system", lambda: {**SYSTEM, "execution_sha256": "0" * 64})
    with pytest.raises(evidence.EvidenceError, match="stale_system_or_configuration"):
        evidence.review_queue(harness.plan, harness.collected)
    monkeypatch.setattr(evidence, "current_system", lambda: deepcopy(SYSTEM))
    monkeypatch.setattr(evidence, "_workflow_rule", lambda _: "0" * 64)
    with pytest.raises(evidence.EvidenceError, match="stale_rule_definition"):
        evidence.review_queue(harness.plan, harness.collected)


def test_json_duplicate_keys_and_overwrite_are_refused(tmp_path):
    path = tmp_path / "input.json"
    path.write_text('{"frame": [], "frame": []}')
    with pytest.raises(evidence.EvidenceError, match="duplicate_json_key"):
        evidence.read(path)
    with pytest.raises(FileExistsError):
        evidence.write_new(path, {"overwritten": True})


def test_registration_requires_exact_plan_already_committed(harness, monkeypatch):
    monkeypatch.undo()
    # Restore only the external Git boundary; exercise actual registration checks.
    git = Mock(side_effect=[json.dumps(harness.plan), "f" * 40])
    monkeypatch.setattr(evidence, "_git", git)
    registration = evidence.registered_plan(evidence.ROOT / "benchmarks/rule-quality/plan.json", harness.plan)
    assert registration["commit"] == "f" * 40
    git.side_effect = ["{}"]
    with pytest.raises(evidence.EvidenceError, match="committed_and_unchanged"):
        evidence.registered_plan(evidence.ROOT / "benchmarks/rule-quality/plan.json", harness.plan)


def test_cli_never_writes_canonical_evidence_and_reports_unauthenticated_identity(harness, monkeypatch, tmp_path, capsys):
    plan = tmp_path / "plan.json"
    collection = tmp_path / "collection.json"
    reviews = tmp_path / "reviews.json"
    existing = tmp_path / "evidence.json"
    output = tmp_path / "candidate.json"
    for path, document in [(plan, harness.plan), (collection, harness.collected), (reviews, reviewed(harness)),
                           (existing, {"schema_version": "v1", "rules": {}})]:
        path.write_text(json.dumps(document))
    assert evidence.main(["import", "--plan", str(plan), "--collection", str(collection), "--reviews", str(reviews),
                          "--evidence", str(existing), "--output", str(output)]) == 0
    assert json.loads(existing.read_text())["rules"] == {}
    assert RULE in json.loads(output.read_text())["rules"]
    status = json.loads(capsys.readouterr().out)
    assert status["review_identity_authenticated"] is status["population_sampling_verified"] is False
    assert status["publication_evidence_validated"] is False
    assert not status["production_ready"]


def test_cli_signed_import_authenticates_and_tampered_receipt_never_writes(harness, monkeypatch, tmp_path, capsys):
    reviews_doc = reviewed(harness)
    existing_doc = {"schema_version": "v1", "rules": {}}
    candidate, _ = evidence.import_reviews(harness.plan, harness.collected, reviews_doc, existing_doc)
    authority = SyntheticAuthority(tmp_path / "trusted-analysis.json")
    signed = authority.sign(candidate["rules"][RULE])
    monkeypatch.setattr(rule_quality_gate, "TRUST_STORE", authority.path)
    paths = {name: tmp_path / f"{name}.json" for name in ("plan", "collection", "reviews", "evidence", "attestation")}
    for name, document in zip(paths, [harness.plan, harness.collected, reviews_doc, existing_doc, signed["attestation"]]):
        paths[name].write_text(json.dumps(document))
    output = tmp_path / "authenticated-candidate.json"
    args = ["import"]
    for name, path in paths.items():
        args.extend([f"--{name}", str(path)])
    assert evidence.main([*args, "--output", str(output)]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["publication_evidence_validated"] is True
    assert status["review_identity_authenticated"] is status["population_sampling_verified"] is True
    assert status["production_ready"] is False
    assert json.loads(output.read_text())["rules"][RULE] == signed
    assert json.loads(paths["evidence"].read_text()) == existing_doc
    receipt = signed["attestation"]
    receipt["payload"]["evidence_digest"] = "sha256:" + "0" * 64
    paths["attestation"].write_text(json.dumps(receipt))
    rejected = tmp_path / "rejected.json"
    assert evidence.main([*args, "--output", str(rejected)]) == 2
    assert not rejected.exists()
    assert json.loads(capsys.readouterr().err)["passed"] is False


def test_system_provenance_binds_code_scanner_dependencies_and_configuration(monkeypatch, tmp_path):
    import sys
    scanner = tmp_path / "bin/semgrep"
    scanner.parent.mkdir()
    scanner.write_bytes(b"synthetic scanner artifact")
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    monkeypatch.setattr(evidence.shutil, "which", lambda _: str(scanner))
    monkeypatch.setitem(sys.modules, "opengrep_runner", SimpleNamespace(
        SCANNER_EXECUTABLE="semgrep", batch_max_files=lambda: 25, batch_max_bytes=lambda: 1048576))
    monkeypatch.setitem(sys.modules, "workflow_action_digest", SimpleNamespace(lookup_enabled=lambda: False))
    monkeypatch.setattr(evidence.subprocess, "run", Mock(return_value=SimpleNamespace(returncode=0, stdout="synthetic-version\n")))
    monkeypatch.setattr(evidence.platform, "platform", lambda: "synthetic-platform")
    monkeypatch.setattr(evidence, "_git", lambda *args: "c" * 40 if args[0] == "rev-parse" else "")
    monkeypatch.setattr(evidence, "load_rules", lambda: {RULE: {"rule_digest": "e" * 64}})
    monkeypatch.setattr(evidence.importlib.metadata, "distributions", lambda: [SimpleNamespace(
        metadata={"Name": "synthetic-package"}, version="1.0", read_text=lambda _: "synthetic-wheel-record")])
    first = evidence.current_system()
    assert first["scanner"]["sha256"] == evidence.bytes_digest(scanner.read_bytes())
    assert first["packages"][0][2] == evidence.bytes_digest(b"synthetic-wheel-record")
    assert "services/analysis-service/src/opengrep_rules/workflow_coverage.yml" in first["checkout_files"]
    assert first["configuration"]["triage"] == "not_called"
    monkeypatch.setenv("OPENGREP_BATCH_MAX_FILES", "26")
    assert evidence.current_system()["execution_sha256"] != first["execution_sha256"]
    monkeypatch.setattr(evidence, "_git", lambda *args: "?? benchmarks/analysis_evidence.py" if args[0] == "status" else "c" * 40)
    with pytest.raises(evidence.EvidenceError, match="commit_measurement_code"):
        evidence.current_system()


def test_cli_collection_failure_never_writes_success_artifact_or_calls_another_unit(harness, monkeypatch, tmp_path, capsys):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(harness.plan))
    reader = Mock()
    reader.get.side_effect = evidence.EvidenceError("requested_source_unavailable")
    monkeypatch.setattr(evidence, "GitHubReader", lambda *_args, **_kwargs: reader)
    output = tmp_path / "collection.json"
    assert evidence.main(["collect", "--plan", str(plan), "--output", str(output)]) == 2
    assert reader.get.call_count == 1 and not output.exists()
    assert not json.loads(capsys.readouterr().err)["passed"]
