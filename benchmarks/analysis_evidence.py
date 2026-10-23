"""Preregister, collect, review and import exact-revision workflow-rule evidence.

No command invents judgments or promotes a rule automatically. Collection is a
read-only GitHub operation and scans source as data, never executes that source.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import quote

from benchmarks.quality_gate import MINIMUM_PRECISION_SAMPLES
from benchmarks.rule_quality_gate import ROOT, SOURCE, evaluate_evidence, evaluate_precision_evidence, load_rules
from benchmarks.analysis_attestation import authenticated_candidate
from scripts.replay.replay import GitHubError, GitHubReader, requested_pull_requests
from scripts.replay import prodfilters


SCHEMA = "analysis-rule-study-v1"
EXAMPLE_RULE = "opengrep.cwe-1357.gha-third-party-action-unpinned"
SHA = re.compile(r"[0-9a-f]{40}")
HASH = re.compile(r"[0-9a-f]{64}")
REPO = re.compile(r"[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*")
HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*")
REVIEW_FIELDS = {"verdict", "reviewer", "reviewed_at", "review_note"}
LIMITATIONS = [
    "Unsigned reviewer identifiers are unauthenticated. Publication requires every named reviewer to sign with a trusted observation-review key.",
    "Frame composition, population representativeness, and repository/fork independence require a trusted signed human audit, not mechanical proof.",
    "Seeded selection is deterministic within the committed frame, not proof of random sampling from a production population.",
    "Local Git commits and SHA-256 digests bind artifacts but are not signatures, trusted timestamps, or authenticated GitHub execution attestations.",
    "This study measures a deterministic Tier 2 workflow rule, not end-to-end Tier 3, recall, repair, or publication accuracy.",
]


class EvidenceError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise EvidenceError(code)


def text(value):
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def bytes_digest(value):
    return hashlib.sha256(value).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def timestamp(value):
    require(isinstance(value, str), "invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError("invalid_timestamp") from error
    require(parsed.tzinfo is not None, "timestamp_requires_timezone")
    return parsed


def canonical_path(value):
    return (text(value) and "\\" not in value and not value.startswith("/")
            and ".." not in value.split("/") and str(PurePosixPath(value)) == value)


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("nonfinite_json")))


def sealed(document, field):
    result = dict(document)
    result[field] = digest(document)
    return result


def verify_seal(document, field):
    require(isinstance(document, dict) and document.get(field) == digest({k: v for k, v in document.items() if k != field}),
            f"invalid_{field}")


def write_new(path, document):
    """Immutable-by-default, private local artifacts; never replace a frozen plan."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def _git(*args):
    result = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, "git_provenance_unavailable")
    return result.stdout.strip()


def current_system():
    """Bind matching code, all rule definitions, dependencies, scanner and effective config."""
    sys.path.insert(0, str(SOURCE))
    try:
        import opengrep_runner as runner
        import workflow_action_digest
    finally:
        sys.path.remove(str(SOURCE))
    require(not workflow_action_digest.lookup_enabled(), "disable_workflow_action_digest_lookup_for_measurement")
    scanner = shutil.which(runner.SCANNER_EXECUTABLE)
    require(scanner is not None, "scanner_unavailable")
    scanner = str(Path(scanner).resolve())
    require(Path(scanner).is_relative_to(Path(sys.prefix).resolve()),
            "activate_the_analysis_environment_so_scanner_and_python_share_a_prefix")
    version = subprocess.run([scanner, "--version", "--disable-version-check"], capture_output=True,
                             text=True, timeout=30)
    require(version.returncode == 0 and text(version.stdout.strip()), "scanner_version_unavailable")
    paths = [p for p in SOURCE.rglob("*") if p.is_file() and "tests" not in p.parts
             and p.suffix in {".py", ".json", ".yml", ".yaml", ".txt"} and "__pycache__" not in p.parts]
    paths += [Path(__file__), ROOT / "scripts/replay/ghcache.py", ROOT / "scripts/replay/prodfilters.py",
              ROOT / "scripts/replay/replay.py", ROOT / "benchmarks/rule_quality_gate.py",
              ROOT / "benchmarks/quality_gate.py", ROOT / "benchmarks/analysis_attestation.py"]
    files = {p.relative_to(ROOT).as_posix(): bytes_digest(p.read_bytes()) for p in sorted(set(paths))}
    dirty = _git("status", "--porcelain", "--untracked-files=all", "--", *files)
    require(not dirty, "commit_measurement_code_and_configuration_before_preregistration")
    definitions = {key: value["rule_digest"] for key, value in load_rules().items()}
    # Posting/evidence-only changes do not change raw matching semantics. Their
    # exact files remain recorded, but may be retired after a successful import.
    executable_files = {key: value for key, value in files.items()
                        if "/opengrep_rules/" not in key and not key.endswith("publication-policy.json")}
    configuration = {"scope": "deterministic_tier2_workflow_rule", "triage": "not_called",
                     "workflow_action_digest_lookup": False,
                     "batch_max_files": runner.batch_max_files(), "batch_max_bytes": runner.batch_max_bytes(),
                     "source_commit": "pr_head", "one_sampling_unit": "repository",
                     "selection": "sha256_seeded_unit_then_finding_v1"}
    packages = sorted((d.metadata["Name"], d.version,
                       bytes_digest(record.encode()) if (record := d.read_text("RECORD")) is not None else None)
                      for d in importlib.metadata.distributions() if d.metadata["Name"])
    execution = {"source_files": executable_files, "rule_definitions": definitions,
                 "python": sys.version, "python_executable_sha256": bytes_digest(Path(sys.executable).read_bytes()),
                 "platform": platform.platform(), "packages": packages,
                 "scanner": {"path": scanner, "sha256": bytes_digest(Path(scanner).read_bytes()),
                             "version": version.stdout.strip()}, "configuration": configuration,
                 "scanner_environment_sha256": {key: bytes_digest(value.encode()) for key, value in os.environ.items()
                                                if key.startswith(("SEMGREP_", "OPENGREP_"))}}
    return {"source_revision": _git("rev-parse", "HEAD"), "checkout_files": files,
            **execution, "execution_sha256": digest(execution)}


def _workflow_rule(rule_id):
    import yaml
    require(text(rule_id) and rule_id.startswith("opengrep."), "only_tier2_workflow_rules_supported")
    raw_id = rule_id.removeprefix("opengrep.")
    rules = yaml.safe_load((SOURCE / "opengrep_rules/workflow_coverage.yml").read_text())["rules"]
    require(any(rule["id"] == raw_id for rule in rules), "only_tier2_workflow_rules_supported")
    return load_rules()[rule_id]["rule_digest"]


def validate_plan(plan):
    verify_seal(plan, "plan_id")
    require(plan.get("schema_version") == SCHEMA and plan.get("split") == "holdout", "invalid_plan_schema_or_split")
    for field in ("corpus", "population", "sampling_plan", "registered_by", "selection_seed"):
        require(text(plan.get(field)), f"missing_plan_{field}")
    timestamp(plan.get("registered_at"))
    require(type(plan.get("sample_size")) is int and plan["sample_size"] >= MINIMUM_PRECISION_SAMPLES,
            "minimum_sample_size_is_100")
    require(isinstance(plan.get("system"), dict) and HASH.fullmatch(str(plan["system"].get("execution_sha256", ""))),
            "missing_system_provenance")
    require(plan.get("rule_digest") == _workflow_rule(plan.get("rule_id")), "stale_rule_definition")
    frame = plan.get("frame")
    require(isinstance(frame, list) and len(frame) >= plan["sample_size"], "frame_smaller_than_preregistered_sample")
    repos, groups = set(), set()
    for unit in frame:
        require(isinstance(unit, dict) and set(unit) == {"repo", "pr", "head_sha", "base_sha", "independence_group"},
                "invalid_frame_unit")
        require(isinstance(unit["repo"], str) and REPO.fullmatch(unit["repo"]), "repository_must_be_canonical_lowercase")
        require(type(unit["pr"]) is int and unit["pr"] > 0, "invalid_frame_pr")
        require(all(isinstance(unit[key], str) and SHA.fullmatch(unit[key]) for key in ("head_sha", "base_sha")),
                "frame_requires_exact_source_commits")
        require(text(unit["independence_group"]), "missing_independence_group")
        require(unit["repo"] not in repos and unit["independence_group"] not in groups, "duplicate_repository_or_independence_group")
        repos.add(unit["repo"])
        groups.add(unit["independence_group"])


def preregister(specification):
    require(isinstance(specification, dict), "invalid_study_specification")
    require(set(specification) == {"rule_id", "corpus", "population", "sampling_plan", "registered_by",
                                   "selection_seed", "sample_size", "frame"}, "invalid_specification_fields")
    plan = sealed({**specification, "schema_version": SCHEMA, "split": "holdout", "system": current_system(),
                   "rule_digest": _workflow_rule(specification.get("rule_id")), "registered_at": now()}, "plan_id")
    validate_plan(plan)
    return plan


def registered_plan(path, plan):
    """Require the exact frozen plan in Git before any source/API/scanner work."""
    relative = Path(path).resolve().relative_to(ROOT).as_posix()
    committed = json.loads(_git("show", f"HEAD:{relative}"), object_pairs_hook=_object)
    require(committed == plan, "plan_must_be_committed_and_unchanged_before_collection")
    commit = _git("log", "-1", "--format=%H", "--", relative)
    require(SHA.fullmatch(commit) is not None, "missing_preregistration_commit")
    return {"path": relative, "commit": commit, "plan_id": plan["plan_id"]}


def assert_current(plan):
    validate_plan(plan)
    system = current_system()
    require(system["execution_sha256"] == plan["system"]["execution_sha256"], "stale_system_or_configuration")
    require(_execution_metadata(system) == _execution_metadata(plan["system"]), "modified_system_provenance")
    return system


def _execution_metadata(system):
    # Data-only registration/review commits may advance HEAD. All actual
    # executable/configuration metadata must still match, not just its hash label.
    return {key: value for key, value in system.items() if key not in {"source_revision", "checkout_files"}}


def _blob(reader, repo, ref, path):
    require(canonical_path(path), "noncanonical_source_path")
    endpoint = f"repos/{repo}/contents/{quote(path, safe='/')}?ref={ref}"
    body = reader.get(endpoint)
    require(isinstance(body, dict) and body.get("type") == "file" and body.get("path") == path
            and body.get("encoding") == "base64" and isinstance(body.get("content"), str), "missing_exact_source_blob")
    try:
        raw = base64.b64decode("".join(body["content"].split()), validate=True)
        content = raw.decode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise EvidenceError("invalid_source_encoding") from error
    require(len(raw) <= prodfilters.CONTENT_BYTE_CAP, "source_exceeds_production_content_cap")
    # GitHub's API exposes the repository's Git blob object ID. SHA-1 is used
    # only to reproduce that protocol identifier; `sha256` above is the
    # security evidence digest.
    blob_sha = hashlib.sha1(  # noqa: S324 -- protocol compatibility, not a security digest
        b"blob " + str(len(raw)).encode() + b"\0" + raw,
        usedforsecurity=False,
    ).hexdigest()
    require(body.get("sha") == blob_sha, "source_blob_digest_mismatch")
    return {"ref": ref, "path": path, "git_blob_sha": blob_sha,
            "sha256": bytes_digest(raw), "content": content}


def verify_patch(patch, before, after, additions, deletions):
    require(isinstance(patch, str) and bool(patch.strip()), "missing_or_truncated_patch")
    old, new = before.splitlines(), after.splitlines()
    old_line = new_line = old_count = new_count = None
    added = removed = 0
    def finished():
        require(old_count == new_count == 0, "truncated_patch_hunk")
    for raw in patch.splitlines():
        if raw.startswith("@@"):
            if old_count is not None:
                finished()
            match = HUNK.fullmatch(raw)
            require(match is not None, "invalid_patch_hunk")
            old_line, old_count = int(match[1]) - 1, int(match[2] or 1)
            new_line, new_count = int(match[3]) - 1, int(match[4] or 1)
        elif raw.startswith("\\ No newline at end of file"):
            continue
        else:
            require(old_count is not None and raw[:1] in {"+", "-", " "}, "invalid_patch_body")
            if raw[0] in " -":
                require(old_count > 0 and 0 <= old_line < len(old) and old[old_line] == raw[1:], "patch_base_source_mismatch")
                old_line += 1
                old_count -= 1
            if raw[0] in " +":
                require(new_count > 0 and 0 <= new_line < len(new) and new[new_line] == raw[1:], "patch_head_source_mismatch")
                new_line += 1
                new_count -= 1
            added += raw[0] == "+"
            removed += raw[0] == "-"
    require(old_count is not None, "missing_patch_hunks")
    finished()
    require(type(additions) is int and type(deletions) is int and added == additions and removed == deletions,
            "patch_change_counts_mismatch")


def fetch_unit(reader, frame):
    repo, number = frame["repo"], frame["pr"]
    pull = requested_pull_requests(reader, repo, [number])[0]
    require((pull.get("head") or {}).get("sha") == frame["head_sha"]
            and (pull.get("base") or {}).get("sha") == frame["base_sha"], "stale_pr_source_refs")
    require(str(((pull.get("base") or {}).get("repo") or {}).get("full_name", "")).lower() == repo,
            "pr_repository_mismatch")
    files = reader.get(f"repos/{repo}/pulls/{number}/files?per_page=100", paginate=True)
    require(isinstance(files, list) and type(pull.get("changed_files")) is int
            and len(files) == pull["changed_files"], "missing_or_truncated_pr_files")
    require(all(isinstance(item, dict) and canonical_path(item.get("filename")) for item in files), "invalid_pr_file")
    require(len({item["filename"] for item in files}) == len(files), "duplicate_pr_file")
    require(len(prodfilters.scoped_files(files)) <= prodfilters.PR_FILE_CAP, "pr_exceeds_production_file_cap")
    sources, payload = [], []
    for item in prodfilters.scoped_files(files):
        path = item["filename"]
        if not prodfilters.is_workflow_path(path):
            continue
        head = _blob(reader, repo, frame["head_sha"], path)
        require(head["git_blob_sha"] == item.get("sha"), "pr_file_blob_mismatch")
        before = None if item["status"] == "added" else _blob(
            reader, repo, frame["base_sha"], item.get("previous_filename", path))
        verify_patch(item.get("patch"), before["content"] if before else "", head["content"],
                     item.get("additions"), item.get("deletions"))
        spans = prodfilters.reviewable_line_spans(item["patch"])
        sources.append({"head": head, "base": before, "patch": item["patch"],
                        "patch_sha256": bytes_digest(item["patch"].encode()), "additions": item["additions"],
                        "deletions": item["deletions"], "reviewable_line_spans": spans})
        payload.append({"path": path, "patch": item["patch"], "content": head["content"],
                        "reviewable_line_spans": spans})
    return {"frame": frame, "pr_metadata": pull, "pr_files": files, "sources": sources,
            "payload_sha256": digest(payload)}, payload


def scan(files):
    sys.path.insert(0, str(SOURCE))
    try:
        from opengrep_runner import run_opengrep_with_limitations
    finally:
        sys.path.remove(str(SOURCE))
    with redirect_stdout(io.StringIO()):
        return run_opengrep_with_limitations(files)


def _observation(plan, unit, finding):
    require(finding.get("rule_id") == plan["rule_id"], "finding_for_different_rule")
    source = next((source["head"] for source in unit["sources"] if source["head"]["path"] == finding.get("file_path")), None)
    require(source is not None and text(finding.get("fingerprint")), "finding_missing_source_or_identity")
    start, end = finding.get("line_start"), finding.get("line_end")
    lines = source["content"].splitlines()
    require(type(start) is int and type(end) is int and 1 <= start <= end <= len(lines), "finding_invalid_source_span")
    spans = next(source["reviewable_line_spans"] for source in unit["sources"] if source["head"]["path"] == finding["file_path"])
    require(any(start <= span["end"] and span["start"] <= end for span in spans), "finding_outside_changed_lines")
    frame = unit["frame"]
    row = {"plan_id": plan["plan_id"], "rule_id": plan["rule_id"], "rule_digest": plan["rule_digest"],
           "sampling_unit": f"github:{frame['repo']}", "repo": frame["repo"], "pr": frame["pr"],
           "head_sha": frame["head_sha"], "base_sha": frame["base_sha"], "fingerprint": finding["fingerprint"],
           "file_path": finding["file_path"], "line_start": start, "line_end": end,
           "source_sha256": source["sha256"], "finding_sha256": digest(finding),
           "source": f"https://github.com/{frame['repo']}/blob/{frame['head_sha']}/{quote(finding['file_path'], safe='/')}#L{start}-L{end}",
           "code_context": [{"line": i + 1, "text": lines[i]} for i in range(max(0, start - 3), min(len(lines), end + 2))]}
    return {**row, "id": digest(row)}


def selection(plan, units):
    selected = []
    for unit in units:
        rows = [_observation(plan, unit, finding) for finding in unit["findings"]]
        require(len({row["fingerprint"] for row in rows}) == len(rows), "duplicate_finding_identity")
        if rows:
            selected.append(min(rows, key=lambda row: digest([plan["selection_seed"], "finding", row["id"]])))
    selected.sort(key=lambda row: digest([plan["selection_seed"], "unit", row["sampling_unit"]]))
    return selected[:plan["sample_size"]]


def collect(plan, registration, reader):
    system = assert_current(plan)
    started_at = now()
    require(timestamp(plan["registered_at"]) <= timestamp(started_at), "registration_after_collection")
    units = []
    for frame in plan["frame"]:
        try:
            unit, payload = fetch_unit(reader, frame)
        except GitHubError as error:
            raise EvidenceError(f"github_source_unavailable:{frame['repo']}#{frame['pr']}") from error
        try:
            findings, limitations = scan(payload)
        except RuntimeError as error:
            raise EvidenceError(f"scanner_execution_failed:{frame['repo']}#{frame['pr']}") from error
        require(not limitations, f"incomplete_scanner_coverage:{frame['repo']}#{frame['pr']}")
        require(isinstance(findings, list), "invalid_scanner_observations")
        unit.update(status="complete", findings=[finding for finding in findings if finding.get("rule_id") == plan["rule_id"]])
        units.append(unit)
    require(assert_current(plan)["execution_sha256"] == system["execution_sha256"], "system_changed_during_collection")
    chosen = selection(plan, units)
    return sealed({"schema_version": SCHEMA, "plan_id": plan["plan_id"], "registration": registration,
                   "system": system, "started_at": started_at, "completed_at": now(), "units": units,
                   "selection": chosen, "selection_complete": len(chosen) == plan["sample_size"],
                   "limitations": LIMITATIONS}, "collection_id")


def validate_collection(plan, collection, *, rerun=False):
    assert_current(plan)
    verify_seal(collection, "collection_id")
    require(collection.get("schema_version") == SCHEMA and collection.get("plan_id") == plan["plan_id"], "stale_collection_plan")
    registration = collection.get("registration")
    require(isinstance(registration, dict) and canonical_path(registration.get("path"))
            and registered_plan(ROOT / registration["path"], plan) == registration,
            "stale_or_missing_preregistration_commit")
    require(collection.get("system", {}).get("execution_sha256") == plan["system"]["execution_sha256"], "stale_collection_system")
    require(_execution_metadata(collection["system"]) == _execution_metadata(plan["system"]), "modified_collection_system_provenance")
    require(timestamp(plan["registered_at"]) <= timestamp(collection.get("started_at"))
            <= timestamp(collection.get("completed_at")) <= timestamp(now()),
            "invalid_collection_chronology")
    units = collection.get("units")
    require(isinstance(units, list) and all(isinstance(unit, dict) for unit in units)
            and [unit.get("frame") for unit in units] == plan["frame"], "missing_duplicate_or_reordered_frame_observations")
    for unit in units:
        require(unit.get("status") == "complete" and isinstance(unit.get("findings"), list), "incomplete_unit")
        class StoredReader:
            def get(self, endpoint, paginate=False):
                frame = unit["frame"]
                if endpoint == f"repos/{frame['repo']}/pulls/{frame['pr']}":
                    return unit["pr_metadata"]
                if endpoint == f"repos/{frame['repo']}/pulls/{frame['pr']}/files?per_page=100":
                    return unit["pr_files"]
                for source in unit["sources"]:
                    for blob in (source["head"], source["base"]):
                        if blob and endpoint == f"repos/{frame['repo']}/contents/{quote(blob['path'], safe='/')}?ref={blob['ref']}":
                            raw = blob["content"].encode()
                            require(bytes_digest(raw) == blob["sha256"], "modified_source_bytes")
                            return {"type": "file", "path": blob["path"], "sha": blob["git_blob_sha"],
                                    "encoding": "base64", "content": base64.b64encode(raw).decode()}
                raise EvidenceError("missing_stored_exact_source")
        rebuilt, payload = fetch_unit(StoredReader(), unit["frame"])
        require(all(unit.get(key) == rebuilt[key] for key in rebuilt), "modified_source_or_payload_provenance")
        if rerun:
            findings, limitations = scan(payload)
            actual = [finding for finding in findings if finding.get("rule_id") == plan["rule_id"]]
            require(not limitations and sorted(actual, key=digest) == sorted(unit["findings"], key=digest), "stale_or_invented_scanner_observations")
    expected = selection(plan, units)
    require(collection.get("selection") == expected and collection.get("selection_complete") is True
            and len(expected) == plan["sample_size"], "missing_duplicate_or_cherry_picked_prediction_selection")
    return expected


def review_queue(plan, collection):
    rows = validate_collection(plan, collection)
    return {"schema_version": SCHEMA, "plan_id": plan["plan_id"], "collection_id": collection["collection_id"],
            "limitations": LIMITATIONS,
            "observations": [{**row, **{field: None for field in sorted(REVIEW_FIELDS)}} for row in rows]}


def import_reviews(plan, collection, reviews, existing, *, attestation=None):
    rows = validate_collection(plan, collection, rerun=True)
    require(isinstance(reviews, dict) and reviews.get("schema_version") == SCHEMA
            and reviews.get("plan_id") == plan["plan_id"] and reviews.get("collection_id") == collection["collection_id"], "stale_review_document")
    judgments = reviews.get("observations")
    require(isinstance(judgments, list) and len(judgments) == len(rows), "missing_or_duplicate_review_rows")
    by_id = {}
    for review in judgments:
        require(isinstance(review, dict) and text(review.get("id")) and review["id"] not in by_id, "duplicate_or_invalid_review_id")
        by_id[review["id"]] = review
    observations = []
    for row in rows:
        review = by_id.get(row["id"], {})
        require(set(review) == set(row) | REVIEW_FIELDS
                and {key: value for key, value in review.items() if key not in REVIEW_FIELDS} == row, "modified_or_stale_review_binding")
        require(review["verdict"] in ("true", "false"), "unresolved_review_judgment")
        require(text(review["reviewer"]) and review["reviewer"].casefold() != plan["registered_by"].casefold()
                and text(review["review_note"]), "reviewer_must_differ_from_registrant_and_supply_note")
        require(timestamp(collection["completed_at"]) <= timestamp(review["reviewed_at"]) <= timestamp(now()), "invalid_review_time")
        observations.append({"id": row["id"], "sampling_unit": row["sampling_unit"], "source": row["source"],
                             "reviewer": review["reviewer"], "verdict": review["verdict"],
                             "reviewed_at": review["reviewed_at"], "review_note": review["review_note"]})
    evidence = {"rule_id": plan["rule_id"], "rule_digest": plan["rule_digest"], "corpus": plan["corpus"], "sampling_plan": plan["sampling_plan"],
                "split": "holdout", "observations": observations,
                "collection_provenance": {"plan_id": plan["plan_id"], "collection_id": collection["collection_id"],
                    "registration": collection["registration"], "system": collection["system"],
                    "reviews_sha256": digest({**reviews, "observations": sorted(judgments, key=lambda row: row["id"])}),
                    "population": plan["population"], "registered_by": plan["registered_by"], "review_identity_authenticated": False,
                    "population_sampling_verified": False, "limitations": LIMITATIONS}}
    statistics = evaluate_precision_evidence(evidence, plan["rule_digest"])
    require(statistics["passed"], "precision_gate_failed:" + ",".join(statistics["reasons"]))
    # An unsigned candidate is useful for accountable review, never promotion.
    decision = {"passed": False, "precision_gate": statistics,
                "reasons": ["review_identity_not_authenticated", "population_sampling_not_verified"]}
    if attestation is not None:
        evidence = authenticated_candidate(evidence, attestation)
        decision = evaluate_evidence(evidence, plan["rule_digest"], rule_id=plan["rule_id"])
    require(isinstance(existing, dict) and existing.get("schema_version") == "v1" and isinstance(existing.get("rules"), dict),
            "invalid_destination_evidence_document")
    prior = existing["rules"].get(plan["rule_id"])
    require(prior is None or prior == evidence, "refuse_to_overwrite_different_rule_evidence")
    return {**existing, "rules": {**existing["rules"], plan["rule_id"]: evidence}}, decision


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("preregister")
    freeze.add_argument("--specification", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    for command in ("collect", "queue", "import"):
        child = sub.add_parser(command)
        child.add_argument("--plan", type=Path, required=True)
        child.add_argument("--output", type=Path, required=True)
        if command == "collect":
            child.add_argument("--cache", type=Path, default=ROOT / "scripts/replay/.cache")
            child.add_argument("--refresh", action="store_true")
        else:
            child.add_argument("--collection", type=Path, required=True)
        if command == "import":
            child.add_argument("--reviews", type=Path, required=True)
            child.add_argument("--evidence", type=Path, default=ROOT / "benchmarks/rule-quality/evidence.json")
            child.add_argument("--attestation", type=Path,
                               help="Purpose-separated receipt signed by trusted reviewers and sampling auditor")
    args = parser.parse_args(argv)
    try:
        if args.command == "preregister":
            result = preregister(read(args.specification))
        else:
            plan = read(args.plan)
            validate_plan(plan)
            registration = registered_plan(args.plan, plan)
            if args.command == "collect":
                result = collect(plan, registration, GitHubReader(args.cache, refresh=args.refresh))
            else:
                collection = read(args.collection)
                require(collection.get("registration") == registration, "stale_or_missing_preregistration_commit")
                if args.command == "queue":
                    result = review_queue(plan, collection)
                else:
                    result, decision = import_reviews(plan, collection, read(args.reviews), read(args.evidence),
                                                     attestation=read(args.attestation) if args.attestation else None)
        # --output is a new candidate document. Canonical evidence replacement and
        # legacy retirement are deliberate review/merge actions, never side effects.
        write_new(args.output, result)
        complete = result.get("selection_complete", True)
        authenticated = args.command == "import" and decision["passed"]
        print(json.dumps({"command": args.command, "output": str(args.output), "complete": complete,
                          "production_ready": False, "publication_evidence_validated": authenticated,
                          "review_identity_authenticated": authenticated,
                          "population_sampling_verified": authenticated}, sort_keys=True))
        return 0 if complete else 2
    except (EvidenceError, GitHubError, OSError, ValueError, TypeError, KeyError, AttributeError,
            RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({"command": args.command, "passed": False, "error_type": type(error).__name__,
                          "reason": str(error) if isinstance(error, EvidenceError) else "invalid_or_unavailable_inputs",
                          "production_ready": False}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
