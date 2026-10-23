"""Offline corpus planning and pre-result intake; never approve a release or review.

Preregistrations bind complete candidate inputs to a committed, append-only identity
before evaluation. Local Git objects establish source provenance without fetching or
executing code. Human independence, licensing, near-clone discovery, and signed review
remain external obligations, not facts a caller can assert into existence here.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any
from urllib.parse import urlsplit

from .release_evidence import (DIGEST, IDENTIFIER, SOURCE_REVISION, ReleaseEvidenceError,
                               canonical_json, digest, fixture_inventory, read_json)

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SCHEMA = "remediation-corpus-preregistration-v1"
LEDGER = "benchmarks/remediation/release/intake"
SPLITS = ("train", "validation", "holdout")
KINDS = ("supported", "negative", "adversarial")


class IntakeError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise IntakeError(reason)


def timestamp(value: Any) -> datetime:
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None,
            "invalid_intake_timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise IntakeError("invalid_intake_timestamp") from error


def repo_url(value: Any) -> str:
    require(isinstance(value, str), "invalid_upstream_repository")
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment and not parsed.port,
            "upstream_repository_must_be_credential_free_https")
    path = parsed.path.rstrip("/").removesuffix(".git")
    require(re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", path) is not None,
            "upstream_repository_must_name_owner_and_repo")
    return f"https://{parsed.hostname.lower()}{path.lower()}"


def relative_path(value: Any) -> str:
    require(isinstance(value, str) and value and "\\" not in value and ":" not in value
            and not any(ord(char) < 32 for char in value), "invalid_intake_path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(part not in {"", ".", ".."} for part in value.split("/")),
            "invalid_intake_path")
    return path.as_posix()


def authors(values: Any) -> set[str]:
    require(isinstance(values, list) and bool(values)
            and all(isinstance(item, str) and IDENTIFIER.fullmatch(item) for item in values)
            and len(set(values)) == len(values), "invalid_intake_authors")
    return set(values)


def source_paths(metadata: dict) -> list[str]:
    return [relative_path(unit["source"]) for unit in [metadata, *metadata.get("additional_units", [])]]


def oracle_paths(metadata: dict) -> set[str]:
    paths = set()
    trusted = metadata.get("trusted_fixture_test")
    if trusted:
        paths.add(relative_path(trusted["path"]))
    for check in metadata.get("verification_checks", []):
        # Intake never executes argv. Bind the actual fixture test files named by checks,
        # not every argument (an exploit payload can itself look like a repository path).
        for argument in check.get("argv", [])[1:]:
            if isinstance(argument, str) and argument.startswith("tests/"):
                paths.add(relative_path(argument))
    require(bool(paths), "missing_oracle_provenance")
    return paths


def lineage_keys(entry: dict) -> set[str]:
    metadata = entry["metadata"]
    keys = {"repository:" + str(metadata["repository_id"])}
    provenance = metadata.get("intake_provenance")
    if provenance:
        keys.update("upstream:" + repo_url(provenance[field]) for field in ("upstream_repository", "lineage_root"))
        keys.add("upstream_revision:" + provenance["upstream_revision"])
    return keys


def validate_registration_document(registration: Any) -> None:
    require(isinstance(registration, dict) and set(registration) == {"schema_version", "registered_at", "manifest_digest",
            "baseline_inventory_digest", "history_digests", "cases", "status"}
            and registration["schema_version"] == SCHEMA
            and registration["status"] == "preregistered_pending_independent_review", "invalid_intake_history")
    timestamp(registration["registered_at"])
    require(all(isinstance(registration[key], str) and DIGEST.fullmatch(registration[key])
                for key in ("manifest_digest", "baseline_inventory_digest")), "invalid_intake_history_digest")
    history = registration["history_digests"]
    require(isinstance(history, list) and all(isinstance(item, str) and DIGEST.fullmatch(item) for item in history)
            and history == sorted(set(history)), "invalid_intake_history_digest")
    cases = registration["cases"]
    require(isinstance(cases, list) and bool(cases), "empty_intake_history")
    ids = set()
    for case in cases:
        require(isinstance(case, dict) and set(case) == {"fixture_id", "repository_id", "split", "kind", "family",
            "fixture_digest", "lineage_keys", "source_digests", "oracle_digests", "case_authors", "oracle_authors"},
            "invalid_intake_history_case")
        require(all(isinstance(case[key], str) and IDENTIFIER.fullmatch(case[key]) for key in ("fixture_id", "repository_id", "family"))
                and case["fixture_id"] not in ids and case["split"] in SPLITS and case["kind"] in KINDS
                and isinstance(case["fixture_digest"], str) and DIGEST.fullmatch(case["fixture_digest"]), "invalid_intake_history_case")
        ids.add(case["fixture_id"])
        keys = case["lineage_keys"]
        require(isinstance(keys, list) and all(isinstance(key, str) for key in keys) and keys == sorted(set(keys))
                and "repository:" + case["repository_id"] in keys
                and any(key.startswith("upstream:") for key in keys)
                and any(key.startswith("upstream_revision:") for key in keys), "incomplete_intake_history_lineage")
        for field in ("source_digests", "oracle_digests"):
            values = case[field]
            require(isinstance(values, dict) and bool(values)
                    and all(relative_path(path) == path and isinstance(value, str) and DIGEST.fullmatch(value)
                            for path, value in values.items()), "invalid_intake_history_artifact")
        require(not authors(case["case_authors"]) & authors(case["oracle_authors"]), "invalid_intake_history_authors")


def assert_no_reuse(baseline: dict, candidates: dict, history: list[dict] | None = None) -> None:
    ids, lineages, blobs = set(baseline), {}, {}
    for fixture_id, entry in baseline.items():
        for key in lineage_keys(entry):
            lineages.setdefault(key, fixture_id)
        for path in source_paths(entry["metadata"]):
            require(path in entry["files"], "source_file_not_in_inventory")
            blobs.setdefault(entry["files"][path], fixture_id)
    for registration in history or []:
        validate_registration_document(registration)
        for case in registration["cases"]:
            fixture_id = case["fixture_id"]
            if fixture_id in baseline:
                require(case["fixture_digest"] == digest(baseline[fixture_id]), "historical_fixture_inputs_changed")
                continue  # An admitted case remains in both the corpus and immutable history.
            require(fixture_id not in ids, "historical_fixture_identity_reused")
            ids.add(fixture_id)
            for key in case["lineage_keys"]:
                require(key not in lineages, "historical_lineage_reused")
                lineages[key] = fixture_id
            for value in case["source_digests"].values():
                require(value not in blobs, "historical_source_reused")
                blobs[value] = fixture_id
    for fixture_id, entry in sorted(candidates.items()):
        require(fixture_id not in ids, "fixture_identity_reused")
        ids.add(fixture_id)
        for key in lineage_keys(entry):
            require(key not in lineages, "repository_lineage_reused_or_cross_split_leakage")
            lineages[key] = fixture_id
        for path in source_paths(entry["metadata"]):
            value = entry["files"][path]
            require(value not in blobs, "source_content_reused_or_cross_split_leakage")
            blobs[value] = fixture_id


def git(repository: Path, *arguments: str) -> bytes:
    try:
        return subprocess.run(["git", "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                               "-c", "protocol.allow=never", "-C", str(repository), *arguments],
                              check=True, capture_output=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise IntakeError("local_git_provenance_unavailable") from error


def ledger_history(repository: Path, excluded_path: Path | None = None, revision: str = "HEAD") -> list[dict]:
    """Never forget a committed preregistration through deletion, modification, or omission."""
    changed = git(repository, "log", "--format=", "--name-only", "--diff-filter=MD", "--no-renames", "HEAD", "--", LEDGER)
    require(not changed.strip(), "committed_intake_ledger_is_not_append_only")
    paths = git(repository, "ls-tree", "-r", "--name-only", revision, "--", LEDGER).decode().splitlines()
    history = []
    for name in paths:
        path = repository / name
        require(not path.is_symlink() and path.is_file()
                and git(repository, "show", f"HEAD:{name}") == path.read_bytes(), "dirty_or_missing_intake_ledger")
        if excluded_path is not None and path.resolve() == excluded_path.resolve():
            continue
        require(path.suffix == ".json", "unexpected_file_in_intake_ledger")
        history.append(read_json(path))
    return history


def validate_candidate(directory: Path, entry: dict, origins: dict[str, str], registered_at: datetime) -> dict:
    from .evaluate import SUPPORTED_FAMILIES, validate_fixture

    metadata, files = entry["metadata"], entry["files"]
    validate_fixture(directory, metadata)
    require(isinstance(metadata["repository_id"], str) and IDENTIFIER.fullmatch(metadata["repository_id"]) is not None
            and metadata["family"] in SUPPORTED_FAMILIES
            and metadata["expected_state"] == ("ready" if metadata["kind"] == "supported" else "unsupported"),
            "invalid_intake_case_identity")
    require(not {"result", "results", "evaluation", "outcome", "model_output"}.intersection(metadata),
            "results_cannot_be_preregistered")
    require(not {"results.json", "evaluation.json", "model-output.json"}.intersection(files),
            "results_cannot_be_preregistered")
    provenance = metadata.get("intake_provenance")
    fields = {"origin", "upstream_repository", "lineage_root", "upstream_revision", "collected_at",
              "case_authors", "oracle_authors", "source_artifacts", "oracle_artifacts",
              "review_document", "review_document_digest", "model_outputs_observed"}
    require(isinstance(provenance, dict) and set(provenance) == fields, "complete_intake_provenance_required")
    require(provenance["origin"] == "independent_repository" and provenance["model_outputs_observed"] is False,
            "independent_pre_result_inputs_required")
    upstream = repo_url(provenance["upstream_repository"])
    repo_url(provenance["lineage_root"])
    require(isinstance(provenance["upstream_revision"], str)
            and SOURCE_REVISION.fullmatch(provenance["upstream_revision"]) is not None, "upstream_revision_not_pinned")
    require(timestamp(provenance["collected_at"]) <= registered_at, "source_collected_after_preregistration")
    require(not authors(provenance["case_authors"]) & authors(provenance["oracle_authors"]),
            "case_and_oracle_authors_must_be_distinct")
    review = relative_path(provenance["review_document"])
    require(review in files and files[review] == provenance["review_document_digest"], "review_document_binding_mismatch")
    require(bool((directory / review).read_bytes().strip()), "empty_review_document")
    sources, oracles = provenance["source_artifacts"], provenance["oracle_artifacts"]
    require(isinstance(sources, dict) and set(sources) == set(source_paths(metadata)), "source_provenance_coverage_mismatch")
    require(isinstance(oracles, dict) and set(oracles) == oracle_paths(metadata), "oracle_provenance_coverage_mismatch")
    references = {relative_path(unit["reference_repair"]) for unit in [metadata, *metadata.get("additional_units", [])]
                  if unit.get("reference_repair")}
    require(not set(sources) & set(oracles) and not references & (set(sources) | set(oracles))
            and review not in set(sources) | set(oracles) | references, "source_oracle_reference_roles_overlap")
    require(upstream in origins, "upstream_checkout_required_no_fetch_is_performed")
    checkout = Path(origins[upstream])
    commit = provenance["upstream_revision"]
    require(git(checkout, "rev-parse", "--verify", f"{commit}^{{commit}}").decode().strip() == commit,
            "upstream_commit_unavailable")
    committed = datetime.fromisoformat(git(checkout, "show", "-s", "--format=%cI", commit).decode().strip())
    require(committed.tzinfo is not None and committed <= timestamp(provenance["collected_at"]),
            "source_collected_before_upstream_commit")
    for path, artifact in sources.items():
        require(isinstance(artifact, dict) and set(artifact) == {"upstream_path", "sha256", "git_blob_oid"},
                "invalid_source_provenance")
        upstream_path = relative_path(artifact["upstream_path"])
        require(path in files and files[path] == artifact["sha256"], "source_digest_mismatch")
        raw = (directory / path).read_bytes()
        # Upstream provenance includes Git's own SHA-1 blob object ID. This is
        # protocol compatibility only; the fixture's security binding is the
        # separately checked SHA-256 digest.
        blob = hashlib.sha1(  # noqa: S324 -- protocol compatibility, not a security digest
            b"blob " + str(len(raw)).encode() + b"\0" + raw,
            usedforsecurity=False,
        ).hexdigest()
        require(artifact["git_blob_oid"] == blob, "source_blob_oid_mismatch")
        tree = git(checkout, "ls-tree", commit, "--", upstream_path).decode().split()
        require(len(tree) >= 3 and tree[0] in {"100644", "100755"} and tree[1] == "blob" and tree[2] == blob,
                "upstream_source_not_regular_matching_blob")
        require(git(checkout, "cat-file", "-t", f"{commit}:{upstream_path}").strip() == b"blob",
                "upstream_source_is_not_blob")
        require(git(checkout, "show", f"{commit}:{upstream_path}") == raw, "upstream_source_content_mismatch")
    for path, value in oracles.items():
        require(path in files and files[path] == value and DIGEST.fullmatch(value) is not None,
                "oracle_digest_mismatch")
        require(bool((directory / path).read_bytes().strip()), "empty_oracle_file")
    return {"fixture_id": metadata["id"], "repository_id": metadata["repository_id"],
            "split": metadata["split"], "kind": metadata["kind"], "family": metadata["family"],
            "fixture_digest": digest(entry), "lineage_keys": sorted(lineage_keys(entry)),
            "source_digests": {path: files[path] for path in sorted(sources)},
            "oracle_digests": {path: files[path] for path in sorted(oracles)},
            "case_authors": provenance["case_authors"], "oracle_authors": provenance["oracle_authors"]}


def preregister(*, manifest: dict, baseline: dict, candidates: dict, candidate_root: Path,
                origins: dict[str, str], registered_at: str, history: list[dict] | None = None) -> dict:
    require(bool(candidates), "no_candidate_cases")
    registered = timestamp(registered_at)
    require(registered <= datetime.now(timezone.utc), "future_preregistration")
    assert_no_reuse(baseline, candidates, history)
    directories = {read_json(path)["id"]: path.parent for path in candidate_root.glob("*/fixture.json")}
    cases = [validate_candidate(directories[key], entry, origins, registered) for key, entry in sorted(candidates.items())]
    registration = {"schema_version": SCHEMA, "registered_at": registered_at, "manifest_digest": digest(manifest),
            "baseline_inventory_digest": digest(baseline), "history_digests": sorted(digest(item) for item in history or []),
            "cases": cases, "status": "preregistered_pending_independent_review"}
    validate_registration_document(registration)
    return registration


def validate_registration(*, registration: dict, registration_path: Path, registration_revision: str,
                          repository: Path, manifest: dict, baseline: dict, candidates: dict,
                          candidate_root: Path, origins: dict[str, str], history: list[dict] | None = None,
                          evaluation: dict | None = None) -> dict:
    require(isinstance(registration_revision, str) and SOURCE_REVISION.fullmatch(registration_revision) is not None,
            "registration_commit_required")
    require(not registration_path.is_symlink(), "registration_symlink_not_allowed")
    try:
        path = registration_path.resolve().relative_to(repository.resolve()).as_posix()
    except ValueError as error:
        raise IntakeError("registration_must_be_in_local_repository") from error
    require(path.startswith(LEDGER + "/") and path.endswith(".json"), "registration_must_use_append_only_intake_ledger")
    require(git(repository, "show", f"{registration_revision}:{path}") == registration_path.read_bytes(),
            "registration_not_identical_to_committed_preregistration")
    committed = datetime.fromisoformat(git(repository, "show", "-s", "--format=%cI", registration_revision).decode().strip())
    require(committed.tzinfo is not None, "registration_commit_time_missing_timezone")
    committed = committed.astimezone(timezone.utc)
    require(timestamp(registration["registered_at"]) <= committed, "registration_timestamp_after_commit")
    committed_history = ledger_history(repository, registration_path, registration_revision)
    merged_history = {digest(item): item for item in [*committed_history, *(history or [])]}
    expected = preregister(manifest=manifest, baseline=baseline, candidates=candidates, candidate_root=candidate_root,
                          origins=origins, registered_at=registration["registered_at"], history=list(merged_history.values()))
    require(canonical_json(registration) == canonical_json(expected), "preregistered_inputs_changed")
    if evaluation is not None:
        require(isinstance(evaluation, dict) and set(evaluation) == {"registration_digest", "registration_revision",
                "source_revision", "started_at", "finished_at", "results"}, "invalid_intake_evaluation")
        require(evaluation["registration_digest"] == digest(registration)
                and evaluation["registration_revision"] == registration_revision, "evaluation_registration_binding_mismatch")
        revision = evaluation["source_revision"]
        require(isinstance(revision, str) and SOURCE_REVISION.fullmatch(revision) is not None, "invalid_evaluation_revision")
        git(repository, "merge-base", "--is-ancestor", registration_revision, revision)
        require(committed < timestamp(evaluation["started_at"]) <= timestamp(evaluation["finished_at"])
                <= datetime.now(timezone.utc), "results_not_after_committed_preregistration")
        rows = evaluation["results"]
        require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows), "invalid_intake_results")
        by_id = {case["fixture_id"]: case for case in expected["cases"]}
        ids = [row.get("fixture_id") for row in rows]
        require(all(isinstance(item, str) for item in ids) and len(ids) == len(set(ids)) and set(ids) == set(by_id),
                "intake_results_missing_duplicate_or_unexpected")
        for row in rows:
            case = by_id[row["fixture_id"]]
            require(all(row.get(field) == case[field] for field in ("repository_id", "split", "kind", "family", "fixture_digest")),
                    "result_preregistered_identity_mismatch")
    return {"schema_version": "v1", "registration_digest": digest(registration),
            "registration_revision": registration_revision, "validated_cases": len(expected["cases"]),
            "scope": "intake_integrity_only", "production_ready": False,
            "review_queue": [{**case, "status": "awaiting_independent_review", "review_approved": False,
                              "result_available": evaluation is not None} for case in expected["cases"]],
            "limitations": ["Git ancestry and declared timestamps are not trusted timestamping or proof of reviewer independence.",
                            "Exact source/declared lineage reuse is refused; unknown forks and semantic near-clones require external review.",
                            "No candidate execution, model call, review signature, or release approval is performed."]}


def release_preregistrations(repository: Path, source_revision: str) -> list[dict]:
    """Derive the complete frozen population from Git, not an evaluation's selection."""
    require(isinstance(source_revision, str) and SOURCE_REVISION.fullmatch(source_revision) is not None,
            "invalid_evaluated_source_revision")
    ledger_history(repository, revision=source_revision)  # Enforce append-only and clean current bytes.
    paths = git(repository, "ls-tree", "-r", "--name-only", source_revision, "--", LEDGER).decode().splitlines()
    require(bool(paths), "committed_preregistration_required_for_release")
    descriptors = []
    for name in paths:
        registration = read_json(repository / name)
        validate_registration_document(registration)
        introduced = git(repository, "log", "--format=%H", "--diff-filter=A", "--no-renames",
                         source_revision, "--", name).decode().splitlines()
        require(len(introduced) == 1 and SOURCE_REVISION.fullmatch(introduced[0]) is not None,
                "registration_introduction_commit_ambiguous")
        descriptors.append({"path": name, "revision": introduced[0], "digest": digest(registration)})
    return descriptors


def inventory_at_revision(repository: Path, relative_root: str, revision: str) -> dict:
    """Read the historical baseline from Git objects, without checking out or running it."""
    root = relative_path(relative_root).rstrip("/") + "/"
    tree = git(repository, "ls-tree", "-rz", "--full-tree", revision, "--", root)
    grouped: dict[str, dict[str, bytes]] = {}
    for record in tree.split(b"\0"):
        if not record:
            continue
        descriptor, encoded_name = record.split(b"\t", 1)
        mode, kind, oid = descriptor.decode().split()
        name = encoded_name.decode("utf-8")
        require(name.startswith(root) and mode in {"100644", "100755"} and kind == "blob",
                "historical_fixture_not_regular_file")
        parts = name[len(root):].split("/")
        if len(parts) < 2 or any(part in {"__pycache__", ".pytest_cache"} for part in parts):
            continue
        grouped.setdefault(parts[0], {})["/".join(parts[1:])] = git(repository, "cat-file", "blob", oid)
    inventory = {}
    for files in grouped.values():
        if "fixture.json" not in files:
            continue
        def unique(pairs):
            document = {}
            for key, value in pairs:
                require(key not in document, "duplicate_historical_fixture_json_key")
                document[key] = value
            return document
        metadata = json.loads(files["fixture.json"], object_pairs_hook=unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(IntakeError("invalid_historical_fixture_json")))
        require(isinstance(metadata, dict) and isinstance(metadata.get("id"), str)
                and metadata["id"] not in inventory, "invalid_historical_fixture_identity")
        inventory[metadata["id"]] = {"metadata": metadata,
            "files": {name: "sha256:" + hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())}}
    return inventory


def validate_release_intake(*, repository: Path, fixture_root: Path, source_revision: str,
                            manifest: dict, evaluation: dict, origin_policy_path: Path) -> dict:
    """Mandatory production population check; a signed row is not proof of intake.

    All committed registrations must be represented, including unsuccessful cases.
    There is no legacy/retroactive exception and no caller-selected ledger subset.
    No candidate or oracle is executed. The returned binding is signed by the
    separate external-review protocol, never an admission flag by itself.
    """
    from .evaluate import validate_fixture

    inventory = fixture_inventory(fixture_root)
    directories = {read_json(path)["id"]: path.parent for path in fixture_root.glob("*/fixture.json")}
    for key, entry in inventory.items():
        try:
            validate_fixture(directories[key], entry["metadata"])
            require(all(path in entry["files"] for path in set(source_paths(entry["metadata"])) | oracle_paths(entry["metadata"])),
                    "missing_full_fixture_source_or_oracle")
        except (ValueError, TypeError, KeyError) as error:
            raise IntakeError("full_release_fixture_validation_required") from error
    descriptors = release_preregistrations(repository, source_revision)
    require(isinstance(evaluation, dict) and evaluation.get("preregistrations") == descriptors,
            "evaluation_must_bind_complete_committed_preregistrations")
    started, finished = evaluation.get("started_at"), evaluation.get("finished_at")
    require(timestamp(started) <= timestamp(finished), "invalid_evaluation_intake_times")
    require(not origin_policy_path.is_symlink(), "release_intake_origin_policy_symlink_forbidden")
    origins = read_json(origin_policy_path)
    require(isinstance(origins, dict) and bool(origins)
            and all(repo_url(key) == key and isinstance(value, str) for key, value in origins.items()),
            "release_intake_origin_policy_required")
    rows = evaluation.get("results")
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows), "invalid_intake_results")
    result_ids = [row.get("fixture_id") for row in rows]
    require(all(isinstance(key, str) for key in result_ids) and len(result_ids) == len(set(result_ids))
            and set(result_ids) == set(inventory), "intake_results_missing_duplicate_or_unexpected")
    by_id = {row["fixture_id"]: row for row in rows}
    covered, reports = set(), []
    relative_root = fixture_root.resolve().relative_to(repository.resolve()).as_posix()
    for descriptor in descriptors:
        registration = read_json(repository / descriptor["path"])
        ids = {case["fixture_id"] for case in registration["cases"]}
        require(not ids & covered and ids <= set(inventory), "registered_population_missing_or_reused")
        covered.update(ids)
        baseline = inventory_at_revision(repository, relative_root, descriptor["revision"])
        current = {key: inventory[key] for key in sorted(ids)}
        intake_results = []
        for key in sorted(ids):
            row = dict(by_id[key])
            expected = digest(current[key])
            require("fixture_digest" not in row or row["fixture_digest"] == expected, "result_fixture_digest_mismatch")
            row["fixture_digest"] = expected  # Recomputed from current files, not a model claim.
            intake_results.append(row)
        report = validate_registration(registration=registration, registration_path=repository / descriptor["path"],
            registration_revision=descriptor["revision"], repository=repository, manifest=manifest, baseline=baseline,
            candidates=current, candidate_root=fixture_root, origins=origins,
            evaluation={"registration_digest": descriptor["digest"], "registration_revision": descriptor["revision"],
                        "source_revision": source_revision, "started_at": started, "finished_at": finished, "results": intake_results})
        reports.append({"registration_digest": report["registration_digest"],
                        "registration_revision": report["registration_revision"], "cases": sorted(ids)})
    require(covered == set(inventory), "unregistered_release_fixtures_forbidden_no_legacy_exception")
    return {"schema_version": "v1", "population": "complete_committed_preregistrations",
            "registrations_digest": digest(descriptors), "validated_population_digest": digest(reports),
            "origin_policy_digest": digest(origins), "started_at": started, "finished_at": finished,
            "fixture_count": len(covered)}


def plan_corpus(manifest: dict, inventory: dict, families: set[str]) -> dict:
    from .evaluate import validate_release_policy
    from .release_evidence import release_fixture_inventory
    validate_release_policy(manifest)
    effective = release_fixture_inventory(inventory, manifest)
    require(bool(families), "missing_supported_families")
    metadata = [entry["metadata"] for entry in inventory.values()]
    kinds = Counter(item["kind"] for item in metadata)
    supported = Counter(item["family"] for item in metadata if item["kind"] == "supported")
    family_gaps = {family: max(0, manifest["minimum_supported_cases_per_family"] - supported[family]) for family in sorted(families)}
    kind_gaps = {kind: max(0, manifest[f"minimum_{kind}_cases"] - kinds[kind]) for kind in ("negative", "adversarial")}
    holdout_metadata = [item for item in metadata if item["split"] == "holdout"]
    holdout_family_gaps = {family: max(0, manifest["minimum_holdout_supported_cases_per_family"]
        - sum(item["kind"] == "supported" and item["family"] == family for item in holdout_metadata)) for family in sorted(families)}
    holdout_kind_gaps = {kind: max(0, manifest[f"minimum_holdout_{kind}_cases"]
        - sum(item["kind"] == kind for item in holdout_metadata)) for kind in ("negative", "adversarial")}
    required_families = {family: max(family_gaps[family], holdout_family_gaps[family]) for family in families}
    required_kinds = {kind: max(kind_gaps[kind], holdout_kind_gaps[kind]) for kind in kind_gaps}
    holdout = sum(item["split"] == "holdout" and item["kind"] == "supported" for item in metadata)
    publishable = sum(item["metadata"]["split"] == "holdout" and item["metadata"]["kind"] == "supported"
                      and item["metadata"]["expected_state"] == "ready" for item in effective.values())
    holdout_gap = max(0, manifest["minimum_precision_predictions"] - publishable)
    total_gap = max(0, manifest["minimum_cases"] - len(metadata))
    return {"schema_version": "v1", "scope": "corpus_capacity_planning_only", "production_ready": False,
            "manifest_digest": digest(manifest), "inventory_digest": digest(inventory),
            "counts": {"total": len(metadata), "by_kind": {kind: kinds[kind] for kind in KINDS},
                       "supported_by_family": {family: supported[family] for family in sorted(families)},
                       "by_split": {split: {"total": sum(item["split"] == split for item in metadata),
                           "by_kind": {kind: sum(item["split"] == split and item["kind"] == kind for item in metadata) for kind in KINDS},
                           "supported_by_family": {family: sum(item["split"] == split and item["kind"] == "supported"
                               and item["family"] == family for item in metadata) for family in sorted(families)}} for split in SPLITS}},
            "deficits": {"headline_minimum_cases": total_gap, "supported_by_family": family_gaps,
                         "holdout_supported_by_family": holdout_family_gaps, "holdout_by_kind": holdout_kind_gaps,
                         **kind_gaps, "effective_total_minimum": max(manifest["minimum_cases"],
                             len(families) * manifest["minimum_supported_cases_per_family"]
                             + manifest["minimum_negative_cases"] + manifest["minimum_adversarial_cases"]),
                         "additional_cases_for_family_and_kind_floors": max(total_gap, sum(family_gaps.values()) + sum(kind_gaps.values())),
                         "additional_cases_for_holdout_strata": sum(holdout_family_gaps.values()) + sum(holdout_kind_gaps.values()),
                         "holdout_supported_capacity": holdout,
                         "holdout_publishable_capacity": publishable,
                         "explicit_release_abstentions": sorted(manifest["release_abstentions"]),
                         "additional_holdout_publication_capacity": holdout_gap,
                         "additional_cases_without_resplitting_or_reusing_lineage": max(total_gap,
                             max(sum(required_families.values()), holdout_gap) + sum(required_kinds.values()))},
            "intake_requests": [{"kind": "supported", "family": family, "count": count,
                                 "preferred_split": "holdout", "status": "new_independent_cases_needed"}
                                for family, count in sorted(required_families.items()) if count]
                                + [{"kind": kind, "count": count, "preferred_split": "holdout", "status": "new_independent_cases_needed"} for kind, count in required_kinds.items() if count],
            "review_queue": [{"fixture_id": key, "split": entry["metadata"]["split"], "kind": entry["metadata"]["kind"],
                              "family": entry["metadata"]["family"], "fixture_digest": digest(entry),
                              "status": "existing_case_not_established_as_preregistered", "review_approved": False}
                             for key, entry in sorted(inventory.items())],
            "limitations": ["Counts are authored case capacity, not independently reviewed model predictions or accuracy.",
                            "Precision still requires reviewed holdout predictions and the unchanged Wilson/coverage gates.",
                            "No train/validation floor is invented and existing cases are never relabeled as fresh holdout."]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "preregister", "validate"))
    parser.add_argument("--manifest", type=Path, default=HERE/"release-manifest.json")
    parser.add_argument("--baseline", type=Path, default=HERE/"fixtures")
    parser.add_argument("--candidates", type=Path)
    parser.add_argument("--origins", type=Path, help="Credential-free upstream URL -> existing local Git checkout; never fetched")
    parser.add_argument("--history", type=Path, action="append", default=[])
    parser.add_argument("--registration", type=Path)
    parser.add_argument("--registration-revision")
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--evaluation", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        from .evaluate import SUPPORTED_FAMILIES
        manifest, baseline = read_json(args.manifest), fixture_inventory(args.baseline)
        if args.command == "plan":
            report = plan_corpus(manifest, baseline, SUPPORTED_FAMILIES)
        else:
            require(args.candidates is not None and args.origins is not None, "candidates_and_local_origins_required")
            candidates = fixture_inventory(args.candidates)
            origins = read_json(args.origins)
            require(isinstance(origins, dict) and all(repo_url(key) == key and isinstance(value, str) for key, value in origins.items()),
                    "invalid_local_origin_mapping")
            history = ledger_history(args.repository, args.registration if args.command == "validate" else None,
                                     (args.registration_revision or "HEAD") if args.command == "validate" else "HEAD")
            for path in args.history:
                record = read_json(path)
                require(digest(record) not in {digest(item) for item in history}, "duplicate_intake_history")
                history.append(record)
            common = {"manifest": manifest, "baseline": baseline, "candidates": candidates,
                      "candidate_root": args.candidates, "origins": origins, "history": history}
            if args.command == "preregister":
                require(args.evaluation is None, "results_cannot_be_preregistered")
                report = preregister(**common, registered_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
            else:
                require(args.registration is not None, "committed_registration_required")
                report = validate_registration(**common, registration=read_json(args.registration), registration_path=args.registration,
                    registration_revision=args.registration_revision, repository=args.repository,
                    evaluation=read_json(args.evaluation) if args.evaluation else None)
        rendered = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output:
            require(not args.output.exists(), "refusing_to_overwrite_intake_artifact")
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(rendered)
        print(rendered, end="")
        return 0
    except (IntakeError, ReleaseEvidenceError, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(json.dumps({"scope": "corpus_intake_only", "production_ready": False,
                          "error": "intake_refused_missing_changed_reused_or_invalid_evidence",
                          "reason_code": str(error) if isinstance(error, IntakeError) else "invalid_or_unreadable_intake_inputs"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
