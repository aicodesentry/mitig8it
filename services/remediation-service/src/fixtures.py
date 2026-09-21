"""Converts a benchmark fixture directory into a complete, self-consistent RepairRequest.

This exists so a development run can exercise the real intake contract (complete Git tree,
digest-bound snapshot files, fixed verification argv) without a control plane, a GitHub
installation, or cloud services. It is a development and evaluation helper: it fabricates
deterministic revision identifiers and therefore must never be used to build a request that
represents a real repository.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .digests import git_blob_sha1
from .git_tree import compute_tree_oid
from .models import GitTreeEntry, RepairRequest
from .retrieval.snapshot import validate_repo_path

EXCLUDED_TOP_LEVEL = {"fixture.json", "expected"}
MAX_FIXTURE_FILE_BYTES = 512_000
DEVELOPMENT_POLICY_VERSION = "fixture-development-v1"


class FixtureLoadError(ValueError):
    pass


def _deterministic_sha(label: str, seed: str) -> str:
    return hashlib.sha1(f"{label}:{seed}".encode("utf-8")).hexdigest()  # noqa: S324 - fabricated development identifier.


def read_fixture(fixture_dir: Path) -> dict[str, Any]:
    path = fixture_dir / "fixture.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FixtureLoadError(f"fixture metadata could not be read: {path}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != "v1":
        raise FixtureLoadError(f"unsupported fixture schema: {path}")
    return document


def snapshot_files(fixture_dir: Path) -> list[dict[str, str]]:
    """Reads every fixture file except its metadata and reference repair."""
    files: list[dict[str, str]] = []
    for path in sorted(fixture_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(fixture_dir).as_posix()
        if relative.split("/", 1)[0] in EXCLUDED_TOP_LEVEL:
            continue
        raw = path.read_bytes()
        if len(raw) > MAX_FIXTURE_FILE_BYTES:
            raise FixtureLoadError(f"fixture file exceeds the snapshot byte limit: {relative}")
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FixtureLoadError(f"fixture file is not UTF-8 text: {relative}") from exc
        files.append({"path": validate_repo_path(relative), "content": content, "sha": git_blob_sha1(raw)})
    if not files:
        raise FixtureLoadError(f"fixture contains no snapshot files: {fixture_dir}")
    return files


def verification_checks(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    """Returns the policy-shaped checks, without the fixture's expected-outcome annotations."""
    declared = fixture.get("verification_checks")
    if not isinstance(declared, list) or not declared:
        raise FixtureLoadError(f"{fixture.get('id')}: verification_checks is required")
    checks: list[dict[str, Any]] = []
    for item in declared:
        if not isinstance(item, dict) or not isinstance(item.get("argv"), list):
            raise FixtureLoadError(f"{fixture.get('id')}: verification check is malformed")
        checks.append(
            {
                "check_id": item["check_id"],
                "kind": item["kind"],
                "argv": [str(part) for part in item["argv"]],
                "timeout_seconds": int(item.get("timeout_seconds", 60)),
            }
        )
    return checks


GENERATED_TEST_DIRECTORY = ".mitig8it/regression"

GENERATED_TEST_TEMPLATE = """// Generated regression reproducer for %(fixture_id)s.
// It must exit non-zero on the original tree and zero on the repaired tree. It runs the
// fixture's audited reproducer from its own file so a development run exercises the
// generated-test path without inventing a second, unreviewed reproducer.
const { spawnSync } = require('node:child_process');

const argv = %(argv)s;
const command = argv[0] === 'node' ? process.execPath : argv[0];
const result = spawnSync(command, argv.slice(1), { cwd: process.cwd(), stdio: 'inherit' });
process.exit(result.status === 0 ? 0 : 1);
"""

PYTHON_GENERATED_TEST_TEMPLATE = """# Generated regression reproducer for %(fixture_id)s.
# It must exit non-zero on the original tree and zero on the repaired tree. It runs the
# fixture's audited reproducer from its own file so a development run exercises the
# generated-test path without inventing a second, unreviewed reproducer.
import subprocess
import sys

argv = %(argv)s
command = sys.executable if argv[0] in ("python3", "python") else argv[0]
result = subprocess.run([command, *argv[1:]], cwd=".")
raise SystemExit(0 if result.returncode == 0 else 1)
"""


def fixture_regression_test(fixture: dict[str, Any], finding_id: str, suffix: str = "") -> dict[str, str]:
    """The generated regression test a development or benchmark run proposes for one finding.

    Real jobs get this file from the agent. Fixtures already ship a reviewed `tests/verify.js`
    reproducer, so the scripted provider generates a test that re-runs exactly that argv rather
    than fabricating fixture-specific assertions the benchmark could not audit. One test is
    proposed per finding, because a candidate claims only findings with their own reproducer.
    """
    checks = fixture.get("verification_checks")
    exploit = next(
        (item for item in checks or [] if isinstance(item, dict) and item.get("kind") == "exploit"), None
    )
    if not isinstance(exploit, dict) or not isinstance(exploit.get("argv"), list) or not exploit["argv"]:
        raise FixtureLoadError(f"{fixture.get('id')}: an exploit check argv is required to generate a regression test")
    name = re.sub(r"[^A-Za-z0-9._-]", "-", f"{fixture.get('id')}-{finding_id}{suffix}").strip("-.") or "finding"
    python = str(fixture.get("source") or "").endswith(".py")
    template = PYTHON_GENERATED_TEST_TEMPLATE if python else GENERATED_TEST_TEMPLATE
    return {
        "finding_id": str(finding_id),
        "path": f"{GENERATED_TEST_DIRECTORY}/{name}.test.{'py' if python else 'js'}",
        "content": template
        % {
            "fixture_id": json.dumps(str(fixture.get("id"))),
            "argv": json.dumps([str(part) for part in exploit["argv"]]),
        },
    }


def _normalized_finding(fixture_id: Any, finding: Any) -> dict[str, Any]:
    if not isinstance(finding, dict):
        raise FixtureLoadError(f"{fixture_id}: finding is required")
    return {key: ("" if value is None and key in {"cwe_id", "rule_id", "category"} else value) for key, value in finding.items()}


def fixture_units(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    """The fixture's repair units, each one affected file with its own finding and repair.

    A single-file fixture has exactly one unit built from the top-level `source`,
    `reference_repair`, and `finding`. A multi-file fixture adds `additional_units`, which is
    how one job can carry findings in several files and therefore several finding groups.
    """
    units = [
        {
            "source": fixture.get("source"),
            "reference_repair": fixture.get("reference_repair"),
            "finding": fixture.get("finding"),
        }
    ]
    extra = fixture.get("additional_units") or []
    if not isinstance(extra, list):
        raise FixtureLoadError(f"{fixture.get('id')}: additional_units must be a list")
    for item in extra:
        if not isinstance(item, dict):
            raise FixtureLoadError(f"{fixture.get('id')}: additional unit is malformed")
        units.append({"source": item.get("source"), "reference_repair": item.get("reference_repair"), "finding": item.get("finding")})
    return units


def fixture_finding(fixture: dict[str, Any]) -> dict[str, Any]:
    return _normalized_finding(fixture.get("id"), fixture.get("finding"))


def fixture_findings(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    return [_normalized_finding(fixture.get("id"), unit["finding"]) for unit in fixture_units(fixture)]


def _read_reference(fixture_dir: Path, fixture_id: Any, reference: Any) -> str | None:
    if not isinstance(reference, str):
        return None
    target = (fixture_dir / reference).resolve()
    if fixture_dir.resolve() not in target.parents or not target.is_file():
        raise FixtureLoadError(f"{fixture_id}: reference repair is outside the fixture")
    return target.read_text(encoding="utf-8")


def reference_replacement(fixture_dir: Path, fixture: dict[str, Any]) -> str | None:
    return _read_reference(fixture_dir, fixture.get("id"), fixture.get("reference_repair"))


def reference_replacements(fixture_dir: Path, fixture: dict[str, Any]) -> dict[str, str]:
    """Maps each affected snapshot path to its reviewed reference repair.

    An abstention fixture declares no reference repair and therefore returns an empty mapping.
    """
    replacements: dict[str, str] = {}
    for unit in fixture_units(fixture):
        content = _read_reference(fixture_dir, fixture.get("id"), unit["reference_repair"])
        if content is not None and isinstance(unit["source"], str):
            replacements[unit["source"]] = content
    return replacements


def build_repair_request(
    fixture_dir: Path,
    fixture: dict[str, Any],
    *,
    job_id: str | None = None,
    versions: dict[str, str] | None = None,
    allow_development_verification: bool = True,
    sandbox_image_digest: str | None = None,
) -> RepairRequest:
    files = snapshot_files(fixture_dir)
    entries = [GitTreeEntry(path=item["path"], mode="100644", type="blob", sha=item["sha"]) for item in files]
    head_tree_oid = compute_tree_oid(entries)
    budget = fixture.get("budget") or {}
    payload = {
        "schema_version": "v1",
        "job_id": job_id or f"fixture-{fixture['id']}",
        "tenant_id": "fixture-development",
        "repository_id": fixture["repository_id"],
        "head_sha": _deterministic_sha("head", head_tree_oid),
        "base_sha": _deterministic_sha("base", head_tree_oid),
        "head_tree_oid": head_tree_oid,
        "tree_entries": [entry.model_dump() for entry in entries],
        "tree_truncated": False,
        "findings": fixture_findings(fixture),
        "files": files,
        "profile": {"source": "benchmark_fixture", "fixture_id": fixture["id"]},
        "policy": {
            "policy_version": DEVELOPMENT_POLICY_VERSION,
            "input_usd_per_million_tokens": 1.0,
            "output_usd_per_million_tokens": 1.0,
            "sandbox_image_digest": sandbox_image_digest,
            "allow_development_verification": allow_development_verification,
            "verification_checks": verification_checks(fixture),
            "max_tool_calls": int(budget.get("max_tool_calls", 20)),
            "max_attempts": int(budget.get("max_attempts", 3)),
            "max_spend_usd": float(budget.get("max_cost_usd", 2.0)),
        },
        "versions": versions or {"benchmark": "fixture-development-v1", "retriever": "v1", "verifier": "v1"},
    }
    return RepairRequest.model_validate(payload)
