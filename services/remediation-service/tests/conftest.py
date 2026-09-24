from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

import pytest

SERVICE_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from src.digests import content_sha256  # noqa: E402
from src.git_tree import compute_tree_oid  # noqa: E402
from src.models import GitTreeEntry  # noqa: E402


REGRESSION_TEST_PATH = ".mitig8it/regression/finding-1.test.js"
# A behavior test: it loads the changed module, calls the affected function with a fake db and
# an injection payload, and exits non-zero only while the payload reaches the SQL text.
REPRODUCING_REGRESSION_TEST = (
    "const { loadUser } = require('../../src/db');\n"
    "let text = '';\n"
    "loadUser({ query: (sql) => { text = String(sql); } }, '1 OR 1=1');\n"
    "process.exit(text.includes('1 OR 1=1') ? 1 : 0);\n"
)
# Passes on both trees, so it demonstrates nothing about the finding.
NON_REPRODUCING_REGRESSION_TEST = (
    "require('../../src/db');\n"
    "process.exit(0);\n"
)


def regression_test_spec(
    content: str = REPRODUCING_REGRESSION_TEST, path: str = REGRESSION_TEST_PATH, finding_id: str = "finding-1"
) -> dict[str, str]:
    return {"finding_id": finding_id, "path": path, "content": content}


def whole_file_change(path: str, original: str, replacement: str) -> dict[str, object]:
    """One hunk replacing every line of a file, for cases stated as a whole-file replacement."""
    lines = original.splitlines(keepends=True)
    return {
        "path": path,
        "start_line": 1,
        "end_line": max(1, len(lines)),
        "original_lines": original.splitlines(),
        "replacement_lines": replacement.splitlines(),
    }


def git_blob(content: str) -> str:
    raw = content.encode()
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()


@pytest.fixture
def source() -> str:
    return "export function loadUser(db, id) {\n  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n}\n"


# The sink is two hops from its input: the SQL text is built by another function, so the template
# sees `db.query(sql)` over a local it cannot trace to a literal and refuses with
# `query_variable_not_assigned_in_scope`. Nothing about the vulnerability is different; only the
# deterministic path's reach is. Tests about what the *model* does with a finding use this, because
# a finding the template repairs first never reaches the model at all.
# `test_template_first.test_the_model_only_fixture_is_refused_by_the_template` pins the reason, so
# this stops being a silent assumption the day the template learns to follow the hop.
MODEL_ONLY_SOURCE = (
    "function buildLookup(id) {\n"
    "  return \"SELECT * FROM users WHERE id = '\" + id + \"'\";\n"
    "}\n"
    "function loadUser(db, id) {\n"
    "  const sql = buildLookup(id);\n"
    "  return db.query(sql);\n"
    "}\n"
    "module.exports = { loadUser };\n"
)
MODEL_ONLY_REPAIRED = (
    "function buildLookup() {\n"
    "  return 'SELECT * FROM users WHERE id = $1';\n"
    "}\n"
    "function loadUser(db, id) {\n"
    "  const sql = buildLookup();\n"
    "  return db.query(sql, [id]);\n"
    "}\n"
    "module.exports = { loadUser };\n"
)
# The finding is on the `db.query(sql)` line, the sink the rule reports.
MODEL_ONLY_LINE = 6


@pytest.fixture
def model_only_source() -> str:
    return MODEL_ONLY_SOURCE


@pytest.fixture
def model_only_payload(request_payload, model_only_source: str) -> dict[str, Any]:
    """`request_payload` over a source the template refuses, for the model-path tests."""
    return with_source(request_payload, model_only_source, line=MODEL_ONLY_LINE)


def with_source(payload: dict[str, Any], text: str, line: int | None = None) -> dict[str, Any]:
    """`payload` with every copy of the affected file replaced, and the finding moved to `line`."""
    updated = {key: list(value) if isinstance(value, list) else value for key, value in payload.items()}
    entries = [
        GitTreeEntry(path=entry["path"], mode=entry["mode"], type=entry["type"], sha=git_blob(text) if entry["path"].startswith("src/db.") else entry["sha"])
        for entry in payload["tree_entries"]
    ]
    updated["tree_entries"] = [entry.model_dump() for entry in entries]
    updated["head_tree_oid"] = compute_tree_oid(entries)
    updated["files"] = [
        {**item, "content": text, "sha": git_blob(text)} if item["path"].startswith("src/db.") else dict(item)
        for item in payload["files"]
    ]
    if line is not None:
        updated["findings"] = [{**item, "line_start": line, "line_end": line} for item in payload["findings"]]
    return updated


def renamed_payload(payload: dict[str, Any], old: str, new: str) -> dict[str, Any]:
    """`payload` with one snapshot path renamed, for the cases that turn on a file's suffix."""
    updated = {key: list(value) if isinstance(value, list) else value for key, value in payload.items()}
    entries = [
        GitTreeEntry(path=new if entry["path"] == old else entry["path"], mode=entry["mode"], type=entry["type"], sha=entry["sha"])
        for entry in payload["tree_entries"]
    ]
    updated["tree_entries"] = [entry.model_dump() for entry in entries]
    updated["head_tree_oid"] = compute_tree_oid(entries)
    updated["files"] = [{**item, "path": new} if item["path"] == old else dict(item) for item in payload["files"]]
    updated["findings"] = [{**item, "file_path": new} if item.get("file_path") == old else dict(item) for item in payload["findings"]]
    return updated


@pytest.fixture
def request_payload(source: str) -> dict[str, Any]:
    entries = [
        GitTreeEntry(path="src/db.ts", mode="100644", type="blob", sha=git_blob(source)),
        GitTreeEntry(path="package.json", mode="100644", type="blob", sha=git_blob('{"dependencies":{"pg":"8.13.0"}}\n')),
    ]
    return {
        "schema_version": "v1",
        "job_id": "job-1",
        "tenant_id": "installation-7",
        "installation_id": "installation-7",
        "repository_id": "repo-9",
        "repository_full_name": "acme/widget",
        "pull_request_id": "pr-node-4",
        "pull_request_number": 4,
        "analysis_run_id": "analysis-2",
        "head_sha": "a" * 40,
        "base_sha": "b" * 40,
        "head_tree_oid": compute_tree_oid(entries),
        "tree_entries": [entry.model_dump() for entry in entries],
        "tree_truncated": False,
        "findings": [{"snapshot_id": "finding-1", "rule_id": "js.sql-injection", "cwe_id": "CWE-89", "file_path": "src/db.ts", "line_start": 2, "line_end": 2}],
        "files": [
            {"path": "src/db.ts", "content": source, "sha": git_blob(source)},
            {"path": "package.json", "content": '{"dependencies":{"pg":"8.13.0"}}\n', "sha": git_blob('{"dependencies":{"pg":"8.13.0"}}\n')},
        ],
        "profile": {"framework": "express", "database": "pg"},
        "policy": {
            "policy_version": "policy-1",
            "input_usd_per_million_tokens": 1.0,
            "output_usd_per_million_tokens": 3.0,
            "sandbox_image_digest": "ghcr.io/mitig8it/remediation-runner@sha256:" + "c" * 64,
            "verification_checks": [
                {"check_id": "exploit", "kind": "exploit", "argv": ["npm", "run", "test:exploit"], "timeout_seconds": 60},
                {"check_id": "behavior", "kind": "behavior", "argv": ["npm", "run", "test:behavior"], "timeout_seconds": 60},
            ],
        },
        "versions": {"repair_model": "repair-model-1", "prompt": "v1", "retriever": "v1", "verifier": "v1"},
    }
