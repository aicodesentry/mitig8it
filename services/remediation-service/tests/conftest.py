from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

import pytest

SERVICE_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from src.git_tree import compute_tree_oid  # noqa: E402
from src.models import GitTreeEntry  # noqa: E402


REGRESSION_TEST_PATH = ".mitig8it/regression/finding-1.test.js"
# Fails on the original interpolated SQL and passes once the file is parameterized.
REPRODUCING_REGRESSION_TEST = (
    "const fs = require('node:fs');\n"
    "const source = fs.readFileSync('src/db.ts', 'utf8');\n"
    "process.exit(source.includes('${id}') ? 1 : 0);\n"
)
# Passes on both trees, so it demonstrates nothing about the finding.
NON_REPRODUCING_REGRESSION_TEST = (
    "const fs = require('node:fs');\n"
    "fs.readFileSync('src/db.ts', 'utf8');\n"
    "process.exit(0);\n"
)


def regression_test_spec(content: str = REPRODUCING_REGRESSION_TEST, path: str = REGRESSION_TEST_PATH) -> dict[str, str]:
    return {"path": path, "content": content}


def git_blob(content: str) -> str:
    raw = content.encode()
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()


@pytest.fixture
def source() -> str:
    return "export function loadUser(db, id) {\n  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n}\n"


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
