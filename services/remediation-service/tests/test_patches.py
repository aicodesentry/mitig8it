from __future__ import annotations

import pytest

from src.digests import content_sha256
from src.models import RepairRequest
from src.patches import PatchPolicyError, build_patch_bundle
from src.retrieval import Snapshot


def test_patch_is_exact_immutable_and_content_addressed(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    replacement = source.replace("db.query(`SELECT * FROM users WHERE id = ${id}`)", "db.query('SELECT * FROM users WHERE id = $1', [id])")
    bundle = build_patch_bundle(request, snapshot, [{"path": "src/db.ts", "base_sha256": content_sha256(source), "replacement_content": replacement}])
    assert bundle.patches[0].new_sha256 == content_sha256(replacement)
    assert bundle.patches[0].contents_base64
    assert bundle.artifact_digest.startswith("sha256:")
    assert "+  return db.query('SELECT * FROM users WHERE id = $1', [id]);" in bundle.patches[0].unified_diff


def test_patch_rejects_stale_base(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    with pytest.raises(PatchPolicyError, match="stale_file_digest"):
        build_patch_bundle(request, Snapshot(request), [{"path": "src/db.ts", "base_sha256": "sha256:" + "0" * 64, "replacement_content": source + "\n"}])


def test_patch_rejects_test_tampering(request_payload):
    test_content = "test('x', () => {})\n"
    request_payload["files"].append({"path": "tests/db.test.ts", "content": test_content})
    request = RepairRequest.model_validate(request_payload)
    with pytest.raises(PatchPolicyError, match="protected_path"):
        build_patch_bundle(request, Snapshot(request), [{"path": "tests/db.test.ts", "base_sha256": content_sha256(test_content), "replacement_content": ""}])


def test_patch_rejects_invalid_javascript_syntax(request_payload):
    original = "module.exports = { ok: true };\n"
    request_payload["files"].append({"path": "src/app.js", "content": original})
    request = RepairRequest.model_validate(request_payload)
    with pytest.raises(PatchPolicyError, match="candidate_syntax_invalid"):
        build_patch_bundle(
            request,
            Snapshot(request),
            [{"path": "src/app.js", "base_sha256": content_sha256(original), "replacement_content": "module.exports = {;\n"}],
        )


def test_patch_accepts_valid_javascript_and_records_no_syntax_limitation(request_payload):
    original = "module.exports = { ok: true };\n"
    request_payload["files"].append({"path": "src/app.js", "content": original})
    request = RepairRequest.model_validate(request_payload)
    bundle = build_patch_bundle(
        request,
        Snapshot(request),
        [{"path": "src/app.js", "base_sha256": content_sha256(original), "replacement_content": "module.exports = { ok: false };\n"}],
    )
    assert not any("syntax check skipped" in item for item in bundle.limitations)


def test_typescript_candidates_record_an_explicit_syntax_check_limitation(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    replacement = source.replace("${id}", "$1")
    bundle = build_patch_bundle(
        request,
        Snapshot(request),
        [{"path": "src/db.ts", "base_sha256": content_sha256(source), "replacement_content": replacement}],
    )
    assert any("syntax check skipped for src/db.ts" in item for item in bundle.limitations)


def test_patch_rejects_an_undeclared_dependency(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    replacement = "import sanitize from 'sanitize-sql';\n" + source
    with pytest.raises(PatchPolicyError, match="missing_dependency:sanitize-sql"):
        build_patch_bundle(
            request,
            Snapshot(request),
            [{"path": "src/db.ts", "base_sha256": content_sha256(source), "replacement_content": replacement}],
        )


def test_patch_allows_node_builtins_and_declared_dependencies(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    replacement = "import path from 'node:path';\nimport pg from 'pg';\n" + source
    bundle = build_patch_bundle(
        request,
        Snapshot(request),
        [{"path": "src/db.ts", "base_sha256": content_sha256(source), "replacement_content": replacement}],
    )
    assert bundle.patches[0].new_sha256 == content_sha256(replacement)
