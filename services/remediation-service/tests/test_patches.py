from __future__ import annotations

import pytest

from tests.conftest import renamed_payload, whole_file_change

from src.digests import content_sha256
from src.models import RepairRequest
from src.patches import PatchPolicyError, build_patch_bundle
from src.retrieval import Snapshot


def test_patch_is_exact_immutable_and_content_addressed(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    snapshot = Snapshot(request)
    replacement = source.replace("db.query(`SELECT * FROM users WHERE id = ${id}`)", "db.query('SELECT * FROM users WHERE id = $1', [id])")
    bundle = build_patch_bundle(request, snapshot, [whole_file_change("src/db.ts", source, replacement)])
    assert bundle.patches[0].new_sha256 == content_sha256(replacement)
    assert bundle.patches[0].contents_base64
    assert bundle.artifact_digest.startswith("sha256:")
    assert "+  return db.query('SELECT * FROM users WHERE id = $1', [id]);" in bundle.patches[0].unified_diff


def test_patch_rejects_stale_base(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    stale = whole_file_change("src/db.ts", source, source + "\n") | {"replaced_sha256": "sha256:" + "0" * 64}
    with pytest.raises(PatchPolicyError, match="stale_hunk_digest"):
        build_patch_bundle(request, Snapshot(request), [stale])


def test_patch_rejects_test_tampering(request_payload):
    test_content = "test('x', () => {})\n"
    request_payload["files"].append({"path": "tests/db.test.ts", "content": test_content})
    request = RepairRequest.model_validate(request_payload)
    with pytest.raises(PatchPolicyError, match="protected_path"):
        build_patch_bundle(request, Snapshot(request), [whole_file_change("tests/db.test.ts", test_content, "")])


def test_patch_rejects_invalid_javascript_syntax(request_payload):
    original = "module.exports = { ok: true };\n"
    request_payload["files"].append({"path": "src/app.js", "content": original})
    request = RepairRequest.model_validate(request_payload)
    with pytest.raises(PatchPolicyError) as raised:
        build_patch_bundle(
            request,
            Snapshot(request),
            [whole_file_change("src/app.js", original, "module.exports = {;\n")],
        )
    assert raised.value.code == "candidate_syntax_invalid:src/app.js"
    # The rejection hands back what node actually said, so the agent can correct that line
    # instead of guessing, and never leaks the host temporary directory it was checked in.
    guidance = raised.value.guidance or ""
    assert "SyntaxError" in guidance
    assert "src/app.js" in guidance
    assert "mitig8it-syntax-" not in guidance
    assert "/var/folders" not in guidance and "/tmp/" not in guidance


def test_patch_accepts_valid_javascript_and_records_no_syntax_limitation(request_payload):
    original = "module.exports = { ok: true };\n"
    request_payload["files"].append({"path": "src/app.js", "content": original})
    request = RepairRequest.model_validate(request_payload)
    bundle = build_patch_bundle(
        request,
        Snapshot(request),
        [whole_file_change("src/app.js", original, "module.exports = { ok: false };\n")],
    )
    assert not any("syntax check skipped" in item for item in bundle.limitations)


def test_typescript_candidates_are_parsed_by_the_type_stripper(request_payload, source):
    """A `.ts` candidate is parsed, not skipped: `node --check` would reject the annotation."""
    request = RepairRequest.model_validate(request_payload)
    annotated = "export function loadUser(db: Db, id: string): Promise<Row[]> {\n  return db.query('SELECT * FROM users WHERE id = $1', [id]);\n}\n"
    bundle = build_patch_bundle(
        request,
        Snapshot(request),
        [whole_file_change("src/db.ts", source, annotated)],
    )
    assert not any("syntax check" in item for item in bundle.limitations), bundle.limitations


def test_a_typescript_candidate_that_does_not_parse_is_rejected(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    with pytest.raises(PatchPolicyError, match="candidate_syntax_invalid:src/db.ts"):
        build_patch_bundle(
            request,
            Snapshot(request),
            [whole_file_change("src/db.ts", source, "export function loadUser(db: Db, id: string {\n")],
        )


def test_a_candidate_with_syntax_the_stripper_refuses_is_rejected(request_payload, source):
    """An enum has to be compiled, not deleted, so strip-only mode refuses the whole file."""
    request = RepairRequest.model_validate(request_payload)
    with pytest.raises(PatchPolicyError, match="candidate_syntax_invalid:src/db.ts"):
        build_patch_bundle(
            request,
            Snapshot(request),
            [whole_file_change("src/db.ts", source, "enum Mode { Read, Write }\n" + source)],
        )


def test_an_unparsed_suffix_still_records_an_explicit_syntax_check_limitation(request_payload, source):
    """`.tsx` is JSX, which strip-only mode does not transform, so it is still only recorded."""
    payload = renamed_payload(request_payload, "src/db.ts", "src/db.tsx")
    request = RepairRequest.model_validate(payload)
    bundle = build_patch_bundle(
        request,
        Snapshot(request),
        [whole_file_change("src/db.tsx", source, source.replace("${id}", "$1"))],
    )
    assert any("syntax check skipped for src/db.tsx" in item for item in bundle.limitations)


def test_patch_rejects_an_undeclared_dependency(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    replacement = "import sanitize from 'sanitize-sql';\n" + source
    with pytest.raises(PatchPolicyError, match="missing_dependency:sanitize-sql"):
        build_patch_bundle(
            request,
            Snapshot(request),
            [whole_file_change("src/db.ts", source, replacement)],
        )


def test_patch_allows_node_builtins_and_declared_dependencies(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    replacement = "import path from 'node:path';\nimport pg from 'pg';\n" + source
    bundle = build_patch_bundle(
        request,
        Snapshot(request),
        [whole_file_change("src/db.ts", source, replacement)],
    )
    assert bundle.patches[0].new_sha256 == content_sha256(replacement)


# --- Line endings -------------------------------------------------------------------------
#
# A suggestion committed on GitHub writes the replaced lines with the line ending the file
# already uses there. The verified bytes must be those bytes, so the replacement reuses the
# replaced block's line ending rather than always writing LF.

from src.patches import _hunk_text  # noqa: E402


def test_a_crlf_block_keeps_crlf():
    assert _hunk_text(["x = 1", "import os"], "x = 0\r\n") == "x = 1\r\nimport os\r\n"


def test_an_lf_block_stays_lf():
    assert _hunk_text(["x = 1", "import os"], "x = 0\n") == "x = 1\nimport os\n"


def test_a_mixed_file_follows_the_replaced_block():
    # A CRLF block inside an otherwise LF file, and an LF block inside a CRLF file.
    assert _hunk_text(["a", "b"], "old\r\n") == "a\r\nb\r\n"
    assert _hunk_text(["a", "b"], "old\n", "\r\n") == "a\nb\n"


def test_a_final_line_without_a_newline_uses_the_file_ending_and_adds_none():
    assert _hunk_text(["a", "b"], "old", "\r\n") == "a\r\nb"
    assert _hunk_text(["a", "b"], "old") == "a\nb"


def test_apply_hunks_on_a_crlf_file_writes_crlf_only(request_payload):
    from src.patches import apply_hunks  # noqa: PLC0415

    source = "import x\r\nconst a = 1;\r\nconst b = 2;\r\n"
    payload = dict(request_payload)
    payload["files"] = [{"path": "src/db.ts", "content": source}]
    payload["tree_entries"] = []
    payload["head_tree_oid"] = None
    snapshot = Snapshot(RepairRequest.model_validate(payload))
    contents = apply_hunks(
        snapshot,
        [
            {
                "path": "src/db.ts",
                "start_line": 2,
                "original_lines": ["const a = 1;"],
                "replacement_lines": ["const a = 10;", "const c = 3;"],
            }
        ],
    )
    assert contents["src/db.ts"] == "import x\r\nconst a = 10;\r\nconst c = 3;\r\nconst b = 2;\r\n"
