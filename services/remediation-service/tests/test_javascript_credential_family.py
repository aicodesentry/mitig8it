"""`hardcoded_credential` on JavaScript and TypeScript: the shape, the repair and its proof.

The September 2026 replay found two `secret.hardcoded.credential` findings and could repair
neither, because the family was Python-only: the Node harness recorded no environment read,
so a repair of it could not be proven and the engine skipped it as `unsupported_rule_family`.
The harness now records environment reads, so the family is supported, and this is what that
support has to do.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from src.families import (
    HARDCODED_CREDENTIAL,
    JAVASCRIPT,
    PYTHON,
    family_assertion,
    family_supported,
    language_of_path,
    rule_family,
)
from src.fixtures import build_repair_request, read_fixture
from src.git_tree import compute_tree_oid
from src.models import FindingSnapshot, GitTreeEntry, RepairRequest
from src.proofs import ProofFallback, generate_proof
from src.retrieval import Snapshot
from src.sites import js_environment_name, js_literal_assignment, js_module_exports_name
from src.templates import TemplateFallback, generate_template
from tests.conftest import git_blob

FIXTURES = Path(__file__).resolve().parents[3] / "benchmarks" / "remediation" / "fixtures"


def _finding(path: str, line: int) -> FindingSnapshot:
    return FindingSnapshot(
        id="secret-1",
        rule_id="cwe-798.js-credential-constant",
        cwe_id="CWE-798",
        category="hardcoded secrets",
        title="Credential held as a literal",
        message="Credential held as a literal",
        affected_path=path,
        line_start=line,
        line_end=line,
    )


class TestFamilySupport:
    def test_javascript_now_supports_the_family(self):
        assert family_supported(HARDCODED_CREDENTIAL, JAVASCRIPT)
        assert family_supported(HARDCODED_CREDENTIAL, PYTHON)

    @pytest.mark.parametrize("path", ["src/config.js", "src/config.ts", "src/config.tsx", "src/config.mjs"])
    def test_every_javascript_suffix_reaches_the_family(self, path):
        assert family_supported(HARDCODED_CREDENTIAL, language_of_path(path))

    def test_a_cwe_798_finding_classifies_into_the_family(self):
        assert rule_family(_finding("src/config.ts", 1)) == HARDCODED_CREDENTIAL

    def test_the_javascript_assertion_names_the_node_harness_calls(self):
        assertion = family_assertion(HARDCODED_CREDENTIAL, JAVASCRIPT)
        assert "h.assert.envRead" in assertion
        assert "h.assert.notInSource" in assertion
        assert "process.env" in assertion
        # The Python assertion is a different harness and must not have been swapped in.
        assert assertion != family_assertion(HARDCODED_CREDENTIAL, PYTHON)


class TestLiteralAssignment:
    @pytest.mark.parametrize(
        "source,expected",
        [
            ('const apiKey = "sk-live-abc123def456";', ("apiKey", "sk-live-abc123def456", '"', "constant")),
            ("let apiKey = 'sk-live-abc123def456';", ("apiKey", "sk-live-abc123def456", "'", "constant")),
            ('export const apiKey = "sk-live-abc123def456";', ("apiKey", "sk-live-abc123def456", '"', "constant")),
            ('const apiKey: string = "sk-live-abc123def456";', ("apiKey", "sk-live-abc123def456", '"', "constant")),
            ("  clientSecret: 'shhh-abc123def456',", ("clientSecret", "shhh-abc123def456", "'", "property")),
        ],
    )
    def test_recognized_shapes(self, source, expected):
        assert js_literal_assignment(source, 1) == expected

    @pytest.mark.parametrize(
        "source",
        [
            "// const apiKey = \"sk-live-abc123def456\";",
            " * const apiKey = \"sk-live-abc123def456\";",
            'const apiKey = `sk-${region}-abc123`;',
            'const apiKey = "sk-live-\\u0061bc";',
            'const apiKey = process.env.API_KEY;',
            "const apiKey = '';",
        ],
        ids=["line comment", "jsdoc line", "template literal", "escape", "already repaired", "empty"],
    )
    def test_shapes_that_are_not_a_literal_assignment(self, source):
        assert js_literal_assignment(source, 1) is None

    def test_a_line_outside_the_file_is_not_an_assignment(self):
        assert js_literal_assignment('const a = "b";', 99) is None


class TestEnvironmentName:
    @pytest.mark.parametrize(
        "identifier,expected",
        [
            ("apiKey", "API_KEY"),
            ("API_KEY", "API_KEY"),
            ("clientSecret", "CLIENT_SECRET"),
            ("stripeAPIKey", "STRIPE_API_KEY"),
            ("_privateKey", "PRIVATE_KEY"),
            ("db_password", "DB_PASSWORD"),
        ],
    )
    def test_derived_from_the_identifier(self, identifier, expected):
        assert js_environment_name(identifier) == expected


class TestExportDetection:
    @pytest.mark.parametrize(
        "source",
        [
            "const apiKey = 'x';\nmodule.exports = { apiKey };",
            "const apiKey = 'x';\nmodule.exports.apiKey = apiKey;",
            "const apiKey = 'x';\nexports.apiKey = apiKey;",
            "export const apiKey = 'x';",
        ],
    )
    def test_exported(self, source):
        assert js_module_exports_name(source, "apiKey")

    def test_not_exported(self):
        assert not js_module_exports_name("const apiKey = 'x';\nmodule.exports = { other };", "apiKey")

    def test_a_mention_inside_a_string_is_not_an_export(self):
        assert not js_module_exports_name("const s = 'module.exports = { apiKey }';", "apiKey")


def _snapshot(request_payload: dict, path: str, source: str):
    """A one-file snapshot over `source`, built from the suite's standard request payload."""
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=git_blob(source))]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": source, "sha": git_blob(source)}]
    payload["findings"] = [
        {
            "snapshot_id": "secret-1",
            "rule_id": "cwe-798.js-credential-constant",
            "cwe_id": "CWE-798",
            "file_path": path,
            "line_start": 1,
            "line_end": 1,
        }
    ]
    request = RepairRequest.model_validate(payload)
    return Snapshot(request), request.findings[0]


class TestTemplate:
    def test_a_constant_is_rewritten_to_a_process_env_read(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "src/config.ts", 'const apiKey = "sk-live-abc123def456";\n')
        patch = generate_template(snapshot, finding, HARDCODED_CREDENTIAL, JAVASCRIPT)
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        assert patch.changes[0]["replacement_lines"] == ["const apiKey = process.env.API_KEY;"]

    def test_a_config_key_keeps_its_indentation_and_trailing_comma(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "src/config.js", "  clientSecret: 'shhh-abc123def456',\n")
        patch = generate_template(snapshot, finding, HARDCODED_CREDENTIAL, JAVASCRIPT)
        assert patch.changes[0]["replacement_lines"] == ["  clientSecret: process.env.CLIENT_SECRET,"]

    def test_no_import_is_added_because_process_is_a_global(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "src/config.js", 'const apiKey = "sk-live-abc123def456";\n')
        patch = generate_template(snapshot, finding, HARDCODED_CREDENTIAL, JAVASCRIPT)
        assert len(patch.changes) == 1

    def test_an_unrecognized_shape_falls_back_with_a_reason(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "src/config.js", "const apiKey = readSecret();\n")
        patch = generate_template(snapshot, finding, HARDCODED_CREDENTIAL, JAVASCRIPT)
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "string_literal_assignment_not_found"

    def test_the_literal_must_be_uniquely_placed_on_its_line(self, request_payload):
        snapshot, finding = _snapshot(
            request_payload, "src/config.js", 'const apiKey = "abc123def456" === "abc123def456" ? 1 : 2;\n'
        )
        patch = generate_template(snapshot, finding, HARDCODED_CREDENTIAL, JAVASCRIPT)
        assert isinstance(patch, TemplateFallback)


class TestGeneratedProof:
    def test_the_proof_asserts_the_env_read_and_the_absent_literal(self, request_payload):
        snapshot, finding = _snapshot(
            request_payload, "src/config.js", 'const apiKey = "sk-live-abc123def456";\nmodule.exports = { apiKey };\n'
        )
        proof = generate_proof(snapshot, finding, HARDCODED_CREDENTIAL, JAVASCRIPT)
        assert not isinstance(proof, ProofFallback), getattr(proof, "reason", None)
        assert 'h.assert.envRead("API_KEY")' in proof.content
        assert 'h.assert.notInSource(m, "sk-live-abc123def456")' in proof.content
        assert 'h.assert.equal(m.apiKey, "value-from-env")' in proof.content
        assert proof.path.endswith(".test.js")

    def test_a_value_the_module_does_not_export_is_not_asserted_on(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "src/config.js", "  clientSecret: 'shhh-abc123def456',\n")
        proof = generate_proof(snapshot, finding, HARDCODED_CREDENTIAL, JAVASCRIPT)
        assert 'h.assert.envRead("CLIENT_SECRET")' in proof.content
        assert "h.assert.equal(m." not in proof.content

    def test_the_proof_needs_no_route(self, request_payload):
        """Every other JavaScript family derives an Express route first. A secret literal is
        not inside a handler, so requiring one would fail every real finding."""
        snapshot, finding = _snapshot(request_payload, "src/config.js", 'const apiKey = "sk-live-abc123def456";\n')
        proof = generate_proof(snapshot, finding, HARDCODED_CREDENTIAL, JAVASCRIPT)
        assert not isinstance(proof, ProofFallback)
        assert proof.site is None


requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="the Node harness runs under node")


@requires_node
class TestFixtures:
    @pytest.mark.parametrize("name", ["js-hardcoded-secret", "js-hardcoded-config-secret"])
    def test_the_template_reproduces_the_reviewed_repair(self, name):
        directory = FIXTURES / name
        fixture = read_fixture(directory)
        request = build_repair_request(directory, fixture)
        snapshot = Snapshot(request)
        finding = request.findings[0]
        patch = generate_template(snapshot, finding, HARDCODED_CREDENTIAL, JAVASCRIPT)
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)

        source = snapshot.full_content(fixture["source"]).splitlines()
        change = patch.changes[0]
        repaired = list(source)
        start = int(change["start_line"]) - 1
        repaired[start : start + len(change["original_lines"])] = change["replacement_lines"]
        expected = (directory / fixture["reference_repair"]).read_text(encoding="utf-8").splitlines()
        assert repaired == expected

    @pytest.mark.parametrize("name", ["js-hardcoded-secret", "js-hardcoded-config-secret"])
    def test_the_fixture_declares_the_family_and_a_node_trusted_test(self, name):
        fixture = json.loads((FIXTURES / name / "fixture.json").read_text(encoding="utf-8"))
        assert fixture["family"] == HARDCODED_CREDENTIAL
        assert fixture["trusted_fixture_test"]["runtime"] == "node"
        assert fixture["finding"]["cwe_id"] == "CWE-798"
