"""`code_injection_eval` on JavaScript and TypeScript: the shape, the repair and its proof.

The family was Python-only because the Node harness stubbed no interpreter: a repair could not
be proven, so the engine skipped every JavaScript finding as `unsupported_rule_family`, which
said nothing about the code. The harness now records `eval`, `new Function`, the `vm` compile
calls, and a string timer without running any of them, so the family is supported and the
refusal moved to where it belongs: a static gate that separates reading a value out of a string
from compiling a program out of one.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from src.families import (
    CODE_INJECTION_EVAL,
    JAVASCRIPT,
    PYTHON,
    family_assertion,
    family_supported,
    language_of_path,
    rule_family,
)
from src.fixtures import build_repair_request, read_fixture
from src.gates import DYNAMIC_CODE_MESSAGE, javascript_dynamic_code, static_gate
from src.git_tree import compute_tree_oid
from src.models import FindingSnapshot, GitTreeEntry, RepairRequest
from src.proofs import ProofFallback, generate_proof
from src.retrieval import Snapshot
from src.sites import SiteError, js_eval_site, js_function_for_line, js_value_origin
from src.templates import TemplateFallback, generate_template
from tests.conftest import git_blob

FIXTURES = Path(__file__).resolve().parents[3] / "benchmarks" / "remediation" / "fixtures"

# The data shape: a request value the function reads back as a document.
PARSER_JS = (
    "// Pricing rules evaluated per request.\n"
    "function applyRule(body, row) {\n"
    "  const expression = body.expression;\n"
    "  return eval(expression);\n"
    "}\n"
    "\n"
    "module.exports = { applyRule };\n"
)
# The code shape: a string compiled into something the module calls later.
COMPILER_JS = (
    "function compileFormula(source) {\n"
    "  const compiled = new Function('row', `return ${source};`);\n"
    "  return (row) => compiled(row);\n"
    "}\n"
    "\n"
    "module.exports = { compileFormula };\n"
)


def _finding(path: str, line: int) -> FindingSnapshot:
    return FindingSnapshot(
        id="eval-1",
        rule_id="cwe-95.eval-injection",
        cwe_id="CWE-95",
        category="code injection",
        title="Code injection",
        message="A value is handed to an interpreter",
        affected_path=path,
        line_start=line,
        line_end=line,
    )


def _snapshot(request_payload: dict, path: str, source: str, line: int):
    """A one-file snapshot over `source`, built from the suite's standard request payload."""
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=git_blob(source))]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": source, "sha": git_blob(source)}]
    payload["findings"] = [
        {
            "snapshot_id": "eval-1",
            "rule_id": "cwe-95.eval-injection",
            "cwe_id": "CWE-95",
            "file_path": path,
            "line_start": line,
            "line_end": line,
        }
    ]
    request = RepairRequest.model_validate(payload)
    return Snapshot(request), request.findings[0]


class TestFamilySupport:
    def test_javascript_now_supports_the_family(self):
        assert family_supported(CODE_INJECTION_EVAL, JAVASCRIPT)
        assert family_supported(CODE_INJECTION_EVAL, PYTHON)

    @pytest.mark.parametrize("path", ["src/rules.js", "src/rules.ts", "src/rules.tsx", "src/rules.mjs"])
    def test_every_javascript_suffix_reaches_the_family(self, path):
        assert family_supported(CODE_INJECTION_EVAL, language_of_path(path))

    def test_a_cwe_95_finding_classifies_into_the_family(self):
        assert rule_family(_finding("src/rules.ts", 1)) == CODE_INJECTION_EVAL

    def test_the_javascript_assertion_names_the_node_harness_calls(self):
        assertion = family_assertion(CODE_INJECTION_EVAL, JAVASCRIPT)
        assert "h.assert.noCode" in assertion and "h.call" in assertion
        # The Python assertion is a different harness and must not have been swapped in.
        assert assertion != family_assertion(CODE_INJECTION_EVAL, PYTHON)


class TestFunctionSite:
    @pytest.mark.parametrize(
        "declaration",
        [
            "function applyRule(body, row) {",
            "async function applyRule(body, row) {",
            "export function applyRule(body, row) {",
            "const applyRule = (body, row) => {",
            "const applyRule = function (body, row) {",
        ],
    )
    def test_recognized_declarations(self, declaration):
        source = PARSER_JS.replace("function applyRule(body, row) {", declaration)
        function = js_function_for_line(source, 4)
        assert (function.name, function.parameters, function.returns_directly) == ("applyRule", ("body", "row"), True)
        assert function.start_line == 2 and function.end_line == 5

    def test_a_parameter_list_the_scan_cannot_line_up_is_refused(self):
        source = PARSER_JS.replace("(body, row)", "({ expression }, row = {})")
        with pytest.raises(SiteError, match="function_parameters_not_plain_names"):
            js_function_for_line(source, 4)

    def test_a_line_outside_any_function_has_no_site(self):
        with pytest.raises(SiteError, match="enclosing_function_not_found"):
            js_function_for_line(PARSER_JS, 7)

    def test_an_identifier_resolves_back_to_the_parameter_and_member_it_came_from(self):
        function = js_function_for_line(PARSER_JS, 4)
        lines = PARSER_JS.splitlines()
        assert js_value_origin(lines, function, 4, "expression") == ("body", ("expression",))
        assert js_value_origin(lines, function, 4, "body") == ("body", ())
        # A local built from something other than a parameter is not request data.
        assert js_value_origin(lines, function, 4, "unrelated") is None

    def test_the_eval_site_is_the_one_shape_both_generators_go_through(self):
        assert js_eval_site(PARSER_JS, 4) == (js_function_for_line(PARSER_JS, 4), "body", ("expression",))
        with pytest.raises(SiteError, match="eval_argument_not_an_identifier"):
            js_eval_site(PARSER_JS.replace("eval(expression)", "eval('return ' + expression)"), 4)


class TestGate:
    def test_reading_a_value_out_of_a_string_is_allowed(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "app.js", PARSER_JS, 4)
        assert not javascript_dynamic_code(snapshot, finding)
        assert static_gate(snapshot, finding, CODE_INJECTION_EVAL, JAVASCRIPT) is None

    @pytest.mark.parametrize(
        "line",
        [
            "  const compiled = new Function('row', 'return ' + source);",
            "  const compiled = vm.compileFunction('return ' + source);",
            "  const compiled = new vm.Script('return ' + source);",
            "  const compiled = vm.runInNewContext(source);",
            "  const compiled = vm.runInThisContext(source);",
        ],
    )
    def test_compiling_a_program_out_of_one_is_refused_with_a_reason(self, request_payload, line):
        source = COMPILER_JS.replace("  const compiled = new Function('row', `return ${source};`);", line)
        snapshot, finding = _snapshot(request_payload, "app.js", source, 2)
        assert javascript_dynamic_code(snapshot, finding)
        assert static_gate(snapshot, finding, CODE_INJECTION_EVAL, JAVASCRIPT) == (
            "dynamic_code_unsupported",
            DYNAMIC_CODE_MESSAGE,
        )

    def test_the_refusal_is_scoped_to_this_family(self, request_payload):
        """A `new Function` near a finding of another family says nothing about that finding:
        a command finding there is judged by the shell gate, which lets this line through."""
        snapshot, finding = _snapshot(request_payload, "app.js", COMPILER_JS, 2)
        assert static_gate(snapshot, finding, "command_arguments", JAVASCRIPT) is None


class TestTemplate:
    def test_an_eval_of_a_request_value_becomes_a_json_parse(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "app.js", PARSER_JS, 4)
        patch = generate_template(snapshot, finding, CODE_INJECTION_EVAL, JAVASCRIPT)
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        assert patch.changes[0]["replacement_lines"] == ["  return JSON.parse(expression);"]
        assert len(patch.changes) == 1, "JSON is a global, so nothing has to be imported"

    def test_an_eval_of_the_parameter_itself_is_rewritten_too(self, request_payload):
        source = PARSER_JS.replace("  const expression = body.expression;\n", "").replace("eval(expression)", "eval(body)")
        snapshot, finding = _snapshot(request_payload, "app.js", source, 3)
        patch = generate_template(snapshot, finding, CODE_INJECTION_EVAL, JAVASCRIPT)
        assert patch.changes[0]["replacement_lines"] == ["  return JSON.parse(body);"]

    @pytest.mark.parametrize(
        "replacement,reason",
        [
            ("eval('return ' + expression)", "eval_argument_not_an_identifier"),
            ("eval(`return ${expression};`)", "eval_argument_not_an_identifier"),
            ("indirect(expression)", "eval_argument_not_an_identifier"),
        ],
    )
    def test_a_shape_that_is_not_an_eval_of_one_value_falls_back_with_a_reason(self, request_payload, replacement, reason):
        source = PARSER_JS.replace("eval(expression)", replacement)
        snapshot, finding = _snapshot(request_payload, "app.js", source, 4)
        patch = generate_template(snapshot, finding, CODE_INJECTION_EVAL, JAVASCRIPT)
        assert isinstance(patch, TemplateFallback) and patch.reason == reason

    def test_a_value_that_does_not_come_from_a_parameter_falls_back(self, request_payload):
        source = PARSER_JS.replace("const expression = body.expression;", "const expression = cache.expression;")
        snapshot, finding = _snapshot(request_payload, "app.js", source, 4)
        patch = generate_template(snapshot, finding, CODE_INJECTION_EVAL, JAVASCRIPT)
        assert isinstance(patch, TemplateFallback) and patch.reason == "eval_argument_not_request_data"


class TestGeneratedProof:
    def test_the_proof_sends_a_payload_then_a_document(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "app.js", PARSER_JS, 4)
        proof = generate_proof(snapshot, finding, CODE_INJECTION_EVAL, JAVASCRIPT)
        assert not isinstance(proof, ProofFallback), getattr(proof, "reason", None)
        # The payload goes where the request put it, and every other parameter gets a plain object.
        assert 'h.call(m.applyRule, { "expression": payload }, {})' in proof.content
        assert "h.assert.noCode();" in proof.content
        assert 'h.call(m.applyRule, { "expression": "[1, 2]" }, {})' in proof.content
        assert 'h.assert.equal(JSON.stringify(parsed.value), "[1,2]")' in proof.content
        assert proof.path.endswith(".test.js")

    def test_a_result_the_function_does_not_return_is_only_asserted_to_be_accepted(self, request_payload):
        source = PARSER_JS.replace("  return eval(expression);", "  row.value = eval(expression);")
        snapshot, finding = _snapshot(request_payload, "app.js", source, 4)
        proof = generate_proof(snapshot, finding, CODE_INJECTION_EVAL, JAVASCRIPT)
        assert "h.assert(parsed.ok" in proof.content
        assert "JSON.stringify(parsed.value)" not in proof.content

    def test_the_proof_needs_no_route(self, request_payload):
        """Every other JavaScript family but the credential one derives an Express route first.
        A parser a route calls is not itself a handler, so requiring one would fail it."""
        snapshot, finding = _snapshot(request_payload, "app.js", PARSER_JS, 4)
        proof = generate_proof(snapshot, finding, CODE_INJECTION_EVAL, JAVASCRIPT)
        assert not isinstance(proof, ProofFallback) and proof.site is None


requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="the Node harness runs under node")


@requires_node
class TestFixtures:
    def test_the_template_reproduces_the_reviewed_repair(self):
        directory = FIXTURES / "js-eval-request-body"
        fixture = read_fixture(directory)
        request = build_repair_request(directory, fixture)
        snapshot = Snapshot(request)
        finding = request.findings[0]
        patch = generate_template(snapshot, finding, CODE_INJECTION_EVAL, JAVASCRIPT)
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        source = snapshot.full_content(fixture["source"]).splitlines()
        change = patch.changes[0]
        repaired = list(source)
        start = int(change["start_line"]) - 1
        repaired[start : start + len(change["original_lines"])] = change["replacement_lines"]
        assert repaired == (directory / fixture["reference_repair"]).read_text(encoding="utf-8").splitlines()

    def test_the_new_function_fixture_stays_a_negative_the_gate_refuses(self):
        directory = FIXTURES / "js-eval-new-function"
        fixture = read_fixture(directory)
        assert fixture["kind"] == "negative" and fixture["expected_state"] == "unsupported"
        assert "dynamic_code_unsupported" in fixture["reason"]
        request = build_repair_request(directory, fixture)
        finding = request.findings[0]
        assert static_gate(Snapshot(request), finding, CODE_INJECTION_EVAL, JAVASCRIPT)[0] == "dynamic_code_unsupported"

    def test_the_fixtures_declare_the_family_and_a_node_trusted_test(self):
        supported = json.loads((FIXTURES / "js-eval-request-body" / "fixture.json").read_text(encoding="utf-8"))
        assert supported["family"] == CODE_INJECTION_EVAL
        assert supported["trusted_fixture_test"]["runtime"] == "node"
        assert supported["finding"]["cwe_id"] == "CWE-95"
