"""Parameter lists that are not a row of plain names, and how a generated call lines up with one.

`function_parameters_not_plain_names` refused 23 findings on the vulnerable corpus, on both
halves. The list it could not read was almost always a destructured parameter: Juice Shop's
coding-challenge fixtures are written `execute: async ({ id }) => {`, and the value the sink
reads is the destructured member rather than any parameter.

A parameter is now modelled rather than pattern-matched: a plain name, a name with a default, a
rest element, or a destructuring with its members. `JsFunction.parameters` is what the parameter
list puts in scope, so a destructured member reads as a name the body has; `parameter_model` is
positional, so a call still puts the response in the second argument. What is still refused is
what a call cannot be built for without guessing: nested destructuring, array patterns, and
defaults inside a destructuring.
"""
from __future__ import annotations

import hashlib

import pytest

from src.families import CODE_INJECTION_EVAL, JAVASCRIPT, PATH_CONTAINMENT
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.proofs import GeneratedProof, generate_proof
from src.retrieval import Snapshot
from src.sites import SiteError, js_function_for_line, js_parameters
from src.templates import TemplatePatch, generate_template


def _blob(content: str) -> str:
    raw = content.encode()
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()


def _generate(request_payload: dict, source: str, line: int, family: str, path: str = "src/files.js"):
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=_blob(source))]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": source, "sha": _blob(source)}]
    payload["findings"] = [
        {"snapshot_id": "d-1", "rule_id": "r", "cwe_id": "CWE-22", "file_path": path,
         "line_start": line, "line_end": line}
    ]
    request = RepairRequest.model_validate(payload)
    snapshot = Snapshot(request)
    finding = request.findings[0]
    return (
        generate_template(snapshot, finding, family, JAVASCRIPT),
        generate_proof(snapshot, finding, family, JAVASCRIPT),
    )


# --- the parameter model --------------------------------------------------------------------

def test_a_plain_list_is_unchanged():
    model = js_parameters("req, res")
    assert [(p.name, p.has_default, p.rest, p.members) for p in model] == [
        ("req", False, False, ()),
        ("res", False, False, ()),
    ]


def test_a_default_records_that_it_has_one_and_keeps_its_name():
    model = js_parameters("name, options = {}")
    assert [(p.name, p.has_default) for p in model] == [("name", False), ("options", True)]


def test_a_default_holding_a_comma_does_not_split_the_list():
    model = js_parameters("name, options = { a: 1, b: 2 }")
    assert [p.name for p in model] == ["name", "options"]


def test_a_rest_element_is_marked_so_a_call_passes_it_nothing():
    model = js_parameters("first, ...rest")
    assert [(p.name, p.rest) for p in model] == [("first", False), ("rest", True)]


def test_a_destructured_parameter_binds_its_members_and_not_itself():
    [parameter] = js_parameters("{ id, name }")
    assert parameter.name is None
    assert parameter.members == ("id", "name")
    assert parameter.bound_names == ("id", "name")


def test_a_renamed_destructured_member_binds_the_new_name():
    [parameter] = js_parameters("{ id: productId }")
    assert parameter.members == ("productId",)


def test_a_typescript_annotation_is_not_part_of_the_name():
    model = js_parameters("{ params }: Request, res: Response, next?: NextFunction")
    assert [p.name for p in model] == [None, "res", "next"]
    assert model[0].members == ("params",)


@pytest.mark.parametrize("declared", ["{ a: { b } }", "[first, second]", "{ a = 1 }", "{ }"])
def test_a_form_a_call_cannot_be_built_for_is_not_modelled(declared: str):
    assert js_parameters(declared) is None


# --- what the site reports -------------------------------------------------------------------

DESTRUCTURED_HELPER = (
    "const fs = require('fs');\n"
    "\n"
    "const BASE = 'uploads';\n"
    "\n"
    "function readUpload({ name }) {\n"
    "  return fs.readFileSync(`${BASE}/${name}`, 'utf8');\n"
    "}\n"
    "\n"
    "module.exports = { readUpload };\n"
)


def test_the_scope_of_a_destructured_helper_reports_its_member_as_a_name_in_scope():
    function = js_function_for_line(DESTRUCTURED_HELPER, 6)
    assert function.name == "readUpload"
    assert function.parameters == ("name",)
    assert function.parameter_model[0].members == ("name",)


def test_a_destructured_first_parameter_does_not_make_a_function_a_handler():
    """A handler's first parameter is the request; a destructuring of it is not that parameter."""
    source = (
        "function serve({ params }, res) {\n"
        "  res.send(params.name);\n"
        "}\n"
        "module.exports = { serve };\n"
    )
    function = js_function_for_line(source, 2)
    assert function.kind == "function"
    assert function.parameters == ("params", "res")


# --- the proof and the template --------------------------------------------------------------

def test_a_proof_puts_the_payload_in_the_destructured_member(request_payload):
    """This is the half that `function_parameters_not_plain_names` refused 24 times."""
    patch, proof = _generate(request_payload, DESTRUCTURED_HELPER, 6, PATH_CONTAINMENT)
    assert isinstance(proof, GeneratedProof), proof
    assert "h.call(m.readUpload, { name: payload })" in proof.content
    assert isinstance(patch, TemplatePatch), patch


def test_a_default_parameter_is_still_passed_positionally(request_payload):
    source = DESTRUCTURED_HELPER.replace("({ name })", "(name, options = {})")
    patch, proof = _generate(request_payload, source, 6, PATH_CONTAINMENT)
    assert isinstance(proof, GeneratedProof), proof
    assert "h.call(m.readUpload, payload, {})" in proof.content
    assert isinstance(patch, TemplatePatch), patch


def test_a_rest_element_is_passed_nothing_and_never_carries_the_payload(request_payload):
    source = DESTRUCTURED_HELPER.replace("({ name })", "(name, ...rest)")
    patch, proof = _generate(request_payload, source, 6, PATH_CONTAINMENT)
    assert isinstance(proof, GeneratedProof), proof
    assert "h.call(m.readUpload, payload)" in proof.content
    assert isinstance(patch, TemplatePatch), patch


def test_an_eval_of_a_destructured_member_is_templated_and_proven(request_payload):
    """Juice Shop's `execute: async ({ id }) => {` shape, which is where the corpus count is."""
    source = (
        "const handlers = {\n"
        "  execute: async ({ expression }) => {\n"
        "    return eval(expression);\n"
        "  }\n"
        "};\n"
        "\n"
        "module.exports = handlers;\n"
    )
    patch, proof = _generate(request_payload, source, 3, CODE_INJECTION_EVAL)
    assert isinstance(patch, TemplatePatch), patch
    assert isinstance(proof, GeneratedProof), proof
    assert "{ expression: payload }" in proof.content


def test_a_handler_with_a_plain_list_still_answers_through_its_second_parameter(request_payload):
    """The positional read: a destructured first parameter must not shift the response."""
    source = (
        "const fs = require('fs');\n"
        "\n"
        "function serveFile(req, res) {\n"
        "  const body = fs.readFileSync(`uploads/${req.params.name}`, 'utf8');\n"
        "  res.send(body);\n"
        "}\n"
        "\n"
        "module.exports = { serveFile };\n"
    )
    patch, _proof = _generate(request_payload, source, 4, PATH_CONTAINMENT)
    assert isinstance(patch, TemplatePatch), patch
    body = [line for change in patch.changes for line in change["replacement_lines"]]
    assert any("res.status(400).end();" in line for line in body)


def test_a_list_the_model_refuses_still_refuses_on_both_halves(request_payload):
    source = DESTRUCTURED_HELPER.replace("({ name })", "([first, second])")
    patch, proof = _generate(request_payload, source, 6, PATH_CONTAINMENT)
    assert patch.reason == "function_parameters_not_plain_names"
    assert proof.reason == "function_parameters_not_plain_names"


def test_the_site_scan_refuses_an_unmodelled_list_by_name():
    source = DESTRUCTURED_HELPER.replace("({ name })", "({ a: { b } })")
    with pytest.raises(SiteError, match="function_parameters_not_plain_names"):
        js_function_for_line(source, 6)
