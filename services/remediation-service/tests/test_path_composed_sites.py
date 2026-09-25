"""Paths built without `path.join`: concatenation, interpolation, and what is left over.

`path_join_not_found_in_scope` said the template could not find a `path.join` in the enclosing
scope. On the vulnerable corpus that was usually true and never the point: the code had not
written one. Juice Shop builds `'./data/static/codefixes/' + key + '.info.yml'`, and
`systeminformation` reads `/proc/meminfo` with no untrusted component at all. One refusal covered
both a shape that can be repaired and a shape that must not be.

The three repair shapes are recognized here, and the rest refuse by what the sink actually does.
"""
from __future__ import annotations

import hashlib

import pytest

from src.families import JAVASCRIPT, PATH_CONTAINMENT
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.proofs import GeneratedProof, generate_proof
from src.retrieval import Snapshot
from src.sites import SiteError, js_composed_path, js_path_sink_argument, js_path_site_in_scope
from src.templates import TemplateFallback, TemplatePatch, generate_template


def _blob(content: str) -> str:
    raw = content.encode()
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()


def _generate(request_payload: dict, source: str, line: int, path: str = "src/files.js"):
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=_blob(source))]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": source, "sha": _blob(source)}]
    payload["findings"] = [
        {"snapshot_id": "p-1", "rule_id": "cwe-22.path-traversal-fs", "cwe_id": "CWE-22",
         "file_path": path, "line_start": line, "line_end": line}
    ]
    request = RepairRequest.model_validate(payload)
    snapshot = Snapshot(request)
    finding = request.findings[0]
    return (
        generate_template(snapshot, finding, PATH_CONTAINMENT, JAVASCRIPT),
        generate_proof(snapshot, finding, PATH_CONTAINMENT, JAVASCRIPT),
    )


def _scope(source: str, line: int):
    """`js_path_site_in_scope` over a whole file, which is the widest a scope ever is."""
    lines = source.splitlines()
    return js_path_site_in_scope(lines, 1, len(lines), line, ("path",))


# --- what a composition splits into ---------------------------------------------------------

@pytest.mark.parametrize(
    ("expression", "base", "user_input"),
    [
        # Juice Shop, routes/vulnCodeFixes.ts and routes/vulnCodeSnippet.ts.
        ("'./data/static/codefixes/' + key + '.info.yml'", "'./data/static/codefixes/'", "String(key) + '.info.yml'"),
        # Juice Shop, routes/languages.ts.
        ("'frontend/dist/frontend/assets/i18n/' + fileName", "'frontend/dist/frontend/assets/i18n/'", "String(fileName)"),
        ("`${base}/${name}`", "String(base) + '/'", "String(name)"),
        ("`uploads/${req.params.name}`", "'uploads/'", "String(req.params.name)"),
        ("`${dir}/${group}/${name}.json`", "String(dir) + '/' + String(group) + '/'", "String(name) + '.json'"),
    ],
)
def test_a_composition_splits_at_its_last_literal_separator(expression: str, base: str, user_input: str):
    """The last separator a literal carries is the last point the code itself fixed."""
    assert js_composed_path(expression) == (base, user_input)


@pytest.mark.parametrize(
    "expression",
    [
        # `systeminformation`, lib/battery.js: a directory variable and a constant filename, so
        # nothing untrusted reaches the sink.
        "battery_path + 'uevent'",
        # A suffix, not a path: there is no separator, so there is no base to contain against.
        "filename + '.new'",
        "'views/userProfile.pug'",
        "`${name}`",
        "justAnIdentifier",
    ],
)
def test_an_expression_with_no_base_or_no_input_is_not_a_composition(expression: str):
    assert js_composed_path(expression) is None


def test_only_a_filesystem_sink_argument_is_read(request_payload=None):
    """`this.snackBar.open(...)` is Angular; the quarantined path rule reports it anyway."""
    assert js_path_sink_argument("        this.snackBar.open(translatedMessage, 'X', {}) ") is None
    assert js_path_sink_argument("  this.dialog.open(QrCodeComponent, {})") is None
    found = js_path_sink_argument("  const t = fs.readFileSync('base/' + name, 'utf8');")
    assert found == ("fs.readFileSync('base/' + name, 'utf8')", "'base/' + name")


# --- the template and the proof --------------------------------------------------------------

CONCATENATED = (
    "const fs = require('fs');\n"
    "\n"
    "function readFix(key) {\n"
    "  return fs.readFileSync('./data/static/codefixes/' + key + '.info.yml', 'utf8');\n"
    "}\n"
    "\n"
    "module.exports = { readFix };\n"
)

INTERPOLATED = (
    "const fs = require('fs');\n"
    "\n"
    "const BASE = 'uploads';\n"
    "\n"
    "function readUpload(name) {\n"
    "  return fs.readFileSync(`${BASE}/${name}`, 'utf8');\n"
    "}\n"
    "\n"
    "module.exports = { readUpload };\n"
)


def test_a_concatenated_path_is_contained_and_the_sink_reads_the_checked_value(request_payload):
    patch, proof = _generate(request_payload, CONCATENATED, line=4)
    assert isinstance(patch, TemplatePatch), patch
    body = [line for change in patch.changes for line in change["replacement_lines"]]
    assert any("const path = require('node:path')" in line for line in body)
    assert any("path.resolve('./data/static/codefixes/')" in line for line in body)
    assert any("String(key) + '.info.yml'" in line for line in body)
    # The argument is replaced by the checked value, and never coerced twice.
    assert any("fs.readFileSync(target, 'utf8')" in line for line in body)
    assert not any("String(String(" in line for line in body)
    assert isinstance(proof, GeneratedProof), proof


def test_an_interpolated_path_is_contained_the_same_way(request_payload):
    patch, proof = _generate(request_payload, INTERPOLATED, line=6)
    assert isinstance(patch, TemplatePatch), patch
    body = [line for change in patch.changes for line in change["replacement_lines"]]
    assert any("path.resolve(String(BASE) + '/')" in line for line in body)
    assert any("String(name)" in line for line in body)
    assert isinstance(proof, GeneratedProof), proof


def test_a_template_literal_reaching_the_sink_through_a_route_answers_400(request_payload):
    source = (
        "const express = require('express');\n"
        "const fs = require('fs');\n"
        "const app = express();\n"
        "\n"
        "app.get('/file/:name', (req, res) => {\n"
        "  const body = fs.readFileSync(`uploads/${req.params.name}`, 'utf8');\n"
        "  res.send(body);\n"
        "});\n"
        "\n"
        "module.exports = app;\n"
    )
    patch, proof = _generate(request_payload, source, line=6)
    assert isinstance(patch, TemplatePatch), patch
    body = [line for change in patch.changes for line in change["replacement_lines"]]
    assert any("res.status(400).end();" in line for line in body)
    assert isinstance(proof, GeneratedProof), proof


# --- the refusals that are left --------------------------------------------------------------

def test_a_constant_path_names_the_constant(request_payload):
    """`systeminformation` reads `/proc/meminfo` in six files. Nothing there is untrusted."""
    with pytest.raises(SiteError) as raised:
        _scope("const fs = require('fs');\nfs.readFileSync('/proc/meminfo', 'utf8');\n", 2)
    assert raised.value.code == "path_argument_is_constant"


def test_a_path_that_arrives_as_one_value_says_so(request_payload):
    """`electerm` opens `file.filePath`; the composition, if any, happened elsewhere."""
    with pytest.raises(SiteError) as raised:
        _scope("const fs = require('fs');\nfs.createReadStream(file.filePath, {});\n", 2)
    assert raised.value.code == "path_argument_not_composed_in_scope"


def test_a_line_with_no_filesystem_sink_at_all_keeps_the_old_reason(request_payload):
    with pytest.raises(SiteError) as raised:
        _scope("const x = new File(['x'], 'pic.png');\n", 1)
    assert raised.value.code == "path_join_not_found_in_scope"


def test_the_refusals_reach_the_template_as_their_own_reason(request_payload):
    source = (
        "const fs = require('fs');\n"
        "\n"
        "function readMeminfo() {\n"
        "  return fs.readFileSync('/proc/meminfo', { encoding: 'utf8' });\n"
        "}\n"
        "\n"
        "module.exports = { readMeminfo };\n"
    )
    patch, proof = _generate(request_payload, source, line=4)
    assert isinstance(patch, TemplateFallback) and patch.reason == "path_argument_is_constant"
    assert proof.reason == "path_argument_is_constant"
