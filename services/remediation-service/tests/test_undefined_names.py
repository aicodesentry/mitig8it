"""Static undefined-name checks on candidate files.

A parse check proves a file compiles and a load check proves its top level runs; neither sees
a name used without its import inside a function body, which fails only when that function is
called. The service parses every changed file and rejects a name the change introduces that
nothing in the file binds, conservatively: a name the original file already used unbound, a
star import, or a dynamic-scope call makes the check abstain rather than guess.
"""
from __future__ import annotations

import pytest

from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.patches import PatchPolicyError, build_patch_bundle, javascript_free_names, python_free_names
from src.retrieval import Snapshot
from tests.conftest import git_blob, whole_file_change

PY_PATH = "app/client.py"
PY_SOURCE = (
    "import os\n"
    "API_KEY = os.environ.get('API_KEY', '')\n"
    "\n"
    "\n"
    "def process_input(user_input):\n"
    "    result = eval(user_input)\n"
    "    return result\n"
)
PY_FIXED_WITHOUT_IMPORT = PY_SOURCE.replace("eval(user_input)", "ast.literal_eval(user_input)")
PY_FIXED = PY_FIXED_WITHOUT_IMPORT.replace("import os\n", "import os\nimport ast\n")

JS_PATH = "src/run.js"
JS_SOURCE = (
    "const { exec } = require('child_process');\n"
    "function run(name, cb) {\n"
    "  return exec('ls ' + name, cb);\n"
    "}\n"
    "module.exports = { run };\n"
)
JS_FIXED_WITHOUT_REQUIRE = JS_SOURCE.replace("exec('ls ' + name, cb)", "execFile('ls', [name], cb)")
JS_FIXED = JS_FIXED_WITHOUT_REQUIRE.replace("const { exec } = require('child_process');\n", "const { execFile } = require('child_process');\n")


def _request(request_payload, path, content, rule_id):
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=git_blob(content))]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": content, "sha": git_blob(content)}]
    line = next(number for number, text in enumerate(content.splitlines(), start=1) if "eval(" in text or "exec(" in text)
    payload["findings"] = [{"snapshot_id": "finding-1", "rule_id": rule_id, "cwe_id": "CWE-95", "file_path": path, "line_start": line, "line_end": line}]
    payload["profile"] = {}
    return RepairRequest.model_validate(payload)


def _bundle(request, path, original, replacement):
    return build_patch_bundle(request, Snapshot(request), [whole_file_change(path, original, replacement)])


# --- Python --------------------------------------------------------------------------------------


def test_a_python_name_used_in_a_function_body_without_its_import_is_rejected(request_payload):
    request = _request(request_payload, PY_PATH, PY_SOURCE, "python.code-injection")
    with pytest.raises(PatchPolicyError) as error:
        _bundle(request, PY_PATH, PY_SOURCE, PY_FIXED_WITHOUT_IMPORT)
    assert error.value.code == "undefined_name:ast"
    assert "NameError" in error.value.guidance and "import ast" in error.value.guidance
    bundle = _bundle(request, PY_PATH, PY_SOURCE, PY_FIXED)
    assert bundle.patches[0].replacement_content == PY_FIXED


def test_a_name_the_original_already_used_unbound_is_not_blamed_on_the_candidate(request_payload):
    original = PY_SOURCE + "\n\ndef other():\n    return missing_helper()\n"
    request = _request(request_payload, PY_PATH, original, "python.code-injection")
    fixed = original.replace("eval(user_input)", "ast.literal_eval(user_input)").replace("import os\n", "import os\nimport ast\n")
    assert python_free_names(original) == {"missing_helper"}
    assert _bundle(request, PY_PATH, original, fixed).changed_lines == 3


def test_a_star_import_or_dynamic_scope_makes_the_python_check_abstain(request_payload):
    starred = "from os import *\n" + PY_SOURCE
    request = _request(request_payload, PY_PATH, starred, "python.code-injection")
    assert python_free_names(starred) is None
    fixed = starred.replace("eval(user_input)", "ast.literal_eval(user_input)")
    assert _bundle(request, PY_PATH, starred, fixed).changed_lines == 2
    assert python_free_names("exec('x = 1')\nprint(x)\n") is None


def test_python_bindings_of_every_kind_count():
    source = (
        "import os as operating\n"
        "from json import loads\n"
        "def f(a, *args, key=None, **kwargs):\n"
        "    global g\n"
        "    g = a\n"
        "    for i in args:\n"
        "        pass\n"
        "    with open('x') as handle:\n"
        "        pass\n"
        "    try:\n"
        "        pass\n"
        "    except ValueError as error:\n"
        "        pass\n"
        "    squares = [n * n for n in args]\n"
        "    if (m := key):\n"
        "        pass\n"
        "    lam = lambda q: q\n"
        "    return operating, loads, key, kwargs, i, handle, error, squares, m, lam, n, len, __file__\n"
        "class C:\n"
        "    attr = 1\n"
    )
    assert python_free_names(source) == set()


# --- JavaScript ----------------------------------------------------------------------------------


def test_a_javascript_identifier_introduced_without_a_require_is_rejected(request_payload):
    request = _request(request_payload, JS_PATH, JS_SOURCE, "js.command-injection")
    with pytest.raises(PatchPolicyError) as error:
        _bundle(request, JS_PATH, JS_SOURCE, JS_FIXED_WITHOUT_REQUIRE)
    assert error.value.code == "undefined_name:execFile"
    assert "ReferenceError" in error.value.guidance
    assert _bundle(request, JS_PATH, JS_SOURCE, JS_FIXED).patches[0].replacement_content == JS_FIXED


def test_javascript_declaration_forms_and_member_access_clear_the_name():
    original = "const a = 1;\n"
    assert javascript_free_names(original, original + "run(a);\n") == {"run"}
    assert javascript_free_names(original, original + "const run = () => a;\nrun(a);\n") == set()
    assert javascript_free_names(original, original + "import { run } from './run.js';\nrun(a);\n") == set()
    assert javascript_free_names(original, original + "const { run } = require('./run');\nrun(a);\n") == set()
    assert javascript_free_names(original, original + "function go(run) { return run(a); }\n") == set()
    assert javascript_free_names(original, original + "const go = (run) => run(a);\n") == set()
    assert javascript_free_names(original, original + "try { a(); } catch (run) { run.x; }\n") == set()
    assert javascript_free_names(original, original + "class K {\n  run(x) { return x; }\n  go() { return this.run(a); }\n}\n") == set()
    # Globals, member access, strings, and comments are never free identifiers.
    assert javascript_free_names(original, original + "process.exit(JSON.stringify(a)); // execFile(\nconst s = 'execFile(';\n") == set()
    assert javascript_free_names(original, original + "const t = obj.execFile(a);\n") == {"obj"}
