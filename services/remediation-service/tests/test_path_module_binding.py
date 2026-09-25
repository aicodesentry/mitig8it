"""How a JavaScript file names `node:path`, and what the containment template does about it.

`path_module_not_required` was the largest single template refusal on the vulnerable corpus:
65 findings on 24 September 2026. It was two defects wearing one name. The first is that the
check read only `const path = require('path')`, so an ESM module that writes
`import path from 'node:path'` counted as not importing path at all. The second is that it ran
*before* the template looked for the join, so a sink that takes a constant and has nothing to
contain was reported as a missing import rather than as a missing sink.

Both are fixed here: the binding is recognized in every style the corpus carries, a file that
does not bind it gets the import as part of the same patch, and a file that binds `path` to
something of its own is refused by name instead of being repaired into a shadowed identifier.
"""
from __future__ import annotations

import hashlib

import pytest

from src.families import JAVASCRIPT, PATH_CONTAINMENT
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.retrieval import Snapshot
from src.sites import (
    js_identifier_is_bound,
    js_import_anchor,
    js_module_binding,
    js_module_style,
    js_path_join_on_line,
)
from src.templates import TemplateFallback, TemplatePatch, generate_template


def _blob(content: str) -> str:
    raw = content.encode()
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()


def _snapshot(request_payload: dict, path: str, source: str, line: int):
    files = {path: source}
    entries = [GitTreeEntry(path=name, mode="100644", type="blob", sha=_blob(text)) for name, text in files.items()]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": name, "content": text, "sha": _blob(text)} for name, text in files.items()]
    payload["findings"] = [
        {"snapshot_id": "p-1", "rule_id": "cwe-22.path-traversal-fs", "cwe_id": "CWE-22",
         "file_path": path, "line_start": line, "line_end": line}
    ]
    request = RepairRequest.model_validate(payload)
    return Snapshot(request), request.findings[0]


def _template(request_payload: dict, source: str, line: int, path: str = "src/files.js"):
    snapshot, finding = _snapshot(request_payload, path, source, line)
    return generate_template(snapshot, finding, PATH_CONTAINMENT, JAVASCRIPT)


# A CommonJS helper with no `path` import at all: the sink concatenates nothing, it joins, so
# the only thing between it and a repair is the import.
COMMONJS_NO_IMPORT = (
    "const fs = require('fs');\n"
    "\n"
    "const BASE = '/srv/uploads';\n"
    "\n"
    "function readUpload(requested) {\n"
    "  return fs.readFileSync(path.join(BASE, requested));\n"
    "}\n"
    "\n"
    "module.exports = { readUpload };\n"
)


# --- what binds the module ------------------------------------------------------------------

@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ("const path = require('path');", "path"),
        ("const path = require('node:path');", "path"),
        ("const p = require('node:path');", "p"),
        ("import path from 'path';", "path"),
        ("import path from 'node:path';", "path"),
        ("import * as path from 'path';", "path"),
        ("import * as nodePath from 'node:path';", "nodePath"),
        ("export const path = require('path');", "path"),
    ],
)
def test_every_binding_style_the_corpus_carries_is_recognized(statement: str, expected: str):
    """`js_require_line` saw one of these eight. The corpus carries at least five of them."""
    binding = js_module_binding(f"{statement}\nconst x = 1;\n", "path", "path")
    assert binding.present, statement
    assert binding.name == expected


def test_a_named_import_binds_members_but_not_a_namespace():
    """`import { join } from 'node:path'` gives the file `join`, not `path`.

    The repair writes `path.resolve` and `path.sep`, so a member import is not a namespace it
    can use: the binding reports the members and still asks for an import of its own.
    """
    binding = js_module_binding("import { join, sep } from 'node:path';\n", "path", "path")
    assert not binding.present
    assert binding.members == frozenset({"join", "sep"})
    assert binding.import_line == "import path from 'node:path'"


def test_a_require_in_a_comment_does_not_count_as_a_binding():
    source = "// const path = require('path');\nconst x = 1;\n"
    assert not js_module_binding(source, "path", "path").present


def test_the_module_style_decides_how_a_missing_import_is_written():
    """An inserted `require` in an ESM module is a syntax error waiting to happen."""
    esm = js_module_binding("import fs from 'node:fs';\n", "path", "path")
    assert esm.style == "esm" and esm.import_line == "import path from 'node:path'"
    commonjs = js_module_binding("const fs = require('fs');\n", "path", "path")
    assert commonjs.style == "commonjs" and commonjs.import_line == "const path = require('node:path')"


def test_an_export_statement_alone_makes_a_file_esm():
    assert js_module_style("export function parse (raw) {\n  return raw;\n}\n") == "esm"
    assert js_module_style("module.exports = { parse };\n") == "commonjs"


def test_an_inserted_import_goes_at_the_top_of_the_import_block_not_above_the_licence():
    """Juice Shop opens every file with a licence header; line 1 is the wrong answer."""
    source = (
        "/*\n"
        " * Copyright (c) 2014-2026 the contributors.\n"
        " * SPDX-License-Identifier: MIT\n"
        " */\n"
        "\n"
        "import fs from 'node:fs';\n"
        "import config from 'config';\n"
    )
    assert js_import_anchor(source) == 6


def test_a_file_with_no_imports_at_all_takes_its_first_real_line():
    assert js_import_anchor("'use strict';\n\n// a note\nconst BASE = '/srv';\n") == 4


# --- the template ---------------------------------------------------------------------------

def test_a_commonjs_module_without_the_import_gets_one_in_the_same_patch(request_payload):
    patch = _template(request_payload, COMMONJS_NO_IMPORT, line=6)
    assert isinstance(patch, TemplatePatch), patch
    inserted = [
        line
        for change in patch.changes
        for line in change["replacement_lines"]
        if line not in change["original_lines"]
    ]
    assert "const path = require('node:path')" in inserted
    assert any("path.resolve(BASE)" in line for line in inserted)
    assert any("path.sep" in line for line in inserted)


def test_an_esm_module_without_the_import_gets_the_import_form(request_payload):
    source = COMMONJS_NO_IMPORT.replace(
        "const fs = require('fs');", "import fs from 'node:fs';"
    ).replace("module.exports = { readUpload };", "export { readUpload };")
    patch = _template(request_payload, source, line=6, path="src/files.ts")
    assert isinstance(patch, TemplatePatch), patch
    inserted = [
        line
        for change in patch.changes
        for line in change["replacement_lines"]
        if line not in change["original_lines"]
    ]
    assert "import path from 'node:path'" in inserted
    assert not any("require(" in line for line in inserted)


def test_a_module_that_already_imports_path_gets_no_second_import(request_payload):
    source = "import path from 'node:path';\n" + COMMONJS_NO_IMPORT.replace("const fs = require('fs');\n", "import fs from 'node:fs';\n")
    patch = _template(request_payload, source, line=7, path="src/files.ts")
    assert isinstance(patch, TemplatePatch), patch
    inserted = [
        line
        for change in patch.changes
        for line in change["replacement_lines"]
        if line not in change["original_lines"]
    ]
    assert not any("from 'node:path'" in line or "require('node:path')" in line for line in inserted)


def test_an_aliased_binding_is_used_by_its_own_name(request_payload):
    """A file that calls the module `nodePath` gets a repair that calls it `nodePath` too."""
    source = COMMONJS_NO_IMPORT.replace(
        "const fs = require('fs');\n",
        "const fs = require('fs');\nconst nodePath = require('node:path');\n",
    ).replace("path.join(BASE, requested)", "nodePath.join(BASE, requested)")
    patch = _template(request_payload, source, line=7)
    assert isinstance(patch, TemplatePatch), patch
    body = [line for change in patch.changes for line in change["replacement_lines"]]
    assert any("nodePath.resolve(BASE)" in line for line in body)
    assert not any("require('node:path')" in line and "const path" in line for line in body)


def test_a_module_with_its_own_path_identifier_is_refused_by_name(request_payload):
    """`routes/videoHandler.ts` in the corpus binds `const path = videoPath()`.

    Inserting `import path from 'node:path'` there would be shadowed at the very line the
    repair rewrites, so the repair is refused rather than written wrong.
    """
    source = (
        "import fs from 'node:fs';\n"
        "\n"
        "export function serve (req, res) {\n"
        "  const path = videoPath();\n"
        "  return fs.createReadStream(path.join(BASE, req.params.name));\n"
        "}\n"
    )
    fallback = _template(request_payload, source, line=5, path="src/video.ts")
    assert isinstance(fallback, TemplateFallback)
    assert fallback.reason == "path_identifier_shadowed"


def test_a_sink_with_no_join_is_refused_for_the_sink_not_for_the_import(request_payload):
    """The refusal that used to read `path_module_not_required` on a constant path.

    `fs.readFile('/proc/meminfo', ...)` has nothing to contain. Naming the import made the
    corpus report 65 findings as an import problem; naming the sink says what is really true.
    """
    source = (
        "const fs = require('fs');\n"
        "\n"
        "function readMeminfo() {\n"
        "  return fs.readFileSync('/proc/meminfo', { encoding: 'utf8' });\n"
        "}\n"
        "\n"
        "module.exports = { readMeminfo };\n"
    )
    fallback = _template(request_payload, source, line=4)
    assert isinstance(fallback, TemplateFallback)
    assert fallback.reason == "path_join_not_found_in_scope"


# --- the join call --------------------------------------------------------------------------

def test_a_three_argument_resolve_keeps_its_whole_base():
    """`dicebear/dicebear` has 35 findings of this shape across its generated test files.

    A pattern that reads "everything up to the first `)`" as the second argument turns the last
    two into a comma expression, and the repair silently drops one of them.
    """
    found = js_path_join_on_line("  const p = path.resolve(__dirname, 'static', `${key}.svg`);", ("path",))
    assert found is not None
    assert found.base == "__dirname, 'static'"
    assert found.user_input == "`${key}.svg`"


def test_a_single_argument_resolve_is_not_a_join():
    assert js_path_join_on_line("  const p = path.resolve(BASE);", ("path",)) is None


def test_a_comma_inside_a_nested_call_does_not_split_the_arguments():
    found = js_path_join_on_line("  const p = path.join(BASE, decode(name, 'utf8'));", ("path",))
    assert found is not None
    assert found.base == "BASE"
    assert found.user_input == "decode(name, 'utf8')"


@pytest.mark.parametrize(
    "source",
    [
        "const path = require('x');\n",
        "let path = 1;\n",
        "function path () {}\n",
        "class path {}\n",
        "const f = (path) => path;\n",
        "try { f(); } catch (path) { g(path); }\n",
    ],
)
def test_an_identifier_the_file_already_declares_is_reported_as_bound(source: str):
    assert js_identifier_is_bound(source, "path")


def test_a_bare_mention_is_not_a_binding():
    assert not js_identifier_is_bound("const x = obj.path;\nfoo('path');\n", "path")
