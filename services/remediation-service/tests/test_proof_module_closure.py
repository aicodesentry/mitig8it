"""What a generated JavaScript proof needs before it can load its module at all.

The September 2026 pairs measurement (`docs/validation/pairs-2026-09.md`) ran every finding
that had both a template patch and a service proof against the original tree and the patched
tree. Seven of the eighteen that did not verify failed for one reason: `h.load` never returned.
The module's own imports, or the imports of a module it imports, reached a package the sandbox
has no copy of, or a TypeScript file Node's stripper refuses. That fails identically on both
trees, which is a proof that cannot fail on the vulnerable code any more than it can pass on
the repaired one.

The loadability check therefore walks the closure a load actually pulls in, and refuses with
the module that caused the failure named. The line it must not cross is refusing a module that
would have loaded: a `require` inside a function body runs when that function is called, not
when the module is imported, so it is not counted.
"""
from __future__ import annotations

import pytest

from src.families import HARDCODED_CREDENTIAL, JAVASCRIPT
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.proofs import ProofFallback, generate_proof
from src.retrieval import Snapshot
from tests.conftest import git_blob

SECRET = 'const apiKey = "sk-live-abc123def456";\nmodule.exports = { apiKey };\n'


def _snapshot(request_payload: dict, files: dict[str, str], subject: str):
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=git_blob(text)) for path, text in files.items()]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": text, "sha": git_blob(text)} for path, text in files.items()]
    line = next(index for index, text in enumerate(files[subject].splitlines(), start=1) if "sk-live" in text)
    payload["findings"] = [{
        "snapshot_id": "secret-1", "rule_id": "cwe-798.js-credential-constant", "cwe_id": "CWE-798",
        "file_path": subject, "line_start": line, "line_end": line,
    }]
    request = RepairRequest.model_validate(payload)
    return Snapshot(request), request.findings[0]


def _proof(request_payload: dict, files: dict[str, str], subject: str = "src/config.js"):
    snapshot, finding = _snapshot(request_payload, files, subject)
    return generate_proof(snapshot, finding, HARDCODED_CREDENTIAL, JAVASCRIPT)


def test_a_load_time_require_of_a_package_the_sandbox_lacks_is_refused_by_name(request_payload):
    # dvna's server.js, one of the eighteen: `var bodyParser = require('body-parser')` on its
    # second line, and thirteen more packages after it.
    proof = _proof(request_payload, {"src/config.js": "var bodyParser = require('body-parser');\n" + SECRET})
    assert isinstance(proof, ProofFallback)
    assert proof.reason == "dependency_not_available_in_sandbox:body-parser"


def test_a_package_reached_through_a_relative_import_is_refused_by_name(request_payload):
    # nodejs-goof's app.js is this shape: it requires './mongoose-db', which requires mongoose.
    proof = _proof(request_payload, {
        "src/config.js": "require('./db');\n" + SECRET,
        "src/db.js": "const mongoose = require('mongoose');\nmodule.exports = mongoose;\n",
    })
    assert isinstance(proof, ProofFallback)
    assert proof.reason == "dependency_not_available_in_sandbox:mongoose"


def test_a_scoped_package_is_named_by_its_scope_and_name(request_payload):
    # electerm's src/client/common/constants.js imports '@electerm/electerm-resource'.
    proof = _proof(request_payload, {"src/config.js": "import res from '@scope/resource'\n" + SECRET})
    assert isinstance(proof, ProofFallback)
    assert proof.reason == "dependency_not_available_in_sandbox:@scope"


def test_unstrippable_typescript_in_an_imported_module_is_refused_with_the_construct(request_payload):
    # juice-shop's register.component.spec.ts: the subject strips cleanly and a module several
    # relative imports away declares an enum, so the load ended in a bare SyntaxError.
    proof = _proof(request_payload, {
        "src/config.ts": "import { Tier } from './tier'\n" + SECRET,
        "src/tier.ts": "export enum Tier { Free, Paid }\n",
    }, subject="src/config.ts")
    assert isinstance(proof, ProofFallback)
    assert proof.reason == "typescript_syntax_not_strippable:enum"


def test_a_faked_package_and_a_node_builtin_are_both_available(request_payload):
    proof = _proof(request_payload, {
        "src/config.js": "const express = require('express');\nconst { Pool } = require('pg');\n"
                         "const path = require('node:path');\nconst { readFile } = require('fs/promises');\n" + SECRET,
    })
    assert not isinstance(proof, ProofFallback), getattr(proof, "reason", None)


def test_a_require_inside_a_function_body_is_not_a_load_time_dependency(request_payload):
    # It runs when the function is called, which the proof never does, so refusing here would
    # lose a module that loads perfectly well.
    proof = _proof(request_payload, {
        "src/config.js": "function render() {\n  return require('marked').parse('x');\n}\n" + SECRET,
    })
    assert not isinstance(proof, ProofFallback), getattr(proof, "reason", None)


def test_a_relative_import_the_snapshot_does_not_carry_is_not_refused(request_payload):
    # The snapshot is a budgeted slice of the tree, so a file missing from it says nothing about
    # the repository. Claiming otherwise would refuse on the harness's own byte budget.
    proof = _proof(request_payload, {"src/config.js": "require('./elsewhere');\n" + SECRET})
    assert not isinstance(proof, ProofFallback), getattr(proof, "reason", None)


@pytest.mark.parametrize("specifier", ["./tier.js", "./tier", "./nested/index.js"])
def test_a_typescript_source_is_found_behind_every_specifier_a_project_writes(request_payload, specifier):
    files = {
        "src/config.ts": f"import {{ Tier }} from '{specifier}'\n" + SECRET,
        "src/tier.ts": "export enum Tier { Free, Paid }\n",
        "src/nested/index.ts": "export enum Tier { Free, Paid }\n",
    }
    proof = _proof(request_payload, files, subject="src/config.ts")
    assert isinstance(proof, ProofFallback)
    assert proof.reason == "typescript_syntax_not_strippable:enum"


def test_an_import_cycle_terminates(request_payload):
    proof = _proof(request_payload, {
        "src/config.js": "require('./a');\n" + SECRET,
        "src/a.js": "require('./b');\n",
        "src/b.js": "require('./a');\nrequire('winston');\n",
    })
    assert isinstance(proof, ProofFallback)
    assert proof.reason == "dependency_not_available_in_sandbox:winston"
