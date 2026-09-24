"""Findings at module scope: code with no enclosing callable, which runs once on import.

`enclosing_function_not_found` was the single largest refusal on the vulnerable corpus, and it
was never about the template: the template rewrites a sink in place wherever the sink is. What
was missing was a way for a generated test to *drive* it, because there is no function to call.
A module-scope proof drives it by setting what the module reads and then importing it, so what
decides whether a proof exists is which of the three sources the tainted value comes from.
"""
from __future__ import annotations

import hashlib

import pytest

from src.families import (
    COMMAND_ARGUMENTS,
    HARDCODED_CREDENTIAL,
    JAVASCRIPT,
    PATH_CONTAINMENT,
    PYTHON,
    SQL_PARAMETERIZATION,
)
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.proofs import ProofFallback, generate_proof
from src.retrieval import Snapshot
from src.sites import ModuleScope, js_site_for_line, python_site_for_line
from src.templates import TemplateFallback, generate_template


def _blob(content: str) -> str:
    raw = content.encode()
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()


def _snapshot(request_payload: dict, path: str, source: str, line: int):
    """A one-file snapshot over `source`, with the finding on `line`."""
    files = {path: source, "package.json": '{"dependencies":{"pg":"8.13.0"}}\n'}
    entries = [GitTreeEntry(path=name, mode="100644", type="blob", sha=_blob(text)) for name, text in files.items()]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": name, "content": text, "sha": _blob(text)} for name, text in files.items()]
    payload["findings"] = [
        {"snapshot_id": "m-1", "rule_id": "r", "cwe_id": "CWE-78", "file_path": path, "line_start": line, "line_end": line}
    ]
    request = RepairRequest.model_validate(payload)
    return Snapshot(request), request.findings[0]


ENV_COMMAND = (
    "const { execSync } = require('child_process');\n"
    "\n"
    "const branch = process.env.BUILD_BRANCH;\n"
    "const log = execSync(`git log ${branch}`).toString();\n"
    "\n"
    "module.exports = { log };\n"
)
ARGV_COMMAND = ENV_COMMAND.replace("process.env.BUILD_BRANCH", "process.argv[2]")
CONFIG_COMMAND = (
    "const { execSync } = require('child_process');\n"
    "const settings = require('./settings');\n"
    "\n"
    "const log = execSync(`git log ${settings.branch}`).toString();\n"
    "\n"
    "module.exports = { log };\n"
)
UNCONTROLLABLE_COMMAND = (
    "const { execSync } = require('child_process');\n"
    "const os = require('node:os');\n"
    "\n"
    "const account = os.userInfo().username;\n"
    "const archive = execSync(`tar -czf /backup/${account}.tgz`).toString();\n"
    "\n"
    "module.exports = { archive };\n"
)


class TestTheSiteModel:
    def test_module_scope_code_is_a_site_rather_than_a_refusal(self):
        site = js_site_for_line(ENV_COMMAND, 4)
        assert isinstance(site, ModuleScope)
        assert (site.start_line, site.end_line) == (1, 6)
        assert site.parameters == () and site.route is None

    @pytest.mark.parametrize(
        ("source", "driver", "key"),
        [(ENV_COMMAND, "env", "BUILD_BRANCH"), (ARGV_COMMAND, "argv", "2"), (CONFIG_COMMAND, "config", "./settings")],
    )
    def test_each_controllable_source_is_named(self, source, driver, key):
        site = js_site_for_line(source, 4)
        assert (site.driver, site.key) == (driver, key)

    def test_a_value_from_a_call_at_import_has_no_driver(self):
        assert js_site_for_line(UNCONTROLLABLE_COMMAND, 5).driver is None

    def test_a_called_member_of_a_builtin_is_not_mistaken_for_a_config(self):
        """`os.userInfo()` is a call, not a value a stub decides: standing in for it would
        replace the function with a payload and break the module instead of driving it."""
        assert js_site_for_line(UNCONTROLLABLE_COMMAND, 5).key == ""


class TestJavaScriptProofs:
    def test_an_env_sourced_sink_is_driven_by_the_environment_the_load_sets(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "app.js", ENV_COMMAND, 4)
        proof = generate_proof(snapshot, finding, COMMAND_ARGUMENTS, JAVASCRIPT)
        assert not isinstance(proof, ProofFallback), getattr(proof, "reason", None)
        assert 'h.load("app.js", { env: { "BUILD_BRANCH": payload } })' in proof.content
        assert "h.assert.argv(h.child_process.calls[0], payload)" in proof.content

    def test_an_argv_sourced_sink_is_driven_by_the_argv_the_load_sets(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "app.js", ARGV_COMMAND, 4)
        proof = generate_proof(snapshot, finding, COMMAND_ARGUMENTS, JAVASCRIPT)
        # The interpreter and the script keep their real places; the payload sits at index 2.
        assert 'h.load("app.js", { argv: ["node", "module", payload] })' in proof.content

    def test_a_required_config_is_driven_by_a_stub(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "app.js", CONFIG_COMMAND, 4)
        proof = generate_proof(snapshot, finding, COMMAND_ARGUMENTS, JAVASCRIPT)
        assert 'h.load("app.js", { stubs: { "./settings": { "branch": payload } } })' in proof.content

    def test_an_uncontrollable_source_is_refused_with_its_reason(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "app.js", UNCONTROLLABLE_COMMAND, 5)
        proof = generate_proof(snapshot, finding, COMMAND_ARGUMENTS, JAVASCRIPT)
        assert isinstance(proof, ProofFallback)
        assert proof.reason == "module_scope_source_not_controllable"

    def test_an_sql_sink_at_module_scope_asserts_on_the_query_the_import_ran(self, request_payload):
        source = (
            "const { Pool } = require('pg');\n"
            "\n"
            "const pool = new Pool();\n"
            "const tenant = process.env.TENANT_ID;\n"
            "const accounts = pool.query(`SELECT id FROM accounts WHERE tenant = '${tenant}'`);\n"
            "\n"
            "module.exports = { accounts };\n"
        )
        snapshot, finding = _snapshot(request_payload, "app.js", source, 5)
        proof = generate_proof(snapshot, finding, SQL_PARAMETERIZATION, JAVASCRIPT)
        assert not isinstance(proof, ProofFallback), getattr(proof, "reason", None)
        assert 'env: { "TENANT_ID": payload }' in proof.content
        assert "h.assert.notIncludes(q.text, payload);" in proof.content
        patch = generate_template(snapshot, finding, SQL_PARAMETERIZATION, JAVASCRIPT)
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        assert "$1" in patch.changes[0]["replacement_lines"][0]

    def test_a_traversal_at_module_scope_requires_the_import_itself_to_refuse(self, request_payload):
        source = (
            "const fs = require('fs');\n"
            "const path = require('path');\n"
            "\n"
            "const DOCS = '/srv/docs';\n"
            "const name = process.env.DOC_NAME;\n"
            "const body = fs.readFileSync(path.join(DOCS, name), 'utf8');\n"
            "\n"
            "module.exports = { body };\n"
        )
        snapshot, finding = _snapshot(request_payload, "app.js", source, 6)
        proof = generate_proof(snapshot, finding, PATH_CONTAINMENT, JAVASCRIPT)
        assert not isinstance(proof, ProofFallback), getattr(proof, "reason", None)
        # The repair throws, and at module scope the throw happens during the import, so the
        # load is what has to be refused. A legitimate name must still import.
        assert "to be refused on import" in proof.content
        assert "expected a legitimate name to still resolve on import" in proof.content
        assert "/etc/passwd" in proof.content

    def test_a_credential_at_module_scope_needs_no_driver_at_all(self, request_payload):
        """The sink is the literal itself, so the assertion is on the load and nothing else."""
        source = "const signingSecret = 'whsec_2f8c11ad93be40f7';\nmodule.exports = { signingSecret };\n"
        snapshot, finding = _snapshot(request_payload, "app.js", source, 1)
        proof = generate_proof(snapshot, finding, HARDCODED_CREDENTIAL, JAVASCRIPT)
        assert not isinstance(proof, ProofFallback), getattr(proof, "reason", None)
        assert 'h.assert.envRead("SIGNING_SECRET")' in proof.content


PY_ENV_COMMAND = (
    "import os\n"
    "import subprocess\n"
    "\n"
    "TARGET = os.environ['BACKUP_TARGET']\n"
    "RESULT = subprocess.run('rsync -a /var/data ' + TARGET, shell=True)\n"
)
PY_ARGV_COMMAND = PY_ENV_COMMAND.replace("os.environ['BACKUP_TARGET']", "sys.argv[1]").replace("import os\n", "import sys\n")
PY_UNCONTROLLABLE = (
    "import getpass\n"
    "import subprocess\n"
    "\n"
    "ACCOUNT = getpass.getuser()\n"
    "RESULT = subprocess.run('tar -czf /backup/' + ACCOUNT + '.tgz', shell=True)\n"
)


class TestPythonProofs:
    def test_module_scope_code_is_a_site_rather_than_a_refusal(self):
        site = python_site_for_line(PY_ENV_COMMAND, 5)
        assert isinstance(site, ModuleScope)
        assert (site.driver, site.key) == ("env", "BACKUP_TARGET")

    def test_an_env_sourced_sink_is_driven_by_the_environment_the_load_sets(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "app.py", PY_ENV_COMMAND, 5)
        proof = generate_proof(snapshot, finding, COMMAND_ARGUMENTS, PYTHON)
        assert not isinstance(proof, ProofFallback), getattr(proof, "reason", None)
        assert 'h.load("app.py", env={"BACKUP_TARGET": payload})' in proof.content
        assert "h.assert_argv(h.subprocess.calls[0], payload)" in proof.content
        patch = generate_template(snapshot, finding, COMMAND_ARGUMENTS, PYTHON)
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        assert patch.changes[0]["replacement_lines"] == ['RESULT = subprocess.run(["rsync", "-a", "/var/data", TARGET])']

    def test_an_argv_sourced_sink_is_driven_by_the_argv_the_load_sets(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "app.py", PY_ARGV_COMMAND, 5)
        proof = generate_proof(snapshot, finding, COMMAND_ARGUMENTS, PYTHON)
        assert 'h.load("app.py", argv=["module", payload])' in proof.content

    def test_an_uncontrollable_source_is_refused_with_its_reason(self, request_payload):
        snapshot, finding = _snapshot(request_payload, "app.py", PY_UNCONTROLLABLE, 5)
        proof = generate_proof(snapshot, finding, COMMAND_ARGUMENTS, PYTHON)
        assert isinstance(proof, ProofFallback)
        assert proof.reason == "module_scope_source_not_controllable"

    def test_a_traversal_at_module_scope_requires_the_import_itself_to_raise(self, request_payload):
        source = (
            "import os\n"
            "\n"
            "ATTACHMENT_DIR = '/srv/attachments'\n"
            "NAME = os.environ['ATTACHMENT']\n"
            "PATH = os.path.join(ATTACHMENT_DIR, NAME)\n"
        )
        snapshot, finding = _snapshot(request_payload, "app.py", source, 5)
        proof = generate_proof(snapshot, finding, PATH_CONTAINMENT, PYTHON)
        assert not isinstance(proof, ProofFallback), getattr(proof, "reason", None)
        assert "to be refused on import" in proof.content
        assert "refused.raised(ValueError)" in proof.content
