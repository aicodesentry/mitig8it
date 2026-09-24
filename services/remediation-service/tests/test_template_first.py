"""Service-generated proofs and template-first patches.

Every generator is exercised on the benchmark fixtures and on the two live files the families
were built for (services/orders.js from nebullii/test-only and text.py from
nebullii/Indoor-Plants, kept under tests/fixtures/live). Each generated test is run through the
real local sandbox driver on both trees: it must fail on the original code and pass on the
template fix, or the pair proves nothing.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from src.agent import ProviderAction, RepairAgent
from src.engine import RepairEngine
from src.families import COMMAND_ARGUMENTS, JAVASCRIPT, PATH_CONTAINMENT, PYTHON, SQL_PARAMETERIZATION, language_of_path, rule_family
from src.fixtures import build_repair_request, read_fixture
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.patches import build_patch_bundle
from src.proofs import GeneratedProof, ProofFallback, generate_proof
from src.retrieval import Snapshot
from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver
from src.sites import js_route_for_line, python_function_for_line, python_import_anchor
from src.templates import TemplateFallback, TemplatePatch, bind_placeholders, combine_templates, generate_template, js_segments, py_segments
from src.verification import Verifier
from tests.conftest import git_blob
from tests.test_python_families import _Scripted

requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="the Node harness runs under node")
requires_python = pytest.mark.skipif(shutil.which("python3") is None, reason="the Python harness runs under python3")
FIXTURES = Path(__file__).resolve().parents[3] / "benchmarks" / "remediation" / "fixtures"
LIVE = Path(__file__).resolve().parent / "fixtures" / "live"
ORDERS_JS = (LIVE / "services" / "orders.js").read_text(encoding="utf-8")
ORDERS_PACKAGE = (LIVE / "services" / "package.json").read_text(encoding="utf-8")
TEXT_PY = (LIVE / "text.py").read_text(encoding="utf-8")

ORDERS_FINDINGS = [
    {"snapshot_id": "sql-13", "rule_id": "javascript.express.security.audit.sqli.node-postgres-sqli", "cwe_id": "CWE-89", "file_path": "services/orders.js", "line_start": 13, "line_end": 13},
    {"snapshot_id": "sql-19", "rule_id": "javascript.express.security.audit.sqli.node-postgres-sqli", "cwe_id": "CWE-89", "file_path": "services/orders.js", "line_start": 19, "line_end": 19},
    {"snapshot_id": "exec-26", "rule_id": "javascript.lang.security.audit.child-process-exec", "cwe_id": "CWE-78", "file_path": "services/orders.js", "line_start": 26, "line_end": 26},
    {"snapshot_id": "traversal-35", "rule_id": "javascript.lang.security.audit.path-traversal", "cwe_id": "CWE-22", "file_path": "services/orders.js", "line_start": 35, "line_end": 35},
    {"snapshot_id": "traversal-35b", "rule_id": "javascript.express.security.audit.express-path-join-resolve-traversal", "cwe_id": "CWE-22", "file_path": "services/orders.js", "line_start": 35, "line_end": 35},
]
TEXT_FINDINGS = [
    {"snapshot_id": "sql-6", "rule_id": "sql.injection.raw_query", "cwe_id": "CWE-89", "file_path": "text.py", "line_start": 6, "line_end": 6},
    {"snapshot_id": "secret-10", "rule_id": "secret.hardcoded.credential", "cwe_id": "CWE-798", "file_path": "text.py", "line_start": 10, "line_end": 10},
    {"snapshot_id": "eval-15", "rule_id": "code.injection.eval", "cwe_id": "CWE-95", "file_path": "text.py", "line_start": 15, "line_end": 15},
]
# A Flask module with the two Python families no benchmark fixture carries yet.
FLASK_PY = (
    "import os\n"
    "import subprocess\n"
    "from flask import Flask, request, send_file\n"
    "\n"
    "app = Flask(__name__)\n"
    'BASE_DIR = "/srv/uploads"\n'
    "\n"
    "\n"
    '@app.route("/files")\n'
    "def download():\n"
    '    name = request.args.get("name")\n'
    "    target = os.path.join(BASE_DIR, name)\n"
    "    return send_file(target)\n"
    "\n"
    "\n"
    '@app.route("/convert", methods=["POST"])\n'
    "def convert():\n"
    '    name = request.form["name"]\n'
    '    subprocess.run("convert " + name + " out.png", shell=True)\n'
    '    return "", 204\n'
)
FLASK_FINDINGS = [
    {"snapshot_id": "traversal-13", "rule_id": "python.flask.path-traversal", "cwe_id": "CWE-22", "file_path": "app.py", "line_start": 13, "line_end": 13},
    {"snapshot_id": "command-19", "rule_id": "python.lang.security.audit.subprocess-shell", "cwe_id": "CWE-78", "file_path": "app.py", "line_start": 19, "line_end": 19},
]


def _request(files: list[tuple[str, str]], findings: list[dict], **policy) -> RepairRequest:
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=git_blob(content)) for path, content in files]
    return RepairRequest.model_validate(
        {
            "schema_version": "v1",
            "job_id": "template-first",
            "tenant_id": "installation-7",
            "repository_id": "repo-9",
            "head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "head_tree_oid": compute_tree_oid(entries),
            "tree_entries": [entry.model_dump() for entry in entries],
            "tree_truncated": False,
            "findings": findings,
            "files": [{"path": path, "content": content, "sha": git_blob(content)} for path, content in files],
            "policy": {
                "policy_version": "policy-1",
                "input_usd_per_million_tokens": 1.0,
                "output_usd_per_million_tokens": 3.0,
                "sandbox_image_digest": None,
                "allow_development_verification": True,
                "verification_checks": [],
                **policy,
            },
            "versions": {"repair_model": "repair-model-1", "prompt": "v1", "retriever": "v1", "verifier": "v1"},
        }
    )


def _generate(request: RepairRequest):
    snapshot = Snapshot(request)
    proofs, templates = {}, {}
    for finding in request.findings:
        family, language = rule_family(finding), language_of_path(finding.affected_path)
        proofs[finding.stable_id] = generate_proof(snapshot, finding, family, language)
        templates[finding.stable_id] = generate_template(snapshot, finding, family, language)
    return snapshot, proofs, templates


async def _verify_templates(request: RepairRequest):
    """Builds the template bundle with the generated proofs and verifies it on the local driver."""
    snapshot, proofs, templates = _generate(request)
    patches = [item for item in templates.values() if isinstance(item, TemplatePatch)]
    changes, dropped = combine_templates(patches)
    assert dropped == {}
    tests = [proofs[patch.finding_id].spec() for patch in patches]
    bundle = build_patch_bundle(request, snapshot, changes, tests)
    verification = await Verifier(InProcessSandboxBroker(LocalSubprocessDriver())).verify(request, snapshot, bundle)
    return bundle, verification


def _outcomes(verification) -> dict[str, tuple[str, str]]:
    checks = {check["check_id"]: check for check in verification.evidence["checks"]}
    return {
        finding_id: (checks[check_id]["baseline"]["status"], checks[check_id]["candidate"]["status"])
        for finding_id, check_id in verification.regression_checks.items()
    }


# --- string shapes ---------------------------------------------------------------------------


def test_string_expressions_split_into_literal_and_interpolated_parts():
    assert js_segments("\"WHERE id = '\" + req.params.id + \"'\"") == [("lit", "WHERE id = '"), ("expr", "req.params.id"), ("lit", "'")]
    assert js_segments("`LIKE '%${req.query.email}%' ORDER BY x`") == [("lit", "LIKE '%"), ("expr", "req.query.email"), ("lit", "%' ORDER BY x")]
    assert py_segments("\"SELECT 1 WHERE e = '\" + email + \"'\"") == [("lit", "SELECT 1 WHERE e = '"), ("expr", "email"), ("lit", "'")]
    assert py_segments('f"SELECT {col} FROM t WHERE id = {user_id}"') == [("lit", "SELECT "), ("expr", "col"), ("lit", " FROM t WHERE id = "), ("expr", "user_id")]
    assert py_segments('"WHERE id = %s AND n = %s" % (user_id, name)') == [("lit", "WHERE id = "), ("expr", "user_id"), ("lit", " AND n = "), ("expr", "name")]
    assert py_segments('"WHERE id = {}".format(user_id)') == [("lit", "WHERE id = "), ("expr", "user_id")]


def test_quoted_interpolations_become_bare_placeholders_and_wildcards_travel_into_the_value():
    text, values = bind_placeholders(js_segments("`LIKE '%${q}%' AND id = '${id}' OR n = ${n}`"), lambda n: f"${n}")
    assert text == "LIKE $1 AND id = $2 OR n = $3"
    assert [(value.expression, value.prefix, value.suffix) for value in values] == [("q", "%", "%"), ("id", "", ""), ("n", "", "")]


# --- site derivation ------------------------------------------------------------------------


def test_the_express_route_around_a_line_is_derived_with_its_inputs():
    route = js_route_for_line(ORDERS_JS, 26)
    assert (route.method, route.route, route.start_line, route.end_line, route.req, route.res) == ("post", "/orders/:id/invoice", 25, 30, "req", "res")
    assert [(item.source, item.name, item.line) for item in route.inputs] == [("params", "id", 26), ("body", "format", 26)]
    traversal = js_route_for_line(ORDERS_JS, 35)
    assert (traversal.route, traversal.start_line, traversal.end_line) == ("/reports/download", 33, 39)
    assert [(item.source, item.name) for item in traversal.inputs] == [("query", "name")]


def test_the_python_function_or_view_around_a_line_is_derived():
    function = python_function_for_line(TEXT_PY, 15)
    assert (function.name, function.parameters, function.route, function.returns_directly) == ("process_input", ("user_input",), None, "result")
    view = python_function_for_line(FLASK_PY, 19)
    assert (view.name, view.route, view.methods) == ("convert", "/convert", ("POST",))
    assert [(item.source, item.name) for item in view.inputs] == [("form", "name")]
    assert python_import_anchor(TEXT_PY, before_line=15) == (2, True)
    assert python_import_anchor('"""doc"""\n\n\ndef f():\n    pass\n') == (1, True)
    assert python_import_anchor("def f():\n    pass\n") == (1, False)


# --- generators on the live files -----------------------------------------------------------


@requires_node
@pytest.mark.asyncio
async def test_every_orders_js_finding_gets_a_proof_that_fails_before_and_passes_after_its_template():
    request = _request([("services/orders.js", ORDERS_JS), ("services/package.json", ORDERS_PACKAGE)], ORDERS_FINDINGS)
    snapshot, proofs, templates = _generate(request)
    assert all(isinstance(item, GeneratedProof) for item in proofs.values()), proofs
    assert all(isinstance(item, TemplatePatch) for item in templates.values()), templates
    assert "h.invoke(app, \"get\", \"/orders/:id\", { params: { \"id\": \"1' OR '1'='1\" } })" in proofs["sql-13"].content
    assert "h.assert.argv(h.child_process.calls[0], payload)" in proofs["exec-26"].content
    assert "h.assert.inside(h.fs.reads, base, { payload })" in proofs["traversal-35"].content
    assert "const base = path.join(path.join(h.root, \"services\"), '..', 'reports');" in proofs["traversal-35"].content
    # The two traversal findings on one line produce one hunk, so the group combines to one change.
    assert [{**change, "finding_id": ""} for change in templates["traversal-35"].changes] == [{**change, "finding_id": ""} for change in templates["traversal-35b"].changes]
    bundle, verification = await _verify_templates(request)
    fixed = bundle.patches[0].replacement_content
    assert "pool.query('SELECT id, status, total FROM orders WHERE id = $1', [req.params.id])" in fixed
    assert "const sql = 'SELECT id, status FROM orders WHERE customer_email LIKE $1 ORDER BY created_at DESC';" in fixed
    assert "pool.query(sql, [`%${req.query.email}%`])" in fixed
    assert "execFile('invoice-render', ['--order', req.params.id, '--format', req.body.format], (error, stdout) => {" in fixed
    assert "const target = path.resolve(baseDir, String(req.query.name));" in fixed
    assert "if (target !== baseDir && !target.startsWith(baseDir + path.sep)) return res.status(400).end();" in fixed
    assert verification.status == "passed", verification.reason_code
    assert set(verification.proven_finding_ids) == {item["snapshot_id"] for item in ORDERS_FINDINGS}
    assert set(_outcomes(verification).values()) == {("failed", "passed")}


@requires_python
@pytest.mark.asyncio
async def test_the_text_py_credential_and_eval_findings_get_proofs_and_templates_and_the_sql_helper_does_not():
    request = _request([("text.py", TEXT_PY)], TEXT_FINDINGS)
    snapshot, proofs, templates = _generate(request)
    # The engine's gate skips the ambiguous SQL helper before any generator runs; on its own the
    # template generator reports the same fact instead of guessing a placeholder syntax.
    assert isinstance(templates["sql-6"], TemplateFallback) and templates["sql-6"].reason == "sql_driver_not_identified"
    assert 'h.load("text.py", env={"API_KEY": "value-from-env"})' in proofs["secret-10"].content
    assert 'h.assert_not_in_source(m, "sk-1234567890abcdef")' in proofs["secret-10"].content
    assert 'h.call(m.process_input, "[1, 2]")' in proofs["eval-15"].content and "h.assert_no_commands()" in proofs["eval-15"].content
    assert templates["eval-15"].changes[0]["replacement_lines"] == ["import os", "import ast"]
    request = _request([("text.py", TEXT_PY)], TEXT_FINDINGS[1:])
    bundle, verification = await _verify_templates(request)
    fixed = bundle.patches[0].replacement_content
    assert 'API_KEY = os.environ["API_KEY"]' in fixed and 'PASSWORD = "admin123"' in fixed
    assert "import os\nimport ast\n" in fixed and "result = ast.literal_eval(user_input)" in fixed
    assert verification.status == "passed" and set(verification.proven_finding_ids) == {"secret-10", "eval-15"}
    assert set(_outcomes(verification).values()) == {("failed", "passed")}


@requires_python
@pytest.mark.asyncio
async def test_python_command_and_traversal_views_get_proofs_and_templates():
    request = _request([("app.py", FLASK_PY)], FLASK_FINDINGS)
    snapshot, proofs, templates = _generate(request)
    assert isinstance(proofs["traversal-13"], GeneratedProof) and isinstance(proofs["command-19"], GeneratedProof)
    assert 'h.invoke(app, "GET", "/files", query={"name": payload})' in proofs["traversal-13"].content
    assert "base = m.BASE_DIR" in proofs["traversal-13"].content
    assert 'h.invoke(app, "POST", "/convert", form={"name": payload})' in proofs["command-19"].content
    bundle, verification = await _verify_templates(request)
    fixed = bundle.patches[0].replacement_content
    assert "from flask import Flask, request, send_file, abort\n" in fixed
    assert "    base_dir = os.path.realpath(BASE_DIR)\n    target = os.path.realpath(os.path.join(base_dir, name))\n    if target != base_dir and not target.startswith(base_dir + os.sep):\n        abort(400)\n    return send_file(target)\n" in fixed
    assert 'subprocess.run(["convert", name, "out.png"])' in fixed
    assert verification.status == "passed" and set(verification.proven_finding_ids) == {"traversal-13", "command-19"}
    assert set(_outcomes(verification).values()) == {("failed", "passed")}


# --- generators on the benchmark fixtures ---------------------------------------------------


@requires_python
@pytest.mark.asyncio
@pytest.mark.parametrize("fixture_name", ["python-sql-sqlite", "python-hardcoded-secret", "python-eval"])
async def test_each_python_fixture_template_matches_the_reference_repair_and_its_proof_proves_it(fixture_name):
    fixture_dir = FIXTURES / fixture_name
    fixture = read_fixture(fixture_dir)
    request = build_repair_request(fixture_dir, fixture)
    request = request.model_copy(update={"policy": request.policy.model_copy(update={"verification_checks": []})})
    snapshot, proofs, templates = _generate(request)
    [finding] = request.findings
    assert isinstance(proofs[finding.stable_id], GeneratedProof), proofs
    assert isinstance(templates[finding.stable_id], TemplatePatch), templates
    bundle, verification = await _verify_templates(request)
    assert bundle.patches[0].replacement_content == (fixture_dir / "expected" / "app.py").read_text(encoding="utf-8")
    assert verification.status == "passed" and verification.proven_finding_ids == [finding.stable_id]
    assert _outcomes(verification)[finding.stable_id] == ("failed", "passed")


@pytest.mark.parametrize("fixture_name", ["sql-parameterized", "command-arguments", "path-containment"])
def test_a_javascript_fixture_without_a_route_falls_back_to_the_model_with_the_reason(fixture_name):
    """The JavaScript fixtures are plain builder functions that call no recorded sink, so no
    harness assertion can prove them: the generators say so and the model writes the test."""
    fixture_dir = FIXTURES / fixture_name
    fixture = read_fixture(fixture_dir)
    request = build_repair_request(fixture_dir, fixture)
    snapshot, proofs, templates = _generate(request)
    [finding] = request.findings
    assert isinstance(proofs[finding.stable_id], ProofFallback) and proofs[finding.stable_id].reason == "enclosing_route_not_found"
    assert isinstance(templates[finding.stable_id], TemplateFallback) and templates[finding.stable_id].reason == "enclosing_route_not_found"


def test_templates_of_one_group_are_combined_and_a_conflicting_one_is_dropped():
    same = TemplatePatch("a", SQL_PARAMETERIZATION, [{"path": "x.js", "finding_id": "a", "start_line": 3, "original_lines": ["q"], "replacement_lines": ["p"]}], "")
    twin = TemplatePatch("b", SQL_PARAMETERIZATION, [{"path": "x.js", "finding_id": "b", "start_line": 3, "original_lines": ["q"], "replacement_lines": ["p"]}], "")
    other = TemplatePatch("c", COMMAND_ARGUMENTS, [{"path": "x.js", "finding_id": "c", "start_line": 3, "original_lines": ["q"], "replacement_lines": ["r"]}], "")
    import_a = TemplatePatch("d", PATH_CONTAINMENT, [{"path": "m.py", "finding_id": "d", "start_line": 1, "original_lines": ["import os"], "replacement_lines": ["import os", "import ast"]}], "")
    import_b = TemplatePatch("e", PATH_CONTAINMENT, [{"path": "m.py", "finding_id": "e", "start_line": 1, "original_lines": ["import os"], "replacement_lines": ["import os", "import subprocess"]}], "")
    changes, dropped = combine_templates([same, twin, other, import_a, import_b])
    assert dropped == {"c": "template_conflict_with_a"}
    assert changes == [
        {"path": "x.js", "finding_id": "a", "start_line": 3, "original_lines": ["q"], "replacement_lines": ["p"]},
        {"path": "m.py", "finding_id": "d", "start_line": 1, "original_lines": ["import os"], "replacement_lines": ["import os", "import ast", "import subprocess"]},
    ]


# --- the engine -----------------------------------------------------------------------------


def _local_agent(provider):
    return RepairAgent(provider, Verifier(InProcessSandboxBroker(LocalSubprocessDriver())))


@requires_node
@requires_python
@pytest.mark.asyncio
async def test_the_engine_proves_every_supported_finding_of_both_live_files_without_the_model():
    files = [("services/orders.js", ORDERS_JS), ("services/package.json", ORDERS_PACKAGE), ("text.py", TEXT_PY)]
    request = _request(files, ORDERS_FINDINGS + TEXT_FINDINGS)
    provider = _Scripted([])
    response = await RepairEngine(lambda group_request: _local_agent(provider)).repair(request)
    assert response.state == "ready", response.reason
    assert provider.calls == 0, "the scripted provider was never needed"
    claimed = sorted(finding_id for candidate in response.candidates for finding_id in candidate.finding_ids)
    assert claimed == ["eval-15", "exec-26", "secret-10", "sql-13", "sql-19", "traversal-35", "traversal-35b"]
    assert [(item["finding_id"], item["code"]) for item in response.skipped] == [("sql-6", "ambiguous_query_api")]
    assert all(candidate.preview["evidence"]["candidate_source"] == "template" for candidate in response.candidates)
    groups = {group["language"]: group for group in response.evidence["groups"]}
    assert groups[JAVASCRIPT]["reason_evidence"]["candidate_sources"] == {finding_id: "template" for finding_id in ["exec-26", "sql-13", "sql-19", "traversal-35", "traversal-35b"]}
    assert groups[PYTHON]["reason_evidence"]["proofs"] == {"eval-15": "service", "secret-10": "service"}
    assert response.evidence["usage"] == {"input_tokens": 0, "output_tokens": 0, "provider_request_ids": []}
    # The combined batch was verified once more on the union of both languages' candidates.
    checks = response.evidence["verification_run"]["checks"]
    assert sum(1 for check in checks if check["kind"] == "exploit") == 7
    assert all(check["baseline"]["status"] == "failed" and check["candidate"]["status"] == "passed" for check in checks if check["kind"] == "exploit")


BROKEN_TEMPLATE_JS = ORDERS_JS.replace("router.get('/orders/:id', async (req, res) => {", "router.get('/orders/:id', async (req, res) => {\n  if (!req.params.id) return res.status(400).end();")


@requires_node
@pytest.mark.asyncio
async def test_the_model_receives_the_proof_and_a_prior_failure_and_a_focused_retry_proves_the_finding():
    """A route the template recognizes but whose shape the proof does not accept on the first
    model attempt: the model is handed the service proof, its first patch fails the proof, and
    the focused single-finding retry proves it with the same proof."""
    source = ORDERS_JS.replace(
        "  const result = await pool.query(\"SELECT id, status, total FROM orders WHERE id = '\" + req.params.id + \"'\");",
        "  const clause = \"WHERE id = '\" + req.params.id + \"'\";\n  const result = await pool.query('SELECT id, status, total FROM orders ' + clause);",
    )
    findings = [{"snapshot_id": "sql-13", "cwe_id": "CWE-89", "file_path": "services/orders.js", "line_start": 14, "line_end": 14}]
    request = _request([("services/orders.js", source), ("services/package.json", ORDERS_PACKAGE)], findings)
    snapshot = Snapshot(request)
    [finding] = request.findings
    proof = generate_proof(snapshot, finding, SQL_PARAMETERIZATION, JAVASCRIPT)
    assert isinstance(proof, GeneratedProof)
    template = generate_template(snapshot, finding, SQL_PARAMETERIZATION, JAVASCRIPT)
    # The interpolated name is a SQL fragment, not a value: binding it would break the query.
    assert isinstance(template, TemplateFallback) and template.reason == "interpolated_sql_fragment"

    def hunk(replacement: list[str]) -> dict:
        return {
            "path": "services/orders.js", "finding_id": "sql-13", "start_line": 13,
            "original_lines": ["  const clause = \"WHERE id = '\" + req.params.id + \"'\";", "  const result = await pool.query('SELECT id, status, total FROM orders ' + clause);"],
            "replacement_lines": replacement,
        }

    def propose(replacement: list[str], hypothesis: str) -> ProviderAction:
        return ProviderAction("propose_patch", {
            "hypothesis": hypothesis, "intended_behavior": "Look up the same order by id.", "assumptions": [],
            "citations": [{"path": "services/orders.js", "line_start": 12, "line_end": 15}], "changes": [hunk(replacement)], "regression_tests": [],
        })

    wrong = propose(["  const clause = \"WHERE id = '\" + String(req.params.id).replace(/'/g, \"''\") + \"'\";", "  const result = await pool.query('SELECT id, status, total FROM orders ' + clause);"], "Escape quotes.")
    right = propose(["  const result = await pool.query('SELECT id, status, total FROM orders WHERE id = $1', [req.params.id]);"], "Bind the id.")
    seen: list[dict] = []

    class Recording(_Scripted):
        async def next_action(self, messages, tools):
            seen.append(json.loads(messages[1]["content"]))
            return await super().next_action(messages, tools)

    providers = iter([Recording([wrong, ProviderAction("request_verification", {})]), Recording([right, ProviderAction("request_verification", {})])])
    response = await RepairEngine(lambda group_request: _local_agent(next(providers))).repair(request.model_copy(update={"policy": request.policy.model_copy(update={"max_attempts": 1})}))
    assert response.state == "ready", response.reason
    [candidate] = response.candidates
    assert candidate.finding_ids == ["sql-13"] and candidate.preview["evidence"]["candidate_source"] == "retry"
    assert "pool.query('SELECT id, status, total FROM orders WHERE id = $1', [req.params.id])" in candidate.patch[0].replacement_content
    assert [entry["path"] for entry in candidate.generated_tests] == [proof.path]
    group = response.evidence["groups"][0]
    assert group["reason_evidence"]["proofs"] == {"sql-13": "service"}
    assert group["reason_evidence"]["templates"] == {"sql-13": "not_attempted:interpolated_sql_fragment"}
    assert group["reason_evidence"]["retries"] == {"sql-13": "proven"}
    # Both model runs saw the proof; the retry also saw why the first patch failed it.
    assert seen[0]["proofs"][0]["finding_id"] == "sql-13" and seen[0]["proofs"][0]["content"] == proof.content
    assert "prior_attempts" not in seen[0] and "prior_attempts" not in seen[1]
    # seen[2] is the retry's first call: the group pass made two calls before it.
    assert seen[2]["prior_attempts"]["sql-13"]["source"] == "model"
    assert seen[2]["prior_attempts"]["sql-13"]["code"] == "not_repaired"
    assert "candidate" in seen[2]["prior_attempts"]["sql-13"]["test_failure_tail"]


@requires_node
@pytest.mark.asyncio
async def test_a_model_test_beside_the_proof_runs_in_addition_and_cannot_replace_it():
    request = _request([("services/orders.js", ORDERS_JS), ("services/package.json", ORDERS_PACKAGE)], ORDERS_FINDINGS[:1])
    snapshot = Snapshot(request)
    [finding] = request.findings
    proof = generate_proof(snapshot, finding, SQL_PARAMETERIZATION, JAVASCRIPT)
    agent = _local_agent(_Scripted([]))
    merged = agent._merge_proofs([{"finding_id": "sql-13", "path": proof.path, "content": "process.exit(1);\n"}])
    agent._proofs = {"sql-13": {"path": proof.path, "content": proof.content, "description": proof.description}}
    merged = agent._merge_proofs([{"finding_id": "sql-13", "path": proof.path, "content": "process.exit(1);\n"}, {"finding_id": "other", "path": ".mitig8it/regression/other.test.js", "content": "x"}])
    assert [(item["finding_id"], item["path"]) for item in merged] == [
        ("sql-13", ".mitig8it/regression/sql-13.test.js"),
        ("sql-13", ".mitig8it/regression/sql-13.model.test.js"),
        ("other", ".mitig8it/regression/other.test.js"),
    ]
    assert merged[0]["content"] == proof.content


# --- a credential inside a multi-line object literal -----------------------------------------

SESSION_JS = """const store = new Map();

function install(app) {
  app.use(session({
    secret: 'keyboard cat',
    resave: true,
  }));
}

module.exports = { install };
"""

# Line 4 is what a rule matching the whole `app.use(session({ ... }))` call reports; line 5 is
# where the credential is. Before the vulnerable-corpus run of September 2026 both the template
# and the proof looked only at the reported line, and refused four real findings because of it.
SESSION_FINDING = {
    "snapshot_id": "session-4",
    "rule_id": "cwe-798.js-session-secret-literal",
    "cwe_id": "CWE-798",
    "file_path": "server.js",
    "line_start": 4,
    "line_end": 7,
}


def _session_snapshot():
    request = _request([("server.js", SESSION_JS)], [SESSION_FINDING])
    return Snapshot(request), request.findings[0]


class TestCredentialInsideAnObjectLiteral:
    def test_the_template_rewrites_the_line_the_credential_is_on(self):
        snapshot, finding = _session_snapshot()
        patch = generate_template(snapshot, finding, "hardcoded_credential", JAVASCRIPT)
        assert isinstance(patch, TemplatePatch), getattr(patch, "reason", patch)
        [change] = patch.changes
        assert change["start_line"] == 5
        assert change["original_lines"] == ["    secret: \'keyboard cat\',"]
        assert change["replacement_lines"] == ["    secret: process.env.SECRET,"]

    def test_the_proof_asserts_on_the_same_credential(self):
        snapshot, finding = _session_snapshot()
        proof = generate_proof(snapshot, finding, "hardcoded_credential", JAVASCRIPT)
        assert isinstance(proof, GeneratedProof), getattr(proof, "reason", proof)
        assert "SECRET" in proof.content
        assert "keyboard cat" in proof.content

    def test_the_search_never_leaves_the_finding(self):
        """A literal outside the reported range is a different finding\'s business.

        Searching the span is only safe because it cannot reach a literal the rule did not
        match. A finding narrowed to the call\'s first line alone has to go back to refusing,
        or the template starts rewriting values nothing reported.
        """
        request = _request([("server.js", SESSION_JS)], [{**SESSION_FINDING, "line_end": 4}])
        patch = generate_template(Snapshot(request), request.findings[0], "hardcoded_credential", JAVASCRIPT)
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "string_literal_assignment_not_found"
