"""Python support in the engine: language detection, per-language families, static gates,
group splitting, and end-to-end repairs of the three Python families with a scripted provider.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from src.agent import ProviderAction, RepairAgent
from src.agent.loop import PYTHON_SYSTEM_PROMPT, SYSTEM_PROMPT, system_prompt
from src.agent.tools import tool_definitions
from src.engine import RepairEngine
from src.families import (
    CODE_INJECTION_EVAL,
    COMMAND_ARGUMENTS,
    HARDCODED_CREDENTIAL,
    JAVASCRIPT,
    PATH_CONTAINMENT,
    PYTHON,
    SQL_PARAMETERIZATION,
    family_assertion,
    family_supported,
    language_of_path,
    rule_family,
)
from src.fixtures import build_repair_request, fixture_regression_test, read_fixture, reference_replacements
from src.gates import python_imports, python_sql_api_known, python_shell_pipeline, static_gate
from src.git_tree import compute_tree_oid
from src.grouping import group_findings_by_language, split_group_by_language
from src.models import FindingSnapshot, GitTreeEntry, RepairRequest
from src.retrieval import Snapshot
from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver
from src.verification import Verifier
from tests.conftest import git_blob, whole_file_change

requires_python = pytest.mark.skipif(shutil.which("python3") is None, reason="the Python harness runs under python3")
FIXTURES = Path(__file__).resolve().parents[3] / "benchmarks" / "remediation" / "fixtures"

# The Indoor-Plants PR file the Python families were built for: an ambiguous SQL helper, two
# hardcoded credentials, and an eval of user input, all in one module.
TEXT_PY = (
    "# Test file for SCRUM-87, 97, 99, 88\n"
    "import os\n"
    "\n"
    "# SQL Injection vulnerability\n"
    "def get_user(user_id):\n"
    '    query = "SELECT * FROM users WHERE id = " + user_id\n'
    "    return execute_query(query)\n"
    "\n"
    "# Hardcoded credentials\n"
    'API_KEY = "sk-aaaaaaaaaaaaaaaa"\n'
    'PASSWORD = "admin123"\n'
    "\n"
    "# Insecure eval\n"
    "def process_input(user_input):\n"
    "    result = eval(user_input)\n"
    "    return result\n"
    "\n"
    "from flask import Flask, request\n"
    "from lxml import etree\n"
    "\n"
    "app = Flask(__name__)\n"
    "\n"
    'if __name__ == "__main__":\n'
    "    app.run()\n"
)
TEXT_PY_REPAIRED = (
    TEXT_PY.replace("import os\n", "import ast\nimport os\n")
    .replace('API_KEY = "sk-aaaaaaaaaaaaaaaa"', 'API_KEY = os.environ["API_KEY"]')
    .replace('PASSWORD = "admin123"', 'PASSWORD = os.environ["PASSWORD"]')
    .replace("result = eval(user_input)", "result = ast.literal_eval(user_input)")
)
CREDENTIAL_TEST = (
    "import harness as h\n"
    "\n"
    "\n"
    "def body():\n"
    '    m = h.load("text.py", env={"API_KEY": "from-env", "PASSWORD": "from-env-2"})\n'
    '    h.assert_equal(m.API_KEY, "from-env")\n'
    '    h.assert_env_read("API_KEY")\n'
    '    h.assert_not_in_source(m, "sk-aaaaaaaaaaaaaaaa")\n'
    "\n"
    "\n"
    "h.run(body)\n"
)
EVAL_TEST = (
    "import harness as h\n"
    "\n"
    "\n"
    "def body():\n"
    '    m = h.load("text.py", env={"API_KEY": "x", "PASSWORD": "y"})\n'
    "    h.call(m.process_input, \"__import__('os').system('id')\")\n"
    "    h.assert_no_commands()\n"
    '    h.assert_equal(h.call(m.process_input, "[1, 2]").value, [1, 2])\n'
    "\n"
    "\n"
    "h.run(body)\n"
)
TEXT_FINDINGS = [
    {"snapshot_id": "sql-6", "rule_id": "sql.injection.raw_query", "cwe_id": "CWE-89", "file_path": "text.py", "line_start": 6, "line_end": 6},
    {"snapshot_id": "secret-10", "rule_id": "secret.hardcoded.credential", "cwe_id": "CWE-798", "file_path": "text.py", "line_start": 10, "line_end": 10},
    {"snapshot_id": "eval-15", "rule_id": "code.injection.eval", "cwe_id": "CWE-95", "file_path": "text.py", "line_start": 15, "line_end": 15},
]


def _finding(**fields) -> FindingSnapshot:
    return FindingSnapshot.model_validate({"snapshot_id": "f", "rule_id": "", "cwe_id": "", **fields})


def _payload(request_payload, files: list[tuple[str, str]], findings: list[dict]) -> dict:
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=git_blob(content)) for path, content in files]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": content, "sha": git_blob(content)} for path, content in files]
    payload["findings"] = findings
    payload["policy"] = {**request_payload["policy"], "sandbox_image_digest": None, "allow_development_verification": True, "verification_checks": []}
    return payload


class _Scripted:
    def __init__(self, actions):
        self.actions = iter(actions)
        self.calls = 0

    async def next_action(self, messages, tools):
        self.calls += 1
        return next(self.actions, ProviderAction("abstain", {"reason_code": "script_exhausted", "explanation": "The scripted provider has no further action."}))


def _local_agent(provider):
    return RepairAgent(provider, Verifier(InProcessSandboxBroker(LocalSubprocessDriver())))


# --- families and languages -----------------------------------------------------------------

@pytest.mark.parametrize(
    ("fields", "family"),
    [
        ({"rule_id": "sql.injection.raw_query"}, SQL_PARAMETERIZATION),
        ({"cwe_id": "CWE-89"}, SQL_PARAMETERIZATION),
        ({"rule_id": "secret.hardcoded.credential"}, HARDCODED_CREDENTIAL),
        ({"cwe_id": "CWE-798"}, HARDCODED_CREDENTIAL),
        ({"title": "Hardcoded API key"}, HARDCODED_CREDENTIAL),
        ({"rule_id": "code.injection.eval"}, CODE_INJECTION_EVAL),
        ({"cwe_id": "CWE-95"}, CODE_INJECTION_EVAL),
        ({"message": "Use of eval on user input"}, CODE_INJECTION_EVAL),
        ({"cwe_id": "CWE-78"}, COMMAND_ARGUMENTS),
        ({"cwe_id": "CWE-22"}, PATH_CONTAINMENT),
        ({"cwe_id": "CWE-79"}, None),
    ],
)
def test_rule_family_detects_the_python_families(fields, family):
    assert rule_family(_finding(**fields)) == family


def test_language_is_decided_by_the_affected_file_extension():
    assert language_of_path("app/views.py") == PYTHON
    assert language_of_path("src/db.ts") == JAVASCRIPT
    assert language_of_path("lib/server.mjs") == JAVASCRIPT
    assert language_of_path("main.rb") is None
    assert language_of_path(None) is None


def test_families_are_supported_per_language():
    assert family_supported(HARDCODED_CREDENTIAL, PYTHON) and family_supported(CODE_INJECTION_EVAL, PYTHON)
    assert not family_supported(HARDCODED_CREDENTIAL, JAVASCRIPT) and not family_supported(CODE_INJECTION_EVAL, JAVASCRIPT)
    assert family_supported(SQL_PARAMETERIZATION, JAVASCRIPT) and family_supported(SQL_PARAMETERIZATION, PYTHON)
    assert not family_supported(SQL_PARAMETERIZATION, None)
    assert "h.db.queries" in family_assertion(SQL_PARAMETERIZATION, PYTHON)
    assert "h.pg.queries" in family_assertion(SQL_PARAMETERIZATION, JAVASCRIPT)
    assert "os.environ" in family_assertion(HARDCODED_CREDENTIAL, PYTHON)
    assert "assert_no_commands" in family_assertion(CODE_INJECTION_EVAL, PYTHON)


def test_a_mixed_language_group_is_split_by_language_in_order():
    shared = [{"path": "shared/config.json"}]
    group = [
        _finding(snapshot_id="a", file_path="src/a.ts", trace=shared),
        _finding(snapshot_id="b", file_path="app/b.py", trace=shared),
        _finding(snapshot_id="c", file_path="src/c.js", trace=shared),
    ]
    split = split_group_by_language(group)
    assert [[f.stable_id for f in sub] for sub in split] == [["a", "c"], ["b"]]
    assert [[f.stable_id for f in sub] for sub in group_findings_by_language(group)] == [["a", "c"], ["b"]]
    assert split_group_by_language(group[:1]) == [group[:1]]


# --- static gates ---------------------------------------------------------------------------

def _snapshot(request_payload, files: list[tuple[str, str]]) -> Snapshot:
    payload = _payload(request_payload, files, [TEXT_FINDINGS[0]])
    return Snapshot(RepairRequest.model_validate(payload))


def test_python_imports_are_a_lexical_scan():
    assert python_imports("import os, sys\nfrom flask import Flask\n  import sqlite3\nfrom .local import x\n") == {"os", "sys", "flask", "sqlite3", ".local"}


def test_sql_api_is_known_for_a_driver_execute_call(request_payload):
    source = "import sqlite3\n\ndef f(conn, email):\n    cur = conn.cursor()\n    cur.execute(\"SELECT 1 WHERE e = '\" + email + \"'\")\n"
    snapshot = _snapshot(request_payload, [("app.py", source)])
    finding = _finding(file_path="app.py", line_start=5, line_end=5)
    assert python_sql_api_known(snapshot, finding)
    assert static_gate(snapshot, finding, SQL_PARAMETERIZATION, PYTHON) is None


def test_sql_api_is_known_through_a_local_module_that_imports_the_driver(request_payload):
    app = "from db import connection\n\ndef f(email):\n    q = \"SELECT 1 WHERE e = '\" + email + \"'\"\n    return connection().execute(q)\n"
    db = "import psycopg2\n\ndef connection():\n    return psycopg2.connect('')\n"
    snapshot = _snapshot(request_payload, [("app.py", app), ("db.py", db)])
    assert python_sql_api_known(snapshot, _finding(file_path="app.py", line_start=4, line_end=4))


def test_an_unknown_query_helper_is_ambiguous(request_payload):
    snapshot = _snapshot(request_payload, [("text.py", TEXT_PY)])
    finding = _finding(file_path="text.py", line_start=6, line_end=6)
    assert not python_sql_api_known(snapshot, finding)
    code, message = static_gate(snapshot, finding, SQL_PARAMETERIZATION, PYTHON)
    assert code == "ambiguous_query_api" and "execute()" in message
    # A driver import alone is not enough: the query still has to reach an execute() call.
    snapshot = _snapshot(request_payload, [("text.py", "import sqlite3\n" + TEXT_PY)])
    assert static_gate(snapshot, _finding(file_path="text.py", line_start=7, line_end=7), SQL_PARAMETERIZATION, PYTHON)[0] == "ambiguous_query_api"


def test_a_python_shell_pipeline_is_skipped(request_payload):
    piped = "import subprocess\n\ndef f(name):\n    return subprocess.run('grep ' + name + ' log | head', shell=True)\n"
    snapshot = _snapshot(request_payload, [("app.py", piped)])
    finding = _finding(file_path="app.py", line_start=4, line_end=4)
    assert python_shell_pipeline(snapshot, finding)
    assert static_gate(snapshot, finding, COMMAND_ARGUMENTS, PYTHON)[0] == "shell_pipeline_unsupported"
    plain = piped.replace(" | head", "")
    snapshot = _snapshot(request_payload, [("app.py", plain)])
    assert static_gate(snapshot, finding, COMMAND_ARGUMENTS, PYTHON) is None


# --- engine skips ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_engine_skips_per_finding_by_language_family_and_gate(request_payload):
    """Every skip is attributable: an unsupported language, a family the language lacks, an
    ambiguous query API, and a JavaScript SQL finding without a pg proof, while the eval finding
    still reaches the agent."""
    files = [("text.py", TEXT_PY), ("main.rb", "x = 1\n"), ("src/db.js", "module.exports = (db, id) => db.query('SELECT ' + id);\n"), ("package.json", '{"dependencies":{}}\n')]
    findings = [
        TEXT_FINDINGS[0],
        {"snapshot_id": "ruby", "rule_id": "sql", "cwe_id": "CWE-89", "file_path": "main.rb", "line_start": 1, "line_end": 1},
        {"snapshot_id": "js-secret", "rule_id": "secret.hardcoded.credential", "cwe_id": "CWE-798", "file_path": "src/db.js", "line_start": 1, "line_end": 1},
        {"snapshot_id": "js-sql", "rule_id": "sql", "cwe_id": "CWE-89", "file_path": "src/db.js", "line_start": 1, "line_end": 1},
        TEXT_FINDINGS[2],
    ]
    seen: list[list[str]] = []
    provider = _Scripted([])

    def factory(group_request):
        seen.append([finding.stable_id for finding in group_request.findings])
        return _local_agent(provider)

    response = await RepairEngine(factory).repair(RepairRequest.model_validate(_payload(request_payload, files, findings)))
    assert seen == [["eval-15"]]
    assert {item["finding_id"]: item["code"] for item in response.skipped} == {
        "sql-6": "ambiguous_query_api",
        "ruby": "unsupported_language",
        "js-secret": "unsupported_rule_family",
        "js-sql": "pg_dependency_not_proven",
    }
    # The eval finding is proven by the template path with the service-generated proof, so the
    # model is never consulted for it.
    assert response.state == "ready", response.reason
    assert [candidate.finding_ids for candidate in response.candidates] == [["eval-15"]]
    assert provider.calls == 0
    group = response.evidence["groups"][0]
    assert group["language"] == PYTHON
    assert group["reason_evidence"]["candidate_sources"] == {"eval-15": "template"}
    assert group["reason_evidence"]["proofs"] == {"eval-15": "service"}


@pytest.mark.asyncio
async def test_a_request_whose_only_finding_is_ambiguous_reports_that_reason(request_payload):
    payload = _payload(request_payload, [("text.py", TEXT_PY)], [TEXT_FINDINGS[0]])
    response = await RepairEngine(lambda request: pytest.fail("no agent should run")).repair(RepairRequest.model_validate(payload))
    assert response.state == "unsupported"
    assert response.reason["code"] == "ambiguous_query_api"
    assert [item["code"] for item in response.skipped] == ["ambiguous_query_api"]


# --- end to end -----------------------------------------------------------------------------

@requires_python
@pytest.mark.asyncio
async def test_engine_repairs_the_credential_and_eval_findings_and_skips_the_ambiguous_sql(request_payload):
    """text.py end to end: the SQL finding is skipped as ambiguous before any agent runs, and the
    credential and eval findings are proven by template hunks with service-generated proofs, so
    the model is never consulted."""
    provider = _Scripted([])
    payload = _payload(request_payload, [("text.py", TEXT_PY)], TEXT_FINDINGS)
    response = await RepairEngine(lambda request: _local_agent(provider)).repair(RepairRequest.model_validate(payload))
    assert response.state == "ready", response.reason
    assert provider.calls == 0
    # One candidate per proven finding, each carrying only its own hunks.
    assert [candidate.finding_ids for candidate in response.candidates] == [["eval-15"], ["secret-10"]]
    eval_candidate, credential_candidate = response.candidates
    assert "ast.literal_eval(user_input)" in eval_candidate.patch[0].replacement_content
    assert "import ast" in eval_candidate.patch[0].replacement_content
    assert 'API_KEY = "sk-' in eval_candidate.patch[0].replacement_content
    assert 'API_KEY = os.environ["API_KEY"]' in credential_candidate.patch[0].replacement_content
    assert "literal_eval" not in credential_candidate.patch[0].replacement_content
    [skip] = response.skipped
    assert (skip["finding_id"], skip["code"]) == ("sql-6", "ambiguous_query_api")
    assert "execute()" in skip["message"]
    checks = {item["check_id"]: item for item in response.evidence["verification_run"]["checks"]}
    for check_id in ("generated_regression_test", "generated_regression_test_2"):
        assert checks[check_id]["argv"][:2] == ["python3", ".mitig8it/harness.py"]
        assert checks[check_id]["baseline"]["status"] == "failed" and checks[check_id]["candidate"]["status"] == "passed"
    assert checks["generated_python_syntax"]["argv"] == ["python3", "-m", "py_compile", "text.py"]
    limitations = credential_candidate.preview["evidence"]["limitations"]
    assert "text.py now reads API_KEY from the environment; the deployment must provide it" in limitations
    assert any(item.startswith("runtime load check skipped for text.py") for item in limitations)
    assert credential_candidate.preview["evidence"]["candidate_source"] == "template"
    group = response.evidence["groups"][0]
    assert group["language"] == PYTHON
    assert group["reason_evidence"]["candidate_sources"] == {"eval-15": "template", "secret-10": "template"}
    assert group["reason_evidence"]["templates"] == {"eval-15": "proven", "secret-10": "proven"}


def _fixture_agent(fixture_dir: Path, fixture: dict, request: RepairRequest):
    replacements = reference_replacements(fixture_dir, fixture)
    originals = {item.path: item.content for item in request.files}
    [finding] = request.findings
    path = finding.affected_path
    proposal = {
        "hypothesis": f"{fixture['family']} in {path}",
        "intended_behavior": "unchanged for legitimate input",
        "assumptions": [],
        "citations": [{"path": path, "line_start": 1, "line_end": 1}],
        "changes": [whole_file_change(path, originals[path], replacements[path])],
        "regression_tests": [fixture_regression_test(fixture, finding.stable_id)],
    }
    return _local_agent(_Scripted([ProviderAction("propose_patch", proposal), ProviderAction("request_verification", {})]))


@requires_python
@pytest.mark.asyncio
@pytest.mark.parametrize("fixture_name", ["python-sql-sqlite", "python-hardcoded-secret", "python-eval"])
async def test_engine_verifies_each_python_fixture_with_the_scripted_reference_repair(fixture_name):
    fixture_dir = FIXTURES / fixture_name
    fixture = read_fixture(fixture_dir)
    request = build_repair_request(fixture_dir, fixture)
    response = await RepairEngine(lambda group_request: _fixture_agent(fixture_dir, fixture, group_request)).repair(request)
    assert response.state == "ready", response.reason
    [candidate] = response.candidates
    assert candidate.patch[0].replacement_content == reference_replacements(fixture_dir, fixture)["app.py"]
    assert candidate.generated_tests[0]["path"].endswith(".test.py")
    assert response.evidence["verification_level"] == "development_unverified"


@pytest.mark.asyncio
async def test_engine_skips_the_ambiguous_python_fixture_before_any_agent_runs():
    fixture_dir = FIXTURES / "python-ambiguous-sql"
    fixture = read_fixture(fixture_dir)
    response = await RepairEngine(lambda request: pytest.fail("no agent should run")).repair(build_repair_request(fixture_dir, fixture))
    assert response.state == "unsupported" and response.reason["code"] == "ambiguous_query_api"


# --- prompt and tools -----------------------------------------------------------------------

def test_python_groups_get_the_python_prompt_and_tools(request_payload):
    python_request = RepairRequest.model_validate(_payload(request_payload, [("text.py", TEXT_PY)], TEXT_FINDINGS))
    assert system_prompt(python_request) is PYTHON_SYSTEM_PROMPT
    assert system_prompt(RepairRequest.model_validate(request_payload)) is SYSTEM_PROMPT
    for needle in (
        "import harness as h",
        ".mitig8it/harness.py",
        "ambiguous_query_api",
        "credential_default_not_preservable",
        "eval_semantics_unknown",
        "ast.literal_eval",
        'os.environ["NAME"]',
        "h.assert_param(",
        "h.assert_argv(",
        "h.assert_inside(",
        "h.assert_env_read(",
        "h.assert_not_in_source(",
        "h.assert_no_commands()",
        "h.run(body)",
    ):
        assert needle in PYTHON_SYSTEM_PROMPT, needle
    assert "require('../harness')" not in PYTHON_SYSTEM_PROMPT
    propose = next(tool for tool in tool_definitions(PYTHON) if tool["function"]["name"] == "propose_patch")
    tests = propose["function"]["parameters"]["properties"]["regression_tests"]
    assert "import harness as h" in tests["description"] and "pytest" in tests["description"]
    assert tests["items"]["properties"]["path"]["description"].endswith(".test.py'.")
    javascript = next(tool for tool in tool_definitions() if tool["function"]["name"] == "propose_patch")
    assert "require('../harness')" in javascript["function"]["parameters"]["properties"]["regression_tests"]["description"]
