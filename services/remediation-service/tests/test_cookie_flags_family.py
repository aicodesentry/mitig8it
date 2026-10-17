"""`cookie_flags` in both toolchains: classification, the site and its refusals, the template,
the generated proof, and the proof run against the original and the repaired tree.

A cookie set without HttpOnly, Secure or SameSite is repaired on the options the code already
passes: all three are set (`sameSite: 'lax'`, not strict) and every other key is kept. A
Django or Flask setting the finding names is turned to True. The proof is executed under the
same harness the sandbox runs and has to fail on the original and pass on the repair.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src.families import (
    COOKIE_FLAGS,
    FAMILY_VERIFICATION,
    JAVASCRIPT,
    LANGUAGE_FAMILIES,
    PYTHON,
    SANDBOX_REGRESSION_TEST,
    family_assertion,
    rule_family,
)
from src.fixtures import build_repair_request, read_fixture
from src.gates import static_gate
from src.models import FindingSnapshot
from src.proofs import HARNESS_FAKED_MODULES, GeneratedProof, ProofFallback, generate_proof
from src.retrieval import Snapshot
from src.sandbox.harness import HARNESS_SOURCE_FILE, PYTHON_HARNESS_SOURCE_FILE
from src.sites import SiteError, js_cookie_site, python_cookie_site
from src.templates import TemplateFallback, TemplatePatch, generate_template
from tests.test_password_hashing_family import _apply, _snapshot

FIXTURES = Path(__file__).resolve().parents[3] / "benchmarks" / "remediation" / "fixtures"
JS_FIXTURES = ["js-cookie-express-session", "js-cookie-session-multiline", "js-res-cookie-route", "js-res-cookie-router-multiline"]
PY_FIXTURES = [
    "python-cookie-django-session-secure",
    "python-cookie-django-csrf-secure",
    "python-cookie-flask-config",
    "python-cookie-flask-set-cookie",
]

EXPRESS_SESSION = """const express = require('express');
const session = require('express-session');

const app = express();
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: false, maxAge: 1000 },
}));
module.exports = app;
"""

RES_COOKIE = """const express = require('express');
const app = express();
app.get('/login', (req, res) => {
  res.cookie('token', req.query.user, { httpOnly: false, maxAge: 1000 });
  res.send('ok');
});
module.exports = app;
"""


def _finding(**overrides) -> FindingSnapshot:
    values = {"id": "f-1", "rule_id": "", "cwe_id": "", "file_path": "app.js", "line_start": 1, "line_end": 1}
    values.update(overrides)
    return FindingSnapshot(**values)


def _run(tmp_path: Path, files: dict[str, str], proof: GeneratedProof) -> subprocess.CompletedProcess:
    for path, text in files.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    (tmp_path / ".mitig8it").mkdir(parents=True, exist_ok=True)
    shutil.copy(HARNESS_SOURCE_FILE, tmp_path / ".mitig8it" / "harness.js")
    shutil.copy(PYTHON_HARNESS_SOURCE_FILE, tmp_path / ".mitig8it" / "harness.py")
    test = tmp_path / proof.path
    test.parent.mkdir(parents=True, exist_ok=True)
    test.write_text(proof.content, encoding="utf-8")
    argv = ["node", str(test)] if proof.language == JAVASCRIPT else [sys.executable, ".mitig8it/harness.py", proof.path]
    return subprocess.run(argv, cwd=tmp_path, capture_output=True, text=True, timeout=60, check=False)


class TestRegistry:
    def test_the_family_is_proven_by_execution_in_both_toolchains(self):
        assert FAMILY_VERIFICATION[COOKIE_FLAGS] == SANDBOX_REGRESSION_TEST
        assert COOKIE_FLAGS in LANGUAGE_FAMILIES[JAVASCRIPT]
        assert COOKIE_FLAGS in LANGUAGE_FAMILIES[PYTHON]
        assert "h.assert.cookieFlags" in family_assertion(COOKIE_FLAGS, JAVASCRIPT)
        assert "h.assert_cookie_flags" in family_assertion(COOKIE_FLAGS, PYTHON)

    def test_the_session_middlewares_load_in_the_sandbox(self):
        assert {"express-session", "cookie-session"} <= HARNESS_FAKED_MODULES

    @pytest.mark.parametrize(
        "fields",
        [
            {"rule_id": "cwe-614.js-session-cookie-insecure", "cwe_id": "CWE-614"},
            {"rule_id": "cwe-614.py-session-cookie-insecure", "cwe_id": "CWE-614"},
            {"rule_id": "session.insecure_cookie", "cwe_id": "CWE-614"},
            {"rule_id": "some.rule", "cwe_id": "CWE-1004"},
        ],
    )
    def test_the_rules_that_report_a_missing_flag_classify_into_the_family(self, fields):
        assert rule_family(_finding(**fields)) == COOKIE_FLAGS

    def test_samesite_none_shares_the_type_but_not_the_family(self):
        finding = _finding(rule_id="cwe-1275.js-cookie-samesite-none", cwe_id="CWE-1275", internal_type="insecure_cookie_flags")
        assert rule_family(finding) is None


class TestJavaScriptSite:
    def test_express_session_rewrites_the_cookie_object_and_keeps_its_keys(self):
        site = js_cookie_site(EXPRESS_SESSION, 5, 8)
        assert site.kind == "express-session"
        assert site.replacement == ("  cookie: { secure: true, maxAge: 1000, httpOnly: true, sameSite: 'lax' },",)

    def test_res_cookie_names_the_cookie(self):
        site = js_cookie_site(RES_COOKIE, 4, 4)
        assert (site.kind, site.name) == ("res.cookie", "token")
        assert "{ httpOnly: true, maxAge: 1000, secure: true, sameSite: 'lax' }" in site.replacement[0]

    def test_a_multiline_object_gets_one_key_per_line_with_its_indentation(self):
        source = "const cookieSession = require('cookie-session');\napp.use(cookieSession({\n  name: 's',\n  secure: false,\n}));\n"
        site = js_cookie_site(source, 2, 5)
        assert site.replacement == ("app.use(cookieSession({", "  name: 's',", "  secure: true,", "  httpOnly: true,", "  sameSite: 'lax',", "}));")

    def test_an_existing_strict_samesite_is_kept(self):
        source = RES_COOKIE.replace("httpOnly: false, maxAge: 1000", "httpOnly: false, sameSite: 'strict'")
        assert "sameSite: 'strict'" in js_cookie_site(source, 4, 4).replacement[0]

    @pytest.mark.parametrize(
        ("source", "code"),
        [
            (RES_COOKIE.replace("httpOnly: false, maxAge: 1000", "httpOnly: false, sameSite: 'none'"), "cookie_samesite_none_is_deliberate"),
            (RES_COOKIE.replace("httpOnly: false, maxAge: 1000", "...defaults, httpOnly: false"), "cookie_options_spread"),
            (RES_COOKIE.replace("httpOnly: false, maxAge: 1000", "httpOnly: false, secure: isProduction"), "cookie_flag_value_not_literal"),
            (RES_COOKIE.replace("httpOnly: false", "httpOnly: true"), "cookie_flag_not_found"),
            (RES_COOKIE.replace("res.cookie('token', req.query.user, {", "track({"), "cookie_options_not_recognized"),
        ],
        ids=["samesite none", "spread", "computed flag", "no false flag", "not a cookie call"],
    )
    def test_each_refusal_is_named(self, source, code):
        with pytest.raises(SiteError) as raised:
            js_cookie_site(source, 4, 4)
        assert raised.value.code == code

    def test_a_session_call_whose_module_is_not_express_session_is_refused(self):
        source = EXPRESS_SESSION.replace("require('express-session')", "require('./my-session')")
        with pytest.raises(SiteError) as raised:
            js_cookie_site(source, 5, 8)
        assert raised.value.code == "cookie_options_not_recognized"


class TestPythonSite:
    def test_a_django_setting_is_turned_on(self):
        site = python_cookie_site("SESSION_COOKIE_SECURE = False  # local\n", 1, 1)
        assert (site.kind, site.name, site.replacement) == ("setting", "SESSION_COOKIE_SECURE", ("SESSION_COOKIE_SECURE = True  # local",))

    def test_a_flask_config_key_names_its_application(self):
        site = python_cookie_site('server = Flask(__name__)\nserver.config["SESSION_COOKIE_SECURE"] = False\n', 2, 2)
        assert (site.kind, site.app) == ("flask_config", "server")

    def test_set_cookie_gets_all_three_flags_and_keeps_its_arguments(self):
        site = python_cookie_site('resp.set_cookie("sid", value, max_age=60, httponly=False)\n', 1, 1)
        assert site.replacement == ('resp.set_cookie("sid", value, max_age=60, httponly=True, secure=True, samesite="Lax")',)

    @pytest.mark.parametrize(
        ("source", "code"),
        [
            ('resp.set_cookie("sid", value, 60, None, "/", None, False)\n', "cookie_flags_passed_positionally"),
            ('resp.set_cookie("sid", value, **options)\n', "cookie_options_spread"),
            ('resp.set_cookie("sid", value, secure=PRODUCTION)\n', "cookie_flag_value_not_literal"),
            ('resp.set_cookie("sid", value, secure=False, samesite="None")\n', "cookie_samesite_none_is_deliberate"),
            ("SESSION_COOKIE_AGE = 60\n", "cookie_flag_not_found"),
        ],
        ids=["positional", "spread", "computed", "samesite none", "nothing to repair"],
    )
    def test_each_refusal_is_named(self, source, code):
        with pytest.raises(SiteError) as raised:
            python_cookie_site(source, 1, 1)
        assert raised.value.code == code


class TestTemplateAndProof:
    def test_an_already_flagged_cookie_falls_back_rather_than_proposing_nothing(self, request_payload):
        source = RES_COOKIE.replace("httpOnly: false, maxAge: 1000", "httpOnly: true, secure: true, sameSite: 'lax'")
        snapshot, finding = _snapshot(request_payload, {"app.js": source}, {"rule_id": "session.insecure_cookie", "cwe_id": "CWE-614", "file_path": "app.js", "line_start": 4, "line_end": 4})
        patch = generate_template(snapshot, finding, COOKIE_FLAGS, JAVASCRIPT)
        assert isinstance(patch, TemplateFallback)

    def test_samesite_none_is_gated_before_any_agent_runs(self, request_payload):
        source = RES_COOKIE.replace("httpOnly: false, maxAge: 1000", "secure: false, sameSite: 'none'")
        snapshot, finding = _snapshot(request_payload, {"app.js": source}, {"rule_id": "session.insecure_cookie", "cwe_id": "CWE-614", "file_path": "app.js", "line_start": 4, "line_end": 4})
        assert static_gate(snapshot, finding, COOKIE_FLAGS, JAVASCRIPT)[0] == "cookie_samesite_none_is_deliberate"

    def test_session_middleware_configured_inside_a_function_is_not_proven_by_the_import(self, request_payload):
        source = EXPRESS_SESSION.replace("app.use(session({", "function configure(app) {\napp.use(session({").replace("}));\nmodule", "}));\n}\nmodule")
        snapshot, finding = _snapshot(request_payload, {"app.js": source}, {"rule_id": "cwe-614.js-session-cookie-insecure", "cwe_id": "CWE-614", "file_path": "app.js", "line_start": 6, "line_end": 9})
        proof = generate_proof(snapshot, finding, COOKIE_FLAGS, JAVASCRIPT)
        assert isinstance(proof, ProofFallback)
        assert proof.reason == "cookie_options_not_at_module_scope"

    def test_a_set_cookie_outside_a_route_has_no_proof(self, request_payload):
        source = 'def remember(response, token):\n    response.set_cookie("t", token, secure=False)\n'
        snapshot, finding = _snapshot(request_payload, {"cookies.py": source}, {"rule_id": "session.insecure_cookie", "cwe_id": "CWE-614", "file_path": "cookies.py", "line_start": 2, "line_end": 2})
        proof = generate_proof(snapshot, finding, COOKIE_FLAGS, PYTHON)
        assert isinstance(proof, ProofFallback)
        assert proof.reason == "cookie_route_not_found"

    def test_a_repair_that_sets_only_secure_fails_the_proof(self, request_payload, tmp_path):
        if shutil.which("node") is None:
            pytest.skip("the Node harness runs under node")
        snapshot, finding = _snapshot(request_payload, {"app.js": RES_COOKIE}, {"rule_id": "session.insecure_cookie", "cwe_id": "CWE-614", "file_path": "app.js", "line_start": 4, "line_end": 4})
        proof = generate_proof(snapshot, finding, COOKIE_FLAGS, JAVASCRIPT)
        partial = RES_COOKIE.replace("httpOnly: false", "httpOnly: true, secure: true")
        result = _run(tmp_path, {"app.js": partial}, proof)
        assert result.returncode == 1
        assert "lacks httpOnly, secure or sameSite" in result.stderr


def _fixture(name: str):
    directory = FIXTURES / name
    fixture = read_fixture(directory)
    request = build_repair_request(directory, fixture)
    language = PYTHON if fixture["source"].endswith(".py") else JAVASCRIPT
    return directory, fixture, Snapshot(request), request.findings[0], language


def _workspace(directory: Path, fixture: dict, text: str) -> dict[str, str]:
    files = {
        str(path.relative_to(directory)): path.read_text(encoding="utf-8")
        for path in directory.rglob("*")
        if path.is_file() and not str(path.relative_to(directory)).startswith(("expected/", "tests/")) and path.name != "fixture.json"
    }
    files[fixture["source"]] = text
    return files


class TestFixtures:
    @pytest.mark.parametrize("name", JS_FIXTURES + PY_FIXTURES)
    def test_the_template_reproduces_the_reviewed_repair(self, name):
        directory, fixture, snapshot, finding, language = _fixture(name)
        assert rule_family(finding) == COOKIE_FLAGS
        patch = generate_template(snapshot, finding, COOKIE_FLAGS, language)
        assert isinstance(patch, TemplatePatch), getattr(patch, "reason", None)
        repaired = _apply(snapshot.full_content(fixture["source"]), patch.changes)
        assert repaired == (directory / fixture["reference_repair"]).read_text(encoding="utf-8")

    @pytest.mark.parametrize("name", JS_FIXTURES + PY_FIXTURES)
    def test_the_proof_fails_on_the_original_and_passes_on_the_repair(self, name, tmp_path):
        if name.startswith("js-") and shutil.which("node") is None:
            pytest.skip("the Node harness runs under node")
        directory, fixture, snapshot, finding, language = _fixture(name)
        proof = generate_proof(snapshot, finding, COOKIE_FLAGS, language)
        assert isinstance(proof, GeneratedProof), getattr(proof, "reason", None)
        original = _run(tmp_path / "original", _workspace(directory, fixture, snapshot.full_content(fixture["source"])), proof)
        assert original.returncode == 1, original.stdout + original.stderr
        repaired_text = (directory / fixture["reference_repair"]).read_text(encoding="utf-8")
        repaired = _run(tmp_path / "repaired", _workspace(directory, fixture, repaired_text), proof)
        assert repaired.returncode == 0, repaired.stdout + repaired.stderr

    def test_the_negative_fixture_is_gated(self):
        _directory, fixture, snapshot, finding, language = _fixture("js-cookie-samesite-none")
        assert fixture["kind"] == "negative"
        assert static_gate(snapshot, finding, COOKIE_FLAGS, language)[0] == "cookie_samesite_none_is_deliberate"

    @pytest.mark.parametrize("name", JS_FIXTURES + PY_FIXTURES + ["js-cookie-samesite-none"])
    def test_the_fixture_declares_the_family(self, name):
        assert json.loads((FIXTURES / name / "fixture.json").read_text(encoding="utf-8"))["family"] == COOKIE_FLAGS
