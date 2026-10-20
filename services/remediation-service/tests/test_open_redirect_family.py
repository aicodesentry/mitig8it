"""`open_redirect` (Python): classification, the site and its refusals, the template, the
generated proof run against the original and the repaired tree, and the engine end to end.

A redirect whose target is read straight off the request is repaired by binding the read to a
variable, checking it, and falling back to the read's own default (else "/") when it would leave
the site: Django's `url_has_allowed_host_and_scheme` against the request's host, or, for Flask,
`urlsplit` accepting only a path on this site. The proof sends two hostile targets and one
same-site path through the view and has to fail on the original and pass on the repair.
"""
from __future__ import annotations

import pytest

from src.agent import RepairAgent
from src.engine import RepairEngine
from src.families import (
    FAMILY_VERIFICATION,
    JAVASCRIPT,
    LANGUAGE_FAMILIES,
    OPEN_REDIRECT,
    PYTHON,
    SANDBOX_REGRESSION_TEST,
    family_assertion,
    family_supported,
    rule_family,
)
from src.gates import REDIRECT_GATE_REFUSALS, static_gate
from src.models import FindingSnapshot
from src.patches import PatchPolicyError, _reject_missing_python_dependencies
from src.proofs import GeneratedProof, ProofFallback, generate_proof
from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver
from src.sandbox.harness import PYTHON_HARNESS_MODULES, python_harness_modules
from src.sites import SiteError, python_redirect_site
from src.templates import TemplatePatch, generate_template
from src.verification import Verifier
from tests.test_password_hashing_family import _apply, _run_proof, _snapshot
from tests.test_python_families import _Scripted
from tests.test_template_first import _request

RULE = "opengrep.cwe-601.py-redirect-request-value"

DJANGO_VIEWS = '''from django.db import connection
from django.http import JsonResponse
from django.shortcuts import redirect


def search(request):
    name = request.GET.get("name", "")
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
        rows = cursor.fetchall()
    return JsonResponse({"results": rows})


def after_export(request):
    return redirect(request.GET.get("next", "/inventory/"))
'''

DJANGO_REPAIRED = '''from django.db import connection
from django.http import JsonResponse
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme


def search(request):
    name = request.GET.get("name", "")
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
        rows = cursor.fetchall()
    return JsonResponse({"results": rows})


def after_export(request):
    next_url = request.GET.get("next", "/inventory/")
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        next_url = "/inventory/"
    return redirect(next_url)
'''

DJANGO_POST = '''from django.http import HttpResponseRedirect


def login(request, tenant):
    if request.method == "POST":
        return HttpResponseRedirect(request.POST["next"])
    return None
'''

FLASK_APP = '''from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/login", methods=["GET", "POST"])
def login():
    return redirect(request.args.get("next"))
'''

FLASK_REPAIRED = '''from flask import Flask, redirect, request
from urllib.parse import urlsplit

app = Flask(__name__)


@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next")
    if not next_url or not next_url.startswith("/") or urlsplit(next_url.replace("\\\\", "/")).netloc:
        next_url = "/"
    return redirect(next_url)
'''

FLASK_FORM = '''from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/accounts/<int:account>/done", methods=["POST"])
def done(account):
    target = redirect(request.form.get("next", "/accounts/"), code=303)
    return target
'''


def _finding(path: str, line: int, **overrides) -> dict:
    return {"rule_id": RULE, "cwe_id": "CWE-601", "category": "open redirect", "file_path": path, "line_start": line, "line_end": line, **overrides}


def _site(request_payload, files: dict[str, str], path: str, line: int):
    snapshot, finding = _snapshot(request_payload, files, _finding(path, line))
    return snapshot, finding


class TestRegistry:
    def test_the_family_is_proven_by_execution_in_python_only(self):
        assert FAMILY_VERIFICATION[OPEN_REDIRECT] == SANDBOX_REGRESSION_TEST
        assert OPEN_REDIRECT in LANGUAGE_FAMILIES[PYTHON]
        assert OPEN_REDIRECT not in LANGUAGE_FAMILIES[JAVASCRIPT]
        assert family_supported(OPEN_REDIRECT, PYTHON) and not family_supported(OPEN_REDIRECT, JAVASCRIPT)
        assert "h.assert_redirect_local" in family_assertion(OPEN_REDIRECT, PYTHON)

    @pytest.mark.parametrize(
        "fields",
        [
            {"rule_id": RULE, "cwe_id": "CWE-601"},
            {"rule_id": "some.rule", "cwe_id": "CWE-601"},
            {"rule_id": "some.rule", "cwe_id": "", "internal_type": "open_redirect"},
        ],
    )
    def test_the_rule_classifies_into_the_family(self, fields):
        assert rule_family(FindingSnapshot(id="f", file_path="views.py", line_start=1, line_end=1, **fields)) == OPEN_REDIRECT

    def test_the_harness_module_table_agrees_with_the_harness(self):
        assert {"django.http", "django.shortcuts", "django.utils.http"} <= PYTHON_HARNESS_MODULES
        assert PYTHON_HARNESS_MODULES == python_harness_modules()


class TestSite:
    def test_the_live_django_view(self):
        site = python_redirect_site(DJANGO_VIEWS, 15, 15)
        assert (site.framework, site.receiver, site.source, site.key) == ("django", "request", "GET", "next")
        assert (site.read, site.fallback, site.variable) == ('request.GET.get("next", "/inventory/")', '"/inventory/"', "next_url")
        assert site.imports_needed == ("from django.utils.http import url_has_allowed_host_and_scheme",)

    def test_a_flask_read_without_a_default_falls_back_to_the_root(self):
        site = python_redirect_site(FLASK_APP, 8, 8)
        assert (site.framework, site.fallback, site.imports_needed) == ("flask", '"/"', ("from urllib.parse import urlsplit",))

    def test_an_existing_import_of_the_check_is_reused(self):
        source = DJANGO_VIEWS.replace("from django.shortcuts import redirect\n", "from django.shortcuts import redirect\nfrom django.utils.http import url_has_allowed_host_and_scheme\n")
        assert python_redirect_site(source, 16, 16).imports_needed == ()

    def test_a_taken_variable_name_moves_to_the_next(self):
        source = DJANGO_VIEWS.replace('name = request.GET.get("name", "")', 'next_url = request.GET.get("name", "")')
        assert python_redirect_site(source, 15, 15).variable == "redirect_url"

    @pytest.mark.parametrize(
        ("source", "line", "code"),
        [
            (DJANGO_VIEWS.replace("from django.shortcuts import redirect", "from .helpers import redirect"), 15, "redirect_function_not_recognized"),
            (DJANGO_VIEWS.replace('request.GET.get("next", "/inventory/")', "request.args.get('next')"), 15, "redirect_request_source_not_recognized"),
            (DJANGO_VIEWS.replace('request.GET.get("next", "/inventory/")', 'request.GET.get(field)'), 15, "redirect_parameter_not_literal"),
            (DJANGO_VIEWS.replace("    return redirect(", "    if request: return redirect("), 15, "redirect_statement_not_recognized"),
            (DJANGO_VIEWS.replace("def after_export(request):", "class Export:\n    def get(self, request):").replace("    return redirect(", "        return redirect("), 16, "redirect_view_not_callable"),
            (DJANGO_VIEWS.replace('"/inventory/"))', 'request.path))'), 15, "redirect_default_not_recognized"),
            (FLASK_APP.replace('@app.route("/login", methods=["GET", "POST"])\n', ""), 7, "redirect_view_not_routed"),
            ("from django.shortcuts import redirect\nTARGET = redirect(request.GET['next'])\n", 2, "redirect_not_in_function"),
            (DJANGO_VIEWS.replace("from django.utils.http", "x").replace("def search(request):", "def search(request, url_has_allowed_host_and_scheme=None):"), 15, "redirect_helper_name_taken"),
            ("def view(request):\n    return render(request)\n", 2, "redirect_call_not_recognized"),
        ],
        ids=["own helper", "flask read in django", "computed key", "one-line if", "class-based view", "default from request", "no route", "module scope", "check name taken", "not a redirect"],
    )
    def test_each_refusal_is_named_and_gated(self, request_payload, source, line, code):
        with pytest.raises(SiteError) as raised:
            python_redirect_site(source, line, line)
        assert raised.value.code == code
        snapshot, finding = _site(request_payload, {"views.py": source}, "views.py", line)
        gate = static_gate(snapshot, finding, OPEN_REDIRECT, PYTHON)
        assert gate is not None and gate[0] == code
        if code in REDIRECT_GATE_REFUSALS:
            assert gate[1] == REDIRECT_GATE_REFUSALS[code]

    def test_a_recognized_redirect_passes_the_gate(self, request_payload):
        snapshot, finding = _site(request_payload, {"inventory/views.py": DJANGO_VIEWS}, "inventory/views.py", 15)
        assert static_gate(snapshot, finding, OPEN_REDIRECT, PYTHON) is None


class TestTemplate:
    def test_the_live_django_view_gets_the_host_check(self, request_payload):
        snapshot, finding = _site(request_payload, {"inventory/views.py": DJANGO_VIEWS}, "inventory/views.py", 15)
        patch = generate_template(snapshot, finding, OPEN_REDIRECT, PYTHON)
        assert isinstance(patch, TemplatePatch), getattr(patch, "reason", None)
        assert _apply(DJANGO_VIEWS, patch.changes) == DJANGO_REPAIRED

    def test_flask_accepts_only_a_path_on_the_site(self, request_payload):
        snapshot, finding = _site(request_payload, {"app.py": FLASK_APP}, "app.py", 8)
        patch = generate_template(snapshot, finding, OPEN_REDIRECT, PYTHON)
        assert isinstance(patch, TemplatePatch), getattr(patch, "reason", None)
        assert _apply(FLASK_APP, patch.changes) == FLASK_REPAIRED

    def test_other_arguments_of_the_redirect_are_kept(self, request_payload):
        snapshot, finding = _site(request_payload, {"app.py": FLASK_FORM}, "app.py", 8)
        patch = generate_template(snapshot, finding, OPEN_REDIRECT, PYTHON)
        repaired = _apply(FLASK_FORM, patch.changes)
        assert '    next_url = request.form.get("next", "/accounts/")\n' in repaired
        assert '        next_url = "/accounts/"\n' in repaired
        assert "    target = redirect(next_url, code=303)\n" in repaired


def _workspace_run(tmp_path, name: str, path: str, text: str, proof: GeneratedProof):
    return _run_proof(tmp_path / name, {path: text}, proof)


class TestProof:
    @pytest.mark.parametrize(
        ("path", "source", "line"),
        [
            ("inventory/views.py", DJANGO_VIEWS, 15),
            ("accounts/views.py", DJANGO_POST, 6),
            ("app.py", FLASK_APP, 8),
            ("app.py", FLASK_FORM, 8),
        ],
        ids=["django GET with default", "django POST subscript", "flask args", "flask form route parameter"],
    )
    def test_the_proof_fails_on_the_original_and_passes_on_the_template(self, request_payload, tmp_path, path, source, line):
        snapshot, finding = _site(request_payload, {path: source}, path, line)
        proof = generate_proof(snapshot, finding, OPEN_REDIRECT, PYTHON)
        assert isinstance(proof, GeneratedProof), getattr(proof, "reason", None)
        original = _workspace_run(tmp_path, "original", path, source, proof)
        assert original.returncode == 1, original.stdout + original.stderr
        assert "must not redirect off the site" in original.stderr
        patch = generate_template(snapshot, finding, OPEN_REDIRECT, PYTHON)
        repaired = _workspace_run(tmp_path, "repaired", path, _apply(source, patch.changes), proof)
        assert repaired.returncode == 0, repaired.stdout + repaired.stderr

    def test_a_repair_that_sends_every_reader_to_the_root_fails(self, request_payload, tmp_path):
        snapshot, finding = _site(request_payload, {"app.py": FLASK_APP}, "app.py", 8)
        proof = generate_proof(snapshot, finding, OPEN_REDIRECT, PYTHON)
        result = _workspace_run(tmp_path, "root", "app.py", FLASK_APP.replace('redirect(request.args.get("next"))', 'redirect("/")'), proof)
        assert result.returncode == 1
        assert "a same-site path must still be the redirect target" in result.stderr

    def test_a_repair_that_only_checks_for_a_leading_slash_fails(self, request_payload, tmp_path):
        snapshot, finding = _site(request_payload, {"app.py": FLASK_APP}, "app.py", 8)
        proof = generate_proof(snapshot, finding, OPEN_REDIRECT, PYTHON)
        naive = FLASK_APP.replace(
            '    return redirect(request.args.get("next"))',
            '    target = request.args.get("next") or "/"\n    return redirect(target if target.startswith("/") else "/")',
        )
        result = _workspace_run(tmp_path, "naive", "app.py", naive, proof)
        assert result.returncode == 1
        assert "//evil.example/" in result.stderr

    def test_a_refused_site_has_no_proof(self, request_payload):
        source = DJANGO_VIEWS.replace("from django.shortcuts import redirect", "from .helpers import redirect")
        snapshot, finding = _site(request_payload, {"views.py": source}, "views.py", 15)
        proof = generate_proof(snapshot, finding, OPEN_REDIRECT, PYTHON)
        assert isinstance(proof, ProofFallback) and proof.reason == "redirect_function_not_recognized"


class TestHarnessHostCheck:
    @pytest.mark.parametrize(
        ("url", "allowed"),
        [
            ("/inventory/", True),
            ("https://testserver/x", True),
            ("https://evil.example/", False),
            ("//evil.example/", False),
            ("/\\evil.example/", False),
            ("\\\\evil.example", False),
            ("///evil.example", False),
            ("javascript:alert(1)", False),
            ("\x01/evil", False),
            ("", False),
        ],
    )
    def test_the_ported_check_matches_django(self, url, allowed):
        from src.sandbox import harness_py

        assert harness_py.url_has_allowed_host_and_scheme(url, {"testserver"}) is allowed

    def test_requiring_https_refuses_an_http_url_on_the_host(self):
        from src.sandbox import harness_py

        assert not harness_py.url_has_allowed_host_and_scheme("http://testserver/x", {"testserver"}, require_https=True)


class TestDependencyGate:
    def test_another_module_of_an_imported_package_is_not_a_new_dependency(self, request_payload):
        snapshot, _ = _site(request_payload, {"views.py": DJANGO_VIEWS}, "views.py", 15)
        _reject_missing_python_dependencies("views.py", DJANGO_VIEWS, DJANGO_REPAIRED, snapshot)

    def test_a_new_top_level_package_is_still_refused(self, request_payload):
        snapshot, _ = _site(request_payload, {"views.py": DJANGO_VIEWS}, "views.py", 15)
        with pytest.raises(PatchPolicyError, match="missing_dependency:requests"):
            _reject_missing_python_dependencies("views.py", DJANGO_VIEWS, DJANGO_VIEWS + "import requests\n", snapshot)

    def test_a_namespace_package_root_does_not_vouch_for_its_siblings(self, request_payload):
        original = "from google.auth import default\n"
        snapshot, _ = _site(request_payload, {"gcp.py": original}, "gcp.py", 1)
        with pytest.raises(PatchPolicyError, match="missing_dependency:google"):
            _reject_missing_python_dependencies("gcp.py", original, original + "from google.cloud import storage\n", snapshot)


@pytest.mark.asyncio
async def test_the_engine_repairs_the_live_view_from_the_template_without_the_model():
    findings = [{"snapshot_id": "redirect-15", **_finding("inventory/views.py", 15)}]
    request = _request([("inventory/views.py", DJANGO_VIEWS)], findings)
    provider = _Scripted([])
    response = await RepairEngine(lambda group_request: RepairAgent(provider, Verifier(InProcessSandboxBroker(LocalSubprocessDriver())))).repair(request)
    assert response.state == "ready", response.reason
    assert provider.calls == 0
    assert [candidate.finding_ids for candidate in response.candidates] == [["redirect-15"]]
    assert response.candidates[0].preview["evidence"]["candidate_source"] == "template"
    checks = [check for check in response.evidence["verification_run"]["checks"] if check["kind"] == "exploit"]
    assert [(check["baseline"]["status"], check["candidate"]["status"]) for check in checks] == [("failed", "passed")]
