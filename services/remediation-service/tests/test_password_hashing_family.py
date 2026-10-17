"""`password_hashing` in both toolchains: classification, the site and its refusals, the
template, the generated proof, and the proof run against the original and the repaired tree.

A fast digest of a password (MD5, SHA-1, SHA-256) is repaired to a salted key-derivation
function from the standard library, and every comparison of the digest in the module becomes a
call to a verifier, because a salted hash is different on every call and `hash(attempt) ==
stored` can never be true again. The proof is executed: it has to fail on the original module
and pass on the repaired one, under the same harness the sandbox runs.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src.families import (
    FAMILY_VERIFICATION,
    JAVASCRIPT,
    LANGUAGE_FAMILIES,
    PASSWORD_HASHING,
    PYTHON,
    SANDBOX_PROVEN_FAMILIES,
    SANDBOX_REGRESSION_TEST,
    family_assertion,
    rule_family,
)
from src.fixtures import build_repair_request, read_fixture
from src.gates import static_gate
from src.git_tree import compute_tree_oid
from src.models import FindingSnapshot, GitTreeEntry, RepairRequest
from src.proofs import GeneratedProof, ProofFallback, generate_proof
from src.retrieval import Snapshot
from src.sandbox.harness import HARNESS_SOURCE_FILE, PYTHON_HARNESS_SOURCE_FILE
from src.sites import SiteError, js_password_hash_site, python_password_hash_site
from src.templates import TemplateFallback, TemplatePatch, generate_template
from tests.conftest import git_blob

FIXTURES = Path(__file__).resolve().parents[3] / "benchmarks" / "remediation" / "fixtures"
JS_FIXTURES = ["js-password-md5-verify", "js-password-sha1-member", "js-password-arrow-base64", "js-password-two-comparisons"]
PY_FIXTURES = [
    "python-password-md5",
    "python-password-sha1-docstring",
    "python-password-sha256-from-import",
    "python-password-alias-crypto-weak-hash",
]
requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="the Node harness runs under node")

JS_MODULE = """const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

function verifyPassword(password, stored) {
  return hashPassword(password) === stored;
}

module.exports = { hashPassword, verifyPassword };
"""

PY_MODULE = '''import hashlib


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, stored):
    return hash_password(password) == stored
'''


def _finding(**overrides) -> FindingSnapshot:
    values = {"id": "f-1", "rule_id": "", "cwe_id": "", "file_path": "auth.js", "line_start": 4, "line_end": 4}
    values.update(overrides)
    return FindingSnapshot(**values)


def _snapshot(request_payload: dict, files: dict[str, str], finding: dict) -> tuple[Snapshot, FindingSnapshot]:
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=git_blob(text)) for path, text in files.items()]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": text, "sha": git_blob(text)} for path, text in files.items()]
    payload["findings"] = [{"snapshot_id": "f-1", **finding}]
    request = RepairRequest.model_validate(payload)
    return Snapshot(request), request.findings[0]


def _apply(source: str, changes: list[dict]) -> str:
    lines = source.splitlines()
    for change in sorted(changes, key=lambda item: item["start_line"], reverse=True):
        start = int(change["start_line"]) - 1
        assert lines[start : start + len(change["original_lines"])] == change["original_lines"]
        lines[start : start + len(change["original_lines"])] = change["replacement_lines"]
    return "\n".join(lines) + "\n"


def _run_proof(tmp_path: Path, files: dict[str, str], proof: GeneratedProof) -> subprocess.CompletedProcess:
    """Materializes a workspace the way the sandbox does and runs the proof under its harness."""
    for path, text in files.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    (tmp_path / ".mitig8it" / "regression").mkdir(parents=True, exist_ok=True)
    shutil.copy(HARNESS_SOURCE_FILE, tmp_path / ".mitig8it" / "harness.js")
    shutil.copy(PYTHON_HARNESS_SOURCE_FILE, tmp_path / ".mitig8it" / "harness.py")
    test = tmp_path / proof.path
    test.parent.mkdir(parents=True, exist_ok=True)
    test.write_text(proof.content, encoding="utf-8")
    argv = ["node", str(test)] if proof.language == JAVASCRIPT else [sys.executable, ".mitig8it/harness.py", proof.path]
    return subprocess.run(argv, cwd=tmp_path, capture_output=True, text=True, timeout=60, check=False)


class TestRegistry:
    def test_the_family_is_proven_by_execution_in_both_toolchains(self):
        assert PASSWORD_HASHING in SANDBOX_PROVEN_FAMILIES
        assert FAMILY_VERIFICATION[PASSWORD_HASHING] == SANDBOX_REGRESSION_TEST
        assert PASSWORD_HASHING in LANGUAGE_FAMILIES[JAVASCRIPT]
        assert PASSWORD_HASHING in LANGUAGE_FAMILIES[PYTHON]

    def test_each_toolchain_names_its_own_harness_assertion(self):
        assert "h.assert.passwordHash" in family_assertion(PASSWORD_HASHING, JAVASCRIPT)
        assert "h.assert_password_hash" in family_assertion(PASSWORD_HASHING, PYTHON)

    @pytest.mark.parametrize(
        "fields",
        [
            {"rule_id": "cwe-916.js-password-weak-hash", "cwe_id": "CWE-916"},
            {"rule_id": "cwe-327.weak-hash-password", "cwe_id": "CWE-916"},
            {"rule_id": "auth.weak_password_hash", "cwe_id": "CWE-916"},
            # Tier 1's weak-hash rule declares CWE-327 for every MD5 call; the analysis service
            # renames it weak_password_hash only when the digested value is a credential.
            {"rule_id": "crypto.weak.hash", "cwe_id": "CWE-327", "internal_type": "weak_password_hash"},
        ],
    )
    def test_the_rules_that_report_a_weak_password_hash_classify_into_the_family(self, fields):
        assert rule_family(_finding(**fields)) == PASSWORD_HASHING

    @pytest.mark.parametrize(
        "fields",
        [
            {"rule_id": "crypto.weak.hash", "cwe_id": "CWE-327", "internal_type": "weak_cipher_algorithm"},
            {"rule_id": "cwe-327.js-ecb-cipher-mode", "cwe_id": "CWE-327"},
        ],
    )
    def test_a_weak_digest_of_something_else_is_not_a_password(self, fields):
        assert rule_family(_finding(**fields)) is None


class TestJavaScriptSite:
    def test_the_function_and_every_comparison_are_found(self):
        site = js_password_hash_site(JS_MODULE, "auth.js", 4, 4)
        assert (site.function, site.parameter, site.algorithm, site.module) == ("hashPassword", "password", "md5", "crypto")
        assert [(item.line, item.password, item.stored, item.negated) for item in site.comparisons] == [(8, "password", "stored", False)]

    @pytest.mark.parametrize(
        ("source", "code"),
        [
            (JS_MODULE.replace(".digest('hex')", ".digest()"), "password_digest_encoding_not_text"),
            (JS_MODULE.replace("require('crypto')", "require('./hasher')"), "password_digest_not_recognized"),
            (JS_MODULE.replace("hashPassword(password) {", "hashPassword(password, pepper) {"), "password_hash_function_not_single_parameter"),
            (JS_MODULE.replace("update(password)", "update(PEPPER)"), "password_hash_input_not_the_parameter"),
            (JS_MODULE.replace("return hashPassword(password) === stored;", "return stored;"), "password_verifier_not_found"),
            (
                JS_MODULE.replace("return hashPassword(password) === stored;", "return db.query('SELECT 1 WHERE h = $1', [hashPassword(password)]);"),
                "password_hash_used_for_lookup",
            ),
            (JS_MODULE.replace("return hashPassword(password) === stored;", "return prefix + hashPassword(password) === stored;"), "password_comparison_not_rewritable"),
            (JS_MODULE.replace("function verifyPassword", "function verifyPasswordHash"), "password_verifier_name_taken"),
            (
                JS_MODULE.replace("function hashPassword(password) {", "function hashPassword(password) {\n  audit(password);"),
                "password_hash_not_returned_by_function",
            ),
        ],
        ids=["binary digest", "not the crypto module", "two parameters", "digest of another value", "no comparison", "lookup", "precedence", "name taken", "extra statement"],
    )
    def test_each_refusal_is_named(self, source, code):
        with pytest.raises(SiteError) as raised:
            js_password_hash_site(source, "auth.js", 4, 5)
        assert raised.value.code == code

    def test_a_method_is_refused_by_name(self):
        source = "const crypto = require('crypto');\nclass A {\n  hash(password) {\n    return crypto.createHash('md5').update(password).digest('hex');\n  }\n}\n"
        with pytest.raises(SiteError) as raised:
            js_password_hash_site(source, "auth.js", 4, 4)
        assert raised.value.code == "password_hash_in_method"

    def test_another_module_that_imports_the_function_refuses_it(self):
        other = {"login.js": "const { hashPassword } = require('./auth');\nmodule.exports = (p, s) => hashPassword(p) === s;\n"}
        with pytest.raises(SiteError) as raised:
            js_password_hash_site(JS_MODULE, "auth.js", 4, 4, other)
        assert raised.value.code == "password_hash_called_from_other_module"


class TestPythonSite:
    def test_the_function_and_every_comparison_are_found(self):
        site = python_password_hash_site(PY_MODULE, "auth.py", 5)
        assert (site.function, site.parameter, site.algorithm, site.argument) == ("hash_password", "password", "md5", "password.encode()")
        assert site.imports_needed == ("hmac", "os")
        assert [(item.line, item.stored, item.negated) for item in site.comparisons] == [(9, "stored", False)]

    @pytest.mark.parametrize(
        ("source", "code"),
        [
            (PY_MODULE.replace(".hexdigest()", ".digest()"), "password_digest_encoding_not_text"),
            (PY_MODULE.replace("def hash_password(password):", "def hash_password(password, pepper):"), "password_hash_function_not_single_parameter"),
            (PY_MODULE.replace("password.encode()", "PEPPER.encode()"), "password_hash_input_not_the_parameter"),
            (PY_MODULE.replace("return hash_password(password) == stored", "return stored"), "password_verifier_not_found"),
            (
                PY_MODULE.replace("return hash_password(password) == stored", "return db.execute('SELECT 1 WHERE h = ?', (hash_password(password),))"),
                "password_hash_used_for_lookup",
            ),
            (PY_MODULE.replace("hash_password(password) == stored", "hash_password(password) in stored"), "password_comparison_not_rewritable"),
            (PY_MODULE + "\n\ndef verify_password_hash():\n    pass\n", "password_verifier_name_taken"),
        ],
        ids=["binary digest", "two parameters", "digest of another value", "no comparison", "lookup", "membership", "name taken"],
    )
    def test_each_refusal_is_named(self, source, code):
        with pytest.raises(SiteError) as raised:
            python_password_hash_site(source, "auth.py", 5)
        assert raised.value.code == code

    def test_a_method_is_refused_by_name(self):
        source = "import hashlib\n\n\nclass A:\n    def hash(self, password):\n        return hashlib.md5(password.encode()).hexdigest()\n"
        with pytest.raises(SiteError) as raised:
            python_password_hash_site(source, "auth.py", 6)
        assert raised.value.code == "password_hash_in_method"

    def test_another_module_that_imports_the_function_refuses_it(self):
        other = {"views.py": "from auth import hash_password\n\nok = hash_password('x') == 'y'\n"}
        with pytest.raises(SiteError) as raised:
            python_password_hash_site(PY_MODULE, "auth.py", 5, other)
        assert raised.value.code == "password_hash_called_from_other_module"


class TestGate:
    def test_a_lookup_is_skipped_before_any_agent_runs(self, request_payload):
        source = JS_MODULE.replace(
            "return hashPassword(password) === stored;", "return db.query('SELECT 1 WHERE h = $1', [hashPassword(password)]);"
        )
        snapshot, finding = _snapshot(request_payload, {"auth.js": source}, {"rule_id": "cwe-916.js-password-weak-hash", "cwe_id": "CWE-916", "file_path": "auth.js", "line_start": 4, "line_end": 4})
        assert static_gate(snapshot, finding, PASSWORD_HASHING, JAVASCRIPT)[0] == "password_hash_used_for_lookup"

    def test_a_shape_the_template_does_not_know_is_left_to_the_model_not_gated(self, request_payload):
        source = JS_MODULE.replace(".digest('hex')", ".digest()")
        snapshot, finding = _snapshot(request_payload, {"auth.js": source}, {"rule_id": "cwe-916.js-password-weak-hash", "cwe_id": "CWE-916", "file_path": "auth.js", "line_start": 4, "line_end": 4})
        assert static_gate(snapshot, finding, PASSWORD_HASHING, JAVASCRIPT) is None


class TestTemplate:
    def test_javascript_repair_salts_the_hash_and_rewrites_the_comparison(self, request_payload):
        snapshot, finding = _snapshot(request_payload, {"auth.js": JS_MODULE}, {"rule_id": "cwe-916.js-password-weak-hash", "cwe_id": "CWE-916", "file_path": "auth.js", "line_start": 4, "line_end": 4})
        patch = generate_template(snapshot, finding, PASSWORD_HASHING, JAVASCRIPT)
        assert isinstance(patch, TemplatePatch), getattr(patch, "reason", None)
        repaired = _apply(JS_MODULE, patch.changes)
        assert "createHash" not in repaired
        assert "crypto.scryptSync(password, salt, 32)" in repaired
        assert "crypto.timingSafeEqual(actual, wanted)" in repaired
        assert "return verifyPasswordHash(password, stored);" in repaired
        assert "password reset" in patch.description

    def test_typescript_gets_a_typed_verifier(self, request_payload):
        source = JS_MODULE.replace("hashPassword(password)", "hashPassword(password: string)", 1)
        snapshot, finding = _snapshot(request_payload, {"auth.ts": source}, {"rule_id": "cwe-916.js-password-weak-hash", "cwe_id": "CWE-916", "file_path": "auth.ts", "line_start": 4, "line_end": 4})
        patch = generate_template(snapshot, finding, PASSWORD_HASHING, JAVASCRIPT)
        assert "function verifyPasswordHash(password: string, stored: string): boolean {" in _apply(source, patch.changes)

    def test_python_repair_adds_only_the_imports_it_needs(self, request_payload):
        snapshot, finding = _snapshot(request_payload, {"auth.py": PY_MODULE}, {"rule_id": "cwe-327.weak-hash-password", "cwe_id": "CWE-916", "file_path": "auth.py", "line_start": 5, "line_end": 5})
        patch = generate_template(snapshot, finding, PASSWORD_HASHING, PYTHON)
        assert isinstance(patch, TemplatePatch), getattr(patch, "reason", None)
        repaired = _apply(PY_MODULE, patch.changes)
        assert repaired.startswith("import hashlib\nimport hmac\nimport os\n")
        assert "hashlib.md5" not in repaired
        assert "return verify_password_hash(password, stored)" in repaired
        compile(repaired, "auth.py", "exec")

    def test_an_unrecognized_shape_falls_back_with_the_site_reason(self, request_payload):
        source = PY_MODULE.replace(".hexdigest()", ".digest()")
        snapshot, finding = _snapshot(request_payload, {"auth.py": source}, {"rule_id": "cwe-327.weak-hash-password", "cwe_id": "CWE-916", "file_path": "auth.py", "line_start": 5, "line_end": 5})
        patch = generate_template(snapshot, finding, PASSWORD_HASHING, PYTHON)
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "password_digest_encoding_not_text"


class TestGeneratedProof:
    def test_an_unexported_hash_function_cannot_be_called_by_a_proof(self, request_payload):
        source = JS_MODULE.replace("module.exports = { hashPassword, verifyPassword };", "module.exports = { verifyPassword };")
        snapshot, finding = _snapshot(request_payload, {"auth.js": source}, {"rule_id": "cwe-916.js-password-weak-hash", "cwe_id": "CWE-916", "file_path": "auth.js", "line_start": 4, "line_end": 4})
        proof = generate_proof(snapshot, finding, PASSWORD_HASHING, JAVASCRIPT)
        assert isinstance(proof, ProofFallback)
        assert proof.reason == "password_hash_function_not_exported"

    def test_the_proof_asserts_salt_recorder_and_verifier(self, request_payload):
        snapshot, finding = _snapshot(request_payload, {"auth.js": JS_MODULE}, {"rule_id": "cwe-916.js-password-weak-hash", "cwe_id": "CWE-916", "file_path": "auth.js", "line_start": 4, "line_end": 4})
        proof = generate_proof(snapshot, finding, PASSWORD_HASHING, JAVASCRIPT)
        assert isinstance(proof, GeneratedProof), getattr(proof, "reason", None)
        assert "first !== second" in proof.content
        assert "h.assert.passwordHash(password);" in proof.content
        assert "m.verifyPassword, password, stored" in proof.content


def _fixture(name: str):
    directory = FIXTURES / name
    fixture = read_fixture(directory)
    request = build_repair_request(directory, fixture)
    snapshot = Snapshot(request)
    finding = request.findings[0]
    language = PYTHON if fixture["source"].endswith(".py") else JAVASCRIPT
    return directory, fixture, snapshot, finding, language


def _workspace(directory: Path, fixture: dict, source_text: str) -> dict[str, str]:
    files = {
        str(path.relative_to(directory)): path.read_text(encoding="utf-8")
        for path in directory.rglob("*")
        if path.is_file() and not str(path.relative_to(directory)).startswith(("expected/", "tests/")) and path.name != "fixture.json"
    }
    files[fixture["source"]] = source_text
    return files


class TestFixtures:
    @pytest.mark.parametrize("name", JS_FIXTURES + PY_FIXTURES)
    def test_the_template_reproduces_the_reviewed_repair(self, name):
        directory, fixture, snapshot, finding, language = _fixture(name)
        assert rule_family(finding) == PASSWORD_HASHING
        patch = generate_template(snapshot, finding, PASSWORD_HASHING, language)
        assert isinstance(patch, TemplatePatch), getattr(patch, "reason", None)
        repaired = _apply(snapshot.full_content(fixture["source"]), patch.changes)
        assert repaired == (directory / fixture["reference_repair"]).read_text(encoding="utf-8")

    @pytest.mark.parametrize("name", JS_FIXTURES + PY_FIXTURES)
    def test_the_proof_fails_on_the_original_and_passes_on_the_repair(self, name, tmp_path):
        if name.startswith("js-") and shutil.which("node") is None:
            pytest.skip("the Node harness runs under node")
        directory, fixture, snapshot, finding, language = _fixture(name)
        proof = generate_proof(snapshot, finding, PASSWORD_HASHING, language)
        assert isinstance(proof, GeneratedProof), getattr(proof, "reason", None)
        original = _run_proof(tmp_path / "original", _workspace(directory, fixture, snapshot.full_content(fixture["source"])), proof)
        assert original.returncode == 1, original.stdout + original.stderr
        assert "per-call salt" in original.stderr
        repaired_text = (directory / fixture["reference_repair"]).read_text(encoding="utf-8")
        repaired = _run_proof(tmp_path / "repaired", _workspace(directory, fixture, repaired_text), proof)
        assert repaired.returncode == 0, repaired.stdout + repaired.stderr

    @requires_node
    def test_a_salted_repair_that_still_digests_the_password_fails_the_recorder(self, request_payload, tmp_path):
        """Salting is not the whole repair: `md5(salt + password)` differs per call and would
        pass a test that only compared two hashes."""
        snapshot, finding = _snapshot(request_payload, {"auth.js": JS_MODULE}, {"rule_id": "cwe-916.js-password-weak-hash", "cwe_id": "CWE-916", "file_path": "auth.js", "line_start": 4, "line_end": 4})
        proof = generate_proof(snapshot, finding, PASSWORD_HASHING, JAVASCRIPT)
        salted = """const crypto = require('crypto');

function hashPassword(password) {
  const salt = crypto.randomBytes(8).toString('hex');
  return salt + ':' + crypto.createHash('md5').update(salt + password).digest('hex');
}

function verifyPassword(password, stored) {
  const [salt, digest] = stored.split(':');
  return crypto.createHash('md5').update(salt + password).digest('hex') === digest;
}

module.exports = { hashPassword, verifyPassword };
"""
        result = _run_proof(tmp_path, {"auth.js": salted}, proof)
        assert result.returncode == 1
        assert "fast hash" in result.stderr

    def test_a_repair_that_breaks_verification_fails_the_proof(self, request_payload, tmp_path):
        snapshot, finding = _snapshot(request_payload, {"auth.py": PY_MODULE}, {"rule_id": "cwe-327.weak-hash-password", "cwe_id": "CWE-916", "file_path": "auth.py", "line_start": 5, "line_end": 5})
        proof = generate_proof(snapshot, finding, PASSWORD_HASHING, PYTHON)
        broken = """import hashlib
import os


def hash_password(password):
    return hashlib.scrypt(password.encode(), salt=os.urandom(16), n=2**14, r=8, p=1).hex()


def verify_password(password, stored):
    return hash_password(password) == stored
"""
        result = _run_proof(tmp_path, {"auth.py": broken}, proof)
        assert result.returncode == 1
        assert "right password to verify" in result.stderr

    def test_the_negative_fixture_is_gated(self):
        _directory, fixture, snapshot, finding, language = _fixture("js-password-lookup")
        assert fixture["kind"] == "negative"
        assert static_gate(snapshot, finding, PASSWORD_HASHING, language)[0] == "password_hash_used_for_lookup"

    @pytest.mark.parametrize("name", JS_FIXTURES + PY_FIXTURES + ["js-password-lookup"])
    def test_the_fixture_declares_the_family(self, name):
        fixture = json.loads((FIXTURES / name / "fixture.json").read_text(encoding="utf-8"))
        assert fixture["family"] == PASSWORD_HASHING
