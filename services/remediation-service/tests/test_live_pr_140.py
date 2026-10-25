"""The five findings nebullii/test-only#140 published without a suggestion block.

The live run (deployed App, and the Action built from live/trust-2026-10-24) produced two fixes
for eight findings. The files are kept under tests/fixtures/live/pr140 exactly as the pull
request had them. Each test below is one of the reasons a finding got no fix, driven through the
same proof generator, template and local sandbox verifier the Action runs:

- web/pricing.js requires './db', and the repository has no db.js. Every proof that loads the
  module failed on both trees, so the exec and path findings were reported as patches whose test
  "still fails". The proof is now refused by name, and with db.js present all three JavaScript
  findings the template covers verify.
- The eval sits in an Express route callback. The eval proof only drove a named function.
- orders/repository.py builds `tar czf /srv/archive/<name>.tgz`. The template's argv list keeps
  the value inside its argument, which is safe, and the proof asked for it to be its own element.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.families import COMMAND_ARGUMENTS, JAVASCRIPT, PYTHON, rule_family
from src.proofs import GeneratedProof, ProofFallback, generate_proof, proof_refusal_message
from src.templates import TemplatePatch, command_value_embedded
from tests.test_template_first import _generate, _outcomes, _request, _verify_templates

requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="the Node harness runs under node")
requires_python = pytest.mark.skipif(shutil.which("python3") is None, reason="the Python harness runs under python3")

LIVE = Path(__file__).resolve().parent / "fixtures" / "live" / "pr140"
PRICING_JS = (LIVE / "web" / "pricing.js").read_text(encoding="utf-8")
REPOSITORY_PY = (LIVE / "orders" / "repository.py").read_text(encoding="utf-8")
# What a repository that has the module would carry. The query callback is never reached by the
# three findings proven here; it only has to load.
DB_JS = "module.exports = { query(text, cb) { if (cb) cb(null, []); } };\n"

PRICING_FINDINGS = [
    {"snapshot_id": "sql-11", "rule_id": "opengrep.cwe-89.js-query-string-concat", "cwe_id": "CWE-89", "file_path": "web/pricing.js", "line_start": 11, "line_end": 11},
    {"snapshot_id": "eval-19", "rule_id": "code.injection.eval", "cwe_id": "CWE-95", "file_path": "web/pricing.js", "line_start": 19, "line_end": 19},
    {"snapshot_id": "exec-24", "rule_id": "opengrep.cwe-78.child-process-exec", "cwe_id": "CWE-78", "file_path": "web/pricing.js", "line_start": 24, "line_end": 24},
    {"snapshot_id": "path-31", "rule_id": "opengrep.cwe-22.path-traversal-fs", "cwe_id": "CWE-22", "file_path": "web/pricing.js", "line_start": 31, "line_end": 31},
]
ARCHIVE_FINDING = {
    "snapshot_id": "cmd-17", "rule_id": "opengrep.cwe-78.command-injection-input", "cwe_id": "CWE-78",
    "file_path": "orders/repository.py", "line_start": 17, "line_end": 17,
}


# --- the module the route file requires is not in the repository -----------------------------


def test_a_proof_for_a_module_whose_local_require_is_missing_is_refused_by_name():
    request = _request([("web/pricing.js", PRICING_JS)], PRICING_FINDINGS[1:])
    _snapshot, proofs, _templates = _generate(request)
    for finding_id in ("eval-19", "exec-24", "path-31"):
        assert isinstance(proofs[finding_id], ProofFallback), finding_id
        assert proofs[finding_id].reason == "local_module_missing:./db"


def test_the_refusal_reads_as_a_sentence_that_names_the_module():
    message = proof_refusal_message("local_module_missing:./db")
    assert "./db" in message and "not in the repository" in message


@requires_node
@pytest.mark.asyncio
async def test_with_the_module_present_eval_exec_and_path_each_fail_before_and_pass_after():
    request = _request([("web/pricing.js", PRICING_JS), ("web/db.js", DB_JS)], PRICING_FINDINGS[1:])
    _snapshot, proofs, templates = _generate(request)
    for finding_id in ("eval-19", "exec-24", "path-31"):
        assert isinstance(proofs[finding_id], GeneratedProof), getattr(proofs[finding_id], "reason", None)
        assert isinstance(templates[finding_id], TemplatePatch), getattr(templates[finding_id], "reason", None)
    bundle, verification = await _verify_templates(request)
    assert verification.status == "passed", verification.reason_code
    assert set(verification.proven_finding_ids) == {"eval-19", "exec-24", "path-31"}
    assert set(_outcomes(verification).values()) == {("failed", "passed")}
    fixed = bundle.patches[0].replacement_content
    assert "const result = JSON.parse(formula);" in fixed
    assert "execFile('lpr', ['-P', 'labels', req.query.file]" in fixed


# --- eval inside an Express route callback -----------------------------------------------------


def test_an_eval_in_a_route_callback_is_driven_through_the_route():
    request = _request([("web/pricing.js", PRICING_JS), ("web/db.js", DB_JS)], [PRICING_FINDINGS[1]])
    _snapshot, proofs, _templates = _generate(request)
    proof = proofs["eval-19"]
    assert isinstance(proof, GeneratedProof), getattr(proof, "reason", None)
    assert 'h.invoke(app, "get", "/rule", { query: { "formula": payload } })' in proof.content
    assert "h.assert.noCode();" in proof.content


# --- a value inside a larger argument ----------------------------------------------------------


def test_the_archive_command_puts_the_value_inside_an_argument():
    assert command_value_embedded(REPOSITORY_PY, 17, PYTHON) is True
    # `'lpr -P labels ' + file`: the value is a whole argument, so the stricter assertion holds.
    assert command_value_embedded(PRICING_JS, 24, JAVASCRIPT) is False


@requires_python
@pytest.mark.asyncio
async def test_a_python_command_with_the_value_inside_an_argument_is_proven():
    request = _request([("orders/repository.py", REPOSITORY_PY)], [ARCHIVE_FINDING])
    _snapshot, proofs, _templates = _generate(request)
    assert "h.assert_argv_embedded(h.subprocess.calls[0], payload)" in proofs["cmd-17"].content
    bundle, verification = await _verify_templates(request)
    assert 'subprocess.run(["tar", "czf", f"/srv/archive/{report_name}.tgz", f"/srv/exports/{report_name}"])' in bundle.patches[0].replacement_content
    assert verification.status == "passed", verification.reason_code
    assert _outcomes(verification)["cmd-17"] == ("failed", "passed")


TAR_JS = (
    "const { exec } = require('child_process');\n"
    "\n"
    "function archive(name, cb) {\n"
    "  exec('tar czf /srv/archive/' + name + '.tgz /srv/exports', cb);\n"
    "}\n"
    "\n"
    "module.exports = { archive };\n"
)


@requires_node
@pytest.mark.asyncio
async def test_a_javascript_command_with_the_value_inside_an_argument_is_proven():
    finding = {"snapshot_id": "tar-4", "rule_id": "opengrep.cwe-78.child-process-exec", "cwe_id": "CWE-78", "file_path": "archive.js", "line_start": 4, "line_end": 4}
    request = _request([("archive.js", TAR_JS)], [finding])
    _snapshot, proofs, _templates = _generate(request)
    assert "h.assert.argvEmbedded(h.child_process.calls[0], payload)" in proofs["tar-4"].content
    bundle, verification = await _verify_templates(request)
    assert "execFile('tar', ['czf', `/srv/archive/${name}.tgz`, '/srv/exports'], cb);" in bundle.patches[0].replacement_content
    assert verification.status == "passed", verification.reason_code
    assert _outcomes(verification)["tar-4"] == ("failed", "passed")


# --- every posting tier 2 rule in the four injection CWEs resolves to a repair family ----------

RULES_DIR = Path(__file__).resolve().parents[2] / "analysis-service" / "src" / "opengrep_rules"
CWE_FAMILY = {"CWE-89": "sql_parameterization", "CWE-78": "command_arguments", "CWE-22": "path_containment", "CWE-95": "code_injection_eval"}


def _posting_injection_rules():
    yaml = pytest.importorskip("yaml")
    rules = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]:
            metadata = rule.get("metadata") or {}
            cwe = str(metadata.get("cwe") or "").split(":")[0].strip()
            posting = str(metadata.get("posting") or "post").strip().lower()
            if cwe in CWE_FAMILY and posting == "post":
                rules.append((path.name, rule["id"], cwe, metadata))
    return rules


def test_every_posting_injection_rule_resolves_to_its_repair_family():
    rules = _posting_injection_rules()
    assert len(rules) > 20, "the rule files were not found"
    wrong = []
    for name, rule_id, cwe, metadata in rules:
        expected = metadata.get("family") or CWE_FAMILY[cwe]
        # The analysis service reports a tier 2 finding as `opengrep.<id>` with the rule's CWE and
        # internal type; nothing else about it is guaranteed.
        finding = SimpleNamespace(
            rule_id=f"opengrep.{rule_id}", cwe_id=cwe, category="", title="", message="",
            internal_type=metadata.get("internal_type") or "",
        )
        if rule_family(finding) != expected:
            wrong.append(f"{name}:{rule_id} -> {rule_family(finding)} (expected {expected})")
    assert not wrong, wrong
