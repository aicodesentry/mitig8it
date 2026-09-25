"""The repair engine, driven the way the action drives it.

The case that matters most is a run with no model key. The engine builds its agent before the
template pass, so an engine left to construct its own aborts the whole request the moment it
finds no key, and no template ever runs. The action passes an agent whose provider abstains
precisely to avoid that, and this file is what keeps it true.

Skipped where the remediation service's dependencies are absent, which is the case in a bare
checkout. Inside the action's image they are always present, so the container build runs it.
"""
from __future__ import annotations

import shutil

import pytest

from orchestrator import remediation

SRC = (
    "import sqlite3\n"
    "\n"
    "\n"
    "def report(conn, name):\n"
    "    return conn.execute(\"SELECT * FROM reports WHERE name = '\" + name + \"'\").fetchall()\n"
)

SQL_FINDING = {
    "fingerprint": "fp-sql",
    "rule_id": "sql.injection.raw_query",
    "cwe_id": "CWE-89",
    "category": "sql injection",
    "title": "SQL injection",
    "description": "User input reaches a query.",
    "file_path": "src/reports.py",
    "line_start": 4,
    "line_end": 4,
    "severity": "high",
}

UNSUPPORTED_FINDING = {
    "fingerprint": "fp-null",
    "rule_id": "null.pointer.deref",
    "cwe_id": "CWE-476",
    "category": "null pointer",
    "title": "Null dereference",
    "description": "",
    "file_path": "src/reports.py",
    "line_start": 4,
    "line_end": 4,
    "severity": "medium",
}


@pytest.fixture(autouse=True)
def engine_available():
    try:
        remediation._modules()
    except Exception as error:  # noqa: BLE001
        pytest.skip(f"the remediation service is not importable here: {error}")


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_BROKER_MODE", "inprocess")
    monkeypatch.setenv("SANDBOX_DRIVER", "local")
    monkeypatch.setenv("SANDBOX_LOCAL_WORKSPACE_ROOT", str(tmp_path / "sandbox"))
    (tmp_path / "sandbox").mkdir()
    # The local driver runs the repository's checks as subprocesses, so it needs a Node runtime.
    if not shutil.which("node"):
        pytest.skip("node is not on PATH")


def build(findings, files=None):
    from src.digests import git_blob_sha1  # noqa: PLC0415

    files = files or {"src/reports.py": SRC}
    entries = [
        {"path": path, "mode": "100644", "type": "blob", "sha": git_blob_sha1(text.encode("utf-8"))}
        for path, text in files.items()
    ]
    return remediation.build_request(
        repository_full_name="acme/widgets",
        pull_request_number=42,
        head_sha="a" * 40,
        base_sha="b" * 40,
        findings=findings,
        files=files,
        tree_entries=entries,
        tree_truncated=False,
        model_configured=False,
    )


def test_only_findings_with_a_supported_family_are_sent_for_repair():
    supported = remediation.supported_findings([SQL_FINDING, UNSUPPORTED_FINDING])
    assert [f["fingerprint"] for f in supported] == ["fp-sql"]


def test_findings_are_ranked_most_severe_first():
    ranked = remediation.rank_findings([UNSUPPORTED_FINDING, SQL_FINDING])
    assert [f["fingerprint"] for f in ranked] == ["fp-sql", "fp-null"]


def test_the_request_declares_the_verification_it_can_actually_achieve():
    """The runner is not an isolated sandbox, and the policy must say so or the engine refuses."""
    request = build([SQL_FINDING])
    assert request.policy.allow_development_verification is True
    assert request.policy.sandbox_image_digest is None
    assert request.policy.input_usd_per_million_tokens > 0, (
        "the engine refuses a request it cannot cost, even when nothing is spent"
    )


def test_the_request_carries_no_model_version_when_no_key_was_given():
    assert "repair_model" not in build([SQL_FINDING]).versions


def test_a_run_without_a_model_key_reaches_the_template_pass(sandbox):
    """The regression this file exists for: no key must not abort before templates run.

    An engine left to build its own agent raises on the missing key and returns
    `runtime_prerequisite_missing` before a single template is tried. With the abstaining
    provider it gets all the way through the template pass and then declines the agent turn, so
    the evidence carries the template and proof records and the reason is our own abstention.
    """
    response = remediation.repair(build([SQL_FINDING]), model_configured=False)

    reason = (response.reason or {}).get("code")
    assert reason != "runtime_prerequisite_missing", (
        "the engine aborted before the template pass, which is exactly what the abstaining "
        "provider exists to prevent"
    )
    assert response.state in {"ready", "unsupported", "inconclusive"}

    evidence = response.evidence or {}
    assert "templates" in evidence, "the template pass did not run"
    assert "proofs" in evidence, "no regression proof was built, so templates had nothing to prove"

    if reason is not None:
        assert reason == "model_not_configured", (
            f"a keyless run should decline as model_not_configured, not {reason!r}"
        )


def test_no_model_is_contacted_without_a_key(sandbox, monkeypatch):
    """A provider that reached the network would be a promise broken, so it must not exist."""
    import src.agent.provider as provider_module  # noqa: PLC0415

    def explode(*_args, **_kwargs):
        raise AssertionError("the action built a real model provider without a key")

    monkeypatch.setattr(provider_module.OpenAICompatibleProvider, "from_env", explode)
    remediation.repair(build([SQL_FINDING]), model_configured=False)


def test_any_candidate_produced_is_labelled_development_unverified(sandbox):
    """Nothing in this container is isolated, so nothing may claim an isolated sandbox."""
    response = remediation.repair(build([SQL_FINDING]), model_configured=False)
    for candidate in response.candidates or []:
        level = (candidate.preview.get("evidence") or {}).get("verification_level")
        assert level == "development_unverified", (
            f"a candidate claimed {level!r} in a runner with no isolation"
        )


def test_fix_sections_carry_the_level_through_to_the_publisher(sandbox):
    """The Verified line the reader sees is driven by this field, so it must not be blank."""
    response = remediation.repair(build([SQL_FINDING]), model_configured=False)
    sections = remediation.fix_sections(response, {"fp-sql": SQL_FINDING})
    assert len(sections) == len(response.candidates or [])
    for section in sections:
        assert section["verification_level"] == "development_unverified"
        assert section["path"] == "src/reports.py"
        assert section["finding_fingerprint"] == "fp-sql"


# --- JavaScript --------------------------------------------------------------------------
#
# The Python case above ran on Node 20 as well, because a Python repair never loads the
# sandbox harness's TypeScript path. JavaScript did not, and nothing in this suite noticed:
# the September 2026 trial produced zero fixes on four JavaScript repositories, including
# findings in the supported `command_arguments` family, and the only trace was one ERROR
# line in a run log. This is the same shape as the `js-command-exec-template` benchmark
# fixture, inlined rather than read from `benchmarks/`, because the image does not carry
# that directory and this has to run inside the image to prove anything.

JS_SRC = (
    "const { exec } = require('node:child_process');\n"
    "\n"
    "function fetchAuthorLog(author, callback) {\n"
    "  return exec(`git log --author=${author} --oneline -n 20`, callback);\n"
    "}\n"
    "\n"
    "module.exports = { fetchAuthorLog };\n"
)

JS_PACKAGE = (
    "{\n"
    '  "name": "action-js-repair",\n'
    '  "version": "0.0.0",\n'
    '  "private": true,\n'
    '  "dependencies": {}\n'
    "}\n"
)

JS_FINDING = {
    "fingerprint": "fp-cmd",
    "rule_id": "cwe-78.child-process-exec",
    "cwe_id": "CWE-78",
    "category": "command injection",
    "title": "Command injection",
    "description": "The author name is interpolated into a template literal handed to exec.",
    "file_path": "app.js",
    "line_start": 4,
    "line_end": 4,
    "severity": "critical",
}


def test_a_javascript_finding_is_in_a_supported_repair_family():
    supported = remediation.supported_findings([JS_FINDING])
    assert [f["fingerprint"] for f in supported] == ["fp-cmd"], (
        "command_arguments on JavaScript is one of the five documented families"
    )


def test_a_javascript_repair_runs_its_verification_in_this_runtime(sandbox):
    """The runtime proof: the engine must reach a verdict rather than refuse the runtime.

    On the Node the image used to pin, this request came back with the harness reporting that
    the runtime lacked `module.stripTypeScriptTypes` and `module.registerHooks`. What is
    asserted here is that no such refusal is reported: a candidate is the good outcome and an
    honest `unsupported` is an acceptable one, but a runtime prerequisite is not.
    """
    request = build([JS_FINDING], files={"app.js": JS_SRC, "package.json": JS_PACKAGE})
    response = remediation.repair(request, model_configured=False)

    reason = (response.reason or {}).get("code")
    assert reason != "runtime_prerequisite_missing", (
        "the engine refused the Node runtime, which is what pinning the remediation "
        "service's NODE_VERSION in action/Dockerfile exists to prevent"
    )
    rendered = repr(response.evidence or {}) + repr(response.reason or {})
    for missing in ("stripTypeScriptTypes", "registerHooks", "--experimental-strip-types"):
        assert missing not in rendered, (
            f"the sandbox harness reported {missing} unavailable in this runtime"
        )
    assert response.state in {"ready", "unsupported", "inconclusive"}


JS_CREDENTIAL_SRC = (
    "// Client for the vendor billing API.\n"
    'const apiKey = "sk-live-7f3a91bc44de2210";\n'
    "\n"
    "function authHeaders() {\n"
    "  return { Authorization: `Bearer ${apiKey}` };\n"
    "}\n"
    "\n"
    "module.exports = { apiKey, authHeaders };\n"
)

JS_CREDENTIAL_FINDING = {
    "fingerprint": "fp-jssecret",
    "rule_id": "cwe-798.js-credential-constant",
    "cwe_id": "CWE-798",
    "category": "hardcoded secrets",
    "title": "Hardcoded API key",
    "description": "A vendor API key literal in the source.",
    "file_path": "app.js",
    "line_start": 2,
    "line_end": 2,
    "severity": "critical",
}


def test_a_javascript_repair_produces_a_clickable_suggestion(sandbox):
    """One whole JavaScript repair, end to end, in the runtime the action ships.

    The `js-hardcoded-secret` benchmark fixture's shape, inlined because the image does not
    carry `benchmarks/`. This is the fixture repair that proves the Node pin: the candidate is
    verified in this container, it comes back `development_unverified` because nothing here is
    isolated, and `fix_sections` turns it into a hunk github-service can render as a suggestion
    block rather than the diff the trial saw.
    """
    request = build(
        [JS_CREDENTIAL_FINDING],
        files={"app.js": JS_CREDENTIAL_SRC, "package.json": JS_PACKAGE},
    )
    response = remediation.repair(request, model_configured=False)
    assert response.state == "ready", f"no verified JavaScript repair: {response.reason}"
    assert response.candidates, "a ready response carried no candidate"

    sections = remediation.fix_sections(response, {"fp-jssecret": JS_CREDENTIAL_FINDING})
    assert len(sections) == len(response.candidates)
    section = sections[0]
    assert section["verification_level"] == "development_unverified"
    assert section["not_suggestable_reason"] == ""
    assert section["hunk"] is not None, (
        "the section came back without a hunk, so github-service would render a diff "
        "instead of a suggestion"
    )
    assert section["hunk"]["start_line"] == 2
    assert section["hunk"]["end_line"] == 2
    assert "sk-live-" not in "\n".join(section["hunk"]["replacement_lines"])
