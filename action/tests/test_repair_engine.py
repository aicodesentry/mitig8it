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
