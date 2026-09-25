"""What the action hands github-service for each repaired finding.

A section without a `hunk` cannot become a suggestion block: `suggestionFor` in
githubInternalOperations.js returns `no_line_change` and the comment falls back to a fenced diff.
The action filled `unified_diff` and never `hunk`, so the one fix the September trial produced was
published as a diff nobody could click. These tests pin the section shape rather than the
rendering, because the rendering is the service's and already has its own tests.

They build the engine's response shape by hand instead of running the engine, so they run on a
bare checkout as well as inside the image.
"""
from __future__ import annotations

from types import SimpleNamespace

from orchestrator import remediation, run

SETTINGS_ORIGINAL = (
    "from pathlib import Path\n"
    "\n"
    "BASE_DIR = Path(__file__).resolve().parent.parent\n"
    "\n"
    "SECRET_KEY = 'django-insecure-9a$k2!f3@x0z^1v8p&q7'\n"
    "\n"
    "DEBUG = True\n"
)
SETTINGS_FIXED = SETTINGS_ORIGINAL.replace(
    "SECRET_KEY = 'django-insecure-9a$k2!f3@x0z^1v8p&q7'",
    "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']",
)

PING_ORIGINAL = (
    "const express = require('express');\n"
    "const app = express();\n"
    "\n"
    "app.get('/ping', (req, res) => {\n"
    "  exec('ping -c 2 ' + req.query.host, (err, out) => res.send(out));\n"
    "});\n"
)
PING_FIXED = (
    "const express = require('express');\n"
    "const { execFile } = require('child_process');\n"
    "const app = express();\n"
    "\n"
    "app.get('/ping', (req, res) => {\n"
    "  execFile('ping', ['-c', '2', req.query.host], (err, out) => res.send(out));\n"
    "});\n"
)


def candidate(changes, finding_ids=("fp-1",), evidence=None):
    return SimpleNamespace(
        candidate_id="cand-1",
        finding_ids=list(finding_ids),
        intended_behavior="Read the secret from the environment.",
        preview={
            "changes": changes,
            "evidence": evidence
            if evidence is not None
            else {
                "verification_level": "development_unverified",
                "limitations": ["the sandbox is this container"],
                "summary": ["Regression test tests/test_secret.py: failed, then passed."],
                "evidence_digest": "abcdef0123456789",
                "generated_tests": [{"path": "tests/test_secret.py", "finding_id": "fp-1"}],
            },
        },
    )


def change(path, original, replacement, diff="--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new\n"):
    return {"path": path, "original": original, "replacement": replacement, "unified_diff": diff}


PYGOAT_FINDING = {
    "fingerprint": "fp-1",
    "rule_id": "cwe-798.py-framework-secret-key-literal",
    "title": "Django SECRET_KEY is a literal",
    "file_path": "pygoat/settings.py",
    "line_start": 5,
    "severity": "critical",
}


def test_a_single_region_fix_carries_a_hunk():
    """The pygoat SECRET_KEY shape: one line replaced, so one suggestion on that line."""
    response = SimpleNamespace(
        candidates=[candidate([change("pygoat/settings.py", SETTINGS_ORIGINAL, SETTINGS_FIXED)])]
    )
    sections = remediation.fix_sections(response, {"fp-1": PYGOAT_FINDING})
    assert len(sections) == 1
    section = sections[0]
    assert section["not_suggestable_reason"] == ""
    assert section["hunk"] == {
        "start_line": 5,
        "end_line": 5,
        "original_lines": ["SECRET_KEY = 'django-insecure-9a$k2!f3@x0z^1v8p&q7'"],
        "replacement_lines": ["SECRET_KEY = os.environ['DJANGO_SECRET_KEY']"],
    }
    assert section["extra_hunks"] == []
    assert section["verification_level"] == "development_unverified"


def test_a_two_region_fix_keeps_one_hunk_and_carries_the_other():
    """The App publishes the finding's region inline and the rest as extra hunks."""
    finding = {
        "fingerprint": "fp-1",
        "rule_id": "cwe-78.child-process-exec",
        "title": "Command injection",
        "file_path": "routes/ping.js",
        "line_start": 5,
        "severity": "critical",
    }
    response = SimpleNamespace(
        candidates=[candidate([change("routes/ping.js", PING_ORIGINAL, PING_FIXED)])]
    )
    section = remediation.fix_sections(response, {"fp-1": finding})[0]
    assert section["not_suggestable_reason"] == ""
    assert section["hunk"]["start_line"] == 5
    assert "execFile(" in section["hunk"]["replacement_lines"][0]
    assert len(section["extra_hunks"]) == 1
    assert "require('child_process')" in "\n".join(section["extra_hunks"][0]["replacement_lines"])


def test_a_fix_in_another_file_says_so_rather_than_suggesting_the_wrong_lines():
    response = SimpleNamespace(
        candidates=[candidate([change("other/file.py", SETTINGS_ORIGINAL, SETTINGS_FIXED)])]
    )
    section = remediation.fix_sections(response, {"fp-1": PYGOAT_FINDING})[0]
    assert section["hunk"] is None
    assert section["not_suggestable_reason"] == "changes_other_file"


def test_a_multi_file_fix_is_shown_as_a_diff():
    response = SimpleNamespace(
        candidates=[
            candidate(
                [
                    change("pygoat/settings.py", SETTINGS_ORIGINAL, SETTINGS_FIXED),
                    change("pygoat/other.py", "a\n", "b\n"),
                ]
            )
        ]
    )
    section = remediation.fix_sections(response, {"fp-1": PYGOAT_FINDING})[0]
    assert section["hunk"] is None
    assert section["not_suggestable_reason"] == "multiple_files"


def test_a_change_that_changes_nothing_reports_no_line_change():
    response = SimpleNamespace(
        candidates=[candidate([change("pygoat/settings.py", SETTINGS_ORIGINAL, SETTINGS_ORIGINAL)])]
    )
    section = remediation.fix_sections(response, {"fp-1": PYGOAT_FINDING})[0]
    assert section["hunk"] is None
    assert section["not_suggestable_reason"] == "no_line_change"


def test_proof_and_evidence_come_from_the_keys_the_app_reads():
    """`evidence.summary` is a list. Rendered into `proof` it reached GitHub as a Python repr."""
    response = SimpleNamespace(
        candidates=[candidate([change("pygoat/settings.py", SETTINGS_ORIGINAL, SETTINGS_FIXED)])]
    )
    section = remediation.fix_sections(response, {"fp-1": PYGOAT_FINDING})[0]
    assert not section["proof"].startswith("[")
    assert "tests/test_secret.py" in section["proof"]
    assert section["evidence"] == [
        "Regression test tests/test_secret.py: failed, then passed.",
        "Evidence digest: abcdef012345.",
    ]


def test_the_hunk_survives_the_publish_envelope():
    """github-service validates the section it receives; a hunk it rejects is a hunk lost."""
    response = SimpleNamespace(
        candidates=[candidate([change("pygoat/settings.py", SETTINGS_ORIGINAL, SETTINGS_FIXED)])]
    )
    sections = remediation.fix_sections(response, {"fp-1": PYGOAT_FINDING})
    request = run.build_publish_request(
        token="t",
        repository="acme/widgets",
        pr_number=7,
        head_sha="a" * 40,
        base_sha="b" * 40,
        installation_id=1,
        actor_login="octocat",
        counts={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        findings=1,
        fix_sections=sections,
        inline_comments=[],
        model_configured=False,
        conclusion="neutral",
    )
    sent = request["fix_sections"][0]
    assert sent["hunk"]["start_line"] == 5
    assert len(request["manifest_digest"]) == 64
