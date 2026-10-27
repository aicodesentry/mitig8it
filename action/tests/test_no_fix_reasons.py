"""Every finding the action publishes without a suggestion carries a one-line reason.

On nebullii/test-only#140 the action built its fix sections from the engine's candidates only,
so a finding the engine skipped, a finding outside every repair family, and a finding in a group
that proved nothing were all published with no fix and no word about why. The App reads the
same reasons from the engine's `skipped` list and renders them through github-service as
`No automatic fix: <reason>`; the action now sends the same sections.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from orchestrator import remediation, run


def finding(fingerprint, *, rule_id="opengrep.cwe-78.child-process-exec", cwe_id="CWE-78", path="web/pricing.js", line=24, severity="critical", **extra):
    return {
        "fingerprint": fingerprint,
        "rule_id": rule_id,
        "cwe_id": cwe_id,
        "category": "command injection",
        "title": "Command injection",
        "description": "",
        "file_path": path,
        "line_start": line,
        "line_end": line,
        "severity": severity,
        **extra,
    }


EXEC = finding("fp-exec")
EVAL = finding("fp-eval", rule_id="code.injection.eval", cwe_id="CWE-95", line=19)
XSS = finding("fp-xss", rule_id="js.xss.res-send", cwe_id="CWE-79", line=8, category="cross-site scripting", title="Reflected XSS")
IN_TEST = finding("fp-test", path="test/pricing.test.js", severity="info")


@pytest.fixture(autouse=True)
def engine_available():
    try:
        remediation._modules()
    except Exception as error:  # noqa: BLE001
        pytest.skip(f"the remediation service is not importable here: {error}")


def test_a_skipped_finding_gets_the_engine_reason():
    sections = remediation.no_fix_sections(
        [EXEC], [], skipped=[{"finding_id": "fp-exec", "code": "local_module_missing:./db", "message": "No regression test could be generated."}],
        fallback="unused",
    )
    assert sections == [
        {
            "finding_fingerprint": "fp-exec",
            "candidate_id": "",
            "path": "web/pricing.js",
            "finding_line": 24,
            "hunk": None,
            "extra_hunks": [],
            "unified_diff": "",
            "not_suggestable_reason": "",
            "skipped_reason": "No regression test could be generated.",
            "finding_ids": ["fp-exec"],
        }
    ]


def test_a_finding_with_a_candidate_section_gets_no_second_line():
    published = [{"finding_fingerprint": "fp-exec", "candidate_id": "cand-1"}]
    assert remediation.no_fix_sections([EXEC], published, skipped=[], fallback="x") == []


def test_a_finding_outside_every_family_says_so():
    [section] = remediation.no_fix_sections([XSS], [], skipped=[], fallback="x")
    assert section["skipped_reason"] == "This finding is outside the enabled repair families."


def test_a_finding_the_engine_said_nothing_about_gets_the_run_reason():
    [section] = remediation.no_fix_sections([EVAL], [], skipped=[], fallback="No verified repair was produced.")
    assert section["skipped_reason"] == "No verified repair was produced."


def test_an_informational_finding_is_not_repaired_and_gets_no_line():
    # The App leaves test-code findings out of repair entirely; so does the action.
    assert remediation.no_fix_sections([IN_TEST], [], skipped=[], fallback="x") == []


class TruncatedTreeReader:
    def git_tree(self, head_sha):
        return {"truncated": True, "tree": []}

    def file_contents(self, paths, ref):  # pragma: no cover - never reached
        raise AssertionError("nothing is fetched for a truncated tree")


def test_a_run_that_could_not_repair_still_says_why(monkeypatch):
    monkeypatch.setattr(run, "annotate", lambda *a, **k: None)
    sections = run.generate_fixes(
        reader=TruncatedTreeReader(),
        repository="acme/widgets",
        pr_number=1,
        head_sha="a" * 40,
        base_sha="b" * 40,
        findings=[EXEC, XSS],
        contents={"web/pricing.js": "exec('lpr ' + x);\n"},
        model_configured=False,
    )
    reasons = {section["finding_fingerprint"]: section["skipped_reason"] for section in sections}
    assert reasons["fp-xss"] == "This finding is outside the enabled repair families."
    assert "too large" in reasons["fp-exec"]


def test_only_sections_with_a_candidate_count_as_fixes():
    sections = [
        {"finding_fingerprint": "fp-1", "candidate_id": "cand-1", "path": "a.py", "unified_diff": "d"},
        {"finding_fingerprint": "fp-2", "candidate_id": "", "path": "b.py", "unified_diff": "", "skipped_reason": "why"},
    ]
    request = run.build_publish_request(
        token="t", repository="acme/widgets", pr_number=7, head_sha="a" * 40, base_sha="b" * 40,
        installation_id=1, actor_login="octocat", counts={"critical": 2, "high": 0, "medium": 0, "low": 0, "info": 0},
        findings=2, fix_sections=sections, inline_comments=[], model_configured=False, conclusion="neutral",
        action_id="action-1",
    )
    assert request["fixes"] == 1
    assert len(request["fix_sections"]) == 2
    # The manifest binds the fixes, not the reasons: adding a reason line changes no digest.
    assert request["manifest_digest"] == run.manifest_digest("action-1", "a" * 40, "b" * 40, sections[:1])


def test_the_local_modules_a_changed_file_loads_are_added_to_the_request():
    # A proof loads the whole module, so a sibling the pull request did not change has to be in
    # the snapshot or the load fails on both trees.
    tree = {"web/pricing.js", "web/db.js", "web/pool.js", "web/unused.js"}
    repository = {
        "web/db.js": "const pool = require('./pool');\nmodule.exports = pool;\n",
        "web/pool.js": "module.exports = {};\n",
    }
    asked = []

    def fetch(paths):
        asked.append(sorted(paths))
        return {path: repository[path] for path in paths if path in repository}

    files = remediation.with_local_imports(
        {"web/pricing.js": "const db = require('./db');\nfunction f() {\n  return require('./unused');\n}\n"}, tree, fetch
    )
    assert sorted(files) == ["web/db.js", "web/pool.js", "web/pricing.js"]
    assert asked == [["web/db.js"], ["web/pool.js"]]
