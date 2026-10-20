"""A finding the action cannot fix says why, under its own comment, in the App's words.

The App publishes each engine skip record as a section whose `skipped_reason` github-service
renders as "No automatic fix: <reason>" (`buildSkippedSection` in githubInternalOperations.js).
The action dropped `response.skipped`, and never asked about findings outside the engine's
families, so on the live PR the comments of five of seven supported findings said nothing about a
fix at all. These tests pin the sections the action now sends; the rendering is the service's.
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from orchestrator import remediation, run

ROOT = Path(__file__).resolve().parents[2]
OPERATIONS = ROOT / "services/github-service/src/services/githubInternalOperations.js"
INLINE_FIXES = ROOT / "services/api-service/src/services/remediationInlineFixes.js"

EVAL_FINDING = {
    "fingerprint": "fp-eval",
    "rule_id": "code.injection.eval",
    "title": "Code injection via eval",
    "file_path": "assistant/agent.py",
    "line_start": 13,
    "severity": "critical",
}
SECRET_FINDING = {
    "fingerprint": "fp-secret",
    "rule_id": "cwe-798.js-credential-config-key",
    "title": "Hardcoded credential",
    "file_path": "web/config.js",
    "line_start": 3,
    "severity": "critical",
}
REDIRECT_FINDING = {
    "fingerprint": "fp-redirect",
    "rule_id": "redirect.open",
    "title": "Open redirect",
    "file_path": "inventory/views.py",
    "line_start": 15,
    "severity": "medium",
}


def a_candidate(finding_id):
    return SimpleNamespace(
        candidate_id="cand-1",
        finding_ids=[finding_id],
        intended_behavior="Read the secret from the environment.",
        preview={
            "changes": [{"path": "web/config.js", "original": "a\nb\nc\n", "replacement": "a\nb\nC\n", "unified_diff": "--- a\n+++ b\n"}],
            "evidence": {"verification_level": "development_unverified"},
        },
    )


def test_a_skip_record_becomes_a_no_fix_section():
    response = SimpleNamespace(
        candidates=[a_candidate("fp-secret")],
        skipped=[{"finding_id": "fp-eval", "code": "model_authored_code", "message": "The code is text a language model returned."}],
        reason=None,
    )
    sections = remediation.fix_sections(response, {"fp-secret": SECRET_FINDING, "fp-eval": EVAL_FINDING})
    assert [section["finding_fingerprint"] for section in sections] == ["fp-secret", "fp-eval"]
    skipped = sections[1]
    assert skipped["skipped_reason"] == "The code is text a language model returned."
    assert skipped["candidate_id"] == "" and skipped["hunk"] is None and skipped["unified_diff"] == ""
    assert (skipped["path"], skipped["finding_line"], skipped["finding_ids"]) == ("assistant/agent.py", 13, ["fp-eval"])
    assert not sections[0].get("skipped_reason")


def test_a_finding_the_response_names_nowhere_gets_the_response_reason():
    response = SimpleNamespace(candidates=[], skipped=[], reason={"code": "invalid_git_tree", "message": "The tree did not match."})
    sections = remediation.fix_sections(response, {"fp-eval": EVAL_FINDING})
    assert [section["skipped_reason"] for section in sections] == ["The tree did not match."]


def test_a_finding_a_candidate_claims_is_not_also_reported_as_skipped():
    response = SimpleNamespace(
        candidates=[a_candidate("fp-secret")],
        skipped=[{"finding_id": "fp-secret", "code": "static_assertion_not_combined", "message": "dropped"}],
        reason=None,
    )
    sections = remediation.fix_sections(response, {"fp-secret": SECRET_FINDING})
    assert len(sections) == 1 and not sections[0].get("skipped_reason")


def test_the_skip_section_passes_github_service_validation_without_a_candidate():
    """`validateFixSection` only lets `candidate_id` be empty when `skipped_reason` is set."""
    source = OPERATIONS.read_text(encoding="utf-8")
    assert "candidate_id: skipped && !raw.candidate_id ? ''" in source
    assert "`No automatic fix: ${section.skipped_reason}`" in source
    section = remediation.skip_section(EVAL_FINDING, "fp-eval", "why")
    app_keys = set(re.findall(r"(\w+):", re.search(r"function emptySection\(finding\) \{\s*return \{(.*?)\};", INLINE_FIXES.read_text(encoding="utf-8"), re.S).group(1)))
    # The App's empty section, less the fields only the App fills: a finding body (the action
    # posts its own comments first), and the covered/superseded links between candidates.
    assert app_keys - {"finding_body", "covered_by", "superseded_by", "finding"} <= set(section)


def test_skip_sections_do_not_count_as_fixes_or_enter_the_manifest():
    fix = remediation.fix_sections(SimpleNamespace(candidates=[a_candidate("fp-secret")], skipped=[], reason=None), {"fp-secret": SECRET_FINDING})
    both = fix + [remediation.skip_section(EVAL_FINDING, "fp-eval", "why")]

    def request(sections):
        return run.build_publish_request(
            token="t", repository="acme/widgets", pr_number=7, head_sha="a" * 40, base_sha="b" * 40,
            installation_id=1, actor_login="octocat", counts={"critical": 2, "high": 0, "medium": 0, "low": 0, "info": 0},
            findings=2, fix_sections=sections, inline_comments=[], model_configured=False, conclusion="neutral", action_id="action-1",
        )

    assert request(both)["fixes"] == 1
    assert request(both)["manifest_digest"] == request(fix)["manifest_digest"]
    assert len(request(both)["fix_sections"]) == 2


def test_sections_are_bounded_with_fixes_kept_first():
    fixes = [{"candidate_id": f"c{i}", "skipped_reason": ""} for i in range(3)]
    reasons = [{"candidate_id": "", "skipped_reason": "why"} for _ in range(run.FIX_SECTION_LIMIT)]
    bounded = run.bounded_sections(reasons + fixes)
    assert len(bounded) == run.FIX_SECTION_LIMIT
    assert bounded[:3] == fixes


def test_the_publish_limit_is_github_service_s():
    match = re.search(r"const FIX_SECTION_LIMIT = (\d+);", OPERATIONS.read_text(encoding="utf-8"))
    assert match and int(match.group(1)) == run.FIX_SECTION_LIMIT


def test_merged_rule_ids_reach_the_engine():
    """The engine's model-output gates read which rule matched, and the survivor may be generic."""
    finding = dict(EVAL_FINDING, merged_rule_ids=["code.injection.eval", "opengrep.cwe-95.py-llm-output-code-execution"])
    assert remediation.merged_rule_ids(finding) == ["code.injection.eval", "opengrep.cwe-95.py-llm-output-code-execution"]
    nested = dict(EVAL_FINDING, evidence_details={"extra": {"merged_rule_ids": ["x"]}})
    assert remediation.merged_rule_ids(nested) == ["x"]
    assert remediation.merged_rule_ids(EVAL_FINDING) == []


@pytest.fixture
def engine():
    try:
        return remediation._modules()
    except Exception as error:  # noqa: BLE001
        pytest.skip(f"the remediation service is not importable here: {error}")


def test_a_finding_outside_every_family_gets_the_engine_s_sentence(engine):
    class NoReader:
        def git_tree(self, sha):  # pragma: no cover - must not be reached
            raise AssertionError("no repairable finding, so the tree is never read")

    sections = run.generate_fixes(
        reader=NoReader(), repository="acme/widgets", pr_number=7, head_sha="a" * 40, base_sha="b" * 40,
        findings=[REDIRECT_FINDING], contents={"inventory/views.py": "x = 1\n"}, model_configured=False,
    )
    assert sections == [remediation.skip_section(REDIRECT_FINDING, "fp-redirect", engine["NO_REPAIR_FAMILY_MESSAGE"])]
    assert remediation.unsupported_reason(REDIRECT_FINDING) == engine["NO_REPAIR_FAMILY_MESSAGE"]
    assert remediation.unsupported_reason(EVAL_FINDING) == ""


def test_a_failed_repair_still_says_why(engine, monkeypatch):
    class Reader:
        def git_tree(self, sha):
            return {"truncated": False, "tree": []}

    def explode(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(remediation, "build_request", explode)
    sections = run.generate_fixes(
        reader=Reader(), repository="acme/widgets", pr_number=7, head_sha="a" * 40, base_sha="b" * 40,
        findings=[EVAL_FINDING, REDIRECT_FINDING], contents={"assistant/agent.py": "exec(code)\n", "inventory/views.py": "x\n"},
        model_configured=False,
    )
    assert [(s["finding_fingerprint"], bool(s["skipped_reason"])) for s in sections] == [("fp-eval", True), ("fp-redirect", True)]
