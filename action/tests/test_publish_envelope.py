"""The publish envelope the action hands to github-service, and the digest it carries.

The action sent `head_sha` as `manifest_digest`. github-service validates the envelope of every
publish that carries fixes, and it wants a bare 64-character SHA-256; a 40-character Git object
ID is not one. Every run that produced a fix died at

    publishing failed: publish error: fixes: manifest_digest must be a SHA-256 digest

after the review and the check run had already been posted, so the job failed with its findings
visible and its outputs never written.

These tests pin three things. The digest satisfies the validator's own rule, read out of the
service source rather than restated here, so tightening the rule breaks the test rather than the
action. It is computed the way the app computes it, checked against Node running the app's
hashing expression. And a run with no fixes still publishes its review and its check run, which
is the case the fix step is skipped in entirely.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from orchestrator import run
from tests import fake_graphql, publisher_harness

REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_OPERATIONS = REPO_ROOT / "services/github-service/src/services/githubInternalOperations.js"

HEAD = "a" * 40
BASE = "b" * 40

SECTIONS = [
    {
        "finding_fingerprint": "fp-1",
        "candidate_id": "cand-1",
        "path": "src/db.js",
        "finding_line": 12,
        "verification_level": "development_unverified",
        "stated_intent": "parameterize the query",
        "proof": "exploit fails on the candidate",
        "limitations": [],
        "evidence": [],
        "finding_ids": ["fp-1"],
        "unified_diff": "--- a/src/db.js\n+++ b/src/db.js\n@@\n-bad\n+good\n",
    },
    {
        "finding_fingerprint": "fp-2",
        "candidate_id": "cand-2",
        "path": "src/cmd.js",
        "finding_line": 30,
        "verification_level": "development_unverified",
        "stated_intent": "pass argv as a list",
        "proof": "exploit fails on the candidate",
        "limitations": [],
        "evidence": [],
        "finding_ids": ["fp-2"],
        "unified_diff": "--- a/src/cmd.js\n+++ b/src/cmd.js\n@@\n-bad\n+good\n",
    },
]

COUNTS = {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0}


NO_COUNTS = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def a_request(sections, counts=None, findings=2, conclusion="failure"):
    """The request as the orchestrator builds it.

    `counts` is passed rather than patched afterwards, because the review's numbers are computed
    once from it and travel as `totals`; a test that edited `counts` on the finished request
    would be describing a state the orchestrator never produces.
    """
    return run.build_publish_request(
        token="ghs-token",
        repository="acme/widgets",
        pr_number=7,
        head_sha=HEAD,
        base_sha=BASE,
        installation_id=42,
        actor_login="octocat",
        counts=COUNTS if counts is None else counts,
        findings=findings,
        fix_sections=sections,
        inline_comments=[],
        model_configured=False,
        conclusion=conclusion,
    )


# --- the validator's own rule ---------------------------------------------------------------

def validator_rule():
    """The digest rule as githubInternalOperations.js states it: the bound and the pattern."""
    source = GITHUB_OPERATIONS.read_text(encoding="utf-8")
    match = re.search(
        r"requireString\(payload\.manifest_digest, 'manifest_digest', (\d+)\);\s*\n\s*"
        r"if \(!/\^\[0-9a-f\]\{(\d+)\}\$/i\.test\(manifestDigest\)\)",
        source,
    )
    assert match, "validateActionEnvelope no longer validates manifest_digest the same way"
    return int(match.group(1)), int(match.group(2))


def test_the_publish_payload_passes_the_github_service_validator():
    maximum, width = validator_rule()
    digest = a_request(SECTIONS)["manifest_digest"]

    assert isinstance(digest, str) and digest
    assert len(digest) <= maximum
    assert re.fullmatch(f"[0-9a-f]{{{width}}}", digest, re.IGNORECASE)
    # The old value, and the shape the remediation service's own digests carry, both fail it.
    assert not re.fullmatch(f"[0-9a-f]{{{width}}}", HEAD, re.IGNORECASE)
    assert not digest.startswith("sha256:")


def test_a_run_with_no_fixes_still_carries_a_valid_digest():
    """The envelope is only validated when sections are sent, but it is always well formed."""
    maximum, width = validator_rule()
    digest = a_request([])["manifest_digest"]

    assert len(digest) <= maximum
    assert re.fullmatch(f"[0-9a-f]{{{width}}}", digest, re.IGNORECASE)


def test_the_digest_binds_the_exact_ordered_set_of_sections():
    """Consent is over a subset in an order. A digest that ignores either binds nothing."""
    baseline = run.manifest_digest("action-1", HEAD, BASE, SECTIONS)

    assert run.manifest_digest("action-1", HEAD, BASE, SECTIONS) == baseline
    assert run.manifest_digest("action-1", HEAD, BASE, list(reversed(SECTIONS))) != baseline
    assert run.manifest_digest("action-1", HEAD, BASE, SECTIONS[:1]) != baseline
    assert run.manifest_digest("action-2", HEAD, BASE, SECTIONS) != baseline
    assert run.manifest_digest("action-1", "c" * 40, BASE, SECTIONS) != baseline

    edited = [dict(SECTIONS[0], unified_diff="--- a/src/db.js\n+++ b/src/db.js\n@@\n-bad\n+other\n"), SECTIONS[1]]
    assert run.manifest_digest("action-1", HEAD, BASE, edited) != baseline


def test_the_digest_is_the_hash_the_app_computes():
    """`hash` in services/api-service/src/db/remediation.js, run by Node against the same manifest.

    JSON.stringify emits keys in insertion order with no whitespace. A Python dump that sorted
    keys would hash a different string for the same manifest and stop being the app's function
    without any test noticing.
    """
    if not shutil.which("node"):
        pytest.skip("node is not on PATH")
    manifest = {
        "job": "action-1",
        "head": HEAD,
        "base": BASE,
        "candidates": [
            {"id": section["candidate_id"], "artifact_digest": run.section_artifact_digest(section)}
            for section in SECTIONS
        ],
    }
    script = (
        "const crypto = require('crypto');"
        f"const manifest = {json.dumps(manifest)};"
        "process.stdout.write(crypto.createHash('sha256').update(JSON.stringify(manifest)).digest('hex'));"
    )
    completed = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=60)
    assert completed.returncode == 0, completed.stderr

    assert completed.stdout.strip() == run.manifest_digest("action-1", HEAD, BASE, SECTIONS)


# --- what the publisher does with it ---------------------------------------------------------

def run_publisher(tmp_path, request):
    """The real publisher against the shared fake GitHub and a fake GraphQL endpoint."""
    server = fake_graphql.FakeGraphQL().start()
    try:
        publisher = publisher_harness.Publisher(tmp_path, graphql_url=server.url())
        completed = publisher.run(request)
        return completed, publisher.calls()
    finally:
        server.stop()


def test_a_publish_with_fixes_is_accepted_end_to_end(tmp_path):
    """The whole path: the orchestrator's request through the real publisher into the validator."""
    if not publisher_harness.node_available():
        pytest.skip("node is not on PATH")
    completed, recorded = run_publisher(tmp_path, a_request(SECTIONS))

    assert completed.returncode == 0, completed.stderr
    assert "manifest_digest" not in completed.stderr
    assert [call["name"] for call in recorded] == ["review", "fixes", "check"]
    fixes = next(call for call in recorded if call["name"] == "fixes")
    assert fixes["sections"] == 2


def test_the_review_and_the_check_still_publish_when_there_are_no_fixes(tmp_path):
    """Zero fixes skips the fix step entirely; nothing else about the publish changes."""
    if not publisher_harness.node_available():
        pytest.skip("node is not on PATH")
    request = a_request([], counts=NO_COUNTS, findings=0, conclusion="success")
    completed, recorded = run_publisher(tmp_path, request)

    assert completed.returncode == 0, completed.stderr
    assert [call["name"] for call in recorded] == ["review", "check"]
    check = next(call for call in recorded if call["name"] == "check")
    assert check["title"] == "No security findings"
    assert check["conclusion"] == "success"


def test_the_title_the_summary_and_the_review_body_state_one_total(tmp_path):
    """Four numbers for one review is what a reader had to reconcile before trusting any.

    On pygoat the trial read "32 critical/high findings" on the check, "37 runtime findings" in
    the check summary, "37 findings detected" in the review body and counted sixteen comments.
    """
    if not publisher_harness.node_available():
        pytest.skip("node is not on PATH")
    counts = {"critical": 22, "high": 10, "medium": 5, "low": 0, "info": 2}
    request = a_request([], counts=counts, findings=39)
    request["inline_comments"] = []
    request["unanchored_findings"] = [
        {"path": "introduction/views.py", "line": 214, "severity": "critical",
         "rule": "cwe-502.pickle-loads", "reason": "line_outside_diff"},
    ]
    request["totals"] = run.review_totals(counts, [], request["unanchored_findings"])
    completed, recorded = run_publisher(tmp_path, request)

    assert completed.returncode == 0, completed.stderr
    check = next(call for call in recorded if call["name"] == "check")
    review = next(call for call in recorded if call["name"] == "review")
    assert "37 findings" in check["title"]
    assert "32 critical or high" in check["title"]
    assert "37 findings outside test code" in check["summary"]
    assert "37 findings detected" in review["body"]


def test_a_finding_off_the_diff_is_named_in_the_review_body(tmp_path):
    """28 of the trial's 93 findings existed only as a number. A number is not actionable."""
    if not publisher_harness.node_available():
        pytest.skip("node is not on PATH")
    counts = {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    request = a_request([], counts=counts, findings=1)
    request["unanchored_findings"] = [
        {"path": "app/routes/error.js", "line": 10, "severity": "critical",
         "rule": "cwe-95.eval-injection", "reason": "line_outside_diff"},
    ]
    request["totals"] = run.review_totals(counts, [], request["unanchored_findings"])
    completed, recorded = run_publisher(tmp_path, request)

    assert completed.returncode == 0, completed.stderr
    body = next(call for call in recorded if call["name"] == "review")["body"]
    assert "Findings on lines this pull request did not change (1)" in body
    assert "`cwe-95.eval-injection`" in body
    assert f"https://github.com/acme/widgets/blob/{HEAD}/app/routes/error.js#L10" in body
    assert "app/routes/error.js:10" in body
