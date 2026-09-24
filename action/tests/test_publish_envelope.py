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

REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_OPERATIONS = REPO_ROOT / "services/github-service/src/services/githubInternalOperations.js"
PUBLISHER = Path(__file__).resolve().parents[1] / "publisher/publish.js"

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


def a_request(sections):
    return run.build_publish_request(
        token="ghs-token",
        repository="acme/widgets",
        pr_number=7,
        head_sha=HEAD,
        base_sha=BASE,
        installation_id=42,
        actor_login="octocat",
        counts=COUNTS,
        findings=2,
        fix_sections=sections,
        inline_comments=[],
        model_configured=False,
        conclusion="failure",
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

STUB_OPERATIONS = """
'use strict';
const fs = require('fs');
const calls = process.env.MITIG8IT_STUB_CALLS;
function record(name, payload) {
  fs.appendFileSync(calls, JSON.stringify({ name, payload }) + '\\n');
}
// The envelope rule this stub enforces is the service's own, copied by the test from
// githubInternalOperations.js so a publish that would be rejected there is rejected here.
function validateEnvelope(payload) {
  const digest = payload.manifest_digest;
  if (typeof digest !== 'string' || !digest || digest.length > 64) throw new Error('manifest_digest is required');
  if (!/^[0-9a-f]{64}$/i.test(digest)) throw new Error('manifest_digest must be a SHA-256 digest');
}
module.exports = {
  submitPullRequestReview: async (p) => { record('review', p); return { review_id: 1 }; },
  postInlineComment: async (p) => { record('inline', p); return { comment_id: 2 }; },
  publishFindingFixSections: async (p) => { validateEnvelope(p); record('fixes', p); return { published: p.sections.length }; },
  createCheckRun: async (p) => { record('check', p); return { check_run_id: 3 }; },
};
"""

STUB_IDENTITY = "'use strict';\nmodule.exports = { useProvider: () => {} };\n"


def stub_service_root(tmp_path):
    services = tmp_path / "github-service/src/services"
    services.mkdir(parents=True)
    (services / "githubInternalOperations.js").write_text(STUB_OPERATIONS, encoding="utf-8")
    (services / "githubIdentity.js").write_text(STUB_IDENTITY, encoding="utf-8")
    return tmp_path / "github-service"


def run_publisher(tmp_path, request):
    """Runs the real publisher against a stub service root and returns (exit code, calls)."""
    calls = tmp_path / "calls.jsonl"
    calls.write_text("", encoding="utf-8")
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    completed = subprocess.run(
        ["node", str(PUBLISHER), str(request_path)],
        capture_output=True,
        text=True,
        timeout=120,
        env={
            "PATH": __import__("os").environ.get("PATH", ""),
            "MITIG8IT_GITHUB_SERVICE_ROOT": str(stub_service_root(tmp_path)),
            "MITIG8IT_STUB_CALLS": str(calls),
        },
    )
    recorded = [json.loads(line) for line in calls.read_text(encoding="utf-8").splitlines() if line]
    return completed, recorded


def test_a_publish_with_fixes_is_accepted_end_to_end(tmp_path):
    """The whole path: the orchestrator's request through the real publisher into the validator."""
    if not shutil.which("node"):
        pytest.skip("node is not on PATH")
    completed, recorded = run_publisher(tmp_path, a_request(SECTIONS))

    assert completed.returncode == 0, completed.stderr
    assert "manifest_digest" not in completed.stderr
    names = [call["name"] for call in recorded]
    assert names == ["review", "fixes", "check"]
    fixes = next(call for call in recorded if call["name"] == "fixes")
    assert len(fixes["payload"]["sections"]) == 2


def test_the_review_and_the_check_still_publish_when_there_are_no_fixes(tmp_path):
    """Zero fixes skips the fix step entirely; nothing else about the publish changes."""
    if not shutil.which("node"):
        pytest.skip("node is not on PATH")
    request = a_request([])
    request["counts"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    request["findings"] = 0
    request["failConclusion"] = "success"
    completed, recorded = run_publisher(tmp_path, request)

    assert completed.returncode == 0, completed.stderr
    names = [call["name"] for call in recorded]
    assert names == ["review", "check"]
    check = next(call for call in recorded if call["name"] == "check")
    assert check["payload"]["title"] == "No blocking security findings"
    assert check["payload"]["conclusion"] == "success"
