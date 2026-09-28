"""The static assertion end to end, over the real scanner, on the shape the corpus is made of.

The subject is the pair `docs/validation/pairs-2026-09.md` counts 84 of: a module-scope credential
in a file whose import closure reaches a package the sandbox has no copy of. The service refuses
to write a proof for it (`dependency_not_available_in_sandbox:js-yaml`), the template writes a
patch for it, and before this level existed the finding shipped nothing.

These tests use the real analysis service through `InProcessRuleOracle`, so they need both the
analysis module importable and its scanner installed. Either one missing skips them, with the
reason named. The repair service's own CI job installs the scanner beside the test environment
rather than in it, because semgrep's `opentelemetry-api` pin and this service's cannot both be
satisfied; `.github/workflows/remediation.yml` says so where it does it.

The last test here is the other half: the state where the module is importable and the scanner is
not. Nothing may be asserted in that state, and before it was tested the assertion came back as a
bare `inconclusive` that read like a rule that had been run.
"""
from __future__ import annotations

import hashlib

import pytest

from src.engine import RepairEngine, static_assertion_reason
from src.families import HARDCODED_CREDENTIAL
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.proofs import ProofFallback, generate_proof
from src.retrieval import Snapshot
from src.templates import TemplateFallback, generate_template
from src.verification.static_assertion import ORACLE_SCANNER_UNAVAILABLE, InProcessRuleOracle
from src.verification.verifier import (
    STATIC_ASSERTION_RULE_NOT_EVALUATED,
    STATIC_ASSERTION_VERIFICATION_LEVEL,
)

RULE = "secret.hardcoded.credential"
PATH = "src/server.js"
LITERAL = "sk-live-7f3a91bc44de2210"
# `js-yaml` is not one of the harness fakes, so the proof generator refuses the site for the
# reason the corpus is full of rather than for anything about this file.
SOURCE = (
    "const yaml = require('js-yaml');\n"
    f"const apiKey = '{LITERAL}';\n"
    "const settings = yaml.load('a: 1');\n"
    "module.exports = { apiKey, settings };\n"
)
MANIFEST = '{"dependencies":{"js-yaml":"4.1.0"}}\n'
FINDING_LINE = 2


def git_blob(content: str) -> str:
    raw = content.encode()
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()


def payload(source: str = SOURCE) -> dict:
    entries = [
        GitTreeEntry(path=PATH, mode="100644", type="blob", sha=git_blob(source)),
        GitTreeEntry(path="package.json", mode="100644", type="blob", sha=git_blob(MANIFEST)),
    ]
    return {
        "schema_version": "v1",
        "job_id": "job-1",
        "tenant_id": "installation-7",
        "installation_id": "installation-7",
        "repository_id": "repo-9",
        "repository_full_name": "acme/widget",
        "pull_request_id": "pr-1",
        "pull_request_number": 4,
        "head_sha": "a" * 40,
        "base_sha": "b" * 40,
        "head_tree_oid": compute_tree_oid(entries),
        "tree_entries": [entry.model_dump() for entry in entries],
        "tree_truncated": False,
        "findings": [{
            "snapshot_id": "secret-1", "rule_id": RULE, "cwe_id": "CWE-798",
            "category": "hardcoded secrets", "file_path": PATH,
            "line_start": FINDING_LINE, "line_end": FINDING_LINE,
        }],
        "files": [
            {"path": PATH, "content": source, "sha": git_blob(source)},
            {"path": "package.json", "content": MANIFEST, "sha": git_blob(MANIFEST)},
        ],
        "policy": {
            "policy_version": "policy-1",
            "input_usd_per_million_tokens": 1.0,
            "output_usd_per_million_tokens": 3.0,
        },
        "versions": {"repair_model": "repair-model-1", "prompt": "v1", "retriever": "v1", "verifier": "v1"},
    }


@pytest.fixture(scope="module")
def oracle():
    unavailable = InProcessRuleOracle.unavailable_reason()
    if unavailable is not None:
        # The reason rather than a guess at it: an environment with the analysis module and no
        # scanner and one with neither are different problems, and a skip that names the wrong one
        # is how this suite came to pass on its author's machine and fail on CI.
        pytest.skip(unavailable)
    return InProcessRuleOracle.load()


def test_the_subject_is_the_pair_the_corpus_counts_84_of():
    """Pins the premise: no service proof for a named reason, and a template patch anyway."""
    request = RepairRequest.model_validate(payload())
    snapshot = Snapshot(request)
    finding = request.findings[0]
    proof = generate_proof(snapshot, finding, HARDCODED_CREDENTIAL, "javascript")
    assert isinstance(proof, ProofFallback)
    assert proof.reason == "dependency_not_available_in_sandbox:js-yaml"
    template = generate_template(snapshot, finding, HARDCODED_CREDENTIAL, "javascript")
    assert not isinstance(template, TemplateFallback)
    # And that refusal is what the engine turns into a recorded static assertion reason.
    assert static_assertion_reason(HARDCODED_CREDENTIAL, f"model:{proof.reason}") == (
        "execution_not_available:dependency_not_available_in_sandbox:js-yaml"
    )


@pytest.mark.asyncio
async def test_a_finding_with_no_proof_ships_a_statically_asserted_candidate(oracle):
    """The whole point: a finding execution could not prove reaches a reviewer with an honest level.

    No model is configured and no sandbox broker is reachable, which is the state of the finding
    before this level existed: template pass skipped for want of a proof, model pass abstaining.
    """
    engine = RepairEngine()
    response = await _repair(engine, payload(), oracle)
    assert response.state == "ready", response.reason
    [candidate] = response.candidates
    assert candidate.finding_ids == ["secret-1"]
    assert response.evidence["verification_level"] == STATIC_ASSERTION_VERIFICATION_LEVEL
    assert candidate.preview["evidence"]["verification_level"] == STATIC_ASSERTION_VERIFICATION_LEVEL
    # The repair is the one the template wrote, and the literal is gone.
    replacement = candidate.patch[0].replacement_content
    assert "process.env.API_KEY" in replacement
    assert LITERAL not in replacement
    # The group's evidence names why the weaker level was used.
    [group] = response.evidence["groups"]
    assert group["reason_evidence"]["static_assertions"]["secret-1"] == "asserted"
    assert group["reason_evidence"]["proofs"]["secret-1"] == "model:dependency_not_available_in_sandbox:js-yaml"
    assert group["reason_evidence"]["candidate_sources"]["secret-1"] == "static_assertion"


@pytest.mark.asyncio
async def test_the_evidence_says_nothing_ran_and_which_rule_no_longer_matches(oracle):
    response = await _repair(RepairEngine(), payload(), oracle)
    run = response.evidence["verification_run"]
    assert run["executed"] is False
    assert run["nothing_executed"] == "No code was executed."
    record = run["findings"]["secret-1"]
    assert record["rule_id"] == RULE
    assert record["match_sets"]["original"]["rule"] == [FINDING_LINE]
    assert record["match_sets"]["patched"]["rule"] == []
    assert all(record["clauses"].values())
    # Clause 4, over the real rule set of both tiers: the patch started nothing new matching.
    assert RULE in record["match_sets"]["original"]["all"]
    assert RULE not in record["match_sets"]["patched"]["all"]
    limitations = " | ".join(response.evidence["limitations"])
    assert "nothing was executed" in limitations
    # And the one thing the ordinary build would have executed is named as not performed: the
    # candidate module was never required, so nothing establishes that it still loads.
    assert f"runtime load check not performed for {PATH}" in limitations


@pytest.mark.asyncio
async def test_policy_off_means_the_finding_ships_nothing_at_all(oracle):
    body = payload()
    body["policy"]["allow_static_assertion_verification"] = False
    response = await _repair(RepairEngine(), body, oracle)
    assert response.state != "ready"
    assert response.candidates == []


@pytest.mark.asyncio
async def test_a_patch_that_still_matches_the_rule_is_refused(oracle):
    """The negative case over the real scanner: a repair that keeps the literal proves nothing.

    The shape is a repair that reads the value from the environment on the finding's own line and
    leaves the secret behind under another name, one line down. Clause 3 holds, because the hunk
    declares that line. Clause 2 does not, because the rule still matches the file.
    """
    from src.patches import build_patch_bundle
    from src.verification import Verifier

    request = RepairRequest.model_validate(payload())
    snapshot = Snapshot(request)
    original = snapshot.full_content(PATH).splitlines()
    change = {
        "path": PATH,
        "start_line": FINDING_LINE,
        "original_lines": [original[FINDING_LINE - 1]],
        "replacement_lines": ["const apiKey = process.env.API_KEY;", f"const password = '{LITERAL}';"],
    }
    bundle = build_patch_bundle(request, snapshot, [change], None)
    result = await Verifier(broker=None, rule_oracle=oracle).verify_static_assertion(
        request, snapshot, bundle, reason="execution_not_available:test"
    )
    assert result.status == "failed"
    assert result.reason_code == "static_assertion_rule_still_matches_patch"
    assert result.proven_finding_ids == []


@pytest.mark.asyncio
async def test_a_scanner_the_process_does_not_have_is_not_a_rule_that_matched_nothing(
    oracle, monkeypatch, tmp_path
):
    """The state this level shipped in on CI, and the one that must never pass a clause.

    A checkout carries the analysis service's module and its rule files, so an oracle loads. It
    does not carry the scanner, because semgrep's `opentelemetry-api~=1.37.0` and this service's
    `==1.44.0` cannot both be satisfied in one environment. Clause 4 is the one that breaks first:
    its input is every rule's matches on both files, and that needs tier 2.

    The patch under test is a correct repair. It is still refused, and the refusal says the rule
    was never evaluated rather than reporting a bare `inconclusive`, because a static assertion is
    the claim that a rule no longer matches and nothing here asked.
    """
    from src.patches import build_patch_bundle
    from src.verification import Verifier

    request = RepairRequest.model_validate(payload())
    snapshot = Snapshot(request)
    original = snapshot.full_content(PATH).splitlines()
    bundle = build_patch_bundle(
        request, snapshot,
        [{
            "path": PATH,
            "start_line": FINDING_LINE,
            "original_lines": [original[FINDING_LINE - 1]],
            "replacement_lines": ["const apiKey = process.env.API_KEY;"],
        }],
        None,
    )
    assert "process.env.API_KEY" in bundle.patches[0].replacement_content
    assert LITERAL not in bundle.patches[0].replacement_content

    # A PATH with no scanner on it, while the module stays imported and the rules stay on disk.
    # That is the repair service's environment, not a broken checkout.
    monkeypatch.setenv("PATH", str(tmp_path))
    assert InProcessRuleOracle.load() is None
    assert "scanner" in (InProcessRuleOracle.unavailable_reason() or "")

    result = await Verifier(broker=None, rule_oracle=oracle).verify_static_assertion(
        request, snapshot, bundle, reason="execution_not_available:test"
    )
    assert result.status != "passed"
    assert result.proven_finding_ids == []
    assert result.reason_code == STATIC_ASSERTION_RULE_NOT_EVALUATED
    assert result.evidence["oracle_reason_code"] == ORACLE_SCANNER_UNAVAILABLE
    assert result.evidence["rule_evaluated"] is False
    # No clause is recorded at all, so nothing downstream can read one as held.
    assert "findings" not in result.evidence
    assert any("never evaluated" in item for item in result.limitations)
    assert result.unproven_findings[0]["finding_id"] == "secret-1"


async def _repair(engine: RepairEngine, body: dict, oracle) -> object:
    """Runs the engine with no provider and no broker, and only the rule oracle available.

    That combination is the honest reproduction of the finding's state: there is nothing to
    execute the repair with, which is exactly when this level is the only one left.
    """
    from src.agent import RepairAgent
    from src.verification import Verifier

    class Abstaining:
        async def next_action(self, messages, tools):
            from src.agent import ProviderAction

            return ProviderAction("abstain", {"reason": "no provider is configured"})

    class DeadBroker:
        async def verify(self, payload, timeout_seconds):
            from src.sandbox import BrokerTransportError

            raise BrokerTransportError("no sandbox is reachable")

    verifier = Verifier(DeadBroker(), rule_oracle=oracle)
    agent = RepairAgent(Abstaining(), verifier)
    return await RepairEngine(lambda request: agent).repair(RepairRequest.model_validate(body))
