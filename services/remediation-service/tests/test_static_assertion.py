"""The static_assertion level: its five clauses, each one's negative case, and its ordering.

Every clause is asserted in both directions, because a clause that only ever passes is not a
check. The oracle is a stub here, so a clause is decided by exactly the match sets the test
hands it: `test_static_assertion_endpoint.py` in the analysis service covers the real scanner.

`contracts/repair-v1.md` states the contract these tests hold.
"""
from __future__ import annotations

import dataclasses

import pytest

from src.families import FAMILY_VERIFICATION, STATIC_ASSERTION, declares_static_assertion
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.patches import NO_LOAD_CHECK_LIMITATION, PatchPolicyError, build_patch_bundle
from src.retrieval import Snapshot
from src.verification import Verifier
from src.verification.static_assertion import (
    ASSERTION_SENTENCE,
    CLAUSE_CODES,
    NOTHING_EXECUTED,
    REFUSAL_NEW_RULE_MATCH,
    REFUSAL_NO_RULE_ID,
    REFUSAL_RULE_NOT_MATCHING_ORIGINAL,
    REFUSAL_RULE_STILL_MATCHES,
    REFUSAL_RULE_UNKNOWN,
    REFUSAL_UNRELATED_FILE,
    REFUSAL_UNRELATED_LINE,
    HttpRuleOracle,
    ORACLE_SCANNER_UNAVAILABLE,
    RULE_NOT_EVALUATED_CODES,
    RuleOracleError,
    changed_lines,
)
from src.verification.verifier import (
    DEVELOPMENT_VERIFICATION_LEVEL,
    ISOLATED_JOB_VERIFICATION_LEVEL,
    PRODUCTION_VERIFICATION_LEVEL,
    SANDBOX_VERIFICATION_LEVELS,
    STATIC_ASSERTION_NOT_PERMITTED,
    STATIC_ASSERTION_ORACLE_UNAVAILABLE,
    STATIC_ASSERTION_RULE_NOT_EVALUATED,
    STATIC_ASSERTION_VERIFICATION_LEVEL,
    VERIFICATION_LEVEL_ORDER,
    VERIFICATION_LEVELS,
)
from tests.conftest import git_blob, with_source

RULE = "secret.hardcoded.credential"
# A module scope credential: the shape the corpus is full of and the shape a proof can rarely
# drive, which is why it is the one this level exists for.
SOURCE = (
    "const region = 'eu-west-1';\n"
    "const apiKey = 'sk-live-7f3a91bc44de2210';\n"
    "module.exports = { apiKey, region };\n"
)
REPAIRED_LINE = "const apiKey = process.env.API_KEY;\n"
FINDING_LINE = 2


def payload(request_payload, source: str = SOURCE) -> dict:
    """`request_payload` over a credential source, with the finding on the literal's line."""
    updated = with_source(request_payload, source, line=FINDING_LINE)
    updated["findings"] = [
        {**item, "rule_id": RULE, "cwe_id": "CWE-798", "category": "hardcoded secrets"} for item in updated["findings"]
    ]
    return updated


OTHER_SOURCE = "const other = 1;\nmodule.exports = { other };\n"


def two_file_payload(request_payload) -> dict:
    """`payload` with a second application file no finding names, for the second-file clause."""
    body = payload(request_payload)
    entries = [GitTreeEntry(**entry) for entry in body["tree_entries"]]
    entries.append(GitTreeEntry(path="src/other.ts", mode="100644", type="blob", sha=git_blob(OTHER_SOURCE)))
    body["tree_entries"] = [entry.model_dump() for entry in entries]
    body["head_tree_oid"] = compute_tree_oid(entries)
    body["files"] = [*body["files"], {"path": "src/other.ts", "content": OTHER_SOURCE, "sha": git_blob(OTHER_SOURCE)}]
    return body


def bundle_for(request: RepairRequest, snapshot: Snapshot, replacement: str, path: str = "src/db.ts", start: int = FINDING_LINE):
    """A bundle replacing one line of the affected file, with no generated test.

    No generated test is the point rather than an omission: this level exists for findings no
    test could cover, so the bundle is the patch alone.
    """
    original = snapshot.full_content(path).splitlines()
    change = {
        "path": path,
        "start_line": start,
        "original_lines": [original[start - 1]],
        "replacement_lines": [replacement.rstrip("\n")],
    }
    return build_patch_bundle(request, snapshot, [change], None)


class StubOracle:
    """An oracle that answers with exactly the match sets a test hands it."""

    def __init__(self, original_rule=(FINDING_LINE,), patched_rule=(), original_all=(RULE,), patched_all=(RULE,), refusal=None, tier="tier1"):
        self.original_rule, self.patched_rule = list(original_rule), list(patched_rule)
        self.original_all, self.patched_all = list(original_all), list(patched_all)
        self.refusal, self.tier = refusal, tier
        self.calls: list[tuple[str, str]] = []

    async def match_sets(self, rule_id, path, original, patched):
        self.calls.append((rule_id, path))
        if self.refusal:
            return {"rule_id": rule_id, "path": path, "tier": None, "refusal": self.refusal, "executed": False, "nothing_executed": NOTHING_EXECUTED}
        return {
            "rule_id": rule_id,
            "path": path,
            "tier": self.tier,
            "refusal": None,
            "original": {
                "rule_matches": [{"rule_id": rule_id, "line": line} for line in self.original_rule],
                "all_matches": [{"rule_id": item, "line": FINDING_LINE} for item in self.original_all],
            },
            "patched": {
                "rule_matches": [{"rule_id": rule_id, "line": line} for line in self.patched_rule],
                "all_matches": [{"rule_id": item, "line": FINDING_LINE} for item in self.patched_all],
            },
            "executed": False,
            "nothing_executed": NOTHING_EXECUTED,
        }


class DeadOracle:
    """An oracle that cannot answer: the analysis service is unreachable."""

    def __init__(self, code="rule_oracle_unreachable"):
        self.code = code

    async def match_sets(self, rule_id, path, original, patched):
        raise RuleOracleError(self.code, "ConnectError: connection refused")


async def assert_with(request_payload, oracle, *, replacement: str = REPAIRED_LINE, source: str = SOURCE, **kwargs):
    request = RepairRequest.model_validate(payload(request_payload, source))
    snapshot = Snapshot(request)
    bundle = bundle_for(request, snapshot, replacement, **kwargs)
    verifier = Verifier(broker=None, rule_oracle=oracle)
    return await verifier.verify_static_assertion(request, snapshot, bundle, reason="execution_not_available:test")


# -- the level and its ordering ----------------------------------------------------------------


def test_the_level_is_the_weakest_one_and_a_sandbox_may_not_claim_it():
    assert VERIFICATION_LEVEL_ORDER == (
        STATIC_ASSERTION_VERIFICATION_LEVEL,
        DEVELOPMENT_VERIFICATION_LEVEL,
        ISOLATED_JOB_VERIFICATION_LEVEL,
        PRODUCTION_VERIFICATION_LEVEL,
    )
    assert VERIFICATION_LEVEL_ORDER.index(STATIC_ASSERTION_VERIFICATION_LEVEL) == 0
    # A level a candidate may carry, which is what `VERIFICATION_LEVELS` means and what a family
    # that can only be asserted asks before it lets a candidate through. Not in the set a driver's
    # evidence may declare: this level is produced by the verifier from a scanner answer, so a
    # sandbox claiming it would be claiming something it never measured.
    assert STATIC_ASSERTION_VERIFICATION_LEVEL in VERIFICATION_LEVELS
    assert STATIC_ASSERTION_VERIFICATION_LEVEL not in SANDBOX_VERIFICATION_LEVELS


def test_the_policy_flag_defaults_to_true(request_payload):
    request_payload["policy"].pop("allow_static_assertion_verification", None)
    assert RepairRequest.model_validate(request_payload).policy.allow_static_assertion_verification is True


def test_only_the_workflow_family_declares_the_level_and_the_predicate_answers_either_way():
    # `workflow_hardening` is the one family whose repair no regression test could demonstrate
    # even in principle: the thing repaired is a document GitHub interprets, so there is no module
    # to load and no call to observe. Every family a proof can drive must answer False here, or
    # the declaration would trade an executed proof for a weaker one.
    assert declares_static_assertion("workflow_hardening") is True
    assert declares_static_assertion("hardcoded_credential") is False
    assert declares_static_assertion(None) is False
    assert declares_static_assertion("workflow_tampering") is False
    declared = sorted(family for family, kind in FAMILY_VERIFICATION.items() if kind == STATIC_ASSERTION)
    assert declared == ["workflow_hardening"]


# -- clause 1: the rule matches the original at the finding's line -----------------------------


@pytest.mark.asyncio
async def test_clause_one_holds_when_the_rule_matches_the_findings_line(request_payload):
    result = await assert_with(request_payload, StubOracle())
    assert result.status == "passed"
    assert result.verification_level == STATIC_ASSERTION_VERIFICATION_LEVEL
    record = result.evidence["findings"]["finding-1"]
    assert record["clauses"]["rule_matches_original_at_finding_line"] is True
    assert record["match_sets"]["original"]["rule"] == [FINDING_LINE]


@pytest.mark.asyncio
async def test_clause_one_fails_when_the_rule_matches_the_original_somewhere_else(request_payload):
    """The rule fires on line 3 but not on the finding's line 2: nothing there was removed."""
    result = await assert_with(request_payload, StubOracle(original_rule=(3,)))
    assert result.status == "failed"
    assert result.reason_code == REFUSAL_RULE_NOT_MATCHING_ORIGINAL
    assert result.proven_finding_ids == []
    assert result.evidence["findings"]["finding-1"]["clauses"]["rule_matches_original_at_finding_line"] is False


@pytest.mark.asyncio
async def test_clause_one_fails_when_the_rule_never_matched_the_original(request_payload):
    result = await assert_with(request_payload, StubOracle(original_rule=()))
    assert result.reason_code == REFUSAL_RULE_NOT_MATCHING_ORIGINAL
    assert "nothing for the patch to have removed" in result.unproven_findings[0]["message"]


@pytest.mark.asyncio
async def test_a_finding_with_no_rule_id_is_refused(request_payload):
    request = RepairRequest.model_validate(payload(request_payload))
    request = request.model_copy(update={"findings": [request.findings[0].model_copy(update={"rule_id": ""})]})
    snapshot = Snapshot(request)
    bundle = bundle_for(request, snapshot, REPAIRED_LINE)
    oracle = StubOracle()
    result = await Verifier(broker=None, rule_oracle=oracle).verify_static_assertion(
        request, snapshot, bundle, reason="execution_not_available:test"
    )
    assert result.reason_code == REFUSAL_NO_RULE_ID
    # Refused without asking: there is no rule to ask about.
    assert oracle.calls == []


# -- clause 2: the rule does not match the patched file anywhere -------------------------------


@pytest.mark.asyncio
async def test_clause_two_fails_when_the_rule_still_matches_the_patch(request_payload):
    """The repair that does not repair: the literal is still there, so the rule still fires."""
    result = await assert_with(request_payload, StubOracle(patched_rule=(FINDING_LINE,)))
    assert result.status == "failed"
    assert result.reason_code == REFUSAL_RULE_STILL_MATCHES
    clauses = result.evidence["findings"]["finding-1"]["clauses"]
    assert clauses["rule_does_not_match_patch"] is False
    assert clauses["rule_matches_original_at_finding_line"] is True


@pytest.mark.asyncio
async def test_clause_two_is_about_the_whole_file_not_the_findings_line(request_payload):
    """A patch that moved the secret rather than removing it is refused, at whatever line."""
    result = await assert_with(request_payload, StubOracle(patched_rule=(3,)))
    assert result.reason_code == REFUSAL_RULE_STILL_MATCHES
    assert "line 3" in result.unproven_findings[0]["message"]


# -- clause 3: only the finding's own file, and only its own lines -----------------------------


@pytest.mark.asyncio
async def test_clause_three_allows_a_line_the_repair_declared(request_payload):
    """A repair that has to add an import above the finding declares it by carrying a hunk there.

    Line 1 is outside the finding's region, so it is only allowed because the bundle's own hunk
    list says the repair changes it.
    """
    request = RepairRequest.model_validate(payload(request_payload))
    snapshot = Snapshot(request)
    original = snapshot.full_content("src/db.ts").splitlines()
    changes = [
        {"path": "src/db.ts", "start_line": 1, "original_lines": [original[0]], "replacement_lines": [original[0], "const os = require('os');"]},
        {"path": "src/db.ts", "start_line": FINDING_LINE, "original_lines": [original[1]], "replacement_lines": [REPAIRED_LINE.rstrip("\n")]},
    ]
    bundle = build_patch_bundle(request, snapshot, changes, None)
    result = await Verifier(broker=None, rule_oracle=StubOracle()).verify_static_assertion(
        request, snapshot, bundle, reason="execution_not_available:test"
    )
    assert result.status == "passed", result.reason_code
    assert result.evidence["findings"]["finding-1"]["clauses"]["patch_confined_to_finding_region"] is True
    assert {"start_line": 1, "end_line": 1} in result.evidence["allowed_regions"]["src/db.ts"]


@pytest.mark.asyncio
async def test_clause_three_fails_when_an_unrelated_line_changed(request_payload):
    """The patch rewrites line 3 as well, and neither a finding nor a declared hunk covers it.

    A bundle that declares its hunks can never fail this way, because a hunk is the declaration:
    what it changes, it declared. The shape that can is a bundle carrying no located hunks, which
    is what a whole-file proposal and a combined batch produce (`PatchBundle.hunks`), and such a
    candidate is held to its findings' own regions.
    """
    request = RepairRequest.model_validate(payload(request_payload))
    snapshot = Snapshot(request)
    replacement = SOURCE.replace("const apiKey = 'sk-live-7f3a91bc44de2210';", REPAIRED_LINE.rstrip("\n")).replace(
        "module.exports = { apiKey, region };", "module.exports = { apiKey };"
    )
    declared = build_patch_bundle(
        request, snapshot,
        [{"path": "src/db.ts", "start_line": 1, "end_line": 3, "original_lines": SOURCE.splitlines(), "replacement_lines": replacement.splitlines()}],
        None,
    )
    bundle = dataclasses.replace(declared, hunks=())
    oracle = StubOracle()
    result = await Verifier(broker=None, rule_oracle=oracle).verify_static_assertion(
        request, snapshot, bundle, reason="execution_not_available:test"
    )
    assert result.status == "failed"
    assert result.reason_code == REFUSAL_UNRELATED_LINE
    assert result.evidence["lines_outside_allowed_regions"]["src/db.ts"] == [3]
    assert result.evidence["allowed_regions"]["src/db.ts"] == [{"start_line": FINDING_LINE, "end_line": FINDING_LINE}]
    # Clause 3 is answered from the patch alone, so no rule was run on a patch already refused.
    assert oracle.calls == []


@pytest.mark.asyncio
async def test_clause_three_fails_when_a_second_file_changed(request_payload):
    """The patch also rewrites a file no finding names, so the assertion covers less than it claims."""
    body = two_file_payload(request_payload)
    request = RepairRequest.model_validate(body)
    snapshot = Snapshot(request)
    original = snapshot.full_content("src/db.ts").splitlines()
    other = snapshot.full_content("src/other.ts").splitlines()
    changes = [
        {"path": "src/db.ts", "start_line": FINDING_LINE, "original_lines": [original[1]], "replacement_lines": [REPAIRED_LINE.rstrip("\n")]},
        {"path": "src/other.ts", "start_line": 1, "original_lines": [other[0]], "replacement_lines": ["const other = 2;"]},
    ]
    bundle = build_patch_bundle(request, snapshot, changes, None)
    oracle = StubOracle()
    result = await Verifier(broker=None, rule_oracle=oracle).verify_static_assertion(
        request, snapshot, bundle, reason="execution_not_available:test"
    )
    assert result.status == "failed"
    assert result.reason_code == REFUSAL_UNRELATED_FILE
    assert result.evidence["paths_outside_findings"] == ["src/other.ts"]
    assert oracle.calls == []


def test_changed_lines_names_the_replaced_lines_and_an_insertions_anchor():
    original = "a\nb\nc\n"
    assert changed_lines(original, "a\nB\nc\n") == [2]
    assert changed_lines(original, "a\nb\nc\nd\n") == [3]
    assert changed_lines(original, "a\nc\n") == [2]
    assert changed_lines(original, original) == []


# -- clause 4: the patch introduces no rule that did not already match -------------------------


@pytest.mark.asyncio
async def test_clause_four_fails_when_the_patch_makes_another_rule_match(request_payload):
    """The clause that makes the level worth showing: one vulnerability traded for another."""
    result = await assert_with(
        request_payload, StubOracle(original_all=(RULE,), patched_all=(RULE, "opengrep.cwe-78.js-exec-interpolated"))
    )
    assert result.status == "failed"
    assert result.reason_code == REFUSAL_NEW_RULE_MATCH
    assert result.evidence["findings"]["finding-1"]["rules_introduced_by_patch"] == ["opengrep.cwe-78.js-exec-interpolated"]
    assert result.evidence["findings"]["finding-1"]["clauses"]["patch_introduces_no_new_rule_match"] is False


@pytest.mark.asyncio
async def test_clause_four_ignores_a_rule_that_already_matched_the_original(request_payload):
    """A pre-existing finding on the same file is not this patch's doing and does not refuse it."""
    other = "opengrep.cwe-327.js-weak-hash"
    result = await assert_with(request_payload, StubOracle(original_all=(RULE, other), patched_all=(other,)))
    assert result.status == "passed", result.reason_code
    assert result.evidence["findings"]["finding-1"]["clauses"]["patch_introduces_no_new_rule_match"] is True


# -- clause 5: nothing was executed ------------------------------------------------------------


@pytest.mark.asyncio
async def test_clause_five_is_recorded_in_those_words_whatever_the_outcome(request_payload):
    passing = await assert_with(request_payload, StubOracle())
    failing = await assert_with(request_payload, StubOracle(patched_rule=(FINDING_LINE,)))
    for result in (passing, failing):
        assert result.evidence["executed"] is False
        assert result.evidence["nothing_executed"] == NOTHING_EXECUTED
        assert all(record["clauses"]["nothing_executed"] is True for record in result.evidence["findings"].values())
    assert NOTHING_EXECUTED in passing.evidence["summary"]
    assert passing.evidence["summary"] == ASSERTION_SENTENCE


@pytest.mark.asyncio
async def test_the_evidence_names_every_clause_and_carries_a_digest(request_payload):
    result = await assert_with(request_payload, StubOracle())
    record = result.evidence["findings"]["finding-1"]
    assert set(record["clauses"]) == set(CLAUSE_CODES)
    assert all(record["clauses"].values())
    assert result.evidence["digest"].startswith("sha256:")
    assert result.evidence_digest is not None
    assert result.evidence["static_assertion_reason"] == "execution_not_available:test"
    assert result.evidence["changed_lines"] == {"src/db.ts": [FINDING_LINE]}


def test_clause_five_reaches_the_bundle_build_so_the_patched_module_is_never_required(request_payload):
    """The bundle a statically asserted candidate is built from loads nothing.

    The ordinary bundle build requires the patched module to check that it still loads, which runs
    whatever that module runs on import. A candidate whose evidence says nothing was executed
    cannot have been built that way, so the static assertion path asks for the build without it.
    The check is recorded as not performed, because a reviewer is owed the fact that nobody has
    established the patched module still loads.
    """
    path = "src/db.ts"
    request = RepairRequest.model_validate(payload(request_payload))
    snapshot = Snapshot(request)
    original = snapshot.full_content(path).splitlines()
    # Parses, and throws the moment it is required. Nothing else distinguishes the two builds.
    change = {
        "path": path,
        "start_line": FINDING_LINE,
        "original_lines": [original[FINDING_LINE - 1]],
        "replacement_lines": [REPAIRED_LINE.rstrip("\n"), "const broken = null.missing;"],
    }
    with pytest.raises(PatchPolicyError) as error:
        build_patch_bundle(request, snapshot, [change], None)
    assert error.value.code == f"candidate_load_failed:{path}"
    bundle = build_patch_bundle(request, snapshot, [change], None, load_checks=False)
    assert NO_LOAD_CHECK_LIMITATION.format(path=path) in bundle.limitations


@pytest.mark.asyncio
async def test_the_limitations_say_no_test_ran(request_payload):
    result = await assert_with(request_payload, StubOracle())
    joined = " | ".join(result.limitations)
    assert "nothing was executed" in joined
    assert "no regression test reproduced this finding" in joined
    assert "the repository's original test suite was not run" in joined
    assert "no type check or build was run" in joined


# -- the oracle: an answer that does not arrive refuses the candidate --------------------------


@pytest.mark.asyncio
async def test_an_unreachable_analysis_service_refuses_the_candidate(request_payload):
    """The case that must never pass: no answer is not an empty match set.

    The verdict-level reason is the one every non-evaluation shares, so a caller never has to
    enumerate transports to learn that no clause was decided; the oracle's own code is kept
    beside it and on the finding, because that is what says what to go and fix.
    """
    result = await assert_with(request_payload, DeadOracle())
    assert result.status == "inconclusive"
    assert result.proven_finding_ids == []
    assert result.reason_code == STATIC_ASSERTION_RULE_NOT_EVALUATED
    assert result.evidence["oracle_reason_code"] == "rule_oracle_unreachable"
    assert result.evidence["rule_evaluated"] is False
    assert "clauses" not in result.evidence
    assert result.evidence_digest is None
    assert result.unproven_findings[0]["code"] == "rule_oracle_unreachable"
    assert "never evaluated" in result.unproven_findings[0]["message"]


@pytest.mark.asyncio
async def test_no_oracle_at_all_refuses_the_candidate(request_payload):
    result = await assert_with(request_payload, None)
    assert result.status == "inconclusive"
    assert result.reason_code == STATIC_ASSERTION_RULE_NOT_EVALUATED
    assert result.evidence["oracle_reason_code"] == STATIC_ASSERTION_ORACLE_UNAVAILABLE
    assert result.proven_finding_ids == []


@pytest.mark.asyncio
async def test_a_response_with_no_match_sets_refuses_the_candidate(request_payload):
    class EmptyOracle:
        async def match_sets(self, rule_id, path, original, patched):
            return {"rule_id": rule_id, "path": path, "tier": "tier1", "refusal": None}

    result = await assert_with(request_payload, EmptyOracle())
    assert result.status == "inconclusive"
    assert result.reason_code == STATIC_ASSERTION_RULE_NOT_EVALUATED
    assert result.evidence["oracle_reason_code"] == "rule_oracle_response_invalid"


@pytest.mark.parametrize("code", sorted(RULE_NOT_EVALUATED_CODES))
@pytest.mark.asyncio
async def test_every_oracle_failure_reads_as_a_rule_that_was_not_evaluated(request_payload, code):
    """One reason code for the whole class, so no caller has to enumerate transports.

    An oracle can give out in several ways and none of them produces match sets, so none of them
    decides a clause. A caller asking "was anything asserted here" gets one answer to compare
    against instead of five, and `oracle_reason_code` still says which way it was.
    """
    result = await assert_with(request_payload, DeadOracle(code))
    assert result.status == "inconclusive"
    assert result.reason_code == STATIC_ASSERTION_RULE_NOT_EVALUATED
    assert result.evidence["oracle_reason_code"] == code
    assert result.evidence["rule_evaluated"] is False
    assert result.proven_finding_ids == []


@pytest.mark.parametrize("missing", ["rule_matches", "all_matches"])
@pytest.mark.asyncio
async def test_a_side_with_a_missing_match_set_refuses_the_candidate(request_payload, missing):
    """The clause that must never be decided from a key the oracle did not send.

    `all_matches` is clause 4's only input. Reading an absent key as an empty list would make the
    clause hold over a rule set nothing ran, which is the exact shape of a fix shipping with the
    claim that no new rule started matching when nothing ever asked.
    """
    class PartialOracle:
        async def match_sets(self, rule_id, path, original, patched):
            sides = {
                side: {
                    "rule_matches": [{"rule_id": rule_id, "line": FINDING_LINE}] if side == "original" else [],
                    "all_matches": [{"rule_id": rule_id, "line": FINDING_LINE}] if side == "original" else [],
                }
                for side in ("original", "patched")
            }
            del sides["patched"][missing]
            return {"rule_id": rule_id, "path": path, "tier": "tier1", "refusal": None, **sides}

    result = await assert_with(request_payload, PartialOracle())
    assert result.status == "inconclusive"
    assert result.reason_code == STATIC_ASSERTION_RULE_NOT_EVALUATED
    assert result.evidence["oracle_reason_code"] == "rule_oracle_response_invalid"
    assert result.proven_finding_ids == []


@pytest.mark.asyncio
async def test_a_rule_the_scanner_does_not_recognize_refuses_the_candidate(request_payload):
    result = await assert_with(request_payload, StubOracle(refusal="rule_not_recognized"))
    assert result.status == "failed"
    assert result.reason_code == REFUSAL_RULE_UNKNOWN
    assert result.evidence["findings"]["finding-1"]["oracle_refusal"] == "rule_not_recognized"


@pytest.mark.asyncio
async def test_policy_can_refuse_the_level_outright(request_payload):
    body = payload(request_payload)
    body["policy"]["allow_static_assertion_verification"] = False
    request = RepairRequest.model_validate(body)
    snapshot = Snapshot(request)
    bundle = bundle_for(request, snapshot, REPAIRED_LINE)
    oracle = StubOracle()
    result = await Verifier(broker=None, rule_oracle=oracle).verify_static_assertion(
        request, snapshot, bundle, reason="execution_not_available:test"
    )
    assert result.status == "unsupported"
    assert result.reason_code == STATIC_ASSERTION_NOT_PERMITTED
    assert oracle.calls == []


def test_the_http_oracle_is_configured_from_the_same_env_the_api_service_uses(monkeypatch):
    monkeypatch.delenv("ANALYSIS_SERVICE_URL", raising=False)
    monkeypatch.delenv("ANALYSIS_SERVICE_INTERNAL_SECRET", raising=False)
    monkeypatch.delenv("GITHUB_SERVICE_INTERNAL_SECRET", raising=False)
    assert HttpRuleOracle.from_env() is None
    monkeypatch.setenv("ANALYSIS_SERVICE_URL", "http://analysis-service:8001/")
    assert HttpRuleOracle.from_env() is None, "a URL without a secret is not a configured oracle"
    monkeypatch.setenv("GITHUB_SERVICE_INTERNAL_SECRET", "s3cret")
    oracle = HttpRuleOracle.from_env()
    assert oracle is not None and oracle.base_url == "http://analysis-service:8001"


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (500, "rule_oracle_rejected_request"),
        # The analysis service answers 503 for exactly one thing: its scanner did not run
        # (`main.verify_static_assertion`). It gets the code that says so, the same one the
        # in-process oracle reports, so the two deployments read alike.
        (503, ORACLE_SCANNER_UNAVAILABLE),
        (400, "rule_oracle_rejected_request"),
    ],
)
@pytest.mark.asyncio
async def test_the_http_oracle_refuses_rather_than_passes_when_the_service_answers_badly(
    monkeypatch, status, code
):
    import httpx

    class Response:
        status_code = status

        def json(self):  # pragma: no cover - never reached on a non-200
            return {}

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    oracle = HttpRuleOracle("http://analysis-service:8001", "s3cret")
    with pytest.raises(RuleOracleError) as excinfo:
        await oracle.match_sets(RULE, "src/db.ts", SOURCE, SOURCE)
    assert excinfo.value.code == code


@pytest.mark.asyncio
async def test_the_http_oracle_sends_the_internal_secret_header(monkeypatch):
    import httpx

    sent: dict = {}

    class Response:
        status_code = 200

        def json(self):
            return {"rule_id": RULE, "path": "src/db.ts", "tier": "tier1", "refusal": None,
                    "original": {"rule_matches": [], "all_matches": []},
                    "patched": {"rule_matches": [], "all_matches": []}}

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, json=None, headers=None):
            sent.update({"url": url, "json": json, "headers": headers})
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    await HttpRuleOracle("http://analysis-service:8001", "s3cret").match_sets(RULE, "src/db.ts", SOURCE, REPAIRED_LINE)
    assert sent["url"] == "http://analysis-service:8001/verify/static-assertion"
    assert sent["headers"]["x-internal-secret"] == "s3cret"
    assert sent["json"]["rule_id"] == RULE and sent["json"]["path"] == "src/db.ts"


# -- several findings in one assertion ---------------------------------------------------------


@pytest.mark.asyncio
async def test_a_finding_whose_file_the_patch_does_not_change_is_reported_not_repaired(request_payload):
    body = payload(request_payload)
    body["findings"] = [
        body["findings"][0],
        {"snapshot_id": "finding-2", "rule_id": RULE, "cwe_id": "CWE-798", "file_path": "package.json", "line_start": 1, "line_end": 1},
    ]
    request = RepairRequest.model_validate(body)
    snapshot = Snapshot(request)
    bundle = bundle_for(request, snapshot, REPAIRED_LINE)
    result = await Verifier(broker=None, rule_oracle=StubOracle()).verify_static_assertion(
        request, snapshot, bundle, reason="execution_not_available:test"
    )
    # The first finding is asserted; the second is reported rather than silently included.
    assert result.status == "passed"
    assert result.proven_finding_ids == ["finding-1"]
    assert [item["finding_id"] for item in result.unproven_findings] == ["finding-2"]
    assert result.unproven_findings[0]["code"] == "not_repaired"
