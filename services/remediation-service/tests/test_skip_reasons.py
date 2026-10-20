"""Every finding a request carries ends in a candidate or in `skipped`, with a sentence."""
from __future__ import annotations

import pytest

from src.agent import ProviderAction, RepairAgent
from src.engine import RepairEngine
from src.gates import MODEL_AUTHORED_CODE_MESSAGE, model_authored_code
from src.models import FindingSnapshot, RepairRequest
from src.skip_reasons import (
    GENERIC_MESSAGE,
    NO_TEMPLATE_MESSAGE,
    complete_skipped,
    reason_sentence,
    unproven_record,
)
from src.verification import Verifier
from tests.test_engine import PassingBroker


class AbstainingProvider:
    def __init__(self, reason_code: str = "", explanation: str = ""):
        self.payload = {"reason_code": reason_code, "explanation": explanation}

    async def next_action(self, messages, tools):  # noqa: ARG002 - provider protocol
        return ProviderAction("abstain", dict(self.payload))


def _engine(provider) -> RepairEngine:
    return RepairEngine(lambda request: RepairAgent(provider, Verifier(PassingBroker())))


def _assert_every_finding_named(request: RepairRequest, response) -> None:
    claimed = {finding_id for candidate in response.candidates for finding_id in candidate.finding_ids}
    named = {item["finding_id"]: item for item in response.skipped}
    for finding in request.findings:
        if finding.stable_id in claimed:
            continue
        assert finding.stable_id in named, f"{finding.stable_id} has neither a candidate nor a skip record"
        assert named[finding.stable_id]["message"].strip()


def test_a_failure_message_wins_over_every_report():
    record = unproven_record(
        "f1",
        failure={"code": "verification_failed", "message": "The patched test still failed."},
        template_entry="not_attempted:command_name_not_literal",
    )
    assert record == {"finding_id": "f1", "code": "verification_failed", "message": "The patched test still failed."}


def test_the_template_refusal_is_named_when_no_model_was_configured():
    record = unproven_record(
        "f1",
        template_entry="not_attempted:command_name_not_literal",
        proof_entry="service",
        group_code="model_not_configured",
        group_message="No model key was given to the action, so only template repairs were attempted.",
    )
    assert record["code"] == "command_name_not_literal"
    assert "program to run" in record["message"]


def test_a_missing_service_proof_defers_to_the_proof_generator_reason():
    record = unproven_record(
        "f1",
        template_entry="not_attempted:no_service_proof",
        proof_entry="model:dependency_not_available_in_sandbox:openai",
    )
    assert record["code"] == "dependency_not_available_in_sandbox"
    assert "imports openai" in record["message"]


def test_a_model_that_says_why_it_abstained_is_quoted():
    record = unproven_record(
        "f1",
        template_entry="not_attempted:sink_not_recognized",
        group_code="needs_design_decision",
        group_message="The fix needs an allowlist the repository does not define.",
    )
    assert record == {"finding_id": "f1", "code": "needs_design_decision", "message": "The fix needs an allowlist the repository does not define."}


def test_an_unknown_template_code_still_gets_a_sentence():
    record = unproven_record("f1", template_entry="not_attempted:something_new")
    assert record == {"finding_id": "f1", "code": "something_new", "message": NO_TEMPLATE_MESSAGE}
    assert reason_sentence("something_new") is None


def test_nothing_recorded_and_a_silent_abstention_still_gets_a_sentence():
    record = unproven_record("f1", group_code="", group_message="")
    assert record == {"finding_id": "f1", "code": "not_repaired", "message": GENERIC_MESSAGE}


def test_complete_skipped_names_every_unclaimed_finding_once():
    skipped = [{"finding_id": "b", "code": "x", "message": ""}]
    completed = complete_skipped(
        [("a",), ("b",), ("c", "c-alias"), ("d",)],
        {"a"},
        skipped,
        {"code": "budget_exhausted", "message": "Out of budget."},
    )
    assert completed == [
        {"finding_id": "b", "code": "x", "message": "Out of budget."},
        {"finding_id": "c", "code": "budget_exhausted", "message": "Out of budget."},
        {"finding_id": "d", "code": "budget_exhausted", "message": "Out of budget."},
    ]
    # A record already under an alias is not duplicated.
    assert complete_skipped([("c", "c-alias")], set(), [{"finding_id": "c-alias", "code": "y", "message": "m"}], None) == [
        {"finding_id": "c-alias", "code": "y", "message": "m"}
    ]


def test_model_authored_code_reads_the_merged_rule_ids():
    survivor = FindingSnapshot.model_validate({
        "snapshot_id": "f1",
        "rule_id": "code.injection.eval",
        "evidence_details": {"extra": {"merged_rule_ids": ["code.injection.eval", "opengrep.cwe-95.py-llm-output-code-execution"]}},
    })
    direct = FindingSnapshot.model_validate({"snapshot_id": "f2", "rule_id": "opengrep.cwe-95.js-llm-output-code-execution"})
    generic = FindingSnapshot.model_validate({"snapshot_id": "f3", "rule_id": "code.injection.eval"})
    assert model_authored_code(survivor) and model_authored_code(direct)
    assert not model_authored_code(generic)


@pytest.mark.asyncio
async def test_a_group_that_proves_nothing_reports_each_finding(model_only_payload):
    """The live shape: a template that does not apply and a model that abstains without a word.

    Before, the group's reason went only into `evidence.groups` and the finding had neither a
    candidate nor a skip record, so the pull request said nothing about it.
    """
    request = RepairRequest.model_validate(model_only_payload)
    response = await _engine(AbstainingProvider()).repair(request)
    assert response.candidates == []
    _assert_every_finding_named(request, response)


@pytest.mark.asyncio
async def test_a_stated_abstention_is_the_finding_reason(model_only_payload):
    request = RepairRequest.model_validate(model_only_payload)
    response = await _engine(AbstainingProvider("needs_allowlist", "The fix needs an allowlist.")).repair(request)
    assert response.skipped == [{"finding_id": "finding-1", "code": "needs_allowlist", "message": "The fix needs an allowlist."}]


@pytest.mark.asyncio
async def test_eval_of_a_model_answer_is_skipped_with_the_sandbox_sentence(request_payload):
    request_payload["findings"][0].update({
        "rule_id": "code.injection.eval",
        "cwe_id": "CWE-95",
        "evidence_details": {"extra": {"merged_rule_ids": ["opengrep.cwe-95.js-llm-output-code-execution"]}},
    })
    request = RepairRequest.model_validate(request_payload)
    response = await _engine(AbstainingProvider()).repair(request)
    assert response.skipped == [{"finding_id": "finding-1", "code": "model_authored_code", "message": MODEL_AUTHORED_CODE_MESSAGE}]
