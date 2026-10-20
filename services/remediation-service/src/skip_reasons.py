"""The one sentence a reader gets when a finding has no fix.

Every finding a request carries ends in a candidate or in `skipped`, and a skip record is only
useful when its message says why in words a pull request author can act on. The engine already
knows the reason in most cases, as a machine code in the group's template and proof reports
(`not_attempted:command_name_not_literal`, `model:eval_argument_not_a_parameter`), but until
this module it published "No regression test reproduced this finding" for all of them, or no
record at all.

`unproven_record` picks the most specific reason the group recorded for one finding, in this
order: a verification or patch policy failure, the template's or the proof generator's own
refusal, the model's stated abstention, and only then a generic sentence. Codes without a
sentence of their own still get a family sentence, never an empty message.
"""
from __future__ import annotations

from typing import Any, Mapping

NOT_REPAIRED = "not_repaired"
GENERIC_MESSAGE = "No candidate fix for this finding could be proven, so none is suggested."
NO_TEMPLATE_MESSAGE = (
    "No repair template recognizes the shape of this code, and no model pass produced a fix "
    "that could be proven."
)
NO_PROOF_MESSAGE = (
    "No regression test could be generated for this code, so no fix for it could be proven."
)

# Template and proof refusal codes with a sentence of their own. The code after the colon in a
# report entry is looked up here first; a parameterized code (`dependency_not_available_in_
# sandbox:openai`) is looked up by its stem and the parameter is passed to the sentence.
_REASON_SENTENCES: dict[str, str] = {
    "eval_argument_not_a_parameter": (
        "The evaluated value is not a parameter of the enclosing function, so no test could feed "
        "it a payload and no fix could be proven."
    ),
    "eval_argument_not_an_identifier": (
        "The evaluated value is an expression rather than a single variable, so no template "
        "rewrite applies to it."
    ),
    "command_name_not_literal": (
        "The program to run is not written in the code, so an argument list cannot be built "
        "without changing which program runs."
    ),
    "subprocess_call_not_found": "No subprocess call was found on the finding's line, so there is nothing to rewrite.",
    "shell_true_not_present": "The process call does not pass shell=True, so the template has nothing to remove.",
    "no_untrusted_parameter": (
        "No function parameter reaches the flagged line, so no test could feed it a payload and "
        "no fix could be proven."
    ),
    "function_not_exported": (
        "The flagged code is not reachable from the module's exports, so no test could call it "
        "to prove a fix."
    ),
    "module_not_loadable_by_node": "The module could not be loaded by Node in the sandbox, so no test could prove a fix.",
    "dependency_not_available_in_sandbox": (
        "The module imports {detail}, which the sandbox does not install, so no test could load "
        "it to prove a fix."
    ),
    "typescript_syntax_not_strippable": (
        "The file uses TypeScript syntax ({detail}) the sandbox cannot strip, so no test could "
        "load it to prove a fix."
    ),
}


def reason_sentence(code: str) -> str | None:
    """The sentence for one template or proof refusal code, or None when it has none."""
    code = str(code or "").strip()
    if not code:
        return None
    stem, _, detail = code.partition(":")
    sentence = _REASON_SENTENCES.get(stem)
    if sentence is None:
        return None
    return sentence.format(detail=detail or "a package")


def _report_code(entry: str | None, prefix: str) -> str | None:
    entry = str(entry or "")
    if not entry.startswith(prefix):
        return None
    return entry[len(prefix):] or None


def unproven_record(
    finding_id: str,
    *,
    failure: Mapping[str, Any] | None = None,
    template_entry: str | None = None,
    proof_entry: str | None = None,
    group_code: str | None = None,
    group_message: str | None = None,
) -> dict[str, str]:
    """The skip record for one finding the group did not claim.

    `template_entry` and `proof_entry` are the finding's values in the group's `templates` and
    `proofs` reports. `group_code` and `group_message` are the reason of the group's model pass,
    which is the model's own abstention when it stopped deliberately. An abstention that only
    says no model was configured explains less than the template's refusal, so it is used last.
    """
    if failure:
        code = str(failure.get("code") or NOT_REPAIRED)
        message = str(failure.get("message") or "").strip()
        if message:
            return {"finding_id": finding_id, "code": code, "message": message}

    template_code = _report_code(template_entry, "not_attempted:")
    if template_code == "no_service_proof":
        template_code = None
    proof_code = _report_code(proof_entry, "model:")

    model_stated = bool(group_message and str(group_message).strip()) and group_code not in (None, "", "model_not_configured")
    if model_stated:
        return {"finding_id": finding_id, "code": str(group_code), "message": str(group_message).strip()}

    for code in (template_code, proof_code):
        sentence = reason_sentence(code or "")
        if sentence:
            return {"finding_id": finding_id, "code": str(code).partition(":")[0], "message": sentence}
    if template_code:
        return {"finding_id": finding_id, "code": template_code.partition(":")[0], "message": NO_TEMPLATE_MESSAGE}
    if proof_code:
        return {"finding_id": finding_id, "code": proof_code.partition(":")[0], "message": NO_PROOF_MESSAGE}
    if group_message and str(group_message).strip():
        return {"finding_id": finding_id, "code": str(group_code or NOT_REPAIRED), "message": str(group_message).strip()}
    return {"finding_id": finding_id, "code": NOT_REPAIRED, "message": GENERIC_MESSAGE}


def complete_skipped(
    finding_ids: list[tuple[str, ...]],
    claimed: set[str],
    skipped: list[dict[str, str]],
    reason: Mapping[str, Any] | None,
) -> list[dict[str, str]]:
    """`skipped` with a record for every finding no candidate claims and no record names.

    The last line of defence for the contract that every finding ends in a candidate or a skip
    record. A record that exists but carries no message is given one too. Each entry of
    `finding_ids` is one finding's identifiers, the first being the one a new record carries:
    candidates name a finding by its stable id, and the retrieval skips by its snapshot id.
    """
    fallback_code = str((reason or {}).get("code") or NOT_REPAIRED)
    fallback_message = str((reason or {}).get("message") or "").strip() or GENERIC_MESSAGE
    completed: list[dict[str, str]] = []
    named: set[str] = set()
    for item in skipped:
        record = {key: str(value) for key, value in dict(item).items()}
        if not record.get("message", "").strip():
            record["message"] = fallback_message
            record["code"] = record.get("code") or fallback_code
        completed.append(record)
        named.add(record.get("finding_id", ""))
    for aliases in finding_ids:
        keys = [key for key in aliases if key]
        if not keys or any(key in claimed or key in named for key in keys):
            continue
        completed.append({"finding_id": keys[0], "code": fallback_code, "message": fallback_message})
        named.add(keys[0])
    return completed
