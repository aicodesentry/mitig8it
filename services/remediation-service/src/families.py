"""Repair families: which one a finding belongs to, and what its regression test must assert.

The engine uses the family to decide support; the agent loop names it in the task prompt and in
a coverage revision, with the harness assertion that proves a repair of that family, so the
model never has to infer either from the scanner's wording.
"""
from __future__ import annotations

from typing import Any

SQL_PARAMETERIZATION = "sql_parameterization"
COMMAND_ARGUMENTS = "command_arguments"
PATH_CONTAINMENT = "path_containment"

# The assertion each family's regression test makes with the sandbox harness
# (contracts/test-harness-v1.md). Quoted to the model verbatim, so it stays short and exact.
FAMILY_ASSERTIONS: dict[str, str] = {
    SQL_PARAMETERIZATION: (
        "const q = h.pg.queries[0]; h.assert.notIncludes(q.text, payload); "
        "h.assert.includes(JSON.stringify(q.values || []), payload)"
    ),
    COMMAND_ARGUMENTS: (
        "h.assert.argv(h.child_process.calls[0], payload) with payload the injected input you sent "
        "(such as 'x; rm -rf /'), not the command name: fails on a shell string (exec, execSync, or "
        "options.shell) and when the payload is not its own args element"
    ),
    PATH_CONTAINMENT: (
        "for (const r of h.fs.reads) h.assert.inside(r, base): each read is { path, resolved }; "
        "base is the directory the handler serves from, resolved as the module resolves it; "
        "a handler that answers 4xx and reads nothing also passes"
    ),
}


def rule_family(finding: Any) -> str | None:
    text = " ".join(
        str(value or "")
        for value in (finding.rule_id, finding.cwe_id, finding.category, finding.title, finding.message)
    ).lower()
    if "cwe-89" in text or "sql injection" in text:
        return SQL_PARAMETERIZATION
    if "cwe-78" in text or "command injection" in text:
        return COMMAND_ARGUMENTS
    if "cwe-22" in text or "path traversal" in text or "path containment" in text:
        return PATH_CONTAINMENT
    return None
