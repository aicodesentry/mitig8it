"""Repair families: which one a finding belongs to, and what its regression test must assert.

The engine uses the family to decide support; the agent loop names it in the task prompt and in
a coverage revision, with the harness assertion that proves a repair of that family, so the
model never has to infer either from the scanner's wording.

A family is language-independent: the same CWE-89 finding is `sql_parameterization` in a Node
router and in a Flask view. What differs per language is the toolchain (Node or Python) and the
harness assertion, so both are looked up by the affected file's language.
"""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

SQL_PARAMETERIZATION = "sql_parameterization"
COMMAND_ARGUMENTS = "command_arguments"
PATH_CONTAINMENT = "path_containment"
HARDCODED_CREDENTIAL = "hardcoded_credential"
CODE_INJECTION_EVAL = "code_injection_eval"

ALL_FAMILIES = (SQL_PARAMETERIZATION, COMMAND_ARGUMENTS, PATH_CONTAINMENT, HARDCODED_CREDENTIAL, CODE_INJECTION_EVAL)

JAVASCRIPT = "javascript"
PYTHON = "python"
SUPPORTED_LANGUAGES = (JAVASCRIPT, PYTHON)

JAVASCRIPT_SUFFIXES = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
PYTHON_SUFFIXES = frozenset({".py"})

# The families each toolchain can repair and prove. A family is listed for a language only once
# the harness can observe the repair: `hardcoded_credential` joined JavaScript when the Node
# harness could record an environment read (`h.assert.envRead`), and `code_injection_eval`
# joined it when the harness could record `eval`, `new Function`, the `vm` compile calls, and a
# string timer without running any of them (`h.assert.noCode`). Both toolchains now repair every
# family; what still decides support per finding is the static gate, which refuses a site that
# compiles a program rather than reading a value.
LANGUAGE_FAMILIES: dict[str, frozenset[str]] = {
    JAVASCRIPT: frozenset(ALL_FAMILIES),
    PYTHON: frozenset(ALL_FAMILIES),
}

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
        "h.fs.reads.length = 0 then h.assert.inside(h.fs.reads, base, { payload }) for payload "
        "'../../etc/passwd' and '..%2f..%2fetc%2fpasswd', then once for a legitimate name; base is "
        "the served directory as the module resolves it. It passes only when a traversal payload "
        "records no read, so resolve with path.resolve(base, name) and answer 400 before any fs "
        "access unless the resolved path is base or starts with base + path.sep; path.basename fails"
    ),
    HARDCODED_CREDENTIAL: (
        "const m = h.load(path, { env: { NAME: 'value-from-env' } }); h.assert.envRead('NAME'); "
        "h.assert.notInSource(m, literal), and h.assert.equal(m.<identifier>, 'value-from-env') when "
        "the module exports it: the value must come from process.env.NAME, with NAME derived from "
        "the identifier the literal was bound to, and the literal must be gone from the file"
    ),
    CODE_INJECTION_EVAL: (
        "with FUNC the function at the finding: h.call(m.FUNC, ...) with a payload that would run "
        "code; h.assert.noCode(); then h.assert.equal(JSON.stringify(h.call(m.FUNC, ...'[1, 2]'...).value), "
        "'[1,2]'): the payload must never be compiled (eval, new Function, the vm compile calls, and "
        "a string setTimeout/setInterval are stubbed and recorded) while a JSON document still parses"
    ),
}

# The Python harness assertions (contracts/test-harness-python-v1.md).
PYTHON_FAMILY_ASSERTIONS: dict[str, str] = {
    SQL_PARAMETERIZATION: (
        "q = h.db.queries[0]; h.assert_not_includes(q['sql'], payload); "
        "h.assert_includes(repr(q['params']), payload): the payload must reach the driver as a "
        "bound parameter (sqlite3 '?', psycopg '%s', SQLAlchemy text() ':name'), never in the SQL text"
    ),
    COMMAND_ARGUMENTS: (
        "h.assert_argv(h.subprocess.calls[0], payload) with payload the injected input you sent "
        "(such as 'x; rm -rf /'): fails on os.system, shell=True, or a single command string, and "
        "when the payload is not its own element of the args list"
    ),
    PATH_CONTAINMENT: (
        "h.fs.reads.clear() then h.assert_inside(h.fs.reads, base, payload=payload) for payload "
        "'../../etc/passwd' and '..%2f..%2fetc%2fpasswd', then once for a legitimate name; base is "
        "the served directory as the module resolves it. It passes only when a traversal payload "
        "records no open() at all, so resolve with os.path.realpath(os.path.join(base, name)) and "
        "abort(400) before any file access unless the result is base or starts with base + os.sep"
    ),
    HARDCODED_CREDENTIAL: (
        "m = h.load(path, env={'NAME': 'value-from-env'}); h.assert_equal(m.NAME, 'value-from-env'); "
        "h.assert_env_read('NAME'); h.assert_not_in_source(m, literal): the module must take the "
        "secret from os.environ and no longer carry the literal"
    ),
    CODE_INJECTION_EVAL: (
        "with FUNC the function at the finding: h.call(m.FUNC, \"__import__('os').system('id')\"); "
        "h.assert_no_commands(); h.assert_equal(h.call(m.FUNC, '[1, 2]').value, [1, 2]): the payload "
        "must never run (os.system and subprocess are stubbed and recorded) while a literal still parses"
    ),
}


def language_of_path(path: str | None) -> str | None:
    """The toolchain a file belongs to, by extension, or None when neither can check it."""
    if not path:
        return None
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in JAVASCRIPT_SUFFIXES:
        return JAVASCRIPT
    if suffix in PYTHON_SUFFIXES:
        return PYTHON
    return None


def family_assertion(family: str | None, language: str | None) -> str | None:
    table = PYTHON_FAMILY_ASSERTIONS if language == PYTHON else FAMILY_ASSERTIONS
    return table.get(family or "")


def family_supported(family: str | None, language: str | None) -> bool:
    return family is not None and language is not None and family in LANGUAGE_FAMILIES.get(language, frozenset())


def rule_family(finding: Any) -> str | None:
    text = " ".join(
        str(value or "")
        for value in (finding.rule_id, finding.cwe_id, finding.category, finding.title, finding.message)
    ).lower()
    if "cwe-89" in text or "sql injection" in text or "sql.injection" in text:
        return SQL_PARAMETERIZATION
    if "cwe-78" in text or "command injection" in text or "command.injection" in text:
        return COMMAND_ARGUMENTS
    if "cwe-22" in text or "path traversal" in text or "path containment" in text or "path.traversal" in text:
        return PATH_CONTAINMENT
    if "cwe-798" in text or "hardcoded credential" in text or "hardcoded.credential" in text or (
        "hardcoded" in text and any(term in text for term in ("secret", "password", "api key", "api_key", "token"))
    ):
        return HARDCODED_CREDENTIAL
    if "cwe-95" in text or "code injection" in text or "code.injection" in text or "eval" in text.split() or ".eval" in text:
        return CODE_INJECTION_EVAL
    return None
