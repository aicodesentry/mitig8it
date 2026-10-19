"""Static, per-finding gates the engine applies before an agent is launched.

Each gate is a cheap lexical check over the exact snapshot that decides whether a bounded
repair of one family can even be attempted for one finding. A gate never repairs anything: it
returns the `(code, message)` the finding is skipped with, or None when the agent may try.
Skipping here is honest and attributable, where a half-informed agent would guess a placeholder
syntax or a shell quoting rule and produce a patch the harness cannot prove.
"""
from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

from .families import (
    CODE_INJECTION_EVAL,
    COMMAND_ARGUMENTS,
    COOKIE_FLAGS,
    JAVASCRIPT,
    PASSWORD_HASHING,
    PYTHON,
    SQL_PARAMETERIZATION,
    STATIC_ASSERTION,
    WORKFLOW,
    family_verification,
)
from .models import FindingSnapshot
from .retrieval import Snapshot
from .sites import SiteError, cookie_site, password_hash_site
from .verification.verifier import STATIC_ASSERTION_VERIFICATION_LEVEL, VERIFICATION_LEVELS

UNSUPPORTED_LANGUAGE_MESSAGE = (
    "The affected file is neither JavaScript/TypeScript nor Python, so no toolchain can check a repair of it."
)
PG_NOT_PROVEN_MESSAGE = "SQL auto-repair requires an exact package manifest proving the pg driver."
SHELL_PIPELINE_MESSAGE = (
    "The command string carries shell syntax an argument list cannot express, so the rewrite "
    "would silently change what runs: this one needs manual handling."
)
AMBIGUOUS_QUERY_API_MESSAGE = (
    "The query is handed to a helper whose placeholder syntax the snapshot does not show: no "
    "sqlite3, psycopg, or SQLAlchemy execute() call takes it at the finding, so a parameterized "
    "rewrite cannot be chosen safely."
)
MODEL_AUTHORED_COMMAND_MESSAGE = (
    "The command is the text a language model returned, so the model decides which program runs. "
    "An argument list would only move that decision from the shell to the program name: the fix "
    "is to map the model's answer onto an allowlist of commands, which needs a design decision "
    "this change does not make."
)
STATIC_ASSERTION_UNAVAILABLE_MESSAGE = (
    "This repair can only be shown to work by static assertion -- the rule fires on the file "
    "before the change and not after it, and nothing else in the file changed -- because no test "
    "can demonstrate that a workflow is secure. That verification level is not available yet, so "
    "the patch is withheld rather than published without evidence. The finding itself is reported "
    "with the change to make."
)
DYNAMIC_CODE_MESSAGE = (
    "The site compiles a program rather than reading a value: new Function and the vm compile "
    "calls hand back something callable later, which no data parser can stand in for. Replacing "
    "it means deciding what the strings are allowed to compute, which is a design decision, not "
    "a rewrite."
)

PASSWORD_LOOKUP_MESSAGE = (
    "The password digest is looked up in a store rather than compared, and a salted hash is "
    "different every time it is computed, so no lookup by it can ever match. Repairing it means "
    "fetching the account by its identifier and verifying the stored hash, which changes the "
    "query and the schema, not one function."
)
PASSWORD_OTHER_MODULE_MESSAGE = (
    "Another module calls this hashing function, and the repair changes what it returns. Those "
    "callers would compare a salted hash with a fresh one and reject every password, so the "
    "change is not made from this file alone."
)
# A site refusal that is a property of the code, not of what the template recognizes: no
# repair of the hashing function alone is safe here, written by a template or a model.
PASSWORD_GATE_REFUSALS = {
    "password_hash_used_for_lookup": PASSWORD_LOOKUP_MESSAGE,
    "password_hash_called_from_other_module": PASSWORD_OTHER_MODULE_MESSAGE,
}

COOKIE_SAMESITE_NONE_MESSAGE = (
    "The cookie is set with SameSite=None, which is how a cookie is made to travel on cross-site "
    "requests on purpose, for an embed or a cross-site sign-in. Setting it to Lax would break that "
    "flow rather than repair it, so whether the cookie should be cross-site at all is a design "
    "decision this change does not make."
)

# Python database APIs whose placeholder syntax the Python harness knows and the prompt names.
PYTHON_SQL_DRIVERS = ("sqlite3", "psycopg2", "psycopg", "sqlalchemy", "pymysql", "MySQLdb", "mysql.connector", "aiosqlite", "asyncpg")
_PYTHON_IMPORT_RE = re.compile(r"^[ \t]*(?:from[ \t]+([\w.]+)[ \t]+import\b|import[ \t]+([\w.]+(?:[ \t]*,[ \t]*[\w.]+)*))", re.MULTILINE)
_PYTHON_EXECUTE_RE = re.compile(r"\.(?:execute|executemany|executescript|exec_driver_sql)\s*\(|\btext\s*\(")
# A process call that hands a command line to a shell: `exec` and `execSync` always do, and
# `spawn`/`spawnSync` do when `shell: true` is set.
_JS_SHELL_CALL_RE = re.compile(r"(?<![\w$])(?:[\w$]+\.)?(?:exec|spawn)(?:Sync)?\s*\(")
# Shell syntax no argument list can express: a pipeline, a redirection, a command separator,
# a substitution, or a background job.
_SHELL_METACHARACTER_RE = re.compile(r"[|&;<>`]|\$\(")
# Compiling a string into something callable, as opposed to reading a value out of one.
_JS_DYNAMIC_CODE_RE = re.compile(r"\bnew\s+Function\s*\(|\bnew\s+vm\.Script\s*\(|\bvm\.(?:runIn\w*Context|compileFunction)\s*\(")
_PYTHON_SHELL_LINE_RE = re.compile(r"\b(?:subprocess\.\w+|os\.system|os\.popen|Popen|check_output|check_call|run)\s*\(")
_PYTHON_PIPE_RE = re.compile(r"\|")
# How far past the finding a Python query may travel before it is executed, in lines.
PYTHON_QUERY_WINDOW_AFTER = 30
PYTHON_QUERY_WINDOW_BEFORE = 5


def python_imports(source: str) -> set[str]:
    """The dotted module names a Python file imports at any indentation; a bounded lexical scan."""
    found: set[str] = set()
    for match in _PYTHON_IMPORT_RE.finditer(source):
        if match.group(1):
            found.add(match.group(1))
        else:
            found.update(part.strip() for part in match.group(2).split(",") if part.strip())
    return found


def _imports_driver(modules: set[str]) -> bool:
    return any(name == driver or name.startswith(driver + ".") for name in modules for driver in PYTHON_SQL_DRIVERS)


def _local_module_paths(snapshot: Snapshot, importer: str, name: str) -> list[str]:
    """Snapshot paths a dotted import may resolve to: beside the importer and at the repository root."""
    if name.startswith("."):
        return []
    relative = name.replace(".", "/")
    bases = {PurePosixPath(importer).parent.as_posix(), ""}
    candidates: list[str] = []
    for base in bases:
        for tail in (f"{relative}.py", f"{relative}/__init__.py"):
            path = f"{base}/{tail}" if base and base != "." else tail
            if path in snapshot.paths and path not in candidates:
                candidates.append(path)
    return candidates


def python_sql_api_known(snapshot: Snapshot, finding: FindingSnapshot) -> bool:
    """True when the finding's query reaches a known driver's execute() in this file.

    The driver has to be imported by the affected file or by a local module it imports (one
    level), and an execute-style call or SQLAlchemy `text(` has to appear in the lines around
    the finding. `execute_query(query)` against an unknown helper satisfies neither.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    imports = python_imports(source)
    known = _imports_driver(imports)
    if not known:
        for name in sorted(imports):
            for local in _local_module_paths(snapshot, path, name):
                if _imports_driver(python_imports(snapshot.full_content(local))):
                    known = True
                    break
            if known:
                break
    if not known:
        return False
    start = max(1, (finding.line_start or 1) - PYTHON_QUERY_WINDOW_BEFORE)
    end = (finding.line_end or finding.line_start or 1) + PYTHON_QUERY_WINDOW_AFTER
    window = snapshot.read(path, start, end).content
    return bool(_PYTHON_EXECUTE_RE.search(window))


def pg_dependency_proven(snapshot: Snapshot) -> bool:
    for path in snapshot.paths:
        if path.rsplit("/", 1)[-1] != "package.json":
            continue
        try:
            manifest = json.loads(snapshot.full_content(path))
        except (TypeError, ValueError):
            continue
        if not isinstance(manifest, dict):
            continue
        dependencies = {**(manifest.get("dependencies") or {}), **(manifest.get("devDependencies") or {})}
        if "pg" in dependencies:
            return True
    return False


def _window(snapshot: Snapshot, finding: FindingSnapshot, before: int, after: int) -> str:
    if not finding.line_start:
        return ""
    return snapshot.read(finding.affected_path, max(1, finding.line_start - before), (finding.line_end or finding.line_start) + after).content


def js_literal_command_text(expression: str) -> str:
    """The text inside the string literals of a JavaScript expression, interpolations dropped.

    A bounded lexical scan, not a parser. It answers one question: did the author write shell
    syntax into the command. An interpolated value or a concatenated identifier contributes
    nothing, because that is the untrusted data the repair exists to keep away from a shell.
    """
    out: list[str] = []
    index, end = 0, len(expression)
    while index < end:
        quote = expression[index]
        if quote in "'\"":
            index += 1
            while index < end and expression[index] != quote:
                if expression[index] == "\\":
                    index += 2
                    continue
                out.append(expression[index])
                index += 1
        elif quote == "`":
            index += 1
            while index < end and expression[index] != "`":
                if expression[index] == "\\":
                    index += 2
                    continue
                if expression.startswith("${", index):
                    depth, index = 1, index + 2
                    while index < end and depth:
                        depth += (expression[index] == "{") - (expression[index] == "}")
                        index += 1
                    continue
                out.append(expression[index])
                index += 1
        index += 1
    return "".join(out)


def javascript_shell_pipeline(snapshot: Snapshot, finding: FindingSnapshot) -> bool:
    """Whether a shell-mode process call near the finding needs semantics an argv list lacks.

    Running through a shell is not itself the problem. `spawn('tar -czf out.tgz ' + name,
    { shell: true })` is a command name and its arguments with a shell wrapped around them, and
    dropping the option while splitting the string into argv is the same rewrite `execFile`
    gets. What an argv list cannot express is shell syntax: a pipeline, a redirection, a
    separator, a substitution, or a background job. So the refusal is narrowed to a command
    whose own literal text carries one of those, where a rewrite would change what runs.
    """
    for line in _window(snapshot, finding, 3, 3).splitlines():
        call = _JS_SHELL_CALL_RE.search(line)
        if call and _SHELL_METACHARACTER_RE.search(js_literal_command_text(line[call.end():])):
            return True
    return False


def javascript_dynamic_code(snapshot: Snapshot, finding: FindingSnapshot) -> bool:
    """Whether the site compiles a program instead of reading a value.

    `eval(raw)` of a request value is a parser written the dangerous way: the repair is to parse
    the value as data and the harness proves nothing was compiled. `new Function(args, body)`,
    `new vm.Script(...)`, and the `vm` compile calls are not that. They hand back something the
    module calls later, with the string deciding what runs, so no data parser stands in for
    them. Replacing one means deciding what those strings are allowed to compute, which the
    engine refuses to guess.
    """
    return bool(_JS_DYNAMIC_CODE_RE.search(_window(snapshot, finding, 2, 2)))


def python_shell_pipeline(snapshot: Snapshot, finding: FindingSnapshot) -> bool:
    """A process call whose command line carries a pipe: an argv list cannot express it."""
    for line in _window(snapshot, finding, 3, 3).splitlines():
        if _PYTHON_SHELL_LINE_RE.search(line) and _PYTHON_PIPE_RE.search(line):
            return True
    return False


def model_authored_command(finding: FindingSnapshot) -> bool:
    """A command whose source is a language model's answer: the `*-llm-output-shell` rules.

    The rule is the only thing that knows the tainted value is the whole answer rather than one
    argument inside a literal command, so the decision is read from it, as the workflow family is.
    The generic command rules match the same line, and the clusterer may keep one of them as the
    finding's `rule_id`; the model rule then survives only in `evidence_details.extra.merged_rule_ids`.
    """
    details = getattr(finding, "evidence_details", None) or {}
    details = details if isinstance(details, dict) else {}
    extra = details.get("extra") if isinstance(details.get("extra"), dict) else {}
    merged = extra.get("merged_rule_ids") if isinstance(extra.get("merged_rule_ids"), list) else []
    return any("llm-output-shell" in str(rule_id or "") for rule_id in [finding.rule_id, *merged])


def static_assertion_level_available() -> bool:
    """Whether the verification level the workflow family needs has landed.

    The level is `feat/static-assertion-verification`'s to implement. The name is declared in the
    verifier so this question can be asked; membership in `VERIFICATION_LEVELS` is what makes it
    real, and adding it there is what turns the workflow family on.
    """
    return STATIC_ASSERTION_VERIFICATION_LEVEL in VERIFICATION_LEVELS


def static_gate(snapshot: Snapshot, finding: FindingSnapshot, family: str, language: str) -> tuple[str, str] | None:
    """The `(code, message)` this finding is skipped with, or None when the agent may attempt it."""
    if family_verification(family) == STATIC_ASSERTION and not static_assertion_level_available():
        # The patch side of this family is built and tested; what is missing is the only kind of
        # proof it could ever have. Publishing it anyway would put an unverified patch in front of
        # a maintainer under the same review as verified ones, so it is refused by name instead.
        return "static_assertion_verification_unavailable", STATIC_ASSERTION_UNAVAILABLE_MESSAGE
    if family == COMMAND_ARGUMENTS and model_authored_command(finding):
        return "model_authored_command", MODEL_AUTHORED_COMMAND_MESSAGE
    if language == WORKFLOW:
        # Nothing below applies: a workflow has no package manifest, no shell call and no
        # compiled string. The only gate it has is the one above.
        return None
    if family == PASSWORD_HASHING:
        try:
            password_hash_site(snapshot, finding, language)
        except SiteError as exc:
            if exc.code in PASSWORD_GATE_REFUSALS:
                return exc.code, PASSWORD_GATE_REFUSALS[exc.code]
    if family == COOKIE_FLAGS:
        try:
            cookie_site(snapshot, finding, language)
        except SiteError as exc:
            if exc.code == "cookie_samesite_none_is_deliberate":
                return exc.code, COOKIE_SAMESITE_NONE_MESSAGE
    if language == JAVASCRIPT:
        if family == SQL_PARAMETERIZATION and not pg_dependency_proven(snapshot):
            return "pg_dependency_not_proven", PG_NOT_PROVEN_MESSAGE
        if family == COMMAND_ARGUMENTS and javascript_shell_pipeline(snapshot, finding):
            return "shell_pipeline_unsupported", SHELL_PIPELINE_MESSAGE
        if family == CODE_INJECTION_EVAL and javascript_dynamic_code(snapshot, finding):
            return "dynamic_code_unsupported", DYNAMIC_CODE_MESSAGE
    elif language == PYTHON:
        if family == SQL_PARAMETERIZATION and not python_sql_api_known(snapshot, finding):
            return "ambiguous_query_api", AMBIGUOUS_QUERY_API_MESSAGE
        if family == COMMAND_ARGUMENTS and python_shell_pipeline(snapshot, finding):
            return "shell_pipeline_unsupported", SHELL_PIPELINE_MESSAGE
    return None
