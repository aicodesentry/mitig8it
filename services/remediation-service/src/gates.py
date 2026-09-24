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

from .families import CODE_INJECTION_EVAL, COMMAND_ARGUMENTS, JAVASCRIPT, PYTHON, SQL_PARAMETERIZATION
from .models import FindingSnapshot
from .retrieval import Snapshot

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
DYNAMIC_CODE_MESSAGE = (
    "The site compiles a program rather than reading a value: new Function and the vm compile "
    "calls hand back something callable later, which no data parser can stand in for. Replacing "
    "it means deciding what the strings are allowed to compute, which is a design decision, not "
    "a rewrite."
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


def static_gate(snapshot: Snapshot, finding: FindingSnapshot, family: str, language: str) -> tuple[str, str] | None:
    """The `(code, message)` this finding is skipped with, or None when the agent may attempt it."""
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
