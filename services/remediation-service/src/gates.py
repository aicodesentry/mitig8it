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

from .families import COMMAND_ARGUMENTS, JAVASCRIPT, PYTHON, SQL_PARAMETERIZATION
from .models import FindingSnapshot
from .retrieval import Snapshot

UNSUPPORTED_LANGUAGE_MESSAGE = (
    "The affected file is neither JavaScript/TypeScript nor Python, so no toolchain can check a repair of it."
)
PG_NOT_PROVEN_MESSAGE = "SQL auto-repair requires an exact package manifest proving the pg driver."
SHELL_PIPELINE_MESSAGE = "Shell pipelines and shell-mode process execution require manual handling."
AMBIGUOUS_QUERY_API_MESSAGE = (
    "The query is handed to a helper whose placeholder syntax the snapshot does not show: no "
    "sqlite3, psycopg, or SQLAlchemy execute() call takes it at the finding, so a parameterized "
    "rewrite cannot be chosen safely."
)

# Python database APIs whose placeholder syntax the Python harness knows and the prompt names.
PYTHON_SQL_DRIVERS = ("sqlite3", "psycopg2", "psycopg", "sqlalchemy", "pymysql", "MySQLdb", "mysql.connector", "aiosqlite", "asyncpg")
_PYTHON_IMPORT_RE = re.compile(r"^[ \t]*(?:from[ \t]+([\w.]+)[ \t]+import\b|import[ \t]+([\w.]+(?:[ \t]*,[ \t]*[\w.]+)*))", re.MULTILINE)
_PYTHON_EXECUTE_RE = re.compile(r"\.(?:execute|executemany|executescript|exec_driver_sql)\s*\(|\btext\s*\(")
_JS_SHELL_RE = re.compile(r"\b(?:exec|spawn)\s*\([^\n]*(?:\||shell\s*:\s*true)")
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


def javascript_shell_pipeline(snapshot: Snapshot, finding: FindingSnapshot) -> bool:
    return bool(_JS_SHELL_RE.search(_window(snapshot, finding, 3, 3)))


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
    elif language == PYTHON:
        if family == SQL_PARAMETERIZATION and not python_sql_api_known(snapshot, finding):
            return "ambiguous_query_api", AMBIGUOUS_QUERY_API_MESSAGE
        if family == COMMAND_ARGUMENTS and python_shell_pipeline(snapshot, finding):
            return "shell_pipeline_unsupported", SHELL_PIPELINE_MESSAGE
    return None
