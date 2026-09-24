"""The service-supplied regression-test harnesses every sandbox workspace carries.

Agent-written regression tests run in a sandbox with no network and nothing installed, so a
test that requires express, supertest, pg, flask, or a test framework crashes on both trees and
proves nothing. Each harness is one dependency-free file the service owns. The Node harness is
materialized at `.mitig8it/harness.js` and the Python harness at `.mitig8it/harness.py`, next to
the generated tests in both the baseline and the candidate workspace, and neither is ever part
of a candidate: not a patch, not a manifest entry, never applied.

The sources live beside this module so the same bytes ship in the service image and are
asserted on by the test suite. Their APIs are documented in contracts/test-harness-v1.md and
contracts/test-harness-python-v1.md.
"""
from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path

HARNESS_PATH = ".mitig8it/harness.js"
HARNESS_SOURCE_FILE = Path(__file__).with_name("harness.js")
PYTHON_HARNESS_PATH = ".mitig8it/harness.py"
PYTHON_HARNESS_SOURCE_FILE = Path(__file__).with_name("harness_py.py")
HARNESS_PATHS = frozenset({HARNESS_PATH, PYTHON_HARNESS_PATH})
# The third-party modules the Python harness fakes into `sys.modules` before it loads a
# repository module (`_install` in harness_py.py). Nothing is installed in the sandbox, but
# these names resolve there because the harness supplies them, so a generated regression test
# may import one: a proof that does `import psycopg` gets the same recorded fake the module
# under test gets, which is what lets it name the driver whose placeholder syntax it asserts on.
# Every other name stays rejected, because `_AutoStubFinder` would hand the test an inert stub
# and the proof would assert on nothing. `python_harness_modules()` keeps this in step with the
# harness source.
PYTHON_HARNESS_MODULES = frozenset(
    {"flask", "psycopg", "psycopg2", "pymysql", "sqlalchemy", "sqlite3", "subprocess"}
)
# Each harness travels inside every verification payload, so it stays small by construction.
# The Node budget was 16 KiB until the environment recorder and its two assertions were added
# for the JavaScript `hardcoded_credential` family, then 20 KiB until the dynamic-code recorder,
# `assert.noCode`, and `call` were added for `code_injection_eval`. 24 KiB is the next size that
# leaves room to extend an assertion without another budget change in the same commit.
MAX_HARNESS_BYTES = 24 * 1024
MAX_PYTHON_HARNESS_BYTES = 40 * 1024
HARNESS_OCCUPIED_LIMITATION = (
    f"the repository already carries {HARNESS_PATH}, so the service test harness was not materialized"
)
PYTHON_HARNESS_OCCUPIED_LIMITATION = (
    f"the repository already carries {PYTHON_HARNESS_PATH}, so the service Python test harness was not materialized"
)


@lru_cache(maxsize=1)
def harness_source() -> str:
    source = HARNESS_SOURCE_FILE.read_text(encoding="utf-8")
    if len(source.encode("utf-8")) > MAX_HARNESS_BYTES:
        raise ValueError("the sandbox test harness exceeds its size budget")
    return source


@lru_cache(maxsize=1)
def python_harness_source() -> str:
    source = PYTHON_HARNESS_SOURCE_FILE.read_text(encoding="utf-8")
    if len(source.encode("utf-8")) > MAX_PYTHON_HARNESS_BYTES:
        raise ValueError("the sandbox Python test harness exceeds its size budget")
    return source


@lru_cache(maxsize=1)
def python_harness_modules() -> frozenset[str]:
    """The module names the Python harness fakes, read out of the harness source itself.

    Parsed rather than restated so `PYTHON_HARNESS_MODULES` cannot drift away from the table
    that actually supplies them. `test_harness` asserts the two agree.
    """
    for node in ast.walk(ast.parse(python_harness_source())):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Dict):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "fakes" for target in node.targets):
            continue
        return frozenset(
            key.value
            for key in node.value.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        )
    raise ValueError("the Python harness no longer declares a `fakes` module table")


def harness_snapshot_entry() -> dict[str, str]:
    """The `{path, content}` entry the verifier adds to the sandbox payload's file list."""
    return {"path": HARNESS_PATH, "content": harness_source()}


def python_harness_snapshot_entry() -> dict[str, str]:
    return {"path": PYTHON_HARNESS_PATH, "content": python_harness_source()}


def is_harness_path(path: str) -> bool:
    return path.strip("/") in HARNESS_PATHS
