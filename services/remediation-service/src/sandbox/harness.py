"""The service-supplied regression-test harness every sandbox workspace carries.

Agent-written regression tests run in a sandbox with no network and nothing installed, so a
test that requires express, supertest, pg, or a test framework crashes on both trees and proves
nothing. The harness is one dependency-free CommonJS file the service owns. It is materialized
at `.mitig8it/harness.js` next to the generated tests in both the baseline and the candidate
workspace, and it is never part of a candidate: not a patch, not a manifest entry, never applied.

The JavaScript source lives beside this module so the same bytes ship in the service image and
are asserted on by the test suite. Its API is documented in contracts/test-harness-v1.md.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

HARNESS_PATH = ".mitig8it/harness.js"
HARNESS_SOURCE_FILE = Path(__file__).with_name("harness.js")
# The harness travels inside every verification payload, so it stays small by construction.
MAX_HARNESS_BYTES = 16 * 1024
HARNESS_OCCUPIED_LIMITATION = (
    f"the repository already carries {HARNESS_PATH}, so the service test harness was not materialized"
)


@lru_cache(maxsize=1)
def harness_source() -> str:
    source = HARNESS_SOURCE_FILE.read_text(encoding="utf-8")
    if len(source.encode("utf-8")) > MAX_HARNESS_BYTES:
        raise ValueError("the sandbox test harness exceeds its size budget")
    return source


def harness_snapshot_entry() -> dict[str, str]:
    """The `{path, content}` entry the verifier adds to the sandbox payload's file list."""
    return {"path": HARNESS_PATH, "content": harness_source()}


def is_harness_path(path: str) -> bool:
    return path.strip("/") == HARNESS_PATH
