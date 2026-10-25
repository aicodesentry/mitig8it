"""The ported suggestion geometry must still behave like the Node it was ported from.

test_node_parity.py compares literals, which is enough for a filter or a cap. `computeRegions` is
an algorithm, and an algorithm copied into another language drifts in ways no literal comparison
sees: an off-by-one on an insertion anchor, a different tie-break in the alignment, a merge rule
applied in the other order. So these tests execute the Node functions and the Python ones on the
same inputs and compare the results.

The Node module cannot simply be required: remediationInlineFixes.js pulls in the api-service's
database layer and its logger. The functions are extracted from its source by name and evaluated
on their own instead, which also means a rename fails here loudly rather than silently testing
nothing.

The tests that read that source are marked `repo_definition`: comparing two files of this
repository is an assertion about the repository, and the image has no reason to carry the
api-service module. The tests that only exercise the port run everywhere, including in the image.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from orchestrator import inline_fixes

REPO_ROOT = Path(__file__).resolve().parents[2]
INLINE_FIXES_JS = REPO_ROOT / "services/api-service/src/services/remediationInlineFixes.js"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="the parity check runs the Node functions"
)


def extract(source: str, declaration: str) -> str:
    """One top-level `function name(...) { ... }` from the module, by brace balance."""
    start = source.index(declaration)
    depth = 0
    index = source.index("{", start)
    for position in range(index, len(source)):
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
            if depth == 0:
                return source[start : position + 1]
    raise AssertionError(f"{declaration} is not brace balanced")


def node_regions(cases: list[dict]) -> list:
    """Run the real `computeRegions` and `computeHunk` over the cases, in one node process."""
    assert INLINE_FIXES_JS.is_file(), f"expected the Node source at {INLINE_FIXES_JS}"
    source = INLINE_FIXES_JS.read_text(encoding="utf-8")
    for name in ("function splitLines(", "function computeRegions(", "function computeHunk("):
        assert name in source, f"remediationInlineFixes.js no longer declares {name}text"
    assert "const MAX_ALIGNED_LINES = " in source, "MAX_ALIGNED_LINES is no longer declared"

    script = "\n".join(
        [
            extract(source, "function splitLines("),
            source[source.index("const MAX_ALIGNED_LINES = ") :].split("\n")[0],
            extract(source, "function computeRegions("),
            extract(source, "function computeHunk("),
            "const cases = JSON.parse(process.env.PARITY_CASES);",
            "const out = cases.map((c) => {",
            "  const regions = computeRegions(c.original, c.replacement, c.preferred);",
            "  return { regions, hunk: computeHunk(c.original, c.replacement, c.line) };",
            "});",
            "process.stdout.write(JSON.stringify(out));",
        ]
    )
    completed = subprocess.run(
        ["node", "-e", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={**os.environ, "PARITY_CASES": json.dumps(cases)},
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


# The shapes that matter, including the one the trial found: a Django SECRET_KEY literal
# replaced in place on one line, and a two-region fix that adds an import at the top and
# rewrites a call further down.
SECRET_KEY_ORIGINAL = (
    "from pathlib import Path\n"
    "\n"
    "BASE_DIR = Path(__file__).resolve().parent.parent\n"
    "\n"
    "SECRET_KEY = 'django-insecure-9a$k2!f3@x0z^1v8p&q7'\n"
    "\n"
    "DEBUG = True\n"
)
SECRET_KEY_REPLACEMENT = SECRET_KEY_ORIGINAL.replace(
    "SECRET_KEY = 'django-insecure-9a$k2!f3@x0z^1v8p&q7'",
    "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']",
)

TWO_REGION_ORIGINAL = (
    "const express = require('express');\n"
    "const app = express();\n"
    "\n"
    "app.get('/ping', (req, res) => {\n"
    "  exec('ping -c 2 ' + req.query.host, (err, out) => res.send(out));\n"
    "});\n"
)
TWO_REGION_REPLACEMENT = (
    "const express = require('express');\n"
    "const { execFile } = require('child_process');\n"
    "const app = express();\n"
    "\n"
    "app.get('/ping', (req, res) => {\n"
    "  execFile('ping', ['-c', '2', req.query.host], (err, out) => res.send(out));\n"
    "});\n"
)

CASES = [
    # The trial's only fix: one line replaced, one region, the finding's own line.
    {"original": SECRET_KEY_ORIGINAL, "replacement": SECRET_KEY_REPLACEMENT, "preferred": 5, "line": 5},
    # A two-region fix: an inserted require at the top and a rewritten call below.
    {"original": TWO_REGION_ORIGINAL, "replacement": TWO_REGION_REPLACEMENT, "preferred": 5, "line": 5},
    # The same two-region fix, with the finding on the inserted region's anchor instead.
    {"original": TWO_REGION_ORIGINAL, "replacement": TWO_REGION_REPLACEMENT, "preferred": 2, "line": 2},
    # Nothing changes.
    {"original": "a\nb\nc\n", "replacement": "a\nb\nc\n", "preferred": 2, "line": 2},
    # An empty original has no region to anchor to.
    {"original": "", "replacement": "a\n", "preferred": 1, "line": 1},
    # A pure insertion at the very top, where `previous < 1` forces the following line.
    {"original": "a\nb\n", "replacement": "x\na\nb\n", "preferred": 99, "line": 1},
    # A pure insertion in the middle, anchored backwards because the finding is elsewhere.
    {"original": "a\nb\nc\n", "replacement": "a\nb\nx\nc\n", "preferred": 99, "line": 1},
    # The same insertion with the finding on the following line, anchored forwards.
    {"original": "a\nb\nc\n", "replacement": "a\nb\nx\nc\n", "preferred": 3, "line": 3},
    # A deletion only.
    {"original": "a\nb\nc\n", "replacement": "a\nc\n", "preferred": 2, "line": 2},
    # A whole-file rewrite.
    {"original": "a\nb\nc\n", "replacement": "x\ny\n", "preferred": 1, "line": 1},
    # Three separate regions, so the merge and the nearest-region choice both run.
    {
        "original": "a\nb\nc\nd\ne\nf\ng\n",
        "replacement": "A\nb\nc\nD\ne\nf\nG\n",
        "preferred": 4,
        "line": 4,
    },
    # A finding line outside every region: the nearest one carries the comment.
    {
        "original": "a\nb\nc\nd\ne\nf\ng\n",
        "replacement": "A\nb\nc\nd\ne\nf\nG\n",
        "preferred": 4,
        "line": 4,
    },
    # No trailing newline on either side.
    {"original": "a\nb", "replacement": "a\nB", "preferred": 2, "line": 2},
    # CRLF, which splitLines normalises before anything is compared.
    {"original": "a\r\nb\r\n", "replacement": "a\r\nB\r\n", "preferred": 2, "line": 2},
    # No preferred line at all.
    {"original": "a\nb\nc\n", "replacement": "a\nb\nx\nc\n", "preferred": None, "line": 0},
]


@pytest.mark.repo_definition
def test_compute_regions_matches_the_api_service():
    expected = node_regions(CASES)
    for case, want in zip(CASES, expected, strict=True):
        got = inline_fixes.compute_regions(case["original"], case["replacement"], case["preferred"])
        assert got == want["regions"], f"computeRegions differs on {case!r}"


@pytest.mark.repo_definition
def test_complete_hunk_matches_the_api_service():
    expected = node_regions(CASES)
    for case, want in zip(CASES, expected, strict=True):
        got = inline_fixes.compute_hunk(case["original"], case["replacement"], case["line"])
        assert got == want["hunk"], f"computeHunk differs on {case!r}"


def test_the_secret_key_shape_is_a_single_line_suggestion():
    """The trial's one fix, which was published as a diff because `hunk` was never filled."""
    regions = inline_fixes.compute_regions(SECRET_KEY_ORIGINAL, SECRET_KEY_REPLACEMENT, 5)
    assert len(regions) == 1
    hunk = inline_fixes.compute_hunk(SECRET_KEY_ORIGINAL, SECRET_KEY_REPLACEMENT, 5)
    assert hunk["start_line"] == 5
    assert hunk["end_line"] == 5
    assert hunk["replacement_lines"] == ["SECRET_KEY = os.environ['DJANGO_SECRET_KEY']"]


def test_a_two_region_fix_is_one_complete_clickable_repair():
    hunk = inline_fixes.compute_hunk(TWO_REGION_ORIGINAL, TWO_REGION_REPLACEMENT, 5)
    assert hunk["start_line"] == 2 and hunk["end_line"] == 5
    replacement = "\n".join(hunk["replacement_lines"])
    assert "require('child_process')" in replacement
    assert "execFile(" in replacement


@pytest.mark.repo_definition
def test_max_aligned_lines_matches_the_api_service():
    source = INLINE_FIXES_JS.read_text(encoding="utf-8")
    line = next(
        line for line in source.splitlines() if line.startswith("const MAX_ALIGNED_LINES = ")
    )
    assert int(line.split("=")[1].strip().rstrip(";")) == inline_fixes.MAX_ALIGNED_LINES


@pytest.mark.repo_definition
def test_max_diff_chars_matches_the_api_service():
    source = INLINE_FIXES_JS.read_text(encoding="utf-8")
    line = next(line for line in source.splitlines() if line.startswith("const MAX_DIFF_CHARS = "))
    assert int(line.split("=")[1].strip().rstrip(";")) == inline_fixes.MAX_DIFF_CHARS


# The proof and evidence sentences, run through both renderers on the same candidates. The
# static assertion and the no-test cases are the ones that matter: a sentence there that differs
# between the App and the action, or that claims a regression test ran, is a false trust claim.
PROOF_FINDING = {
    "id": "f1",
    "fingerprint": "f1",
    "rule_id": "cwe-89.sql-injection",
    "title": "SQL injection",
    "file_path": "services/orders.js",
    "line_start": 3,
}
PROOF_CASES = [
    {"level": "static_assertion", "evidence": {"verification_level": "static_assertion"}},
    {
        "level": "static_assertion",
        "evidence": {
            "verification_level": "static_assertion",
            "generated_tests": [{"path": "tests/x.test.js", "finding_id": "f1"}],
        },
    },
    {"level": "isolated_job", "evidence": {"verification_level": "isolated_job"}},
    {"level": "", "evidence": {}},
    {
        "level": "isolated_job",
        "evidence": {
            "verification_level": "isolated_job",
            "generated_tests": [{"path": "tests/orders.test.js", "finding_id": "f1"}],
            "limitations": ["syntax check skipped"],
            "evidence_digest": "a" * 64,
        },
    },
    {
        "level": "isolated_job",
        "evidence": {
            "verification_level": "isolated_job",
            "generated_tests": [
                {"path": "tests/orders.test.js", "finding_id": "f1", "assertion": "a quoted id is data."}
            ],
        },
    },
]


def node_proofs(cases: list[dict]) -> list:
    source = INLINE_FIXES_JS.read_text(encoding="utf-8")
    start = source.index("const STATIC_ASSERTION_LEVEL = ")
    constants = source[start : source.index("function candidateLevel(")]
    script = "\n".join(
        [
            constants,
            extract(source, "function candidateLevel("),
            extract(source, "function evidenceLines("),
            extract(source, "function proofLine("),
            "const cases = JSON.parse(process.env.PARITY_CASES);",
            "const finding = JSON.parse(process.env.PARITY_FINDING);",
            "const out = cases.map((c) => {",
            "  const candidate = { verification_level: c.level, preview: { evidence: c.evidence } };",
            "  return { proof: proofLine(candidate, finding), evidence: evidenceLines(candidate) };",
            "});",
            "process.stdout.write(JSON.stringify(out));",
        ]
    )
    completed = subprocess.run(
        ["node", "-e", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={
            **os.environ,
            "PARITY_CASES": json.dumps(cases),
            "PARITY_FINDING": json.dumps(PROOF_FINDING),
        },
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


@pytest.mark.repo_definition
def test_proof_and_evidence_sentences_match_the_api_service():
    expected = node_proofs(PROOF_CASES)
    for case, want in zip(PROOF_CASES, expected, strict=True):
        proof = inline_fixes.proof_line(case["evidence"], PROOF_FINDING, case["level"])
        evidence = inline_fixes.evidence_lines(case["evidence"], case["level"])
        assert proof == want["proof"], f"proofLine differs on {case!r}"
        assert evidence == want["evidence"], f"evidenceLines differs on {case!r}"
        if case["level"] == "static_assertion" or not case["evidence"].get("generated_tests"):
            assert "regression test failed" not in proof.lower()
            assert "failed on the original code" not in proof
            assert not any("failed on the original code" in line for line in evidence)
