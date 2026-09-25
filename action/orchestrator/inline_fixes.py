"""The App's suggestion geometry, ported so the action publishes the same suggestion blocks.

github-service renders a suggestion block only when a fix section carries a `hunk`: `suggestionFor`
in services/github-service/src/services/githubInternalOperations.js returns the `no_line_change`
reason the moment `section.hunk` is absent, and `buildFixSection` then falls back to a fenced diff
with "Shown as a diff: the fix cannot be expressed as a line replacement". The action filled
`unified_diff` and never `hunk`, so every fix it has ever produced was a diff nobody could click,
while `action/README.md` promised a suggestion block. The hunk is the whole difference.

The geometry is the api-service's, not a new one. `computeRegions` and `primaryRegion` in
services/api-service/src/services/remediationInlineFixes.js decide which contiguous regions of the
original a replacement changes, which of them the finding's comment carries and which travel as
extra hunks in comments of their own. They are ported line for line here rather than re-derived,
because a second opinion about where a fix starts is a fix the App and the action would render
differently on the same candidate. tests/test_inline_fix_parity.py executes the Node functions and
compares them against these on the same inputs, so a change on either side fails the build.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

# remediationInlineFixes.js: const MAX_ALIGNED_LINES = 1500;
MAX_ALIGNED_LINES = 1500

# remediationInlineFixes.js: const MAX_DIFF_CHARS = 6000;
MAX_DIFF_CHARS = 6000

TRUNCATION_NOTICE = "\n... (diff truncated; the full change is in the Mitig8it preview)"


def split_lines(text: Any) -> List[str]:
    """The JS `splitLines`: CRLF normalised, and one trailing newline dropped rather than kept."""
    normalized = str(text if text is not None else "").replace("\r\n", "\n")
    if not normalized:
        return []
    lines = normalized.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def truncate_diff(diff: Any) -> str:
    """The JS `truncateDiff`, which bounds what one comment can carry."""
    text = str(diff or "")
    if len(text) <= MAX_DIFF_CHARS:
        return text
    return text[:MAX_DIFF_CHARS] + TRUNCATION_NOTICE


def _preferred(preferred_line: Any) -> int:
    """`Number(preferredLine)` in JS: anything unparseable compares equal to no line number."""
    try:
        value = int(preferred_line)
    except (TypeError, ValueError):
        return -1
    return value


def _changed_blocks(a: Sequence[str], b: Sequence[str]) -> List[List[int]]:
    """The JS block walk over the middle: `[aStart, aEnd, bStart, bEnd]` per changed run.

    A middle too large to align line by line is one block, exactly as the JS gives up at the same
    size rather than paying for a quadratic table on a rewritten file.
    """
    if len(a) * len(b) > MAX_ALIGNED_LINES * MAX_ALIGNED_LINES:
        return [[0, len(a), 0, len(b)]]

    # The longest common subsequence table, filled from the end, as the JS fills it.
    table = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) - 1, -1, -1):
        row = table[i]
        below = table[i + 1]
        for j in range(len(b) - 1, -1, -1):
            row[j] = below[j + 1] + 1 if a[i] == b[j] else max(below[j], row[j + 1])

    blocks: List[List[int]] = []
    i = 0
    j = 0
    open_block: Optional[List[int]] = None
    while i < len(a) or j < len(b):
        if i < len(a) and j < len(b) and a[i] == b[j]:
            if open_block is not None:
                blocks.append(open_block)
                open_block = None
            i += 1
            j += 1
            continue
        if open_block is None:
            open_block = [i, i, j, j]
        if j < len(b) and (i >= len(a) or table[i][j + 1] >= table[i + 1][j]):
            j += 1
            open_block[3] = j
        else:
            i += 1
            open_block[1] = i
    if open_block is not None:
        blocks.append(open_block)
    return blocks


def compute_regions(
    original: Any,
    replacement: Any,
    preferred_line: Any = None,
) -> List[Dict[str, Any]]:
    """Every contiguous region of the original that the replacement changes, in file order.

    A port of `computeRegions`. Hunks are on the original's line numbers. A pure insertion is
    anchored to a neighbouring line, preferring the finding's own line, because GitHub's
    suggestion has to replace at least one line. Returns [] when nothing changes or the
    original is empty.
    """
    before = split_lines(original)
    after = split_lines(replacement)
    if not before:
        return []

    prefix = 0
    while prefix < len(before) and prefix < len(after) and before[prefix] == after[prefix]:
        prefix += 1
    suffix = 0
    while (
        suffix < len(before) - prefix
        and suffix < len(after) - prefix
        and before[len(before) - 1 - suffix] == after[len(after) - 1 - suffix]
    ):
        suffix += 1

    a = before[prefix : len(before) - suffix]
    b = after[prefix : len(after) - suffix]
    if not a and not b:
        return []

    wanted = _preferred(preferred_line)
    regions: List[Dict[str, Any]] = []
    for a_start, a_end, b_start, b_end in _changed_blocks(a, b):
        replacement_lines = list(b[b_start:b_end])
        if a_end > a_start:
            regions.append(
                {
                    "start_line": prefix + a_start + 1,
                    "end_line": prefix + a_end,
                    "original_lines": list(a[a_start:a_end]),
                    "replacement_lines": replacement_lines,
                }
            )
            continue
        # An insertion between original lines `prefix + a_start` and the one after it.
        previous = prefix + a_start
        following = previous + 1
        if following <= len(before) and (wanted == following or previous < 1):
            regions.append(
                {
                    "start_line": following,
                    "end_line": following,
                    "original_lines": [before[following - 1]],
                    "replacement_lines": [*replacement_lines, before[following - 1]],
                }
            )
        else:
            regions.append(
                {
                    "start_line": previous,
                    "end_line": previous,
                    "original_lines": [before[previous - 1]],
                    "replacement_lines": [before[previous - 1], *replacement_lines],
                }
            )

    # An insertion anchored on a line another region already replaces folds into that region.
    merged: List[Dict[str, Any]] = []
    for region in regions:
        last = merged[-1] if merged else None
        if last is not None and region["start_line"] <= last["end_line"]:
            lines = region["replacement_lines"]
            originals = region["original_lines"]
            if len(originals) == 1 and lines and lines[-1] == originals[0]:
                anchored = lines[:-1]
            else:
                anchored = lines[1:]
            last["replacement_lines"] = [*last["replacement_lines"], *anchored]
            continue
        merged.append(dict(region))
    return merged


def evidence_lines(evidence: Dict[str, Any]) -> List[str]:
    """The `**Evidence:**` lines of a fix's details block, as `evidenceLines` builds them.

    The engine states each candidate's evidence in full sentences under `summary`; the action
    was putting that list into `proof` instead, where `str()` on a Python list rendered
    `**Proof:** ['Regression test ...']` into the pull request. Both fields are built here now,
    each from the key the App reads.
    """
    summary = [
        str(item).strip()
        for item in (evidence.get("summary") or [])
        if str(item or "").strip()
    ]
    if summary:
        lines = summary[:20]
        digest = str(evidence.get("evidence_digest") or "")
        if digest:
            lines = [*lines, f"Evidence digest: {digest[:12]}."]
        return lines

    tests = [
        str(test.get("path") or test.get("name"))
        for test in (evidence.get("generated_tests") or [])
        if isinstance(test, dict) and (test.get("path") or test.get("name"))
    ]
    limitations = [str(item) for item in (evidence.get("limitations") or [])]
    lines = [
        f"Regression test {', '.join(tests)}: failed on the original code, passed on the fix."
        if tests
        else "Generated regression test: failed on the original code, passed on the fix."
    ]
    syntax_not_run = any(
        re.search(r"syntax check (skipped|unavailable)", item, re.IGNORECASE)
        for item in limitations
    )
    lines.append(
        "Syntax check: not run (see limitations)."
        if syntax_not_run
        else "Syntax check: passed on the fixed file."
    )
    digest = str(evidence.get("evidence_digest") or "")
    if digest:
        lines.append(f"Evidence digest: {digest[:12]}.")
    return lines


def proof_line(evidence: Dict[str, Any], finding: Dict[str, Any]) -> str:
    """What the regression test asserted, in one sentence, as `proofLine` states it."""
    tests = [
        test
        for test in (evidence.get("generated_tests") or [])
        if isinstance(test, dict) and (test.get("path") or test.get("name"))
    ]
    fingerprint = str(finding.get("fingerprint") or "")
    own = [test for test in tests if test.get("finding_id") and test.get("finding_id") == fingerprint]
    chosen = (own or tests or [None])[0]
    if chosen is None:
        return "the generated regression test failed on the original code and passed on the fix."
    name = str(chosen.get("path") or chosen.get("name"))
    stated = str(
        chosen.get("assertion") or chosen.get("asserts") or chosen.get("description") or ""
    ).strip().rstrip(".")
    path = str(finding.get("file_path") or "")
    line = finding.get("line_start")
    location = f" at {path}{f':{line}' if line else ''}" if path else ""
    what = str(finding.get("title") or finding.get("rule_id") or "finding")
    asserted = stated or f"the {what}{location} is no longer reproducible"
    return (
        f"regression test {name} asserts that {asserted}; it failed on the original code and "
        "passed on the fix."
    )


def primary_region(
    regions: Sequence[Dict[str, Any]],
    finding_line: Any,
) -> Optional[Dict[str, Any]]:
    """The region a finding's comment carries: the one on its line, else the nearest.

    A port of `primaryRegion`. The JS throws on an empty list rather than returning null; the
    caller here never has one, and None is returned instead of raising so a malformed candidate
    cannot take down a review that is otherwise ready to publish.
    """
    if not regions:
        return None
    try:
        line = int(finding_line)
    except (TypeError, ValueError):
        line = 0
    for region in regions:
        if region["start_line"] <= line <= region["end_line"]:
            return region
    best = None
    best_distance = None
    for region in regions:
        distance = min(abs(region["start_line"] - line), abs(region["end_line"] - line))
        if best_distance is None or distance < best_distance:
            best = region
            best_distance = distance
    return best
