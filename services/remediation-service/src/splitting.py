"""Attributes a group proposal's hunks to findings, so one candidate can be built per finding.

A group proposal is one set of hunks and one regression test per finding. Publishing it as one
candidate ties every finding to every hunk: a hunk for a finding whose test still fails ships
beside a proven fix, and a reviewer cannot apply one finding's change without the others. The
engine therefore splits a verified proposal into per-finding candidates, and this module decides
which hunks belong to which finding.

Attribution rules, in order:

- A hunk whose `finding_id` names a group finding is owned by that finding. An untagged hunk is
  owned by the nearest finding on its path: one whose reported range it overlaps, else the one
  with the smallest line distance, ties going to request order. A hunk on a path no finding
  names has no owner and is shared by every candidate.
- An import-only hunk (it inserts nothing but import lines) is a prerequisite: it is shared by
  every finding whose own hunks use a name it binds, whatever it was tagged with. One nobody
  uses by name stays with its tagged owner.
- A finding's candidate carries its own hunks, the hunks that overlap its reported range (a
  co-located finding is fixed by the same hunk), the prerequisites they use, and the ownerless
  hunks.
- A hunk owned by an unproven finding is dropped from every candidate. A proven finding left
  with nothing, or whose test no longer passes without the dropped hunk, becomes unproven too
  with reason `dependent_hunk_unproven`.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Sequence

from .families import PYTHON, language_of_path
from .models import FindingSnapshot
from .patches import LocatedHunk

DEPENDENT_HUNK_UNPROVEN = "dependent_hunk_unproven"

_PYTHON_IMPORT_LINE_RE = re.compile(r"^\s*(?:import\s+\S|from\s+\S+\s+import\s+\S)")
_JS_IMPORT_LINE_RE = re.compile(
    r"^\s*(?:(?:const|let|var)\s+.+?=\s*require\s*\(.+\)\s*;?|import\s+.+?\s+from\s+['\"].+['\"]\s*;?|import\s+['\"].+['\"]\s*;?)\s*(?://.*)?$"
)
_JS_REQUIRE_BINDING_RE = re.compile(r"^\s*(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[\w$]+)\s*=\s*require\b")
_JS_IMPORT_BINDING_RE = re.compile(r"^\s*import\s+(.+?)\s+from\s+['\"]")
_JS_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")


def is_import_only(hunk: LocatedHunk) -> bool:
    """True when the hunk adds or rewrites nothing but import lines.

    Every line it adds is an import, and every replaced line it does not keep is an import too,
    so an insertion anchored on a code line and a widened `require` destructuring both count.
    """
    added = [line for line in hunk.replacement_lines if line not in hunk.original_lines]
    removed = [line for line in hunk.original_lines if line not in hunk.replacement_lines]
    if not added:
        return False
    pattern = _PYTHON_IMPORT_LINE_RE if language_of_path(hunk.path) == PYTHON else _JS_IMPORT_LINE_RE
    return all(pattern.match(line) for line in added + removed if line.strip())


def _python_import_names(line: str) -> set[str]:
    try:
        tree = ast.parse(line.strip())
    except SyntaxError:
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update((alias.asname or alias.name).split(".", 1)[0] for alias in node.names if alias.name != "*")
    return names


def _js_pattern_names(pattern: str) -> set[str]:
    """Names a JavaScript binding pattern introduces: `{ a, b: c }` binds a and c, `x` binds x."""
    text = pattern.strip()
    if text.startswith("{") or text.startswith("["):
        names: set[str] = set()
        for part in text.strip("{}[]").split(","):
            item = part.strip()
            if not item:
                continue
            if ":" in item:
                item = item.split(":", 1)[1].strip()
            match = _JS_IDENT_RE.search(item)
            if match:
                names.add(match.group(0))
        return names
    return {match.group(0) for match in [_JS_IDENT_RE.search(text)] if match}


def _js_import_names(line: str) -> set[str]:
    match = _JS_REQUIRE_BINDING_RE.match(line)
    if match:
        return _js_pattern_names(match.group(1))
    match = _JS_IMPORT_BINDING_RE.match(line)
    if not match:
        return set()
    clause = match.group(1).strip()
    names: set[str] = set()
    star = re.search(r"\*\s+as\s+([\w$]+)", clause)
    if star:
        names.add(star.group(1))
    braces = re.search(r"\{([^}]*)\}", clause)
    if braces:
        for part in braces.group(1).split(","):
            item = part.strip()
            if not item:
                continue
            if " as " in item:
                item = item.split(" as ", 1)[1].strip()
            found = _JS_IDENT_RE.search(item)
            if found:
                names.add(found.group(0))
    default = re.match(r"([\w$]+)", clause)
    if default and default.group(1) not in {"type", "typeof"}:
        names.add(default.group(1))
    return names


def imported_names(hunk: LocatedHunk) -> set[str]:
    """The names an import-only hunk newly binds: bound by an added line, not by a replaced one."""
    parse = _python_import_names if language_of_path(hunk.path) == PYTHON else _js_import_names
    added: set[str] = set()
    removed: set[str] = set()
    for line in hunk.replacement_lines:
        if line not in hunk.original_lines:
            added |= parse(line)
    for line in hunk.original_lines:
        if line not in hunk.replacement_lines:
            removed |= parse(line)
    return added - removed


def _finding_range(finding: FindingSnapshot) -> tuple[int, int]:
    start = max(1, int(finding.line_start or 1))
    return start, max(start, int(finding.line_end or start))


def _distance(hunk: LocatedHunk, finding: FindingSnapshot) -> int:
    start, end = _finding_range(finding)
    if hunk.start_line <= end and start <= hunk.end_line:
        return 0
    return min(abs(hunk.start_line - end), abs(start - hunk.end_line))


def _uses_any(hunks: Sequence[LocatedHunk], names: set[str]) -> bool:
    text = "\n".join(line for hunk in hunks for line in hunk.replacement_lines)
    return any(re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", text) for name in names)


@dataclass(frozen=True)
class HunkAttribution:
    # Hunk index to the finding that owns it, None for a prerequisite or an ownerless hunk.
    owners: dict[int, str | None]
    # Finding id to the hunk indexes its candidate carries, in proposal order.
    per_finding: dict[str, list[int]]
    prerequisites: frozenset[int] = field(default_factory=frozenset)
    shared: frozenset[int] = field(default_factory=frozenset)


def attribute_hunks(findings: Sequence[FindingSnapshot], hunks: Sequence[LocatedHunk]) -> HunkAttribution:
    by_id = {finding.stable_id: finding for finding in findings}
    owners: dict[int, str | None] = {}
    prerequisites: set[int] = set()
    shared: set[int] = set()
    for index, hunk in enumerate(hunks):
        if is_import_only(hunk):
            prerequisites.add(index)
            owners[index] = hunk.finding_id if hunk.finding_id in by_id else None
            continue
        if hunk.finding_id in by_id:
            owners[index] = hunk.finding_id
            continue
        on_path = [finding for finding in findings if finding.affected_path == hunk.path]
        if not on_path:
            owners[index] = None
            shared.add(index)
            continue
        owners[index] = min(on_path, key=lambda finding: _distance(hunk, finding)).stable_id

    per_finding: dict[str, list[int]] = {}
    for finding in findings:
        own = {
            index
            for index, hunk in enumerate(hunks)
            if index not in prerequisites
            and (
                owners[index] == finding.stable_id
                or (index not in shared and hunk.path == finding.affected_path and _distance(hunk, finding) == 0)
            )
        }
        per_finding[finding.stable_id] = sorted(own | shared)
    used: set[int] = set()
    for index in sorted(prerequisites):
        names = imported_names(hunks[index])
        for finding_id, indexes in per_finding.items():
            if names and _uses_any([hunks[i] for i in indexes if i not in prerequisites], names):
                indexes.append(index)
                used.add(index)
    for index in sorted(prerequisites - used):
        owner = owners[index]
        if owner in per_finding:
            per_finding[owner].append(index)
    for indexes in per_finding.values():
        indexes.sort()
    return HunkAttribution(owners, per_finding, frozenset(prerequisites), frozenset(shared))


def split_hunks(
    findings: Sequence[FindingSnapshot], hunks: Sequence[LocatedHunk], proven: Sequence[str]
) -> dict[str, list[LocatedHunk]]:
    """The hunks each proven finding's candidate carries, after dropping unproven findings' hunks."""
    attribution = attribute_hunks(findings, hunks)
    proven_ids = set(proven)
    # A prerequisite is shared by use, so an unproven tag on it does not drop it from a proven
    # finding that needs the name it binds.
    dropped = {
        index
        for index, owner in attribution.owners.items()
        if owner is not None and owner not in proven_ids and index not in attribution.prerequisites
    }
    return {
        finding_id: [hunks[index] for index in attribution.per_finding.get(finding_id, []) if index not in dropped]
        for finding_id in proven
    }
