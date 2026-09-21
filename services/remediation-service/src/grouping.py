"""Groups findings into the connected components one repair agent may work on.

Section 7 of the implementation plan requires one repair agent per connected group of
findings, grouped by shared files and call paths before execution, so that two agents can
never propose conflicting edits to the same file without a combined verification run.

Two findings are connected when they name any file in common. A finding's files are its own
affected path plus every repository path named by its scanner trace, because a source/sink
trace is exactly the call-path evidence the plan asks to group on. Trace content arrives from
the control plane and is treated as bounded untrusted data: only string path fields are read,
and the number of inspected steps is capped.
"""
from __future__ import annotations

from typing import Any

from .models import FindingSnapshot

TRACE_PATH_KEYS = ("path", "file_path", "file", "filename")
TRACE_LOCATION_KEYS = ("location", "physical_location", "position")
MAX_TRACE_STEPS = 100


def _string_paths(value: Any) -> set[str]:
    if not isinstance(value, dict):
        return set()
    return {value[key] for key in TRACE_PATH_KEYS if isinstance(value.get(key), str) and value[key]}


def trace_paths(trace: list[dict[str, Any]]) -> set[str]:
    paths: set[str] = set()
    for step in list(trace)[:MAX_TRACE_STEPS]:
        paths |= _string_paths(step)
        if isinstance(step, dict):
            for key in TRACE_LOCATION_KEYS:
                paths |= _string_paths(step.get(key))
    return paths


def finding_paths(finding: FindingSnapshot) -> set[str]:
    """Every repository path this finding is anchored to."""
    paths = set(trace_paths(finding.trace))
    if finding.affected_path:
        paths.add(finding.affected_path)
    return paths


def group_findings(findings: list[FindingSnapshot]) -> list[list[FindingSnapshot]]:
    """Returns connected components over shared file paths, in first-appearance order.

    A single finding always produces a single group, so a one-finding job behaves exactly as
    it did before grouping existed.
    """
    parent = list(range(len(findings)))

    def root(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = root(left), root(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    owner: dict[str, int] = {}
    for index, finding in enumerate(findings):
        for path in sorted(finding_paths(finding)):
            if path in owner:
                union(owner[path], index)
            else:
                owner[path] = index
    components: dict[int, list[FindingSnapshot]] = {}
    for index, finding in enumerate(findings):
        components.setdefault(root(index), []).append(finding)
    return [components[key] for key in sorted(components)]


def split_group_by_language(group: list[FindingSnapshot]) -> list[list[FindingSnapshot]]:
    """Splits one connected group into one sub-group per toolchain, in first-appearance order.

    A group is verified by one sandbox run of one language's harness, so a JavaScript finding
    and a Python finding that happen to share a trace path still get separate agent loops. A
    group whose findings all share a language is returned unchanged.
    """
    from .families import language_of_path

    by_language: dict[str | None, list[FindingSnapshot]] = {}
    for finding in group:
        by_language.setdefault(language_of_path(finding.affected_path), []).append(finding)
    return list(by_language.values())


def group_findings_by_language(findings: list[FindingSnapshot]) -> list[list[FindingSnapshot]]:
    """Connected components over shared paths, each further split by the affected file's language."""
    return [sub_group for group in group_findings(findings) for sub_group in split_group_by_language(group)]
