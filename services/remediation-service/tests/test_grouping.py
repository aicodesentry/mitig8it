from __future__ import annotations

from src.grouping import finding_paths, group_findings
from src.models import FindingSnapshot


def finding(identifier: str, path: str, trace: list[dict] | None = None) -> FindingSnapshot:
    return FindingSnapshot(snapshot_id=identifier, file_path=path, trace=trace or [])


def ids(groups: list[list[FindingSnapshot]]) -> list[list[str]]:
    return [[item.stable_id for item in group] for group in groups]


def test_single_finding_is_one_group():
    assert ids(group_findings([finding("a", "src/a.ts")])) == [["a"]]


def test_findings_in_different_files_are_separate_groups():
    groups = group_findings([finding("a", "src/a.ts"), finding("b", "src/b.ts")])
    assert ids(groups) == [["a"], ["b"]]


def test_findings_in_the_same_file_are_one_group():
    groups = group_findings([finding("a", "src/a.ts"), finding("b", "src/a.ts")])
    assert ids(groups) == [["a", "b"]]


def test_a_shared_trace_file_connects_findings_in_different_files():
    groups = group_findings(
        [
            finding("a", "src/a.ts", [{"path": "src/shared.ts", "line": 4}]),
            finding("b", "src/b.ts", [{"location": {"file_path": "src/shared.ts"}}]),
            finding("c", "src/c.ts"),
        ]
    )
    assert ids(groups) == [["a", "b"], ["c"]]


def test_groups_are_transitively_connected_and_keep_first_appearance_order():
    groups = group_findings(
        [
            finding("a", "src/a.ts"),
            finding("b", "src/b.ts"),
            finding("c", "src/c.ts", [{"path": "src/a.ts"}, {"path": "src/b.ts"}]),
        ]
    )
    assert ids(groups) == [["a", "b", "c"]]


def test_trace_paths_ignore_non_string_and_unbounded_content():
    hit = finding("a", "src/a.ts", [{"path": 7}, {"path": "src/b.ts"}, {"note": "not a path"}])
    assert finding_paths(hit) == {"src/a.ts", "src/b.ts"}
