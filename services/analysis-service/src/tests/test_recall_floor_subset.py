"""The committed corpus subset behind the required recall floor, checked without a scan.

`scripts/replay/fixture_subset.py check` scans the subset in its own CI job. What can go wrong
without a scan is checked here: a file edited by hand, a file left behind, a licence missing, a
label the full baseline holds as hit that the subset quietly stopped carrying, and an
`expected.json` that names different labels from the manifest.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
SUBSET_PY = REPO_ROOT / "scripts" / "replay" / "fixture_subset.py"
CORPUS = REPO_ROOT / "benchmarks" / "vulnerable-corpus"


def _load():
    spec = importlib.util.spec_from_file_location("fixture_subset_under_test", SUBSET_PY)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUBSET = _load()
MANIFEST = SUBSET.load_manifest()


def test_the_committed_files_are_exactly_what_the_manifest_records():
    assert SUBSET.manifest_problems(MANIFEST) == []


def test_every_repository_is_permissively_licensed_and_its_licence_is_committed():
    labels = json.loads((CORPUS / "labels.json").read_text(encoding="utf-8"))
    licence_of = {item["repo"]: item["licence"] for item in labels["repositories"]}
    for item in MANIFEST["repositories"]:
        assert licence_of[item["repo"]] in SUBSET.PERMISSIVE_LICENCES
        assert item["licence"] == licence_of[item["repo"]]
        assert item["licence_files"], f"{item['repo']} has no licence file"
        for relative in item["licence_files"]:
            assert (SUBSET.LICENCES / SUBSET.repo_dir(item["repo"]) / relative).is_file()


def test_the_subset_carries_every_permissive_label_the_full_baseline_holds_as_hit():
    """The floor cannot fall by the subset shrinking: a hit label has to be in it."""
    labels = json.loads((CORPUS / "labels.json").read_text(encoding="utf-8"))
    licence_of = {item["repo"]: item["licence"] for item in labels["repositories"]}
    baseline = json.loads((CORPUS / "recall-baseline.json").read_text(encoding="utf-8"))["labels"]
    should = {
        label["id"]
        for label in labels["labels"]
        if baseline[label["id"]]["hit"] and licence_of[label["repo"]] in SUBSET.PERMISSIVE_LICENCES
    }
    carried = {label_id for item in MANIFEST["files"] for label_id in item["labels"]}
    assert should == carried


def test_expected_names_exactly_the_manifest_labels_and_records_the_floor():
    expected, floor = SUBSET.load_expected()
    carried = {label_id for item in MANIFEST["files"] for label_id in item["labels"]}
    assert set(expected) == carried
    assert floor == sum(1 for entry in expected.values() if entry["hit"])


def test_no_committed_file_still_holds_a_secret_the_build_redacted():
    for item in MANIFEST["files"]:
        for redaction in item.get("redacted") or []:
            assert redaction["line"] > 0
            assert redaction["gitleaks_rule"]


def test_a_changed_byte_and_a_stray_file_are_both_reported(tmp_path):
    trees = tmp_path / "trees"
    licences = tmp_path / "licences"
    shutil.copytree(SUBSET.TREES, trees)
    shutil.copytree(SUBSET.LICENCES, licences)
    first = MANIFEST["files"][0]
    target = trees / SUBSET.repo_dir(first["repo"]) / first["path"]
    target.write_bytes(target.read_bytes() + b"\n")
    (trees / "stray.py").write_text("x = 1\n", encoding="utf-8")

    problems = SUBSET.manifest_problems(MANIFEST, trees, licences)

    assert f"{first['repo']}/{first['path']}: differs from the pinned file" in problems
    assert "stray.py: on disk but not in the manifest" in problems


def test_redaction_keeps_every_line_and_column():
    text = "a = 1\nKEY = 'abcdef0123456789'\n-----BEGIN KEY-----\nzzz\n-----END KEY-----\nb = 2\n"
    secrets = [
        {"Secret": "abcdef0123456789", "StartLine": 2, "RuleID": "generic-api-key"},
        {"Secret": "-----BEGIN KEY-----\nzzz\n-----END KEY-----", "StartLine": 3, "RuleID": "private-key"},
    ]
    redacted, applied = SUBSET.redact(text, secrets)
    assert len(redacted) == len(text)
    assert redacted.count("\n") == text.count("\n")
    assert "abcdef" not in redacted and "BEGIN" not in redacted
    assert redacted.splitlines()[0] == "a = 1" and redacted.splitlines()[-1] == "b = 2"
    assert [entry["line"] for entry in applied] == [2, 3]


@pytest.mark.parametrize("hit,floor,fails", [(105, 105, False), (106, 105, False), (104, 105, True)])
def test_the_floor(hit, floor, fails):
    assert (SUBSET.floor_message(hit, floor) is not None) is fails
