"""The Action's half of `.mitig8it.yml`, against the contract both halves are built from.

contracts/repository-configuration-v1.json states the glob dialect and the parse rules once.
services/api-service/tests/repositoryConfig.test.js runs the same cases through the App's
implementation. Neither side is tested against the other's behaviour, because then the first one
to drift would take the other with it; both are tested against the written contract, so a change
in either has to change the contract first, and the change shows up in one diff on both sides.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orchestrator import pr_scope, repo_config

pytest.importorskip("yaml", reason="PyYAML parses .mitig8it.yml")

CONTRACT = json.loads(
    (Path(__file__).resolve().parents[2] / "contracts/repository-configuration-v1.json").read_text(encoding="utf-8")
)


# --- the dialect ------------------------------------------------------------------------------

@pytest.mark.parametrize("case", CONTRACT["match_cases"], ids=lambda case: case["name"])
def test_the_contract_match_cases(case):
    exclusions = repo_config.Exclusions(case["patterns"])
    for path in case["excluded"]:
        assert exclusions.matches(path), f"{path!r} should be excluded by {case['patterns']!r}"
    for path in case["kept"]:
        assert not exclusions.matches(path), f"{path!r} should be kept by {case['patterns']!r}"


@pytest.mark.parametrize("case", CONTRACT["parse_cases"], ids=lambda case: case["name"])
def test_the_contract_parse_cases(case):
    if case["valid"]:
        assert list(repo_config.parse(case["yaml"]).patterns) == case["patterns"]
    else:
        with pytest.raises(repo_config.ConfigError):
            repo_config.parse(case["yaml"])


def test_partition_keeps_the_order_it_was_given():
    exclusions = repo_config.Exclusions(["a/**"])
    kept, excluded = exclusions.partition(["a/1.js", "b/1.js", "a/2.js", "b/2.js"])
    assert kept == ["b/1.js", "b/2.js"]
    assert excluded == ["a/1.js", "a/2.js"]


# --- reading the file off the checkout ---------------------------------------------------------

def test_a_repository_with_no_file_excludes_nothing(tmp_path):
    exclusions, problem = repo_config.load(tmp_path)
    assert problem is None
    assert not exclusions
    assert not exclusions.matches("benchmarks/remediation/fixtures/a.js")


def test_the_file_is_read_from_the_checkout(tmp_path):
    (tmp_path / ".mitig8it.yml").write_text("exclude:\n  - benchmarks/**\n", encoding="utf-8")
    exclusions, problem = repo_config.load(tmp_path)
    assert problem is None
    assert exclusions.matches("benchmarks/remediation/fixtures/a.js")
    assert not exclusions.matches("services/api-service/src/index.js")


def test_a_file_that_does_not_parse_excludes_nothing_and_says_so(tmp_path):
    """An unreadable configuration must not become an empty review or a full one by accident."""
    (tmp_path / ".mitig8it.yml").write_text("exclude: [unterminated\n", encoding="utf-8")
    exclusions, problem = repo_config.load(tmp_path)
    assert not exclusions
    assert problem and ".mitig8it.yml" in problem and "nothing was excluded" in problem


def test_an_oversized_file_is_refused(tmp_path):
    (tmp_path / ".mitig8it.yml").write_text("exclude:\n" + "  - a/**\n" * 20000, encoding="utf-8")
    exclusions, problem = repo_config.load(tmp_path)
    assert not exclusions
    assert problem and "bytes" in problem


# --- what the scope module does with it ---------------------------------------------------------

def changed(*paths):
    return [
        {"filename": path, "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b\n", "additions": 1, "deletions": 1}
        for path in paths
    ]


def test_excluded_files_never_reach_the_analysis():
    exclusions = repo_config.Exclusions(["benchmarks/remediation/fixtures/**"])
    files = changed("src/a.js", "benchmarks/remediation/fixtures/sqli.js", "src/b.js")

    scoped = pr_scope.scope_changed_files(files, exclusions)

    assert [entry["path"] for entry in scoped] == ["src/a.js", "src/b.js"]
    assert pr_scope.excluded_file_count(files, exclusions) == 1


def test_nothing_changes_when_there_is_no_configuration():
    files = changed("src/a.js", "benchmarks/remediation/fixtures/sqli.js")
    assert pr_scope.scope_changed_files(files) == pr_scope.scope_changed_files(files, repo_config.Exclusions())
    assert pr_scope.excluded_file_count(files, repo_config.Exclusions()) == 0


def test_an_excluded_file_is_not_counted_against_the_file_cap():
    """The cap measures the review, and an excluded path is not part of it."""
    exclusions = repo_config.Exclusions(["vendor/**"])
    files = changed(*[f"vendor/{index}.js" for index in range(300)], *[f"src/{index}.js" for index in range(10)])

    scoped = pr_scope.scope_changed_files(files, exclusions)

    assert len(scoped) == 10
    assert pr_scope.changed_file_limitation(files, exclusions) is None
    assert pr_scope.excluded_file_count(files, exclusions) == 300


def test_the_summary_sentence_counts_and_names_the_file():
    assert repo_config.exclusion_summary(0) is None
    assert repo_config.exclusion_summary(1) == "1 file excluded by .mitig8it.yml"
    assert repo_config.exclusion_summary(34) == "34 files excluded by .mitig8it.yml"
    assert repo_config.limitation(34) == {"kind": "path_exclusion", "message": "34 files excluded by .mitig8it.yml"}


# --- this repository's own file ------------------------------------------------------------------

@pytest.mark.repo_definition
def test_this_repository_excludes_its_own_deliberately_vulnerable_corpora():
    """The action reviewed this repository and posted 34 findings on fixtures that are meant to
    be vulnerable. The file at the root is what stops that, so it is asserted here."""
    root = Path(__file__).resolve().parents[2]
    exclusions, problem = repo_config.load(root)

    assert problem is None
    assert exclusions.matches("benchmarks/remediation/fixtures/sql-parameterized-001/db.js")
    assert exclusions.matches("benchmarks/vulnerable-corpus/anything.py")
    assert exclusions.matches("action/tests/fixtures/pull_request_opened.json")
    assert not exclusions.matches("benchmarks/remediation/evaluate.py")
    assert not exclusions.matches("services/api-service/src/index.js")
