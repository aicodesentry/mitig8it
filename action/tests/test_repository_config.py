"""The Action's half of `.mitig8it.yml`, against the contract both halves are built from.

contracts/repository-configuration-v1.json states the glob dialect and the parse rules once.
services/api-service/tests/repositoryConfig.test.js runs the same cases through the App's
implementation. Neither side is tested against the other's behaviour, because then the first one
to drift would take the other with it; both are tested against the written contract, so a change
in either has to change the contract first, and the change shows up in one diff on both sides.

The contract is a repository file and not a runtime input: `repo_config.py` implements the
dialect rather than reading the JSON, so the image does not carry it. The tests that read it,
and the one that reads this repository's own `.mitig8it.yml`, are therefore `repo_definition`
and run in the host job only. They read inside the test body rather than at import, because a
marker deselects a test after its module has already been imported: a module-level read would
fail collection in the image no matter how it is marked. Everything else here exercises the
module itself and runs in the image too.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orchestrator import pr_scope, repo_config

pytest.importorskip("yaml", reason="PyYAML parses .mitig8it.yml")

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPO_ROOT / "contracts/repository-configuration-v1.json"


def contract():
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


# --- the dialect, as the contract states it ----------------------------------------------------

@pytest.mark.repo_definition
def test_every_contract_match_case():
    failures = []
    for case in contract()["match_cases"]:
        exclusions = repo_config.Exclusions(case["patterns"])
        for path in case["excluded"]:
            if not exclusions.matches(path):
                failures.append(f"{case['name']}: {path!r} should be excluded by {case['patterns']!r}")
        for path in case["kept"]:
            if exclusions.matches(path):
                failures.append(f"{case['name']}: {path!r} should be kept by {case['patterns']!r}")
    assert not failures, "\n".join(failures)


@pytest.mark.repo_definition
def test_every_contract_parse_case():
    failures = []
    for case in contract()["parse_cases"]:
        if case["valid"]:
            try:
                patterns = list(repo_config.parse(case["yaml"]).patterns)
            except repo_config.ConfigError as error:
                failures.append(f"{case['name']}: should parse, raised {error}")
                continue
            if patterns != case["patterns"]:
                failures.append(f"{case['name']}: parsed {patterns!r}, expected {case['patterns']!r}")
        else:
            try:
                repo_config.parse(case["yaml"])
            except repo_config.ConfigError:
                continue
            failures.append(f"{case['name']}: should have been refused")
    assert not failures, "\n".join(failures)


# --- the dialect, exercised without the contract file ------------------------------------------

@pytest.mark.parametrize(
    ("patterns", "path", "excluded"),
    [
        (["a/**"], "a/b.js", True),
        (["a/**"], "a", True),
        (["a/**"], "ab/c.js", False),
        (["docs/*.md"], "docs/a.md", True),
        (["docs/*.md"], "docs/nested/a.md", False),
        (["**/vendor/**"], "vendor/a.js", True),
        (["**/vendor/**"], "x/y/vendor/a.js", True),
        (["build"], "build/main.js", True),
        (["build"], "builder/main.js", False),
        (["a/?.js"], "a/b.js", True),
        (["a/?.js"], "a/bc.js", False),
        ([""], "a.js", False),
        ([], "a.js", False),
    ],
)
def test_the_dialect_in_the_image(patterns, path, excluded):
    """A copy of the contract's shape that travels with the code, so the image tests it too."""
    assert repo_config.Exclusions(patterns).matches(path) is excluded


def test_partition_keeps_the_order_it_was_given():
    exclusions = repo_config.Exclusions(["a/**"])
    kept, excluded = exclusions.partition(["a/1.js", "b/1.js", "a/2.js", "b/2.js"])
    assert kept == ["b/1.js", "b/2.js"]
    assert excluded == ["a/1.js", "a/2.js"]


def test_a_scalar_exclude_and_a_non_string_entry_are_refused():
    with pytest.raises(repo_config.ConfigError):
        repo_config.parse("exclude: a/**\n")
    with pytest.raises(repo_config.ConfigError):
        repo_config.parse("exclude:\n  - 7\n")


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
    """The action reviewed this repository and posted findings on fixtures that are meant to be
    vulnerable, and on benchmark case files and validation prose. The file at the root is what
    stops that, so it is asserted here."""
    exclusions, problem = repo_config.load(REPO_ROOT)

    assert problem is None
    for path in (
        "benchmarks/remediation/fixtures/sql-parameterized-001/db.js",
        "benchmarks/vulnerable-corpus/anything.py",
        "benchmarks/tier1-precision/cases.json",
        "benchmarks/tier2-precision/cases.json",
        "docs/validation/tier2-precision.md",
        "action/tests/fixtures/pull_request_opened.json",
    ):
        assert exclusions.matches(path), path
    for path in ("services/api-service/src/index.js", "docs/README.md", "scripts/replay/prodfilters.py"):
        assert not exclusions.matches(path), path
