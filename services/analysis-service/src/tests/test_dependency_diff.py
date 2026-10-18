"""`dependency_diff`: newly added lockfile entries, three signals, all quarantined.

Each format has a fixture that raises the signals it can carry and a fixture that must stay
silent: a version bump of an entry that already existed, a registry download, a name that is on
the popular list rather than near it.
"""
from __future__ import annotations

import json

import pytest

import dependency_diff as dd
import main
from main import partition_by_posting_policy


def patch_of(*hunks: str) -> str:
    return "\n".join(hunks)


# -- package-lock.json --------------------------------------------------------------------------

PACKAGE_LOCK_ADDED = patch_of(
    "@@ -40,6 +40,24 @@",
    '     "node_modules/left-pad": {',
    '       "version": "1.3.0"',
    "     },",
    '+    "node_modules/node-sass": {',
    '+      "version": "9.0.0",',
    '+      "resolved": "https://registry.npmjs.org/node-sass/-/node-sass-9.0.0.tgz",',
    '+      "integrity": "sha512-abc",',
    '+      "hasInstallScript": true,',
    '+      "dependencies": {',
    '+        "nan": "^2.17.0"',
    "+      }",
    "+    },",
    '+    "node_modules/semvar": {',
    '+      "version": "7.6.0",',
    '+      "resolved": "https://registry.npmjs.org/semvar/-/semvar-7.6.0.tgz"',
    "+    },",
    '+    "node_modules/forked-thing": {',
    '+      "version": "1.0.0",',
    '+      "resolved": "git+ssh://git@github.com/someone/forked-thing.git#0123456789abcdef"',
    "+    },",
    '     "node_modules/zod": {',
)

PACKAGE_LOCK_BUMP = patch_of(
    "@@ -40,6 +40,6 @@",
    '     "node_modules/node-sass": {',
    '-      "version": "8.0.0",',
    '+      "version": "9.0.0",',
    '-      "resolved": "https://registry.npmjs.org/node-sass/-/node-sass-8.0.0.tgz",',
    '+      "resolved": "https://registry.npmjs.org/node-sass/-/node-sass-9.0.0.tgz",',
    '+      "hasInstallScript": true,',
    "     },",
)


def rules_at(findings):
    return sorted((finding["rule_id"], finding["line_start"]) for finding in findings)


class TestPackageLock:
    def test_the_three_signals_on_their_opening_lines(self):
        findings = dd.dependency_diff_findings("package-lock.json", PACKAGE_LOCK_ADDED)
        assert rules_at(findings) == [
            (dd.RULE_ID_INSTALL_SCRIPT, 43),
            (dd.RULE_ID_NAME_NEAR_POPULAR, 52),
            (dd.RULE_ID_NON_REGISTRY_SOURCE, 56),
        ]
        near = next(f for f in findings if f["rule_id"] == dd.RULE_ID_NAME_NEAR_POPULAR)
        assert near["evidence_details"]["extra"]["popular_name"] == "semver"
        assert near["code_snippet"] == '"node_modules/semvar": {'

    def test_a_version_bump_is_not_a_new_dependency(self):
        assert dd.dependency_diff_findings("package-lock.json", PACKAGE_LOCK_BUMP) == []

    def test_a_nested_node_modules_key_is_read_by_its_package_name(self):
        patch = patch_of(
            "@@ -1,1 +1,4 @@",
            '+    "node_modules/a/node_modules/@scope/pkg": {',
            '+      "version": "1.0.0",',
            '+      "hasInstallScript": true',
            "+    },",
        )
        [finding] = dd.dependency_diff_findings("app/package-lock.json", patch)
        assert finding["evidence_details"]["extra"]["dependency_name"] == "@scope/pkg"


# -- pnpm-lock.yaml -----------------------------------------------------------------------------

PNPM_ADDED = patch_of(
    "@@ -100,3 +100,14 @@ packages:",
    "   /zod@3.22.4:",
    "     resolution: {integrity: sha512-abc}",
    "     dev: false",
    "+  /esbuild@0.19.0:",
    "+    resolution: {integrity: sha512-def}",
    "+    requiresBuild: true",
    "+    dev: true",
    "+",
    "+  /lodahs@4.17.21:",
    "+    resolution: {integrity: sha512-ghi}",
    "+",
    "+  '@acme/tool@1.0.0':",
    "+    resolution: {tarball: https://codeload.github.com/acme/tool/tar.gz/abc}",
    "+    name: '@acme/tool'",
)


class TestPnpm:
    def test_the_three_signals(self):
        findings = dd.dependency_diff_findings("pnpm-lock.yaml", PNPM_ADDED)
        assert rules_at(findings) == [
            (dd.RULE_ID_INSTALL_SCRIPT, 103),
            (dd.RULE_ID_NAME_NEAR_POPULAR, 108),
            (dd.RULE_ID_NON_REGISTRY_SOURCE, 111),
        ]

    def test_a_snapshot_entry_for_the_same_package_is_not_a_second_finding(self):
        patch = patch_of(
            "@@ -1,1 +1,6 @@",
            "+  esbuild@0.19.0:",
            "+    resolution: {integrity: sha512-def}",
            "+    requiresBuild: true",
            "+  esbuild@0.19.0:",
            "+    optionalDependencies:",
            "+      '@esbuild/darwin-arm64': 0.19.0",
        )
        assert len(dd.dependency_diff_findings("pnpm-lock.yaml", patch)) == 1


# -- yarn.lock ----------------------------------------------------------------------------------

YARN_ADDED = patch_of(
    "@@ -10,3 +10,12 @@",
    ' "zod@^3.22.0":',
    '   version "3.22.4"',
    "",
    '+"left-pad@^1.3.0":',
    '+  version "1.3.0"',
    '+  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"',
    "+",
    '+"mything@github:someone/mything#main":',
    '+  version "0.0.1"',
    '+  resolved "https://codeload.github.com/someone/mything/tar.gz/0123456"',
    "+",
    '+"chalks@^1.0.0":',
    '+  version "1.0.0"',
)


class TestYarn:
    def test_a_source_and_a_near_miss(self):
        findings = dd.dependency_diff_findings("yarn.lock", YARN_ADDED)
        assert rules_at(findings) == [
            (dd.RULE_ID_NAME_NEAR_POPULAR, 21),
            (dd.RULE_ID_NON_REGISTRY_SOURCE, 17),
        ]

    def test_berry_resolution_to_the_registry_is_silent_and_to_git_is_not(self):
        patch = patch_of(
            "@@ -1,1 +1,6 @@",
            '+"zod@npm:^3.22.0":',
            '+  version: 3.22.4',
            '+  resolution: "zod@npm:3.22.4"',
            '+"thing@git+https://github.com/x/thing.git#commit=abc":',
            '+  version: 0.0.1',
            '+  resolution: "thing@git+https://github.com/x/thing.git#commit=abc"',
        )
        assert rules_at(dd.dependency_diff_findings("yarn.lock", patch)) == [(dd.RULE_ID_NON_REGISTRY_SOURCE, 4)]


# -- poetry.lock --------------------------------------------------------------------------------

POETRY_ADDED = patch_of(
    "@@ -1,3 +1,20 @@",
    " [[package]]",
    ' name = "requests"',
    ' version = "2.31.0"',
    "+",
    "+[[package]]",
    '+name = "reqeusts"',
    '+version = "1.0.0"',
    "+",
    "+[[package]]",
    '+name = "internal-lib"',
    '+version = "0.1.0"',
    "+",
    "+[package.dependencies]",
    '+requests = "*"',
    "+",
    "+[package.source]",
    '+type = "git"',
    '+url = "https://github.com/acme/internal-lib.git"',
    '+reference = "main"',
)


class TestPoetry:
    def test_a_git_source_and_a_near_miss(self):
        findings = dd.dependency_diff_findings("poetry.lock", POETRY_ADDED)
        assert rules_at(findings) == [
            (dd.RULE_ID_NAME_NEAR_POPULAR, 6),
            (dd.RULE_ID_NON_REGISTRY_SOURCE, 10),
        ]


# -- requirements*.txt --------------------------------------------------------------------------

REQUIREMENTS_ADDED = patch_of(
    "@@ -1,2 +1,8 @@",
    " flask==3.0.0",
    " requests==2.31.0",
    "+boto3==1.34.0",
    "+-r base.txt",
    "+numpi==1.26.0  # typo",
    "+mylib @ git+https://github.com/acme/mylib.git@v1",
    "+git+https://github.com/acme/other.git#egg=other",
    "+    --hash=sha256:abc",
)


class TestRequirements:
    def test_sources_and_a_near_miss_and_nothing_for_a_popular_name(self):
        findings = dd.dependency_diff_findings("requirements-dev.txt", REQUIREMENTS_ADDED)
        assert rules_at(findings) == [
            (dd.RULE_ID_NAME_NEAR_POPULAR, 5),
            (dd.RULE_ID_NON_REGISTRY_SOURCE, 6),
            (dd.RULE_ID_NON_REGISTRY_SOURCE, 7),
        ]

    def test_pypi_names_are_compared_normalized(self):
        """`typing_extensions` is `typing-extensions`, which is on the list, so it is not a miss."""
        patch = patch_of("@@ -0,0 +1,1 @@", "+Typing_Extensions==4.9.0")
        assert dd.dependency_diff_findings("requirements.txt", patch) == []


# -- the pieces ---------------------------------------------------------------------------------

class TestThePieces:
    @pytest.mark.parametrize(
        "left,right,expected",
        [
            ("lodash", "lodahs", True),
            ("semver", "semvr", True),
            ("semver", "semverr", True),
            ("semver", "semvar", True),
            ("semver", "semver", False),
            ("semver", "esmvre", False),
            ("react", "preact", True),
        ],
    )
    def test_within_one_edit(self, left, right, expected):
        assert dd.within_one_edit(left, right) is expected

    def test_short_popular_names_are_not_compared(self):
        """`ms` and `qs` are both real; a two-letter name has too many neighbours to mean anything."""
        assert dd.near_popular_name("ns", dd.NPM) is None

    @pytest.mark.parametrize(
        "source,flagged",
        [
            ("https://registry.npmjs.org/a/-/a-1.0.0.tgz", False),
            ("https://npm.internal.example/repository/npm/a/-/a-1.0.0.tgz", False),
            ("http://registry.npmjs.org/a/-/a-1.0.0.tgz", True),
            ("git+ssh://git@github.com/x/y.git#abc", True),
            ("github:x/y#main", True),
            ("https://codeload.github.com/x/y/tar.gz/abc", True),
            ("", False),
        ],
    )
    def test_non_registry_source(self, source, flagged):
        assert (dd.non_registry_source(source) is not None) is flagged

    def test_only_named_lockfiles_are_read(self):
        assert dd.dependency_diff_findings("package.json", PACKAGE_LOCK_ADDED) == []
        assert dd.dependency_diff_findings("docs/requirements.md", REQUIREMENTS_ADDED) == []

    def test_the_list_is_checked_in_with_its_provenance(self):
        document = json.loads(dd.TOP_PACKAGES_PATH.read_text(encoding="utf-8"))
        assert len(document["npm"]) == 200 and len(document["pypi"]) == 200
        assert document["provenance"]["npm"]["url"].startswith("https://")
        assert document["provenance"]["pypi"]["url"].startswith("https://")


# -- the finding and the policy -----------------------------------------------------------------

class TestTheFindingAndThePolicy:
    def test_the_finding_is_medium_canonical_and_says_no_fix_is_offered(self):
        for finding in dd.dependency_diff_findings("package-lock.json", PACKAGE_LOCK_ADDED):
            assert finding["severity"] == "medium"
            assert finding["internal_type"] == "supply_chain_risk"
            assert finding["cwe_id"] == "CWE-1357"
            assert "No automatic fix is offered" in finding["remediation"]
            assert finding["remediation_patch"] == ""
            assert finding["evidence_details"]["extra"]["fix_offered"] is False

    def test_every_signal_starts_quarantined(self):
        assert set(dd.POSTING) == {
            dd.RULE_ID_INSTALL_SCRIPT,
            dd.RULE_ID_NON_REGISTRY_SOURCE,
            dd.RULE_ID_NAME_NEAR_POPULAR,
        }
        assert set(dd.POSTING) <= main.QUARANTINED_RULE_IDS
        findings = dd.dependency_diff_findings("package-lock.json", PACKAGE_LOCK_ADDED)
        postable, withheld = partition_by_posting_policy(findings)
        assert postable == [] and len(withheld) == 3

    def test_tier1_runs_it_on_a_changed_lockfile(self):
        changed = main.ChangedFile(path="package-lock.json", patch=PACKAGE_LOCK_ADDED, additions=18, deletions=0)
        rule_ids = {finding["rule_id"] for finding in main.pattern_findings([changed])}
        assert set(dd.POSTING) <= rule_ids
