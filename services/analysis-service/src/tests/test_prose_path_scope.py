"""Code-shape rules must not fire on prose.

Replaying merged pull requests of public repositories turned up high-severity
access-control findings raised against `History.md`, because a changelog entry quoted an
example route. Documentation never executes, so a rule that recognizes the shape of
executable code cannot have a true positive there. A rule that looks for committed data,
such as a credential literal, still scans those files: a secret pasted into a README is
still a leaked secret.
"""

import pytest

import main
from main import AnalyzePRRequest, ChangedFile, pattern_findings
from security_rules import SECURITY_RULES
from test_code_scope import is_prose_path

CHANGELOG_PATCH = (
    "@@ -3034,2 +3034,3 @@\n"
    "+  * Added route `Collection`, ex: `app.get('/user/:id').remove();`\n"
    "+  * Fix a global leak when multiple subnets are trusted\n"
)
SECRET_IN_DOCS_PATCH = (
    "@@ -1,1 +1,2 @@\n"
    "+Set `api_key = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"` in your configuration.\n"
)


class TestProseClassification:
    @pytest.mark.parametrize("path", [
        "History.md", "docs/guide.rst", "README.markdown", "NOTES.txt",
        "CHANGELOG", "AUTHORS", "locale/de/LC_MESSAGES/django.po", "site/page.mdx",
    ])
    def test_prose_paths(self, path):
        assert is_prose_path(path) is True

    @pytest.mark.parametrize("path", [
        "lib/response.js", "svc/handler.py", "Makefile", "deploy/values.yaml",
        "src/app.tsx", ".github/workflows/publish.yml", "scripts/run",
    ])
    def test_source_and_unknown_paths_are_not_prose(self, path):
        assert is_prose_path(path) is False

    def test_no_path_is_not_prose(self):
        assert is_prose_path("") is False
        assert is_prose_path(None) is False


class TestCodeShapeRulesSkipProse:
    def test_a_changelog_quoting_a_route_raises_nothing(self):
        findings = pattern_findings([ChangedFile(path="History.md", patch=CHANGELOG_PATCH)])
        assert findings == []

    def test_the_same_text_in_a_source_file_still_raises(self):
        findings = pattern_findings([ChangedFile(path="lib/routes.js", patch=CHANGELOG_PATCH)])
        assert {finding["rule_id"] for finding in findings}

    def test_a_secret_in_documentation_is_still_reported(self):
        findings = pattern_findings([ChangedFile(path="README.md", patch=SECRET_IN_DOCS_PATCH)])
        assert [finding["rule_id"] for finding in findings] == ["secret.hardcoded.credential"]

    def test_exactly_one_rule_opts_into_prose(self):
        assert [rule.rule_id for rule in SECURITY_RULES if rule.scans_prose] == [
            "secret.hardcoded.credential"
        ]


class TestEndToEnd:
    def test_tier1_on_a_changelog_only_pull_request(self):
        payload = AnalyzePRRequest(
            repository_full_name="expressjs/express",
            pull_request_number=7466,
            commit_sha="a" * 40,
            files=[ChangedFile(path="History.md", patch=CHANGELOG_PATCH)],
        )
        assert main.analyze_tier1_payload(payload)["findings"] == []
