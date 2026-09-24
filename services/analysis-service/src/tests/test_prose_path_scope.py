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
from test_code_scope import is_non_code_text_path, is_prose_path, is_template_path

CHANGELOG_PATCH = (
    "@@ -3034,2 +3034,3 @@\n"
    "+  * Added route `Collection`, ex: `app.get('/user/:id').remove();`\n"
    "+  * Fix a global leak when multiple subnets are trusted\n"
)
SECRET_IN_DOCS_PATCH = (
    "@@ -1,1 +1,2 @@\n"
    "+Set `api_key = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"` in your configuration.\n"
)
# A real unguarded route, not a changelog quotation of one. PR 441 re-anchored
# `auth.bypass.missing_check` so the truncated example in CHANGELOG_PATCH no longer
# matches anywhere, in prose or in source. The path scope still has to be a path scope
# rather than a blanket suppression, so the source-file half of that claim is made with
# a route the re-anchored rule does match.
ROUTE_PATCH = (
    "@@ -1,1 +1,2 @@\n"
    "+app.get('/user/:id', (req, res) => { res.send(db.users[req.params.id]); });\n"
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

    def test_a_route_in_a_source_file_still_raises(self):
        findings = pattern_findings([ChangedFile(path="lib/routes.js", patch=ROUTE_PATCH)])
        assert "auth.bypass.missing_check" in {finding["rule_id"] for finding in findings}

    def test_the_same_route_quoted_in_prose_raises_nothing(self):
        findings = pattern_findings([ChangedFile(path="History.md", patch=ROUTE_PATCH)])
        assert findings == []

    def test_a_secret_in_documentation_is_still_reported(self):
        findings = pattern_findings([ChangedFile(path="README.md", patch=SECRET_IN_DOCS_PATCH)])
        assert [finding["rule_id"] for finding in findings] == ["secret.hardcoded.credential"]

    def test_exactly_one_rule_opts_into_prose(self):
        assert [rule.rule_id for rule in SECURITY_RULES if rule.scans_prose] == [
            "secret.hardcoded.credential"
        ]


class TestCodeShapeRulesSkipTemplates:
    """The same argument, for the same reason, one file type over.

    Tier 2 gained sixteen template extensions so `template_coverage.yml` could read them.
    Tier 1 was never extension-gated -- the orchestrator hands it every changed file -- so
    its regexes had been reading templates all along; widening tier 2 only made it visible,
    because the replay's snapshot walk selects files with the tier 2 filter.

    What it found in `OWASP/NodeGoat` was thirteen findings across seven `.html` files:
    `rate_limit.missing` on `signup.html`, and `nosql.injection`,
    `code.injection.eval`, `authz.missing_function_level`, `redirect.open`,
    `integer.overflow` and `null.pointer.deref` on the tutorial pages, which quote
    vulnerable code as documentation. Not one of them can be true in a template.
    """

    TEMPLATE_ROUTE_PATCH = (
        "@@ -1,1 +1,4 @@\n"
        "+<pre><code>app.get('/user/:id', function (req, res) {\n"
        "+  db.users.find({ name: req.query.name });\n"
        "+});</code></pre>\n"
    )
    SECRET_IN_TEMPLATE_PATCH = (
        "@@ -1,1 +1,2 @@\n"
        "+<script>const api_key = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\";</script>\n"
    )

    @pytest.mark.parametrize("path", [
        "app/views/layout.html", "views/products.ejs", "src/App.vue", "page.svelte",
        "templates/xss_lab.jinja2", "views/admin.hbs", "email/body.htm", "views/x.pug",
    ])
    def test_template_paths(self, path):
        assert is_template_path(path) is True
        assert is_non_code_text_path(path) is True

    @pytest.mark.parametrize("path", [
        "lib/response.js", "svc/handler.py", "src/app.tsx", "Makefile", "scripts/run",
    ])
    def test_source_paths_are_not_templates(self, path):
        assert is_template_path(path) is False
        assert is_non_code_text_path(path) is False

    def test_no_path_is_not_a_template(self):
        assert is_template_path("") is False
        assert is_template_path(None) is False

    def test_prose_is_still_non_code_text(self):
        """The template gate is added to the prose gate, not swapped for it."""
        assert is_template_path("History.md") is False
        assert is_non_code_text_path("History.md") is True

    def test_a_tutorial_page_quoting_a_route_raises_nothing(self):
        findings = pattern_findings(
            [ChangedFile(path="app/views/tutorial/a1.html", patch=self.TEMPLATE_ROUTE_PATCH)]
        )
        assert findings == []

    def test_the_same_text_in_a_source_file_still_raises(self):
        findings = pattern_findings(
            [ChangedFile(path="app/routes/index.js", patch=self.TEMPLATE_ROUTE_PATCH)]
        )
        assert {finding["rule_id"] for finding in findings}

    def test_a_secret_in_a_template_is_still_reported(self):
        findings = pattern_findings(
            [ChangedFile(path="app/views/layout.html", patch=self.SECRET_IN_TEMPLATE_PATCH)]
        )
        assert [finding["rule_id"] for finding in findings] == ["secret.hardcoded.credential"]


class TestEndToEnd:
    def test_tier1_on_a_changelog_only_pull_request(self):
        payload = AnalyzePRRequest(
            repository_full_name="expressjs/express",
            pull_request_number=7466,
            commit_sha="a" * 40,
            files=[ChangedFile(path="History.md", patch=CHANGELOG_PATCH)],
        )
        assert main.analyze_tier1_payload(payload)["findings"] == []
