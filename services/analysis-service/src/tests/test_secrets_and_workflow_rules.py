"""What happens when the secrets detector and the workflow rules meet on one file.

Neither of these two questions could be asked when either side was written. The secrets
detector reads the added lines of every analyzable file, and until the workflow category
existed a `.github/workflows/*.yml` file carried no tier 2 rules at all, so the detector was
the only thing that ever reported one. The subsumption table in `finding_quality` was written
the other way round: its one entry is a pair of workflow rules, and every finding it had ever
seen came from the scanner.

Two things follow, and both are asserted here rather than left to be discovered on a real
pull request.

**Both can report the same line, and when they do it is two defects, not one described
twice.** A `run:` step can interpolate `github.event` into a shell command *and* carry a
committed access token on the same line. Those have two different fixes -- move the
interpolation into an `env:` binding, and rotate the key -- and doing either one leaves the
other. So neither finding may be dropped, and neither is folded into the other as a
supporting detection. The thing that would be wrong is a *duplicate*: two findings naming the
same defect, which is what `main.LEGACY_CREDENTIAL_RULE_ID` is suppressed to avoid. No
workflow rule claims a credential literal, so the duplicate cannot arise here, and the last
test in the first class is what fails if one ever starts to.

**The subsumption fold cannot swallow a secret.** `_apply_subsumption` is a no-op unless some
finding carries an internal type that is a key in `SUBSUMED_INTERNAL_TYPES`, and on a workflow
pull request one now often does -- so the pass wakes up on exactly the pull requests where a
secrets finding is most likely to be beside it, and then walks every other finding as a
candidate to drop. It drops nothing it should not today. A credential removed from a review
because a line eight lines away was also flagged is the worst outcome this repository has, and
it would be silent, so the property is pinned twice: on the table's contents and on the
clusterer's behaviour.
"""
from __future__ import annotations

import yaml

import secret_detection as sd
from finding_quality import SUBSUMED_INTERNAL_TYPES, cluster_findings
from main import pattern_findings, partition_by_posting_policy
from opengrep_runner import RULES_DIR, run_opengrep

WORKFLOW_PATH = ".github/workflows/triage.yml"

# A workflow with two independent defects on line 12: `github.event.issue.title` interpolated
# straight into a shell command, and a GitHub personal access token written into the same
# command. The token is a syntactically valid `ghp_` key that grants nothing; it is here
# because the format signal verifies structure, so a placeholder would not reach the detector.
# GitHub's own documentation example token, assembled rather than written out. The file would
# otherwise hold a credential-shaped literal, which our own scanner flags and which a
# repository that ships a secrets detector has no business carrying. Only the shape is under
# test: the point is that a workflow line can carry both a secret and an injection.
EXAMPLE_GITHUB_TOKEN = "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a"

WORKFLOW = """name: triage
on:
  issues:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - name: Post the title
        run: curl -H "Authorization: token TOKEN_PLACEHOLDER" -d "${{ github.event.issue.title }}" https://api.github.com/x
""".replace("TOKEN_PLACEHOLDER", EXAMPLE_GITHUB_TOKEN)
COLLIDING_LINE = next(
    number
    for number, text in enumerate(WORKFLOW.split("\n"), start=1)
    if "ghp_" in text
)

SECRET_RULE_ID = sd.RULE_ID_FORMAT
INTERPOLATION_RULE_ID = "opengrep.cwe-78.gha-run-untrusted-interpolation"


def _added_patch(text: str) -> str:
    lines = text.split("\n")
    return f"@@ -0,0 +1,{len(lines)} @@\n" + "\n".join(f"+{line}" for line in lines)


class _File:
    """The attribute shape `pattern_findings` reads off a `ChangedFile`."""

    def __init__(self, path: str, patch: str, content: str):
        self.path = path
        self.patch = patch
        self.content = content
        self.reviewable_line_spans = []


def _postable(findings):
    postable, _quarantined = partition_by_posting_policy(findings)
    return postable


def _production_order(path: str, text: str):
    """Tier 1 then tier 2 then posting policy then clustering: `analyze_pull_request_payload`.

    Written out rather than calling the endpoint's own function so the composition under test
    is the one being asserted about, and so no LLM triage call sits in the middle of it. The
    tier order is fixed in `run_tiers_concurrently` for exactly this reason: it is what makes
    clustering's input, and therefore its output, the same on every run.
    """
    patch = _added_patch(text)
    tier1 = pattern_findings([_File(path, patch, text)], [])
    tier2 = run_opengrep([{"path": path, "patch": patch, "content": text, "reviewable_line_spans": []}])
    return cluster_findings(_postable([*tier1, *tier2]))


class TestASecretAndAWorkflowRuleOnTheSameLine:
    def test_the_detector_reports_the_token_in_the_workflow_file(self):
        """The detector is not scoped away from `.github/workflows/`, and must not be.

        A key committed to a workflow is leaked exactly as hard as one committed to a module,
        and the workflow rules do not look for one.
        """
        matches = sd.secret_matches(WORKFLOW_PATH, _added_patch(WORKFLOW), WORKFLOW)

        assert [(match.rule_id, match.line_number) for match in matches] == [
            (SECRET_RULE_ID, COLLIDING_LINE)
        ]

    def test_a_workflow_rule_reports_the_same_line(self):
        findings = run_opengrep(
            [
                {
                    "path": WORKFLOW_PATH,
                    "patch": _added_patch(WORKFLOW),
                    "content": WORKFLOW,
                    "reviewable_line_spans": [],
                }
            ]
        )

        assert INTERPOLATION_RULE_ID in {finding["rule_id"] for finding in findings}
        assert COLLIDING_LINE in {
            finding["line_start"]
            for finding in findings
            if finding["rule_id"] == INTERPOLATION_RULE_ID
        }

    def test_both_survive_the_whole_pipeline(self):
        """Two fixes are needed, so two findings are posted. Neither is suppressed."""
        findings = _production_order(WORKFLOW_PATH, WORKFLOW)

        on_the_line = [
            finding for finding in findings if finding["line_start"] == COLLIDING_LINE
        ]
        assert {finding["rule_id"] for finding in on_the_line} == {
            SECRET_RULE_ID,
            INTERPOLATION_RULE_ID,
        }

    def test_neither_is_folded_into_the_other(self):
        """They are not the same flaw, so nothing is merged and nothing is recorded as support.

        A `merged_rule_ids` key here would mean one of the two reached the reviewer only as a
        sentence inside the other's evidence, which is a fix a reviewer would not make.
        """
        findings = _production_order(WORKFLOW_PATH, WORKFLOW)

        on_the_line = [
            finding for finding in findings if finding["line_start"] == COLLIDING_LINE
        ]
        assert len(on_the_line) == 2
        assert all("merged_rule_ids" not in finding for finding in on_the_line)
        # Different internal types, which is also why `_same_cluster` never considered them.
        assert len({finding["internal_type"] for finding in on_the_line}) == 2

    def test_no_workflow_rule_claims_a_credential_literal(self):
        """The reason the pair above is two defects rather than one reported twice.

        `cwe-200.gha-secret-in-untrusted-checkout-job` is about a `${{ secrets.X }}` reference
        reaching an untrusted job, not about a literal, and no other workflow rule looks at a
        value at all. A workflow rule that started reporting the credential would duplicate the
        detector's finding, and the answer then would be a suppression like the one
        `main.LEGACY_CREDENTIAL_RULE_ID` gets -- not this test still passing.
        """
        document = yaml.safe_load((RULES_DIR / "workflow_coverage.yml").read_text(encoding="utf-8"))
        internal_types = {
            rule.get("metadata", {}).get("internal_type") for rule in document["rules"]
        }

        secret_internal_types = {
            finding["internal_type"]
            for finding in sd.secret_findings(WORKFLOW_PATH, _added_patch(WORKFLOW), WORKFLOW)
        }
        assert secret_internal_types
        assert internal_types.isdisjoint(secret_internal_types)


class TestSubsumptionCannotSwallowASecret:
    FILE = ".github/workflows/publish.yml"

    # The internal types the two signals actually produce, read off real findings rather than
    # written down, so renaming one in the taxonomy cannot quietly empty this set.
    SECRET_INTERNAL_TYPES = {
        finding["internal_type"]
        for finding in (
            sd.secret_findings(
                "config/app.js",
                _added_patch('const API_TOKEN = "npm_wJ5kQ2xR8tLm4vZ1pN7bY3hG6sD0aF9cE2uI";'),
                "",
            )
            + sd.secret_findings(
                "config/app.js",
                _added_patch(
                    'const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";'
                ),
                "",
            )
        )
    }

    def _secret(self, line=12):
        return {
            "rule_id": sd.RULE_ID_FORMAT,
            "internal_type": next(iter(self.SECRET_INTERNAL_TYPES)),
            "file_path": self.FILE,
            "line_start": line,
            "line_end": line,
            "severity": "critical",
            "confidence": 0.9,
            "code_snippet": '          SENTRY_TOKEN: "ghp_16C7e42F292c6912E7710c838347Ae178B4a"',
            "description": "A GitHub personal access token appears on a line this change adds.",
            "taxonomy_mappings": {"cwe": ["CWE-798"], "owasp": ["A07:2021"]},
        }

    def _checkout(self, line=10):
        return {
            "rule_id": "opengrep.cwe-829.gha-untrusted-checkout-privileged-trigger",
            "internal_type": "untrusted_code_checkout",
            "file_path": self.FILE,
            "line_start": line,
            "line_end": line,
            "severity": "critical",
            "confidence": 0.9,
            "code_snippet": "          ref: ${{ github.event.pull_request.head.sha }}",
            "description": "This workflow checks out the pull request's own revision.",
            "taxonomy_mappings": {"cwe": ["CWE-829"], "owasp": ["A08:2021"]},
        }

    def _persist(self, line=11):
        return {
            "rule_id": "opengrep.cwe-522.gha-persist-credentials-on-untrusted-checkout",
            "internal_type": "workflow_credential_persistence",
            "file_path": self.FILE,
            "line_start": line,
            "line_end": line,
            "severity": "high",
            "confidence": 0.85,
            "code_snippet": "          persist-credentials: true",
            "description": "This checkout keeps the job's token in `.git/config`.",
            "taxonomy_mappings": {"cwe": ["CWE-522"], "owasp": ["A07:2021"]},
        }

    def test_the_two_signals_produce_the_internal_types_this_class_checks(self):
        assert len(self.SECRET_INTERNAL_TYPES) == 1

    def test_no_subsumed_set_contains_a_secrets_internal_type(self):
        """The table's values are what gets dropped. A secret must never be among them."""
        for survivor, subsumed in SUBSUMED_INTERNAL_TYPES.items():
            assert self.SECRET_INTERNAL_TYPES.isdisjoint(subsumed), (
                f"`{survivor}` would drop a secrets finding at the same site"
            )

    def test_a_secret_survives_beside_the_pair_that_does_fold(self):
        """The fold runs -- the credential persistence finding is folded -- and the secret stays.

        Two lines away from the checkout, well inside `SUBSUMPTION_LINE_WINDOW`, so this is
        the arrangement that would lose the credential if the table ever grew the wrong entry.
        """
        clustered = cluster_findings([self._checkout(), self._persist(), self._secret()])

        rule_ids = {finding["rule_id"] for finding in clustered}
        assert self._persist()["rule_id"] not in rule_ids
        assert rule_ids == {self._checkout()["rule_id"], sd.RULE_ID_FORMAT}

    def test_the_folded_survivor_does_not_absorb_the_secret_as_support(self):
        clustered = cluster_findings([self._checkout(), self._persist(), self._secret()])

        checkout = next(
            finding
            for finding in clustered
            if finding["rule_id"] == self._checkout()["rule_id"]
        )
        assert sd.RULE_ID_FORMAT not in checkout["merged_rule_ids"]

    def test_the_secret_keeps_its_own_line_and_severity(self):
        """It is reported where the key is, at the severity the detector gave it."""
        clustered = cluster_findings([self._checkout(), self._persist(), self._secret()])

        secret = next(
            finding for finding in clustered if finding["rule_id"] == sd.RULE_ID_FORMAT
        )
        assert secret["line_start"] == self._secret()["line_start"]
        assert secret["severity"] == self._secret()["severity"]
        assert "merged_rule_ids" not in secret
