"""One defect on one line is one comment, even when both tiers recognise it.

The README says findings are deduplicated and clustered so the same issue does not arrive
twice. On a real pull request it arrived twice: a line that a tier 1 regex and a tier 2 AST
rule both matched produced two inline comments, with near-identical remediation text under
each. That is issue 487, and it is the most common reason a team mutes a review bot.

The cause was not the clustering. `cluster_findings` folds the pair correctly when it is given
both. The cause was that nothing gave it both. The control plane calls `/analyze/pr/tier1` and
`/analyze/pr/tier2` as two separate requests and concatenates the two lists, and each endpoint
had already clustered its own findings and only its own. The concatenated list goes on to
`/analyze/pr/tier3`, which classified it and returned it without ever clustering across the
join, so a cross-tier pair had no point in the pipeline where anything could see it as a pair.

The fix is one `cluster_findings` call in the tier 3 handler, and what is asserted here is the
behaviour at that seam rather than the call: a cross-tier pair folds, and two genuinely
different defects on one line do not.

The second half matters as much as the first. `test_secrets_and_workflow_rules.py` pins the
case this must never break: a `run:` step can interpolate untrusted event data into a shell
command and carry a committed token on the same line. Those are two defects with two different
fixes, and folding them would drop a credential from a review because something else was
flagged eight columns away. The fold keys on the internal type, not the line, which is what
keeps the two cases apart.
"""
from __future__ import annotations

import pytest

from main import (
    TriageRequest,
    classify_findings,
    partition_by_posting_policy,
    pattern_findings,
    triage_findings_payload,
)
from finding_quality import cluster_findings
from opengrep_runner import run_opengrep, scanner_available

# A credential both tiers recognise, and a query built by concatenation, in one small file.
SOURCE = '''\
import sqlite3

DB_PASSWORD = "Sup3rS3cret-storefront-2026"


def find_orders(customer_id):
    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()
    query = "SELECT id, total FROM orders WHERE customer_id = '%s'" % customer_id
    cursor.execute(query)
    return cursor.fetchall()
'''

PATH = "storefront/orders.py"


def _added_patch(text: str) -> str:
    lines = text.split("\n")
    return f"@@ -0,0 +1,{len(lines)} @@\n" + "\n".join(f"+{line}" for line in lines)


class _File:
    """The attribute shape `pattern_findings` reads off a `ChangedFile`."""

    def __init__(self, path: str, patch: str, content: str):
        self.path = path
        self.patch = patch
        self.content = content


def _tier(findings):
    """What a tier endpoint does to its own findings before returning them."""
    kept, _ = partition_by_posting_policy(findings)
    return cluster_findings(classify_findings(kept))


def _both_tiers(path: str, text: str):
    patch = _added_patch(text)
    tier1 = _tier(pattern_findings([_File(path, patch, text)], []))
    tier2 = _tier(
        run_opengrep(
            [{"path": path, "patch": patch, "content": text, "reviewable_line_spans": []}]
        )
    )
    # The control plane concatenates the two responses. Nothing clusters across the join.
    return tier1, tier2, tier1 + tier2


def _lines(findings):
    return [int(f.get("line_start") or 0) for f in findings]


def _through_tier3(findings, path: str, text: str):
    payload = TriageRequest(
        repository_full_name="acme/storefront",
        pull_request_number=1,
        commit_sha="a" * 40,
        findings=findings,
        file_patches={path: _added_patch(text)},
        repo_profile={},
    )
    return triage_findings_payload(payload)["findings"]


pytestmark = pytest.mark.skipif(
    not scanner_available(), reason="the AST scanner is not installed in this environment"
)


class TestOneDefectIsOneComment:
    def test_the_two_tiers_really_do_both_match_the_line(self):
        """Otherwise the test below passes without measuring anything."""
        tier1, tier2, merged = _both_tiers(PATH, SOURCE)
        shared = set(_lines(tier1)) & set(_lines(tier2))
        assert shared, (
            "no line was matched by both tiers, so this fixture cannot show a cross-tier "
            f"duplicate. Tier 1 lines: {sorted(_lines(tier1))}. Tier 2: {sorted(_lines(tier2))}."
        )

    def test_a_line_both_tiers_match_arrives_once(self):
        _, _, merged = _both_tiers(PATH, SOURCE)
        final = _through_tier3(merged, PATH, SOURCE)

        counts: dict[int, int] = {}
        for line in _lines(final):
            counts[line] = counts.get(line, 0) + 1
        repeated = {line: n for line, n in counts.items() if n > 1}

        assert not repeated, (
            f"line(s) {sorted(repeated)} of {PATH} carry more than one finding after tier 3, "
            f"so a reviewer gets more than one comment on them. Each tier endpoint clusters "
            f"only its own findings; the tier 3 handler is the only place that sees both."
        )

    def test_nothing_is_lost_that_was_not_a_duplicate(self):
        """The fold removes descriptions of one defect, never a defect."""
        _, _, merged = _both_tiers(PATH, SOURCE)
        final = _through_tier3(merged, PATH, SOURCE)

        assert set(_lines(final)) == set(_lines(merged)), (
            "the fold changed which lines are reported, not just how many findings each "
            f"line carries. Before: {sorted(set(_lines(merged)))}. "
            f"After: {sorted(set(_lines(final)))}."
        )


class TestTwoDefectsOnOneLineSurvive:
    """The fold keys on the defect, not the line."""

    def test_two_different_internal_types_on_one_line_are_both_kept(self):
        line = 12
        findings = [
            {
                "rule_id": "secret.hardcoded.credential",
                "internal_type": "hardcoded_secret",
                "file_path": ".github/workflows/triage.yml",
                "line_start": line,
                "line_end": line,
                "code_snippet": 'run: curl -H "token ghp_x" https://api.example.com/$TITLE',
                "severity": "critical",
                "category": "hardcoded credential",
                "title": "Hardcoded secret or credential",
                "description": "Hardcoded secret or credential",
                "confidence": 0.94,
            },
            {
                "rule_id": "opengrep.cwe-78.gha-run-untrusted-interpolation",
                "internal_type": "command_injection",
                "file_path": ".github/workflows/triage.yml",
                "line_start": line,
                "line_end": line,
                "code_snippet": 'run: curl -H "token ghp_x" https://api.example.com/$TITLE',
                "severity": "critical",
                "category": "command injection",
                "title": "Untrusted event data interpolated into a run step",
                "description": "Untrusted event data interpolated into a run step",
                "confidence": 0.90,
            },
        ]

        final = _through_tier3(findings, ".github/workflows/triage.yml", SOURCE)

        types = {f.get("internal_type") for f in final}
        assert types == {"hardcoded_secret", "command_injection"}, (
            "a committed credential and a shell injection on one line are two defects with "
            "two different fixes. Folding them drops one of them from the review, and the "
            f"credential is the one that cannot be allowed to go missing. Kept: {types}."
        )
