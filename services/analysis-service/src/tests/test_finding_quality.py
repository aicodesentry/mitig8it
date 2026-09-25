from finding_quality import (
    cluster_findings,
    extract_match_context,
    is_transcript_artifact_line,
    pattern_matches_reviewable_content,
)
from security_rules import SECURITY_RULES


def _find(rule_id):
    return next(rule for rule in SECURITY_RULES if rule.rule_id == rule_id)


class TestTranscriptFiltering:
    def test_flags_transcript_artifact_line(self):
        assert is_transcript_artifact_line('    218 +        patch = "+API_KEY = \'sk_live_1234567890abcdef\'"')

    def test_keeps_real_code_line(self):
        assert not is_transcript_artifact_line('api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"')

    def test_ignores_secret_match_in_transcript_text(self):
        rule = _find("secret.hardcoded.credential")
        patch = '+    218 +        patch = "+API_KEY = \'sk_live_1234567890abcdef\'"'
        assert not pattern_matches_reviewable_content(patch, rule.pattern)

    def test_keeps_real_secret_match(self):
        rule = _find("secret.hardcoded.credential")
        patch = '+api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"'
        assert pattern_matches_reviewable_content(patch, rule.pattern)

    def test_extract_match_context_prefers_real_code_over_transcript(self):
        rule = _find("code.injection.eval")
        patch = "\n".join(
            [
                "@@ -1,2 +1,3 @@",
                '+    68 -            "patch": "+const result = eval(req.body.code)",',
                "+const result = eval(user_input)",
            ]
        )
        context = extract_match_context(patch, rule.pattern)
        assert context["matched_text"] == "const result = eval(user_input)"


def test_source_comments_and_literals_cannot_hide_runtime_eval():
    rule = _find("code.injection.eval")
    for suffix in (" # git add .", " # pytest", ' # "diff_hunk"', " # OpenGrep validation failed"):
        assert pattern_matches_reviewable_content("+eval(user_input)" + suffix, rule.pattern)


# Tier 1 and tier 2 both detect one raw SQL query on one line. Before the taxonomy was
# made tier-independent they carried different internal types (`sql_injection` against
# the opengrep check id), never clustered, and the pull request received two inline
# comments and two GitHub suggestions on the same line.
class TestCrossTierClustering:
    FILE = "services/orders.js"
    LINE = "  const rows = await db.query(`SELECT * FROM orders WHERE id = ` + id);"

    def _tier1(self):
        from main import generate_finding

        patch = "@@ -1,2 +1,3 @@\n+const db = require('./db');\n+" + self.LINE
        return generate_finding(_find("sql.injection.raw_query"), self.FILE, patch)

    def _tier2(self):
        from opengrep_runner import _build_finding

        match = {
            "check_id": "cwe-89.sql-template-literal",
            "path": "scan-root/" + self.FILE,
            "start": {"line": 2},
            "end": {"line": 2},
            "extra": {
                "message": "SQL query built from a template literal",
                "severity": "ERROR",
                "lines": self.LINE,
                "metadata": {"cwe": "CWE-89", "owasp": "A03:2021", "category": "SQL injection", "confidence": "0.9"},
            },
        }
        content = "const db = require('./db');\n" + self.LINE + "\n"
        return _build_finding(match, "scan-root", {self.FILE: content})

    def test_both_tiers_name_the_same_internal_type(self):
        assert self._tier1()["internal_type"] == "sql_injection"
        assert self._tier2()["internal_type"] == "sql_injection"

    def test_the_two_tiers_cluster_into_one_finding_that_keeps_both_rule_ids(self):
        tier1 = self._tier1()
        tier2 = self._tier2()
        assert tier1["fingerprint"] != tier2["fingerprint"]

        clustered = cluster_findings([tier1, tier2])

        assert len(clustered) == 1
        survivor = clustered[0]
        assert survivor["merged_rule_ids"] == [tier2["rule_id"], tier1["rule_id"]]
        assert survivor["evidence_details"]["extra"]["merged_rule_ids"] == survivor["merged_rule_ids"]
        # The survivor keeps the higher-confidence evidence and the union of the taxonomy.
        assert survivor["confidence"] >= max(tier1["confidence"], tier2["confidence"])
        assert survivor["cwe_id"] == "CWE-89"
        assert tier1["rule_id"] in survivor["evidence"]

    def test_a_single_finding_is_left_untouched(self):
        clustered = cluster_findings([self._tier1()])

        assert len(clustered) == 1
        assert "merged_rule_ids" not in clustered[0]


# One `md5(password.encode())` produced two comments on the same line for the whole
# September 2026 action trial: a critical "Password hashed with weak algorithm" from tier 2
# and a medium "Weak cryptographic hash used for security context" from tier 1, on
# `introduction/mitre.py:161` and `introduction/views.py:1026`. The clusterer merges only
# within one internal type and the two rules disagreed about the name: CWE-916
# (`weak_password_hash`) against CWE-327 (`weak_cipher_algorithm`). They agree now.
class TestWeakPasswordHashClustering:
    FILE = "introduction/mitre.py"
    LINE = "    hashed = hashlib.md5(password.encode()).hexdigest()"

    def _tier1(self, line=None):
        from main import generate_finding

        patch = "@@ -1,2 +1,3 @@\n+def login(request):\n+" + (line or self.LINE)
        return generate_finding(_find("crypto.weak.hash"), self.FILE, patch)

    def _tier2(self):
        from opengrep_runner import _build_finding

        match = {
            "check_id": "cwe-327.weak-hash-password",
            "path": "scan-root/" + self.FILE,
            "start": {"line": 2},
            "end": {"line": 2},
            "extra": {
                "message": "Password hashed with weak algorithm - use bcrypt or argon2",
                "severity": "ERROR",
                "lines": self.LINE,
                "metadata": {
                    "cwe": "CWE-916", "owasp": "A02:2021",
                    "category": "weak password hashing", "confidence": "0.88",
                },
            },
        }
        content = "def login(request):\n" + self.LINE + "\n"
        return _build_finding(match, "scan-root", {self.FILE: content})

    def test_both_tiers_name_the_same_internal_type(self):
        assert self._tier1()["internal_type"] == "weak_password_hash"
        assert self._tier2()["internal_type"] == "weak_password_hash"

    def test_the_two_rules_cluster_into_one_comment(self):
        tier1 = self._tier1()
        tier2 = self._tier2()

        clustered = cluster_findings([tier1, tier2])

        assert len(clustered) == 1
        survivor = clustered[0]
        assert set(survivor["merged_rule_ids"]) == {tier1["rule_id"], tier2["rule_id"]}
        # The worse of the two is what a reader is left with.
        assert survivor["severity"] == "critical"

    def test_a_weak_hash_of_something_that_is_not_a_credential_keeps_its_own_type(self):
        """dvna's `md5(req.query.login)` reset token is a weak cipher, not a password hash."""
        finding = self._tier1("    const token = md5(req.query.login).digest();")
        assert finding["internal_type"] == "weak_cipher_algorithm"
