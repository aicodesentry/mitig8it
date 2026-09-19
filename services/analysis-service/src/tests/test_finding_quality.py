from finding_quality import (
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
