"""A finding comment says each thing once.

The ten-repository trial read 65 comments and 40 of them said one sentence twice: the
headline, then the same words again after "Remediation:". The description was already
compared against the title and dropped when it repeated it, which left the remediation
compared against an empty string and always kept. The App's copy of this rule lives in
`services/api-service/src/services/prAnalysisOrchestrator.js` and its own test asserts the
same shapes.
"""
from orchestrator.run import render_finding_comment

REPEATED = "EJS unescaped output tag. `<%-` writes raw HTML; use `<%=` so the value is escaped"


def finding(**over):
    base = {
        "title": REPEATED, "description": REPEATED, "remediation": REPEATED,
        "evidence": "OpenGrep AST match on rule `cwe-79.ejs-unescaped-output`",
        "severity": "high", "confidence": 0.9, "cwe_id": "CWE-79",
        "file_path": "views/admin.ejs", "line_start": 17,
    }
    base.update(over)
    return base


def test_a_remediation_that_repeats_the_title_is_dropped():
    body = render_finding_comment(finding())
    assert body.count("EJS unescaped output tag") == 1
    assert "Remediation:" not in body


def test_a_remediation_that_adds_something_is_kept():
    body = render_finding_comment(finding(remediation="Replace `<%-` with `<%=` on this line."))
    assert "Remediation: Replace" in body
    assert body.count("EJS unescaped output tag") == 1


def test_spacing_and_a_trailing_stop_do_not_make_a_repeat_look_different():
    body = render_finding_comment(finding(remediation=f"  {REPEATED}.  "))
    assert "Remediation:" not in body


def test_a_remediation_repeating_a_surviving_description_is_still_dropped():
    body = render_finding_comment(finding(title="Unescaped output", description=REPEATED, remediation=REPEATED))
    assert body.count("EJS unescaped output tag") == 1
