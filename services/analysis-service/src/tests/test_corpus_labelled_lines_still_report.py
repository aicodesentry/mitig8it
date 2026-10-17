"""Labelled corpus lines that a trial reported missing, re-checked and pinned.

`docs/validation/action-trial-2026-09.md` opens its "What is still wrong" list with a lost true
positive: pygoat `introduction/views.py:963`, `ssrf.untrusted_url_fetch`, CWE-918, on
`response = requests.get(url)` two lines below `url = request.POST["url"]`. It is a line
`benchmarks/vulnerable-corpus/labels.json` labels (`pygoat-ssrf-lab2`), the Action reported it
before the trial's fixes and not after, and the note calls it "the only labelled line the fixes
cost".

Re-run against `main` on 29 September 2026, over the real file at the pinned corpus ref, the
finding is produced and it lands on line 963. So the regression is not present here, whether it was
fixed by one of the merges since `integration/2026-09-24` or was only ever on that branch. What was
missing was a test, which is why nobody could tell.

That is what this file is. A labelled line that a trial says went missing gets a case here, so the
next time it goes missing a suite says so rather than a hand-read of sixty review comments five days
later.

The fixture is the shape, not a vendored copy of somebody else's repository: the two lines that make
the finding true, in the Django view they appear in, at the line numbers the label names. Anchoring
is asserted as well as presence, because a finding one line off its sink cannot be posted on the
line a reviewer has to change and a diff that only touches the sink leaves it with nowhere to go.
"""
from __future__ import annotations

import pytest

from main import AnalyzePRRequest, analyze_pull_request_payload

# `url` reaches `requests.get` with nothing between the two but a `try:`. This is
# `pygoat-ssrf-lab2` in the corpus, reduced to the view it lives in and padded so the sink sits on
# line 963, the line the label names.
SSRF_VIEW_TAIL = '''@authentication_decorator
def ssrf_lab2(request):
    if request.method == "GET":
        return render(request, "Lab/ssrf/ssrf_lab2.html")

    elif request.method == "POST":
        url = request.POST["url"]
        try:
            response = requests.get(url)
            return render(request, "Lab/ssrf/ssrf_lab2.html", {"response": response.content.decode()})
        except Exception:
            return render(request, "Lab/ssrf/ssrf_lab2.html", {"error": "Invalid URL"})
'''

SINK_LINE = 963
SINK_TEXT = "            response = requests.get(url)"


def _file_with_sink_at(line: int) -> list[str]:
    """The view, padded above so that `requests.get(url)` is on `line`."""
    tail = SSRF_VIEW_TAIL.splitlines()
    offset = tail.index(SINK_TEXT)
    padding = line - 1 - offset
    assert padding >= 0, "the sink cannot sit above the top of the file"
    header = ["import requests", "from django.shortcuts import render"]
    filler = ["# padding, so the sink sits on the line the corpus labels"] * (padding - len(header))
    lines = header + filler + tail
    assert lines[line - 1] == SINK_TEXT, lines[line - 1]
    return lines


def _payload(lines: list[str], line: int) -> AnalyzePRRequest:
    """One changed line, which is how the trial put a labelled line into a diff."""
    original = lines[line - 1]
    changed = f"{original}  # reviewed"
    head = "\n".join(lines[: line - 1] + [changed] + lines[line:]) + "\n"
    patch = "\n".join(
        [
            f"@@ -{line - 2},5 +{line - 2},5 @@",
            f" {lines[line - 3]}",
            f" {lines[line - 2]}",
            f"-{original}",
            f"+{changed}",
            f" {lines[line]}",
            "",
        ]
    )
    return AnalyzePRRequest.model_validate(
        {
            "repository_full_name": "aicodesentry/corpus-regression",
            "pull_request_number": 1,
            "commit_sha": "a" * 40,
            "files": [
                {
                    "path": "introduction/views.py",
                    "patch": patch,
                    "content": head,
                    "reviewable_line_spans": [{"start": line, "end": line}],
                }
            ],
        }
    )


def _ssrf(findings: list[dict]) -> list[dict]:
    return [
        finding
        for finding in findings
        if finding.get("cwe_id") == "CWE-918"
        or finding.get("internal_type") == "server_side_request_forgery"
    ]


@pytest.fixture(scope="module")
def analysed() -> dict:
    lines = _file_with_sink_at(SINK_LINE)
    return analyze_pull_request_payload(_payload(lines, SINK_LINE))


def test_the_pygoat_ssrf_label_still_produces_a_finding(analysed):
    """The claim in the trial's defect 1, asserted rather than re-read by hand."""
    assert _ssrf(analysed["findings"]), (
        "no server-side request forgery finding for `requests.get(url)` two lines below "
        "`url = request.POST[\"url\"]`. This is corpus label pygoat-ssrf-lab2 and "
        "docs/validation/action-trial-2026-09.md defect 1 is about losing it."
    )


def test_the_finding_lands_on_the_line_the_corpus_labels(analysed):
    """One line off is not a near miss: it is a comment a reviewer cannot act on.

    A finding anchored above the sink also falls outside a diff that touches only the sink, which
    turns it into one of the trial's "findings with nowhere to go" rather than an inline comment.
    """
    lines = [finding.get("line_start") for finding in _ssrf(analysed["findings"])]
    assert SINK_LINE in lines, f"anchored at {lines}, expected {SINK_LINE}"


def test_the_finding_is_not_quarantined_away(analysed):
    """The rule posts. If it is ever quarantined, that should be a decision, not a surprise."""
    assert "ssrf.untrusted_url_fetch" not in (analysed.get("quarantined_findings") or {})
