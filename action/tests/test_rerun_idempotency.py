"""A second run over the same pull request converges instead of accumulating.

The self-review reached 74 open threads on one pull request: 37 from a first run, still open, and
37 from a second beside them, none resolved. Two things caused it and both are fixed here.

Nothing ever closed a thread. github-service edits its own comment in place when the same finding
comes back, but a finding that goes away kept its thread open forever, and there is no REST
endpoint for resolving a review thread, so nothing in the repository had ever spoken to the
GraphQL API that has one.

And the finding fingerprint hashes the line number (`make_fingerprint` in the analysis service),
so a push that shifts a line retires every marker at once. That is why a whole run was orphaned
rather than a comment here and there. Resolution is what makes that survivable: the previous
run's threads are for fingerprints the current run does not report, so they are closed.

A finding the run reported but could not anchor to a changed line has no comment and must still
count as present, or its thread would be resolved as though the finding had gone away. That is
why the publisher is given every finding's fingerprint and not only the commented ones.
"""
from __future__ import annotations

import pytest

from orchestrator import run
from tests import fake_graphql, publisher_harness

HEAD = "a" * 40
BASE = "b" * 40
COUNTS = {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0}


def finding(fingerprint, path="src/db.js", line=12, title="SQL injection"):
    return {
        "fingerprint": fingerprint,
        "file_path": path,
        "line_start": line,
        "severity": "high",
        "title": title,
        "rule_id": "sql.injection.raw_query",
    }


def a_request(findings, *, bot_login="github-actions[bot]"):
    # New-side lines 10 through 15, so a finding on 12, 13 or 14 anchors and one on 900 does not.
    patch = "@@ -10,6 +10,6 @@\n a\n+b\n+c\n+d\n+e\n+f\n"
    patches = {"src/db.js": patch, "src/cmd.js": patch}
    comments = run.build_inline_comments(findings, patches)
    return run.build_publish_request(
        token="ghs-token",
        repository="acme/widgets",
        pr_number=7,
        head_sha=HEAD,
        base_sha=BASE,
        installation_id=42,
        actor_login="octocat",
        counts=COUNTS,
        findings=len(findings),
        fix_sections=[],
        inline_comments=comments,
        model_configured=False,
        conclusion="failure",
        active_fingerprints=[run.comment_fingerprint(f) for f in findings],
        bot_login=bot_login,
    )


@pytest.fixture
def graphql():
    server = fake_graphql.FakeGraphQL().start()
    yield server
    server.stop()


@pytest.fixture
def publisher(tmp_path, graphql):
    if not publisher_harness.node_available():
        pytest.skip("node is not on PATH")
    return publisher_harness.Publisher(tmp_path, graphql_url=graphql.url())


def marker(fingerprint):
    return f"<!-- mitig8it-finding:{fingerprint} -->"


def test_a_second_run_edits_resolves_and_creates_without_duplicating(publisher, graphql):
    """The whole defect, in one test.

    Run one reports `stays` and `goes`. Run two reports `stays` (with different text) and
    `arrives`. The result must be: the comment for `stays` edited in place, the thread for
    `goes` resolved, one comment created for `arrives`, and nothing duplicated.
    """
    first = [finding("fp-stays", line=12), finding("fp-goes", path="src/cmd.js", line=13)]
    completed = publisher.run(a_request(first))
    assert completed.returncode == 0, completed.stderr

    created = [call for call in publisher.calls() if call["name"] == "create"]
    assert len(created) == 2
    assert len(publisher.state()["comments"]) == 2

    # GitHub opens a thread per comment. The fake is told about the ones the first run created.
    for comment in publisher.state()["comments"]:
        graphql.add_thread(comment["body"])
    publisher.clear_calls()

    second = [
        finding("fp-stays", line=12, title="SQL injection (rephrased)"),
        finding("fp-arrives", path="src/cmd.js", line=14, title="Command injection"),
    ]
    completed = publisher.run(a_request(second))
    assert completed.returncode == 0, completed.stderr

    calls = publisher.calls()
    edits = [call for call in calls if call["name"] == "edit"]
    creates = [call for call in calls if call["name"] == "create"]

    assert [call["marker"] for call in edits] == [marker("fp-stays")]
    assert edits[0]["changed"] is True
    assert [call["marker"] for call in creates] == [marker("fp-arrives")]

    # Three findings were ever reported, so there are exactly three comments: no duplicates.
    bodies = [comment["body"] for comment in publisher.state()["comments"]]
    assert len(bodies) == 3
    assert sum(1 for body in bodies if marker("fp-stays") in body) == 1

    resolved = graphql.resolved_bodies()
    assert len(resolved) == 1 and marker("fp-goes") in resolved[0]
    assert [body for body in graphql.open_bodies() if marker("fp-stays") in body]


def test_a_third_run_with_no_findings_resolves_everything_it_had_open(publisher, graphql):
    """A pull request that fixed everything ends up showing that, not a wall of old threads."""
    completed = publisher.run(a_request([finding("fp-one"), finding("fp-two", path="src/cmd.js")]))
    assert completed.returncode == 0, completed.stderr
    for comment in publisher.state()["comments"]:
        graphql.add_thread(comment["body"])

    completed = publisher.run(a_request([]))
    assert completed.returncode == 0, completed.stderr

    assert len(graphql.resolved_bodies()) == 2
    assert graphql.open_bodies() == []


def test_an_unanchored_finding_keeps_its_thread_open(publisher, graphql):
    """A finding on a line the pull request did not touch has no comment but has not gone away."""
    anchored = finding("fp-anchored", line=12)
    # Line 900 is outside every patch, so build_inline_comments drops it.
    unanchored = finding("fp-unanchored", line=900)
    request = a_request([anchored, unanchored])
    assert [c["fingerprint"] for c in request["inline_comments"]] == ["fp-anchored"]
    assert request["active_fingerprints"] == ["fp-anchored", "fp-unanchored"]

    graphql.add_thread(marker("fp-unanchored") + "\nreported earlier, still true")
    completed = publisher.run(request)

    assert completed.returncode == 0, completed.stderr
    assert graphql.resolved_bodies() == []


def test_a_human_thread_is_never_touched(publisher, graphql):
    """Only a thread whose first comment is ours, carrying our marker, is ever ours to close."""
    graphql.add_thread("please rename this variable", login="a-reviewer")
    graphql.add_thread(marker("fp-someone-else") + "\nnot posted by us", login="other[bot]")

    completed = publisher.run(a_request([finding("fp-new")]))

    assert completed.returncode == 0, completed.stderr
    assert graphql.resolved_bodies() == []


def test_an_already_resolved_thread_is_left_alone(publisher, graphql):
    """Re-resolving is not free: it is a mutation per thread on every run forever."""
    thread = graphql.add_thread(marker("fp-old") + "\nold finding")
    thread.is_resolved = True

    completed = publisher.run(a_request([finding("fp-new")]))

    assert completed.returncode == 0, completed.stderr
    assert not [call for call in graphql.calls if call.startswith("resolve:")]


def test_minimize_is_the_fallback_when_a_token_may_not_resolve(tmp_path):
    """Not every token that can comment can resolve, and a stale thread is worth minimizing."""
    if not publisher_harness.node_available():
        pytest.skip("node is not on PATH")
    server = fake_graphql.FakeGraphQL(resolve_fails=True).start()
    try:
        publisher = publisher_harness.Publisher(tmp_path, graphql_url=server.url())
        server.add_thread(marker("fp-old") + "\nold finding")

        completed = publisher.run(a_request([finding("fp-new")]))

        assert completed.returncode == 0, completed.stderr
        assert any(call.startswith("minimize:") for call in server.calls)
        assert server.threads[0].is_minimized is True
    finally:
        server.stop()


def test_a_thread_that_can_be_neither_resolved_nor_minimized_is_reported(tmp_path):
    """Reported as an annotation, never fatal: the review itself published."""
    if not publisher_harness.node_available():
        pytest.skip("node is not on PATH")
    server = fake_graphql.FakeGraphQL(resolve_fails=True, minimize_fails=True).start()
    try:
        publisher = publisher_harness.Publisher(tmp_path, graphql_url=server.url())
        server.add_thread(marker("fp-old") + "\nold finding")

        completed = publisher.run(a_request([finding("fp-new")]))

        assert completed.returncode == 1
        assert "fp-old" in completed.stderr
        # The review and the check still published.
        assert [call["name"] for call in publisher.calls()] == ["review", "create", "check"]
    finally:
        server.stop()


# --- the pieces, without a subprocess ----------------------------------------------------------

def test_a_finding_without_a_fingerprint_still_gets_a_matchable_marker():
    """An empty fingerprint rendered `<!-- mitig8it-finding: -->`, which the service's own
    pattern does not match, so every run created a second comment."""
    derived = run.comment_fingerprint({"rule_id": "r", "file_path": "a.js", "line_start": 3})
    assert derived and derived.startswith("derived-")
    body = run.render_finding_comment({"rule_id": "r", "file_path": "a.js", "line_start": 3})
    import re

    assert re.search(r"<!-- mitig8it-finding:[^>]+ -->", body)
    # Stable across two runs over the same tree, which is what idempotency needs.
    assert run.comment_fingerprint({"rule_id": "r", "file_path": "a.js", "line_start": 3}) == derived
    assert run.comment_fingerprint({"rule_id": "r", "file_path": "a.js", "line_start": 4}) != derived


def test_the_scanner_fingerprint_is_preferred_when_there_is_one():
    assert run.comment_fingerprint({"fingerprint": "abc123", "rule_id": "r"}) == "abc123"
