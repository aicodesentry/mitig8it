"""No documented install may tell a reader to run a moving branch.

The quickstart said `uses: aicodesentry/mitig8it/action@main` for as long as the action existed.
`main` is this repository's default branch: it moves every time a pull request lands, and whatever
is on it runs in the reader's runner with the reader's token on their next push. That is precisely
the shape this product's own highest-precision rule reports in other people's workflows --
`cwe-1357.gha-third-party-action-unpinned`, measured at 1.00 over 46 findings in
docs/validation/workflow-tampering-2026-09.md -- and a security tool may not ship advice it
violates in its own five-line install.

The fix was one character in four files, which is exactly the kind of fix that comes back. These
tests read the documentation.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_definition

REPO_ROOT = Path(__file__).resolve().parents[2]

# What a reader is told to install: the front page, the action's own page, the getting-started
# pages and the bug template's example. Every one of these is advice a stranger acts on.
#
# Deliberately not here: docs/validation/** and docs/release-notes/**. Those record what was run
# on a given day, refs and all. The September 2026 trial genuinely ran
# `action@integration/2026-09-24`, and rewriting that to `@v1` would make the record false rather
# than make the advice better. docs/history/** is the same.
DOCUMENTED_PATHS = [
    "README.md",
    "action/README.md",
    ".github/ISSUE_TEMPLATE/bug.yml",
    *sorted(str(p.relative_to(REPO_ROOT)) for p in (REPO_ROOT / "docs/getting-started").glob("*.md")),
]

# Every way this repository's own action can be named, with whatever ref follows.
OUR_ACTION = re.compile(r"aicodesentry/mitig8it(?:/action)?@([^\s`'\"),]+)")

# The two refs a reader may be handed. `v1` or `v1.2.3` is a release this repository controls and
# promises not to break within the major; a 40-character hex string is a commit nobody can move.
RELEASE_TAG = re.compile(r"^v\d+(?:\.\d+){0,2}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")

FORBIDDEN_HINT = (
    "A documented install must name a release tag (v1, v1.0.0) or a full 40-character commit "
    "sha. A branch name moves, and cwe-1357.gha-third-party-action-unpinned is this product's "
    "own rule against exactly that."
)


def documented_files():
    for relative in DOCUMENTED_PATHS:
        path = REPO_ROOT / relative
        assert path.is_file(), f"{relative} is in the documented set but does not exist"
        yield relative, path.read_text(encoding="utf-8")


def is_placeholder(ref: str) -> bool:
    """`action@<ref>` in a sentence about how `uses:` resolves is not an install."""
    return "<" in ref or ">" in ref


def unwrapped(text: str) -> str:
    """Prose in these files wraps at a hundred columns, so a phrase can straddle two lines."""
    return " ".join(text.split())


def test_the_documented_set_is_not_empty():
    """A glob that matched nothing would make every test below pass vacuously."""
    files = list(documented_files())
    assert len(files) >= 4, f"only {len(files)} documented files were found"


def test_no_documented_install_names_a_branch():
    offences = []
    for relative, text in documented_files():
        for ref in OUR_ACTION.findall(text):
            if is_placeholder(ref):
                continue
            if not (RELEASE_TAG.match(ref) or COMMIT_SHA.match(ref)):
                offences.append(f"{relative}: @{ref}")
    assert not offences, f"{offences} -- {FORBIDDEN_HINT}"


@pytest.mark.parametrize("branch", ["main", "master", "develop", "HEAD"])
def test_no_documented_install_names_these_branches_in_particular(branch):
    """Named so the failure message says `@main` rather than only "not a version"."""
    offences = [
        relative
        for relative, text in documented_files()
        if f"aicodesentry/mitig8it/action@{branch}" in text
        or f"aicodesentry/mitig8it@{branch}" in text
    ]
    assert not offences, f"{offences} still install the action from @{branch}. {FORBIDDEN_HINT}"


def test_the_quickstart_actually_shows_an_install():
    """The tests above are satisfied by a file with no install in it at all."""
    for relative in ("README.md", "action/README.md", "docs/getting-started/github-action.md"):
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        refs = [ref for ref in OUR_ACTION.findall(text) if not is_placeholder(ref)]
        assert refs, f"{relative} no longer shows how to install the action"
        assert any(RELEASE_TAG.match(ref) for ref in refs), (
            f"{relative} shows no release tag; a reader cannot retype a 40-character sha from a page"
        )


def test_the_quickstart_says_a_digest_is_stronger():
    """`@v1` is still a tag, and a tag can be moved by whoever owns it -- us.

    The rule's own remediation is the 40-character digest, so a quickstart that stops at `@v1`
    has improved the advice without completing it. Each of these pages has to say what the
    stronger pin is and how to obtain one.
    """
    for relative in ("README.md", "action/README.md", "docs/getting-started/github-action.md"):
        text = unwrapped((REPO_ROOT / relative).read_text(encoding="utf-8"))
        assert "A digest pin is stronger" in text or "The strongest pin" in text, (
            f"{relative} shows @v1 without saying that a digest pin is stronger"
        )
        assert "commits/v1 --jq .sha" in text, (
            f"{relative} says a digest is stronger without saying how to obtain one"
        )


def test_the_workflows_in_this_repository_pin_every_third_party_action():
    """The rule excludes `actions/*` and `github/*`; everything else needs the full sha.

    The release workflow is the reason this test exists: it is the one workflow here that reaches
    for a third-party action, and it is also the workflow that publishes.
    """
    pattern = re.compile(r"^\s*(?:-\s+)?uses\s*:\s*['\"]?([^\s'\"#]+)", re.MULTILINE)
    offences = []
    for workflow in sorted((REPO_ROOT / ".github/workflows").glob("*.y*ml")):
        for reference in pattern.findall(workflow.read_text(encoding="utf-8")):
            if reference.startswith("./") or reference.startswith("docker://"):
                continue
            name, _, ref = reference.partition("@")
            if name.lower().startswith(("actions/", "github/")):
                continue
            if not COMMIT_SHA.match(ref):
                offences.append(f"{workflow.name}: {reference}")
    assert not offences, (
        f"{offences} are third-party actions referenced by tag or branch. "
        "cwe-1357.gha-third-party-action-unpinned is our own rule; pin the full commit sha and "
        "keep the version in a trailing comment."
    )
