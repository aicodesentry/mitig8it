"""Every review names the version that produced it.

A bug report against this action used to have to name a date. "The review on the 24th said X" is
unanswerable once main has moved, and nothing on the pull request said which code had run: the
check summary, the review body and the footer all identified the tool and not the version.

The version is composed once, in `run.version_identity`, and rendered twice, in the check run
summary and in the review body's footer. These tests cover both halves, plus the case the label
exists for: a run that built its own image must never claim to be the released one.
"""
from __future__ import annotations

import re

import pytest

from orchestrator import run
from tests import fake_graphql, publisher_harness
from tests.test_publish_envelope import NO_COUNTS, a_request, run_publisher

REGISTRY = {
    "MITIG8IT_ACTION_VERSION": "1.0.0",
    "MITIG8IT_ACTION_IMAGE_DIGEST": "sha256:" + "ab12cd34" * 8,
    "MITIG8IT_ACTION_SOURCE": "registry",
    "MITIG8IT_ACTION_REF": "v1",
}


# --- the label ---------------------------------------------------------------------------------

def test_a_released_ref_running_the_published_image_reports_the_version():
    identity = run.version_identity(REGISTRY)
    assert identity["label"] == "v1.0.0"
    assert identity["version"] == "1.0.0"
    assert identity["source"] == "registry"


def test_a_released_ref_that_had_to_build_says_so():
    """The pull can fail: a private package, a registry outage, a runner with no route to it.

    The action falls back to building, which produces the same review, so the run is fine. What
    would not be fine is the review claiming to be the published image: a maintainer chasing a
    defect would compare the wrong bytes against it.
    """
    identity = run.version_identity({**REGISTRY, "MITIG8IT_ACTION_SOURCE": "source"})
    assert identity["label"] == "v1.0.0 (built from source, not the released image)"


def test_a_branch_names_the_branch_and_claims_no_version():
    identity = run.version_identity(
        {"MITIG8IT_ACTION_REF": "main", "MITIG8IT_ACTION_SOURCE": "source"}
    )
    assert identity["label"] == "unreleased (main, built from source)"
    assert identity["version"] == ""


def test_a_local_checkout_says_it_is_a_local_checkout():
    """`uses: ./action`, which is what the dogfood workflow and every local run take."""
    identity = run.version_identity({})
    assert identity["label"] == "unreleased (local checkout, built from source)"


def test_no_environment_ever_produces_a_bare_version_that_was_not_released():
    """The failure this guards against is a label a user could quote as a release when it is not."""
    for environ in (
        {},
        {"MITIG8IT_ACTION_REF": "main"},
        {"MITIG8IT_ACTION_SOURCE": "registry"},
        {"MITIG8IT_ACTION_VERSION": "", "MITIG8IT_ACTION_SOURCE": "registry"},
    ):
        label = run.version_identity(environ)["label"]
        assert label.startswith("unreleased"), f"{environ} produced {label!r}"


def test_whitespace_in_the_environment_is_not_a_version():
    identity = run.version_identity({"MITIG8IT_ACTION_VERSION": "  ", "MITIG8IT_ACTION_SOURCE": "registry"})
    assert identity["label"].startswith("unreleased")


# --- the publish request -----------------------------------------------------------------------

def test_the_request_carries_the_label_the_orchestrator_composed():
    request = a_request([], counts=NO_COUNTS, findings=0, conclusion="success")
    assert "versionLabel" in request, "the publisher has nothing to render"


def test_a_caller_that_names_no_label_still_gets_one(monkeypatch):
    """`build_publish_request` falls back to reading the environment, never to nothing.

    An empty string in the payload would render as "Mitig8it  found 0 findings", which reads like
    a rendering bug rather than like a missing version.
    """
    for key, value in REGISTRY.items():
        monkeypatch.setenv(key, value)
    request = a_request([], counts=NO_COUNTS, findings=0, conclusion="success")
    assert request["versionLabel"] == "v1.0.0"


# --- what the reader sees ---------------------------------------------------------------------

def a_published_request():
    request = a_request([], counts=NO_COUNTS, findings=0, conclusion="success")
    request["versionLabel"] = "v1.0.0"
    return request


def test_the_check_summary_and_the_review_body_both_name_the_version(tmp_path):
    if not publisher_harness.node_available():
        pytest.skip("node is not on PATH")
    completed, recorded = run_publisher(tmp_path, a_published_request())

    assert completed.returncode == 0, completed.stderr
    check = next(call for call in recorded if call["name"] == "check")
    review = next(call for call in recorded if call["name"] == "review")
    assert "Mitig8it v1.0.0 found" in check["summary"], check["summary"]
    assert "Mitig8it v1.0.0" in review["body"], review["body"]


def test_the_two_places_cannot_disagree(tmp_path):
    """One string, composed once, rendered twice. `counts` follows the same rule for the same reason.

    The trial read four different totals for one review because three renderers each did their own
    arithmetic. A version derived independently in two places would drift the same way.
    """
    if not publisher_harness.node_available():
        pytest.skip("node is not on PATH")
    request = a_published_request()
    request["versionLabel"] = "v9.9.9 (built from source, not the released image)"
    completed, recorded = run_publisher(tmp_path, request)

    assert completed.returncode == 0, completed.stderr
    check = next(call for call in recorded if call["name"] == "check")
    review = next(call for call in recorded if call["name"] == "review")
    assert "v9.9.9 (built from source, not the released image)" in check["summary"]
    assert "v9.9.9 (built from source, not the released image)" in review["body"]


def test_a_request_with_no_label_reports_that_rather_than_a_version(tmp_path):
    """An older orchestrator, or a caller that did not set it. Never a fabricated version."""
    if not publisher_harness.node_available():
        pytest.skip("node is not on PATH")
    request = a_published_request()
    del request["versionLabel"]
    completed, recorded = run_publisher(tmp_path, request)

    assert completed.returncode == 0, completed.stderr
    check = next(call for call in recorded if call["name"] == "check")
    assert "an unreported version" in check["summary"]
    assert not re.search(r"\bv\d", check["summary"]), (
        f"a request with no label produced a version number: {check['summary']}"
    )


def test_the_review_body_tells_the_reader_to_quote_it(tmp_path):
    """The version is only worth carrying if a bug report names it."""
    if not publisher_harness.node_available():
        pytest.skip("node is not on PATH")
    completed, recorded = run_publisher(tmp_path, a_published_request())

    assert completed.returncode == 0, completed.stderr
    review = next(call for call in recorded if call["name"] == "review")
    assert "bug report" in review["body"]


def test_the_version_is_on_a_clean_review_too(tmp_path):
    """A clean run is the one a maintainer is most likely to doubt, and the version is the answer."""
    if not publisher_harness.node_available():
        pytest.skip("node is not on PATH")
    completed, recorded = run_publisher(tmp_path, a_published_request())

    assert completed.returncode == 0, completed.stderr
    check = next(call for call in recorded if call["name"] == "check")
    assert check["title"] == "No security findings"
    assert "v1.0.0" in check["summary"]
    review = next(call for call in recorded if call["name"] == "review")
    assert "no security issues found" in review["body"]
    assert "v1.0.0" in review["body"]


assert fake_graphql  # imported for the harness's side of the publish; referenced so linters agree
