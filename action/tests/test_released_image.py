"""Which image a run uses, decided by the step in action.yml, exercised as shell.

The action used to build its container on every run, so a first review waited for a full container
build before a line of the caller's code was read. A released ref now pulls the image the release
workflow published; every other ref builds from source exactly as before.

That decision is four conditions of shell in `action.yml`, and shell in a YAML string is the kind
of code that is never run until a user runs it. These tests extract the step's `run:` block and
execute it with bash against a fabricated `released-image.env`, so every branch of the decision is
exercised on a laptop with no Docker and no runner.

The failure this guards against is specific and silent in both directions. A ref that should build
but pulls runs somebody else's image; a ref that should pull but builds is merely slow, and slow is
the defect the pull exists to fix.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml is needed to read the action definition")

pytestmark = pytest.mark.repo_definition

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION_YML = REPO_ROOT / "action/action.yml"
MANIFEST = REPO_ROOT / "action/released-image.env"

OURS = "aicodesentry/mitig8it"
IMAGE = "ghcr.io/aicodesentry/mitig8it-action"
DIGEST = "sha256:" + "ab12cd34" * 8

FULL_MANIFEST = f"""# a comment, and a blank line, both of which a real one has
MITIG8IT_VERSION=1.0.0
MITIG8IT_IMAGE={IMAGE}
MITIG8IT_IMAGE_DIGEST={DIGEST}
"""


def step_named(fragment: str) -> dict:
    document = yaml.safe_load(ACTION_YML.read_text(encoding="utf-8"))
    matches = [s for s in document["runs"]["steps"] if fragment in str(s.get("name", ""))]
    assert len(matches) == 1, f"expected exactly one step whose name contains {fragment!r}"
    return matches[0]


_calls = iter(range(1, 10_000))


def decide(tmp_path: Path, *, repository: str, ref: str, manifest: str | None) -> dict:
    """Run the decision step's own shell and return the outputs it wrote."""
    step = step_named("Decide whether to pull")
    script = step["run"]
    assert "${{" not in script, (
        "the decision step now interpolates a workflow expression into its script, which this "
        "harness cannot reproduce; pass the value through the step's env instead"
    )

    # Its own directory per call. Sharing one made `manifest=None` read the previous call's file,
    # which is how a test of the missing-manifest case came to assert nothing at all.
    tmp_path = tmp_path / f"run-{next(_calls)}"
    tmp_path.mkdir()
    manifest_path = tmp_path / "released-image.env"
    if manifest is not None:
        manifest_path.write_text(manifest, encoding="utf-8")
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")

    completed = subprocess.run(
        ["bash", "-c", script],
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "ACTION_REPOSITORY": repository,
            "ACTION_REF": ref,
            "MANIFEST": str(manifest_path),
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, (
        f"the decision step exited {completed.returncode}: {completed.stderr}"
    )
    outputs = {}
    for line in output.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            outputs[key] = value
    outputs["_log"] = completed.stdout
    return outputs


# --- the released ref pulls -------------------------------------------------------------------

@pytest.mark.parametrize("ref", ["v1", "v1.0", "v1.0.0", "d3b07384d113edec49eaa6238ad5ff00a5f2b4c8"])
def test_a_released_ref_uses_the_published_image(tmp_path, ref):
    result = decide(tmp_path, repository=OURS, ref=ref, manifest=FULL_MANIFEST)
    assert result["source"] == "registry", result["_log"]
    assert result["reference"] == f"{IMAGE}:1.0.0@{DIGEST}"


def test_the_reference_carries_both_the_tag_and_the_digest(tmp_path):
    """The tag is for a human reading a log; the digest is what the daemon verifies.

    `docker pull name:tag@sha256:...` fails if the registry serves a different manifest, which is
    the whole point of writing the digest into the repository rather than pulling `:1.0.0`.
    """
    result = decide(tmp_path, repository=OURS, ref="v1", manifest=FULL_MANIFEST)
    assert ":1.0.0@sha256:" in result["reference"]


def test_the_owner_name_is_compared_without_case(tmp_path):
    """GitHub preserves the case the URL was typed in; the repository is the same repository."""
    result = decide(tmp_path, repository="AICodeSentry/Mitig8it", ref="v1", manifest=FULL_MANIFEST)
    assert result["source"] == "registry", result["_log"]


# --- everything else builds ------------------------------------------------------------------

def test_a_local_path_builds_from_source(tmp_path):
    """`uses: ./action` sets no action repository and no action ref. The dogfood takes this path."""
    result = decide(tmp_path, repository="", ref="", manifest=FULL_MANIFEST)
    assert result["source"] == "build"
    assert "a local path" in result["_log"]


def test_a_fork_builds_its_own_code(tmp_path):
    """A fork's ref must never pull our image: the point of a fork is that the code differs."""
    result = decide(tmp_path, repository="someone-else/mitig8it", ref="v1", manifest=FULL_MANIFEST)
    assert result["source"] == "build"
    assert "someone-else/mitig8it" in result["_log"]


@pytest.mark.parametrize("ref", ["main", "master", "fix/action-trial-findings", "integration/2026-09-24", "v", "1.0.0"])
def test_a_branch_builds_from_source(tmp_path, ref):
    """A branch has no published image, and `1.0.0` without the `v` is not a tag this repo cuts."""
    result = decide(tmp_path, repository=OURS, ref=ref, manifest=FULL_MANIFEST)
    assert result["source"] == "build", f"{ref} was treated as a release: {result['_log']}"


def test_a_ref_that_disagrees_with_the_manifest_builds(tmp_path):
    """`v2` pointing at a commit whose manifest says 1.0.0 must not pull the 1.x image.

    This is the check that makes the major tag safe. `v1` is moved on every 1.x release, so the
    file it lands on always says 1.something; the day a `v2` tag lands on an unrewritten commit,
    the mismatch builds from source instead of reviewing code with the wrong engine.
    """
    result = decide(tmp_path, repository=OURS, ref="v2", manifest=FULL_MANIFEST)
    assert result["source"] == "build"
    assert "does not name the released version" in result["_log"]


def test_a_more_precise_ref_than_the_release_builds(tmp_path):
    result = decide(tmp_path, repository=OURS, ref="v1.0.1", manifest=FULL_MANIFEST)
    assert result["source"] == "build"


def test_an_empty_manifest_builds(tmp_path):
    """What `main` looks like. The unreleased state has to be the safe one."""
    result = decide(
        tmp_path,
        repository=OURS,
        ref="v1",
        manifest="MITIG8IT_VERSION=\nMITIG8IT_IMAGE=\nMITIG8IT_IMAGE_DIGEST=\n",
    )
    assert result["source"] == "build"
    assert "not a release" in result["_log"]


def test_a_missing_manifest_builds(tmp_path):
    """Deleting the file must degrade to the old behaviour, not fail the caller's job."""
    result = decide(tmp_path, repository=OURS, ref="v1", manifest=None)
    assert result["source"] == "build"


@pytest.mark.parametrize(
    "digest",
    [
        "d3b07384d113edec49eaa6238ad5ff00a5f2b4c8",  # a git sha, not a manifest digest
        "sha256:notahexdigestatall",
        "sha512:" + "ab" * 32,
        "latest",
    ],
)
def test_a_digest_that_is_not_a_sha256_manifest_digest_builds(tmp_path, digest):
    manifest = FULL_MANIFEST.replace(DIGEST, digest)
    result = decide(tmp_path, repository=OURS, ref="v1", manifest=manifest)
    assert result["source"] == "build"
    assert "digest" in result["_log"]


@pytest.mark.parametrize(
    "image",
    [
        "docker.io/aicodesentry/mitig8it-action",
        "$(id)",
        "ghcr.io/aicodesentry/mitig8it-action; id",
        "",
    ],
)
def test_an_image_that_is_not_a_plain_ghcr_repository_builds(tmp_path, image):
    """The file is data that becomes a `docker pull` argument, so it is validated first."""
    manifest = FULL_MANIFEST.replace(IMAGE, image)
    result = decide(tmp_path, repository=OURS, ref="v1", manifest=manifest)
    assert result["source"] == "build", result["_log"]


def test_the_manifest_is_never_sourced(tmp_path):
    """A pinned ref must not be able to run shell in the caller's runner by being checked out."""
    canary = tmp_path / "canary"
    manifest = (
        f"MITIG8IT_VERSION=1.0.0\n"
        f"MITIG8IT_IMAGE={IMAGE}\n"
        f"MITIG8IT_IMAGE_DIGEST={DIGEST}\n"
        f"touch {canary}\n"
    )
    decide(tmp_path, repository=OURS, ref="v1", manifest=manifest)
    assert not canary.exists(), "released-image.env was sourced rather than parsed"

    script = step_named("Decide whether to pull")["run"]
    for forbidden in (". ${MANIFEST}", "source ", "eval "):
        assert forbidden not in script, f"the decision step uses {forbidden!r} on the manifest"


# --- the version is reported either way -------------------------------------------------------

def test_the_version_is_reported_even_when_building_from_source(tmp_path):
    """The review has to name what produced it on every ref, not only on a released one."""
    released = decide(tmp_path, repository=OURS, ref="v1", manifest=FULL_MANIFEST)
    assert released["version"] == "1.0.0"
    assert released["digest"] == DIGEST

    branch = decide(tmp_path, repository=OURS, ref="main", manifest=FULL_MANIFEST)
    assert "version" in branch, "the decision step stopped reporting a version when it builds"

    local = decide(tmp_path, repository="", ref="", manifest=None)
    assert local["version"] == "", "a local checkout must not claim a released version"


# --- the committed manifest, and the steps that read the decision ------------------------------

def test_the_committed_manifest_claims_no_release():
    """This file is written on the release commit, not on main.

    If main ever carried a version and a digest, `uses: ...@main` would still build (the ref check
    catches it) but a `v1` tag landing on an unrewritten main would pull a stale image. Empty here
    is the correct state, and the release workflow fills it in on the commit it tags.
    """
    text = MANIFEST.read_text(encoding="utf-8")
    values = {}
    for line in text.splitlines():
        if line.startswith("MITIG8IT_") and "=" in line:
            key, _, value = line.partition("=")
            values[key] = value.strip()
    assert set(values) == {"MITIG8IT_VERSION", "MITIG8IT_IMAGE", "MITIG8IT_IMAGE_DIGEST"}
    assert all(value == "" for value in values.values()), (
        f"{MANIFEST} claims a release on a branch: {values}"
    )
    assert "release.yml" in text, "the file does not say what writes it"


def test_the_file_the_release_writes_is_the_file_the_action_accepts(tmp_path):
    """The loop, closed, without a registry and without Docker.

    One program writes `released-image.env` (a Python heredoc in release.yml) and another reads it
    (a bash step in action.yml). Nothing exercised the pair, and a mismatch between them would not
    show up until a released ref silently built from source in a user's runner, which is the exact
    failure the published image exists to prevent and the one nobody would report.

    So: run the release workflow's own writer over a copy of the committed file, then hand the
    result to the action's own decision and require a registry pull.
    """
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    )
    step = next(
        s for s in workflow["jobs"]["release"]["steps"]
        if s.get("name") == "Write the release commit"
    )
    script = step["run"]
    assert "<<'PYTHON'" in script, "the release no longer writes the file with a Python heredoc"
    writer = script.split("<<'PYTHON'\n", 1)[1].split("\nPYTHON\n", 1)[0]

    tree = tmp_path / "checkout"
    (tree / "action").mkdir(parents=True)
    target = tree / "action/released-image.env"
    target.write_text(MANIFEST.read_text(encoding="utf-8"), encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "-", "1.4.2", IMAGE, DIGEST],
        input=writer,
        cwd=tree,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr

    written = target.read_text(encoding="utf-8")
    assert "MITIG8IT_VERSION=1.4.2" in written
    assert f"MITIG8IT_IMAGE={IMAGE}" in written
    assert f"MITIG8IT_IMAGE_DIGEST={DIGEST}" in written
    # The comments explaining the file survive, because they are what a reader finds it by.
    assert "release.yml" in written

    result = decide(tmp_path, repository=OURS, ref="v1.4.2", manifest=written)
    assert result["source"] == "registry", result["_log"]
    assert result["reference"] == f"{IMAGE}:1.4.2@{DIGEST}"

    # And the major tag the release moves resolves to the same image.
    assert decide(tmp_path, repository=OURS, ref="v1", manifest=written)["source"] == "registry"


def test_the_release_writer_refuses_a_file_it_does_not_recognise(tmp_path):
    """A `released-image.env` that lost a key must fail the release, not be released half-written."""
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    )
    step = next(
        s for s in workflow["jobs"]["release"]["steps"]
        if s.get("name") == "Write the release commit"
    )
    writer = step["run"].split("<<'PYTHON'\n", 1)[1].split("\nPYTHON\n", 1)[0]

    tree = tmp_path / "checkout"
    (tree / "action").mkdir(parents=True)
    (tree / "action/released-image.env").write_text("MITIG8IT_VERSION=\n", encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "-", "1.4.2", IMAGE, DIGEST],
        input=writer,
        cwd=tree,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0, "a file missing two of its three keys was accepted"
    assert "MITIG8IT_IMAGE" in completed.stderr


def test_every_build_step_is_skipped_when_the_image_was_pulled():
    """A pulled image that still paid for a build would have bought nothing.

    The condition has to allow for the pull failing, which is why it is not simply
    `source == 'build'`: a released ref whose registry is unreachable falls back to building.
    """
    document = yaml.safe_load(ACTION_YML.read_text(encoding="utf-8"))
    expected = "steps.image.outputs.source != 'registry' || steps.pull.outputs.pulled == 'false'"
    build_steps = [
        step
        for step in document["runs"]["steps"]
        if "build-image.sh" in str(step.get("run", ""))
        or str(step.get("uses", "")).startswith("actions/cache@")
        or "cache key" in str(step.get("name", ""))
    ]
    assert len(build_steps) == 3, f"expected three build steps, found {len(build_steps)}"
    for step in build_steps:
        assert step.get("if") == expected, (
            f"step {step.get('name')!r} runs unconditionally: {step.get('if')!r}"
        )


def test_the_pull_step_verifies_the_digest_and_tags_what_the_run_step_runs():
    step = step_named("Pull the released image")
    assert step.get("if") == "steps.image.outputs.source == 'registry'"
    run = step["run"]
    assert 'docker pull --quiet "${REFERENCE}"' in run
    assert 'docker tag "${REFERENCE}" mitig8it-action:local' in run, (
        "the review step runs mitig8it-action:local, so the pulled image has to answer to that name"
    )
    assert "pulled=false" in run, "a pull that fails must be recoverable, not fatal"


def test_the_review_step_is_told_what_produced_it():
    """The four variables the orchestrator turns into the version line the review carries."""
    document = yaml.safe_load(ACTION_YML.read_text(encoding="utf-8"))
    review = [s for s in document["runs"]["steps"] if s.get("id") == "review"][0]
    for name in (
        "MITIG8IT_ACTION_VERSION",
        "MITIG8IT_ACTION_IMAGE_DIGEST",
        "MITIG8IT_ACTION_SOURCE",
        "MITIG8IT_ACTION_REF",
    ):
        assert name in review["env"], f"{name} is not passed to the review step"
        assert f"--env {name}" in review["run"], f"{name} never reaches the container"


def test_the_reported_source_is_what_happened_not_what_was_intended():
    """A released ref whose pull failed must not tell the user it ran the published image."""
    document = yaml.safe_load(ACTION_YML.read_text(encoding="utf-8"))
    review = [s for s in document["runs"]["steps"] if s.get("id") == "review"][0]
    assert "steps.pull.outputs.pulled == 'true'" in review["env"]["MITIG8IT_ACTION_SOURCE"], (
        "the reported source is derived from the intention rather than from the pull's result"
    )
