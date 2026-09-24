"""The action definition and the workflows that use it must stay well formed.

Both of the first CI failures on this branch were in this file's territory and neither was
caught by a test. The action was declared a container action, which makes GitHub build it with
the action directory as the Docker context, so every root-relative COPY in the Dockerfile
pointed at nothing. And a workflow line held an unquoted `: ` inside a plain scalar, which made
the whole file unparsable; GitHub reports that as "this run likely failed because of a workflow
file issue", names no file and no line, and runs no jobs at all.

Neither failure needs a runner to detect. These tests read the YAML.
"""
from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml is needed to read the action definition")

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION_YML = REPO_ROOT / "action/action.yml"
DOCKERFILE = REPO_ROOT / "action/Dockerfile"
WORKFLOWS = REPO_ROOT / ".github/workflows"
OUR_WORKFLOWS = ["action-build.yml", "mitig8it-self-review.yml"]

EXPECTED_INPUTS = {
    "github-token", "fail-on", "post-fixes",
    "model-api-key", "model-provider", "model", "max-files",
}
EXPECTED_OUTPUTS = {"findings", "critical", "high", "fixes", "conclusion"}


def load(path: Path) -> dict:
    assert path.is_file(), f"expected a YAML file at {path}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def action() -> dict:
    return load(ACTION_YML)


# --- the contract callers depend on --------------------------------------------------------

def test_the_input_contract_is_unchanged(action):
    assert set(action["inputs"]) == EXPECTED_INPUTS


def test_the_output_contract_is_unchanged(action):
    assert set(action["outputs"]) == EXPECTED_OUTPUTS


def test_fail_on_defaults_to_none(action):
    """Installing a security review must not break a merge on the day it is installed."""
    assert action["inputs"]["fail-on"]["default"] == "none"


def test_the_token_defaults_to_the_workflow_s_own(action):
    assert action["inputs"]["github-token"]["default"] == "${{ github.token }}"


def test_every_output_is_produced_by_the_review_step(action):
    """An output wired to a missing step silently resolves to the empty string."""
    step_ids = {step.get("id") for step in action["runs"]["steps"]}
    for name, spec in action["outputs"].items():
        value = spec["value"]
        assert "steps.review.outputs." in value, f"output {name} is not wired to a step"
        assert "review" in step_ids, "the review step id no longer exists"


# --- the build context, which is what broke ---------------------------------------------------

def test_the_action_is_composite_not_a_container_action(action):
    """A container action is built with the action directory as its Docker context.

    This image is built from the repository root, because it bundles the services that live
    beside the action. Declaring it a container action makes every COPY in the Dockerfile fail.
    """
    assert action["runs"]["using"] == "composite"


def test_the_image_is_built_from_the_repository_root(action):
    build = "\n".join(
        step.get("run", "") for step in action["runs"]["steps"]
    )
    assert "github.action_path }}/.." in build, (
        "the build context must be the parent of the action path, which is the repository root "
        "both for `uses: ./action` and for a remote `uses: owner/repo/action@ref`"
    )
    assert "${ACTION_PATH}/Dockerfile" in build, "the Dockerfile must be named explicitly"


def test_the_dockerfile_copies_paths_that_exist_from_the_repository_root():
    """Every COPY source must resolve against the root, which is the context being used."""
    sources = []
    for raw in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line.upper().startswith("COPY "):
            continue
        parts = [p for p in line.split()[1:] if not p.startswith("--")]
        # The last token is the destination inside the image.
        sources.extend(parts[:-1])
    assert sources, "the Dockerfile has no COPY instructions, which cannot be right"
    for source in sources:
        assert (REPO_ROOT / source).exists(), (
            f"COPY source {source!r} does not exist relative to the repository root"
        )


def test_every_composite_run_step_declares_a_shell(action):
    """A composite `run` step without `shell` is a definition error GitHub rejects."""
    for step in action["runs"]["steps"]:
        if "run" in step:
            assert step.get("shell"), f"step {step.get('name')!r} has run but no shell"


def test_the_build_is_cached(action):
    uses = [step.get("uses", "") for step in action["runs"]["steps"]]
    assert any(u.startswith("actions/cache@") for u in uses), "the layer cache step is missing"
    for pin in uses:
        if pin:
            assert "@" in pin and len(pin.split("@")[1]) == 40, (
                f"{pin} is not pinned to a full commit SHA"
            )


def test_the_token_is_never_passed_on_a_command_line(action):
    """A token in argv shows up in a process listing and in a shell trace."""
    for step in action["runs"]["steps"]:
        run = step.get("run", "")
        assert "inputs.github-token" not in run, (
            "the token must reach the container through the step environment, not the script"
        )


def test_the_container_exit_status_is_forwarded(action):
    """fail-on is worthless if a failing review still exits 0."""
    run = "\n".join(step.get("run", "") for step in action["runs"]["steps"])
    assert 'exit "${status}"' in run


# --- the workflows ------------------------------------------------------------------------------

@pytest.mark.parametrize("name", OUR_WORKFLOWS)
def test_the_workflow_parses(name):
    """An unparsable workflow fails the whole run before any job starts."""
    document = load(WORKFLOWS / name)
    assert document, f"{name} parsed as empty"
    assert "jobs" in document and document["jobs"], f"{name} declares no jobs"


@pytest.mark.parametrize("name", OUR_WORKFLOWS)
def test_the_workflow_requests_no_more_permission_than_it_needs(name):
    document = load(WORKFLOWS / name)
    permissions = document.get("permissions") or {}
    assert permissions.get("contents") == "read", (
        f"{name} must not grant write access to contents"
    )


def test_the_self_review_grants_exactly_the_three_documented_permissions():
    document = load(WORKFLOWS / "mitig8it-self-review.yml")
    assert document["permissions"] == {
        "contents": "read",
        "pull-requests": "write",
        "checks": "write",
    }, "the dogfood workflow must match the permissions block the README tells people to use"


def test_the_self_review_uses_the_local_action():
    document = load(WORKFLOWS / "mitig8it-self-review.yml")
    steps = document["jobs"]["review"]["steps"]
    assert any(step.get("uses") == "./action" for step in steps)


def test_ci_builds_the_image_the_same_way_the_action_does():
    """CI must exercise the path a user takes, not an easier one."""
    document = load(WORKFLOWS / "action-build.yml")
    runs = "\n".join(
        step.get("run", "")
        for job in document["jobs"].values()
        for step in job["steps"]
    )
    assert "docker build --file action/Dockerfile" in runs
    assert runs.rstrip().endswith(".") or " ." in runs, (
        "the build context must be the repository root"
    )
