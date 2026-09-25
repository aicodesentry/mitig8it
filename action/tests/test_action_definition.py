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

# These read the workflow files, which the image has no reason to carry: they describe how the
# repository builds and runs the action, not what the image contains. The in-image run excludes
# them; the host job runs them.
pytestmark = pytest.mark.repo_definition

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION_YML = REPO_ROOT / "action/action.yml"
DOCKERFILE = REPO_ROOT / "action/Dockerfile"
BUILD_SCRIPT = REPO_ROOT / "action/build-image.sh"
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


def test_the_image_is_built_by_the_shared_script(action):
    build = "\n".join(step.get("run", "") for step in action["runs"]["steps"])
    assert "build-image.sh" in build, (
        "the action must build through the shared script, so it and CI cannot drift apart"
    )
    assert "github.action_path }}/build-image.sh" in build


def test_the_build_script_uses_the_repository_root_as_the_context():
    """The context must be the action's parent, which is the root in both `uses:` forms."""
    script = BUILD_SCRIPT.read_text(encoding="utf-8")
    assert 'ROOT="$(CDPATH=\'\' cd -- "${SCRIPT_DIR}/.." && pwd)"' in script
    assert '"${ROOT}"' in script, "the root must be passed as the build context"
    assert '--file "${DOCKERFILE}"' in script, "the Dockerfile must be named explicitly"


def test_the_build_script_asks_for_a_builder_that_can_export_a_cache():
    """buildx's default docker driver cannot export a cache and fails the build outright.

    The error is "Cache export is not supported for the docker driver", and it stops the build
    rather than degrading, so a cache requires a docker-container builder.
    """
    script = BUILD_SCRIPT.read_text(encoding="utf-8")
    assert "--driver docker-container" in script
    assert "docker buildx inspect" in script, "the builder must be created idempotently"
    assert "--load" in script, "the image must still land in the local daemon for docker run"


def test_the_build_script_falls_back_rather_than_failing():
    """No buildx, no builder, or no cache directory must all still produce an image."""
    script = BUILD_SCRIPT.read_text(encoding="utf-8")
    assert "docker build --file" in script, "the plain fallback build is missing"
    assert "without a layer cache" in script, "the fallback should say why it is slower"


def test_the_build_script_is_executable():
    assert BUILD_SCRIPT.stat().st_mode & 0o111, "build-image.sh is not executable"


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
    assert "./action/build-image.sh" in runs, (
        "CI must build through the same script the composite action uses"
    )


def test_the_in_image_test_run_excludes_the_repository_definition_tests():
    """Those tests read files the image does not carry, and are run by the host job instead."""
    document = load(WORKFLOWS / "action-build.yml")
    runs = "\n".join(
        step.get("run", "")
        for job in document["jobs"].values()
        for step in job["steps"]
    )
    assert 'pytest tests -q -m "not repo_definition"' in runs


def test_the_marker_is_registered():
    """An unregistered marker is silently a no-op under strict settings and a warning otherwise."""
    ini = (REPO_ROOT / "action/pytest.ini").read_text(encoding="utf-8")
    assert "repo_definition:" in ini


# --- the Node runtime ----------------------------------------------------------------------

REMEDIATION_DOCKERFILE = REPO_ROOT / "services/remediation-service/Dockerfile"

NODE_ARGS = ("NODE_VERSION", "NODE_SHA256_X64", "NODE_SHA256_ARM64")


def node_args(path):
    """The three pinned Node build arguments of a Dockerfile, by name."""
    values = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line.startswith("ARG "):
            continue
        name, _, value = line[4:].partition("=")
        if name.strip() in NODE_ARGS:
            values[name.strip()] = value.strip()
    return values


def test_the_action_pins_the_remediation_service_s_node():
    """The repair engine's sandbox harness decides this version, so one of them cannot choose.

    The harness loads its generated proofs through `module.stripTypeScriptTypes` and resolves
    their imports through `module.registerHooks`, which arrived in Node 22.6 and 22.15. The
    action's image pinned 20 while claiming in a comment to match the remediation service, and
    the result was that every JavaScript and TypeScript verification refused to run inside it:
    the September 2026 trial produced zero fixes on four JavaScript repositories. Comparing the
    two files is what stops a bump on one side turning that back on.
    """
    action_args = node_args(DOCKERFILE)
    service_args = node_args(REMEDIATION_DOCKERFILE)
    assert set(service_args) == set(NODE_ARGS), (
        f"{REMEDIATION_DOCKERFILE} no longer declares {NODE_ARGS}"
    )
    assert action_args == service_args, (
        "action/Dockerfile and services/remediation-service/Dockerfile must pin the same Node: "
        f"{action_args} against {service_args}"
    )


def test_the_image_proves_the_node_features_the_sandbox_harness_needs():
    """A pin is a claim; the probe in the build is what makes it a fact."""
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    for feature in (
        "stripTypeScriptTypes",
        "registerHooks",
        "--experimental-strip-types",
    ):
        assert feature in dockerfile, (
            f"the image no longer proves {feature} is available at build time"
        )
