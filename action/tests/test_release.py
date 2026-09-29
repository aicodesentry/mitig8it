"""The release gate, and the workflow that is supposed to be gated by it.

A release workflow is run for the first time on the day it matters, by the one person who cannot
easily undo what it did: it pushes an image, moves tags and creates a public release. The parts of
it that can be tested without releasing anything are tested here.

`scripts/release-changelog.py` holds the two rules that refuse a release, and it is a script rather
than shell in a YAML string for exactly this reason. The rest of these read `release.yml` and assert
the ordering and the guards that make a wrong release impossible rather than merely unlikely.

These live under `action/tests` because that is where the tests which read this repository's own
definition already live (`test_action_definition.py` reads the workflows and the services'
requirement files). They carry the `repo_definition` marker, so the in-image run skips them.
"""
from __future__ import annotations

import datetime as dt
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml is needed to read the workflow")

pytestmark = pytest.mark.repo_definition

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github/workflows/release.yml"
SCRIPT = REPO_ROOT / "scripts/release-changelog.py"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

HEADER = "# Changelog\n\n## [Unreleased]\n\nNothing yet.\n\n"


def a_changelog(*entries: str) -> str:
    return HEADER + "\n".join(entries)


ONE_ZERO = "## [1.0.0] - 2026-09-27\n\n### Added\n\n- The first release.\n"
ONE_ZERO_UNDATED = "## [1.0.0] - unreleased\n\n### Added\n\n- The first release.\n"
ONE_ONE = "## [1.1.0] - 2026-10-04\n\n### Added\n\n- Something later.\n"


def run_script(command: str, version: str, text: str, tmp_path: Path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(text, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(SCRIPT), command, version, "--changelog", str(changelog)],
        capture_output=True,
        text=True,
        check=False,
    )


# --- what the gate refuses --------------------------------------------------------------------

def test_a_documented_dated_version_passes(tmp_path):
    result = run_script("check", "1.0.0", a_changelog(ONE_ZERO), tmp_path)
    assert result.returncode == 0, result.stderr


def test_a_tag_the_changelog_does_not_document_is_refused(tmp_path):
    """The brief's rule: refuse a tag that does not match the version in the changelog."""
    result = run_script("check", "1.2.3", a_changelog(ONE_ZERO), tmp_path)
    assert result.returncode == 1
    assert "documents no version 1.2.3" in result.stderr
    assert "1.0.0" in result.stderr, "the message should say what the changelog does document"


def test_an_undated_section_is_refused(tmp_path):
    """The committed entry reads `- unreleased`, which is honest in the repo and wrong in a release.

    Refusing here is what makes setting the date a step of the procedure instead of a thing to
    remember, and it is why nothing in this repository invents a release date.
    """
    result = run_script("check", "1.0.0", a_changelog(ONE_ZERO_UNDATED), tmp_path)
    assert result.returncode == 1
    assert "unreleased" in result.stderr
    assert "invent a date" in result.stderr


@pytest.mark.parametrize("date", ["27/09/2026", "September 2026", "2026-13-01", "2026-9-7", "soon"])
def test_a_date_that_is_not_iso_is_refused(tmp_path, date):
    text = a_changelog(ONE_ZERO.replace("2026-09-27", date))
    result = run_script("check", "1.0.0", text, tmp_path)
    assert result.returncode == 1


def test_releasing_a_version_that_is_not_the_newest_documented_is_refused(tmp_path):
    """Tagging 1.0.0 while 1.1.0 is written above it means the tag and the notes disagree."""
    result = run_script("check", "1.0.0", a_changelog(ONE_ONE, ONE_ZERO), tmp_path)
    assert result.returncode == 1
    assert "1.1.0" in result.stderr


def test_the_unreleased_section_is_not_mistaken_for_a_release(tmp_path):
    """It is a `## [...]` heading like any other, and it must never be the version being released."""
    result = run_script("check", "1.0.0", a_changelog(ONE_ZERO), tmp_path)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("version", ["1.0", "v1.0.0", "1.0.0-rc1", "one", "1.0.0.0"])
def test_a_version_that_is_not_semver_is_refused(tmp_path, version):
    result = run_script("check", version, a_changelog(ONE_ZERO), tmp_path)
    assert result.returncode == 1


def test_an_empty_section_is_refused(tmp_path):
    text = a_changelog("## [1.0.0] - 2026-09-27\n\n")
    result = run_script("check", "1.0.0", text, tmp_path)
    assert result.returncode == 1
    assert "empty" in result.stderr


def test_a_version_documented_twice_is_refused(tmp_path):
    result = run_script("check", "1.0.0", a_changelog(ONE_ZERO, ONE_ZERO), tmp_path)
    assert result.returncode == 1
    assert "more than once" in result.stderr


# --- the notes the release carries ------------------------------------------------------------

def test_the_notes_are_the_section_and_nothing_else(tmp_path):
    result = run_script("notes", "1.0.0", a_changelog(ONE_ONE.replace("1.1.0", "1.0.1"), ONE_ZERO), tmp_path)
    # 1.0.1 is newest here, so 1.0.0 is not releasable, but the notes for it are still extractable.
    assert result.returncode == 1, "notes should not be produced for a version that cannot be released"

    result = run_script("notes", "1.0.0", a_changelog(ONE_ZERO), tmp_path)
    assert result.returncode == 0, result.stderr
    assert "The first release." in result.stdout
    assert "Unreleased" not in result.stdout
    assert "## [1.0.0]" not in result.stdout, "the heading is the release title, not the body"


def test_the_notes_stop_at_the_next_heading(tmp_path):
    text = a_changelog(ONE_ZERO.replace("1.0.0", "1.0.1"), ONE_ZERO)
    result = run_script("notes", "1.0.1", text, tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("The first release.") == 1


# --- this repository's own changelog ------------------------------------------------------------

def test_the_changelog_is_keep_a_changelog_shaped():
    text = CHANGELOG.read_text(encoding="utf-8")
    assert "keepachangelog.com" in text, "the format the file claims should be the format it links"
    assert "## [Unreleased]" in text
    assert "## [1.0.0]" in text


def test_the_changelog_names_no_release_date_nobody_has_chosen():
    """A release date is a decision, and it may not be a date nobody could have released on.

    This test used to require `1.0.0 - unreleased` outright, and it said that dating the heading
    should be a deliberate edit to this test rather than a tidy-up. That edit is this one: 1.0.0 was
    dated 2026-09-29 in order to cut it, because the gate in `release.yml` refuses a heading that
    still reads `unreleased` and `docs/releasing.md` makes setting it step one.

    What remains worth refusing is the thing the original assertion was really protecting against, a
    release that claims to have happened on a day it did not. So a dated section has to carry a real
    ISO date that is not in the future. `unreleased` is still accepted, because that is the honest
    state of every version this repository has not decided to cut yet, and it is what the next
    section will read.
    """
    sys.modules.pop("release_changelog", None)
    import importlib.util

    spec = importlib.util.spec_from_file_location("release_changelog", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    text = CHANGELOG.read_text(encoding="utf-8")
    section = module.find(text, "1.0.0")
    date = section["date"]
    assert section["body"].strip(), "the 1.0.0 section is empty"

    if date == "unreleased":
        return

    assert module.ISO_DATE.match(date), (
        f"CHANGELOG.md dates 1.0.0 as {date!r}, which is neither 'unreleased' nor an ISO date. The "
        "release gate reads this heading, so a malformed date fails a release rather than a test."
    )
    assert date <= dt.date.today().isoformat(), (
        f"CHANGELOG.md dates 1.0.0 as {date!r}, which is in the future. A changelog date is the day "
        "the release went out, not the day somebody hoped it would."
    )


def test_every_dated_section_is_a_date_that_has_happened():
    """The same rule for every version, so the next release inherits the guard."""
    sys.modules.pop("release_changelog", None)
    import importlib.util

    spec = importlib.util.spec_from_file_location("release_changelog", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    today = dt.date.today().isoformat()
    for section in module.sections(CHANGELOG.read_text(encoding="utf-8")):
        date = section["date"]
        if date == "unreleased" or not module.SEMVER.match(section["version"]):
            continue
        assert module.ISO_DATE.match(date), f"{section['version']} carries {date!r}, not an ISO date"
        assert date <= today, f"{section['version']} is dated {date!r}, which is in the future"


# --- the workflow -----------------------------------------------------------------------------

@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def steps_of(workflow: dict, job: str) -> list:
    return workflow["jobs"][job]["steps"]


def test_the_workflow_parses_and_has_both_jobs(workflow):
    """An unparsable workflow fails the whole run before any job starts, naming no file and no line."""
    assert set(workflow["jobs"]) == {"gate", "release"}
    assert workflow["jobs"]["release"]["needs"] == "gate"


def test_it_triggers_on_a_version_tag_and_by_hand(workflow):
    # `on` is the YAML 1.1 boolean True once safe_load has read it.
    triggers = workflow[True]
    assert triggers["push"]["tags"] == ["v*.*.*"]
    assert "workflow_dispatch" in triggers
    assert set(triggers["workflow_dispatch"]["inputs"]) == {"version", "dry-run"}
    assert triggers["workflow_dispatch"]["inputs"]["dry-run"]["default"] is True, (
        "a dispatch must not release by accident; the dry run is the default"
    )
    assert "pull_request" not in triggers and "schedule" not in triggers


def test_the_workflow_is_read_only_by_default(workflow):
    assert workflow["permissions"] == {"contents": "read"}


def test_only_the_release_job_can_write_and_it_says_what_it_writes(workflow):
    # The gate reads: the repository, and the Actions API for whether CI passed on this commit.
    # `actions: read` has to be spelled out, because a `permissions` block makes every scope it
    # does not name `none`, and a gate that 403s where it expects a conclusion fails the wrong way.
    assert workflow["jobs"]["gate"]["permissions"] == {"contents": "read", "actions": "read"}
    assert workflow["jobs"]["release"]["permissions"] == {
        "contents": "write",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }


def test_every_third_party_action_is_pinned_by_digest(workflow):
    """The repository's own rule is watching. `actions/*` is excluded by the rule, not by us."""
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            uses = step.get("uses")
            if not uses:
                continue
            name, _, ref = uses.partition("@")
            assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref), (
                f"{uses} is not pinned to a full commit sha"
            )
            del name


def test_the_release_is_provenanced_and_has_an_sbom(workflow):
    uses = [step.get("uses", "") for step in steps_of(workflow, "release")]
    assert any(u.startswith("actions/attest-build-provenance@") for u in uses), (
        "the published image carries no provenance attestation"
    )
    assert any(u.startswith("anchore/sbom-action@") for u in uses), "the release carries no SBOM"


def test_the_attestation_binds_the_digest_not_the_tag(workflow):
    """A tag can be moved after the attestation. A digest is the thing that was attested."""
    step = next(
        s for s in steps_of(workflow, "release")
        if str(s.get("uses", "")).startswith("actions/attest-build-provenance@")
    )
    assert "steps.push.outputs.digest" in step["with"]["subject-digest"]
    assert step["with"]["push-to-registry"] is True


def test_the_gate_checks_the_changelog_the_ancestry_the_suites_and_the_prior_release(workflow):
    names = [str(step.get("name", "")) for step in steps_of(workflow, "gate")]
    joined = " | ".join(names)
    for expected in ("changelog", "on main", "passed on this commit", "not already a release", "no release already"):
        assert expected in joined, f"the gate has no step about {expected!r}: {joined}"


def test_the_gate_uses_the_tested_script_rather_than_its_own_regex(workflow):
    runs = "\n".join(str(step.get("run", "")) for step in steps_of(workflow, "gate"))
    assert "scripts/release-changelog.py check" in runs


def test_nothing_is_published_before_the_suites_have_run(workflow):
    """"Refuse to release if the tests have not passed" has to be an ordering, not a hope."""
    steps = steps_of(workflow, "release")
    names = [str(step.get("name", "")) for step in steps]

    def index(fragment: str) -> int:
        matches = [i for i, name in enumerate(names) if fragment in name]
        assert matches, f"no step named like {fragment!r}: {names}"
        return matches[0]

    suites = index("action's own suites")
    in_image = index("image's own tests")
    refusal = index("refuses to run without a token")
    push = index("Push the image")
    for gate, label in ((suites, "the host suites"), (in_image, "the in-image suites"), (refusal, "the token refusal")):
        assert gate < push, f"{label} runs after the image is published"
    assert index("Build the image") < in_image


def test_the_tags_move_only_after_the_image_exists(workflow):
    names = [str(step.get("name", "")) for step in steps_of(workflow, "release")]
    assert names.index("Push the image and record its digest") < names.index("Write the release commit")
    assert names.index("Write the release commit") < names.index("Point the tags at the release commit")
    assert names.index("Point the tags at the release commit") < names.index("Create the GitHub release"), (
        "the release would be created against a tag that still points at the pre-release commit"
    )


def test_every_step_that_publishes_is_skipped_on_a_dry_run(workflow):
    """A dry run is how the machinery is proven without releasing. It has to be airtight."""
    publishing = (
        "Log in to ghcr.io",
        "Push the image and record its digest",
        "Attest the build provenance",
        "Write the release commit",
        "Point the tags at the release commit",
        "Create the GitHub release",
    )
    by_name = {str(step.get("name", "")): step for step in steps_of(workflow, "release")}
    for name in publishing:
        assert name in by_name, f"{name} is no longer a step, so this list is stale"
        assert by_name[name].get("if") == "env.DRY_RUN != 'true'", (
            f"{name} would run on a dry run"
        )


def test_the_dry_run_still_builds_and_tests_and_still_makes_an_sbom(workflow):
    """A dry run that skipped the build would prove nothing about the release it is standing in for."""
    for name in ("Build the image", "The action's own suites", "Generate an SBOM for the image"):
        step = next(s for s in steps_of(workflow, "release") if s.get("name") == name)
        assert "if" not in step, f"{name} is skipped on a dry run, so a dry run proves less than it claims"


def test_the_image_is_built_by_the_shared_script(workflow):
    """The published image has to be built the way the image CI proves buildable is built."""
    runs = "\n".join(str(step.get("run", "")) for step in steps_of(workflow, "release"))
    assert "./action/build-image.sh" in runs


def test_the_registry_token_never_reaches_a_command_line(workflow):
    """The same rule the action follows for the caller's token, for the same reason."""
    for step in steps_of(workflow, "release"):
        run = str(step.get("run", ""))
        assert "${{ github.token }}" not in run, (
            f"step {step.get('name')!r} puts a token in argv, where a process listing can read it"
        )
    login = next(s for s in steps_of(workflow, "release") if s.get("name") == "Log in to ghcr.io")
    assert "--password-stdin" in login["run"]


def test_the_release_is_serialised_and_never_cancelled(workflow):
    assert workflow["concurrency"]["group"] == "release"
    assert workflow["concurrency"]["cancel-in-progress"] is False, (
        "a release cancelled between the push and the tag leaves an image no ref names"
    )


def test_the_image_name_is_declared_once(workflow):
    assert workflow["env"]["IMAGE"] == "ghcr.io/aicodesentry/mitig8it-action"
    assert workflow["env"]["IMAGE"] in (REPO_ROOT / "docs/releasing.md").read_text(encoding="utf-8")
