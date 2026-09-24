"""The action's dependency list must cover what the services it runs actually need.

The action installs one environment for two services that pin some packages differently. This
test reads both service requirement files and checks that every package either appears in the
action's list at a version at least as new, or is on the short list of dependencies the action
deliberately leaves out. A new dependency in either service fails here rather than at runtime
inside a customer's job.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# These compare declaration files against each other. The image installs what they describe but
# does not carry the services' own requirement lists, so the comparison belongs to the
# repository, not to the image. The in-image run excludes them; the host job runs them.
pytestmark = pytest.mark.repo_definition

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION_REQUIREMENTS = REPO_ROOT / "action/requirements.txt"
ANALYSIS_REQUIREMENTS = REPO_ROOT / "services/analysis-service/src/requirements.txt"
REMEDIATION_REQUIREMENTS = REPO_ROOT / "services/remediation-service/requirements.txt"

# Deliberately not installed. Each backs a production backend the action does not have, and none
# is imported by the code paths the action runs. See the note in action/requirements.txt.
EXCLUDED = {
    "google-cloud-run",
    "google-cloud-storage",
    "kubernetes",
    "psycopg",
    # Unpinnable alongside semgrep, and a no-op without an OTLP endpoint. See the note in
    # action/requirements.txt.
    "opentelemetry-api",
    "opentelemetry-sdk",
    "opentelemetry-exporter-otlp-proto-http",
}

PIN = re.compile(r"^([A-Za-z0-9._-]+)(?:\[[^\]]+\])?==(.+)$")


def parse(path: Path) -> dict[str, str]:
    assert path.is_file(), f"expected a requirements file at {path}"
    pins: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = PIN.match(line)
        assert match, f"{path.name} has an unpinned or unparsable requirement: {line!r}"
        pins[match.group(1).lower()] = match.group(2)
    return pins


def version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def test_every_analysis_dependency_is_installed():
    action = parse(ACTION_REQUIREMENTS)
    for name, version in parse(ANALYSIS_REQUIREMENTS).items():
        assert name in action, f"the action does not install {name}, which analysis-service pins"
        assert version_tuple(action[name]) >= version_tuple(version), (
            f"the action pins {name}=={action[name]}, below analysis-service's {version}"
        )


def test_every_remediation_dependency_is_installed_or_deliberately_excluded():
    action = parse(ACTION_REQUIREMENTS)
    for name, version in parse(REMEDIATION_REQUIREMENTS).items():
        if name in EXCLUDED:
            assert name not in action, (
                f"{name} is on the exclusion list but the action installs it; update one or the "
                "other so the reason stays true"
            )
            continue
        assert name in action, f"the action does not install {name}, which remediation-service pins"
        assert version_tuple(action[name]) >= version_tuple(version), (
            f"the action pins {name}=={action[name]}, below remediation-service's {version}"
        )


def test_the_exclusion_list_is_justified_in_the_file():
    """Each excluded package must be named in the note, so the reason cannot rot silently."""
    text = ACTION_REQUIREMENTS.read_text(encoding="utf-8")
    for name in EXCLUDED:
        assert name in text, f"{name} is excluded but not explained in action/requirements.txt"


def test_semgrep_is_installed_because_the_scan_fails_closed_without_it():
    """Tier 2 raises rather than returning nothing when semgrep is missing, so it must ship."""
    assert "semgrep" in parse(ACTION_REQUIREMENTS)
