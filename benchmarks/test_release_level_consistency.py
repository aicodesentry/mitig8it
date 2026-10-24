"""The production deploy and the runtime publication gate must agree on the sandbox level.

deploy-remediation-cloudrun.yml maps the selected sandbox driver to the verification level it
provides and refuses to deploy unless the release artifact names that level. The runtime gates
(api-service remediationPolicy.releaseEvidenceIdentity, github-service
qualityPublication.releaseIdentity) refuse to publish unless the artifact names one exact level.
If no level the deploy can produce is a level the runtime accepts, no release artifact can both
deploy and publish: verified fixes can never be posted in production. This test states that
contract; it fails while the two disagree.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_GATES = (
    ROOT / "services/api-service/src/services/remediationPolicy.js",
    ROOT / "services/github-service/src/services/qualityPublication.js",
)
ADMISSION_STEP = "Resolve the authenticated production sandbox digest before any push"


def runtime_accepted_levels() -> set[str]:
    levels = set()
    for path in RUNTIME_GATES:
        found = set(re.findall(r"sandbox\?\.verification_level !== '([a-z_]+)'", path.read_text()))
        assert found, f"no release verification level found in {path.relative_to(ROOT)}"
        levels.add(frozenset(found))
    # Both runtime gates must require the same level, or one side posts what the other refuses.
    assert len(levels) == 1, f"runtime gates disagree: {sorted(map(sorted, levels))}"
    return set(next(iter(levels)))


def deploy_provided_levels() -> dict[str, str]:
    workflow = yaml.safe_load((ROOT / ".github/workflows/deploy-remediation-cloudrun.yml").read_text())
    step = next(s for s in workflow["jobs"]["deploy"]["steps"] if s.get("name") == ADMISSION_STEP)
    provided = dict(re.findall(r"^\s*([a-z_]+)\)\s*PROVIDED_LEVEL='([a-z_]+)'", step["run"], re.MULTILINE))
    assert provided, "the production admission step no longer maps sandbox drivers to levels"
    return provided


def test_runtime_gates_agree_on_one_level():
    assert runtime_accepted_levels()


def test_every_level_the_production_deploy_admits_is_one_the_runtime_publishes():
    accepted = runtime_accepted_levels()
    provided = deploy_provided_levels()
    mismatched = {driver: level for driver, level in provided.items() if level not in accepted}
    assert not mismatched, (
        f"deploy drivers provide {mismatched}, the runtime accepts only {sorted(accepted)}: "
        "no release artifact can both deploy and publish"
    )
