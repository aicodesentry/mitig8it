"""The Grafana rules and the Cloud Monitoring policies have to page for the same things.

`infrastructure/remediation/grafana/alerts/remediation-rules.yaml` says in its own header
that the Cloud Monitoring equivalents live in `infrastructure/monitoring/*.tf` and to
"keep the two in step". Nothing checked that, and they drifted: Grafana folded the
absent-series case into `noDataState: Alerting` on the stall rule, while the Terraform
had always carried it as a separate `condition_absent` combined with OR. Because the
metrics sidecar is opt-in, the Grafana form fired on no data on every evaluation forever
for any deployment that had not enabled it.

These tests pin the shape that made that possible, not the exact text of either file.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml is needed to read the alert rules")

REPO_ROOT = Path(__file__).resolve().parents[1]
GRAFANA = REPO_ROOT / "infrastructure/remediation/grafana/alerts/remediation-rules.yaml"
TERRAFORM = REPO_ROOT / "infrastructure/monitoring/main.tf"

# A rule that pages and treats an absent series as an incident can only be trusted once
# something is guaranteed to be scraping. Nothing in this repository guarantees that: the
# sidecar is opt-in. So such a rule has to be paused, and the pause has to be explained
# where the person enabling the scrape will read it.
SIDECAR_VARIABLE = "METRICS_SIDECAR_ENABLED"


@pytest.fixture(scope="module")
def grafana_rules() -> list[dict]:
    document = yaml.safe_load(GRAFANA.read_text(encoding="utf-8"))
    return [rule for group in document["groups"] for rule in group["rules"]]


def test_no_unpaused_page_rule_alerts_on_absent_data(grafana_rules: list[dict]) -> None:
    """The defect this file exists to prevent, stated as a property.

    An unpaused rule that pages on no data fires continuously for as long as nothing is
    scraping, and nothing here guarantees a scrape.
    """
    offenders = [
        rule["alert"]
        for rule in grafana_rules
        if rule.get("noDataState") == "Alerting"
        and not rule.get("isPaused", False)
        and rule.get("labels", {}).get("severity") == "page"
    ]
    assert not offenders, (
        f"{offenders} page on absent data while unpaused. The metrics sidecar is opt-in, so "
        "these fire on every evaluation until somebody enables it. Either pause the rule or "
        "let absence read as OK and assert it in a rule of its own."
    )


def test_the_stall_rule_does_not_carry_the_absence_case(grafana_rules: list[dict]) -> None:
    """Stall and absence are separate incidents, as the Terraform has always had them."""
    stalled = next(r for r in grafana_rules if r["alert"] == "Mitig8itReviewsStalled")
    assert stalled["noDataState"] == "OK", (
        "the stall rule is reporting absent metrics again. The gauge is set to 0 on every "
        "queue observation, so a healthy scraped API reports 0 rather than nothing."
    )
    assert not stalled.get("isPaused", False), (
        "the stall rule must never be paused: it is the only thing that pages for a real "
        "backlog, and a paused page is a silent outage."
    )


def test_absence_is_asserted_by_a_rule_of_its_own(grafana_rules: list[dict]) -> None:
    absent = [
        rule for rule in grafana_rules
        if "absent(" in str(rule.get("expr", ""))
    ]
    assert absent, (
        "no rule asserts that the analysis metrics are arriving. infrastructure/monitoring/"
        "main.tf carries a condition_absent for exactly this, and the two are meant to agree."
    )
    for rule in absent:
        assert rule.get("isPaused", False), (
            f"{rule['alert']} asserts absence and is not paused. While {SIDECAR_VARIABLE} is "
            "opt-in this rule is true by construction."
        )


def test_terraform_still_asserts_absence_separately() -> None:
    """If the Terraform drops its absence condition, Grafana's split is no longer parity."""
    terraform = TERRAFORM.read_text(encoding="utf-8")
    assert "condition_absent" in terraform, (
        "infrastructure/monitoring/main.tf no longer asserts an absent series. Grafana splits "
        "stall from absence to match it; decide both together or they drift again."
    )
    assert 'combiner     = "OR"' in terraform or 'combiner = "OR"' in terraform, (
        "the stalled policy combined its stall and absence conditions with OR. If that "
        "changed, the Grafana side needs the same decision."
    )


def test_both_systems_watch_the_same_absence_metric() -> None:
    """Parity that matters: paging on a different series is not paging for the same thing."""
    grafana = GRAFANA.read_text(encoding="utf-8")
    terraform = TERRAFORM.read_text(encoding="utf-8")
    metric = "mitig8it_analysis_runs_started_total"
    assert f"absent({metric})" in grafana, f"Grafana's absence rule should watch {metric}"
    assert metric in terraform, f"the Terraform absence condition should watch {metric}"


def test_the_runbook_says_to_unpause_when_the_scrape_is_enabled() -> None:
    """A paused page is only safe if unpausing it is part of turning the scrape on.

    This is the inverse failure of the one that prompted the change: metrics flowing, the
    absence rule still paused, and a dead API saying nothing.
    """
    runbook = (REPO_ROOT / "docs/runbooks/observability.md").read_text(encoding="utf-8")
    enablement = re.split(r"(?m)^#+ ", runbook)
    mentions = [
        section for section in enablement
        if SIDECAR_VARIABLE in section and "Mitig8itAnalysisMetricsAbsent" in section
    ]
    assert mentions, (
        f"the runbook section that tells somebody to set {SIDECAR_VARIABLE} does not mention "
        "unpausing Mitig8itAnalysisMetricsAbsent. Enabling the scrape and arming the rule that "
        "watches it have to be one procedure, or the rule stays paused and nothing watches."
    )
