"""Every tier 2 coverage rule declares what the product needs to report it.

A rule's metadata is not documentation. `internal_type` is what the product groups and
deduplicates on, so a rule that passes its own check id makes a category of one; `family`
is what decides whether a finding reaches the repair engine; `posting` is what decides
whether it reaches a reviewer at all. Each of those is wrong silently, so each is asserted
here rather than discovered in a replay.
"""
from __future__ import annotations

import pytest
import yaml

from opengrep_runner import (
    POSTING_POST,
    POSTING_QUARANTINE,
    RULES_DIR,
    canonical_check_id,
    load_rule_metadata,
    quarantined_rule_ids,
)
from taxonomy import CANONICAL_INTERNAL_TYPES

COVERAGE_FILES = ("javascript_coverage.yml", "python_coverage.yml")

# The five remediation families, as services/remediation-service/src/families.py names them,
# and the CWE each one is derived from there by `rule_family()`. A rule that declares a
# family its CWE does not produce would be handed to the engine as something else.
FAMILY_CWE = {
    "sql_parameterization": "CWE-89",
    "command_arguments": "CWE-78",
    "path_containment": "CWE-22",
    "hardcoded_credential": "CWE-798",
    "code_injection_eval": "CWE-95",
}


def _coverage_rules() -> list[tuple[str, dict]]:
    rules: list[tuple[str, dict]] = []
    for name in COVERAGE_FILES:
        document = yaml.safe_load((RULES_DIR / name).read_text(encoding="utf-8"))
        for rule in document["rules"]:
            rules.append((name, rule))
    return rules


COVERAGE_RULES = _coverage_rules()
IDS = [rule["id"] for _, rule in COVERAGE_RULES]


class TestRuleShape:
    def test_rule_ids_are_unique_across_every_rule_file(self):
        seen: dict[str, str] = {}
        duplicates: list[str] = []
        for path in sorted(RULES_DIR.glob("*.yml")):
            for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]:
                if rule["id"] in seen:
                    duplicates.append(f"{rule['id']} in {path.name} and {seen[rule['id']]}")
                seen[rule["id"]] = path.name
        assert not duplicates, duplicates

    @pytest.mark.parametrize("rule", [rule for _, rule in COVERAGE_RULES], ids=IDS)
    def test_rule_declares_cwe_severity_and_confidence(self, rule):
        metadata = rule.get("metadata") or {}
        assert str(metadata.get("cwe", "")).startswith("CWE-"), rule["id"]
        assert rule.get("severity") in {"ERROR", "WARNING", "INFO"}, rule["id"]
        confidence = float(metadata["confidence"])
        assert 0.0 < confidence <= 1.0, rule["id"]
        assert rule.get("languages"), rule["id"]

    @pytest.mark.parametrize("rule", [rule for _, rule in COVERAGE_RULES], ids=IDS)
    def test_internal_type_is_canonical_and_not_the_check_id(self, rule):
        internal_type = (rule.get("metadata") or {}).get("internal_type")
        assert internal_type, f"{rule['id']} declares no internal_type"
        assert internal_type != rule["id"], f"{rule['id']} passes its own check id"
        assert internal_type in CANONICAL_INTERNAL_TYPES, (
            f"{rule['id']} declares {internal_type!r}, which is not in the canonical set; "
            "add it to taxonomy.CANONICAL_INTERNAL_TYPES deliberately or use an existing type"
        )

    @pytest.mark.parametrize("rule", [rule for _, rule in COVERAGE_RULES], ids=IDS)
    def test_family_agrees_with_the_cwe_the_engine_reads(self, rule):
        metadata = rule.get("metadata") or {}
        family = metadata.get("family")
        if family is None:
            return
        assert family in FAMILY_CWE, f"{rule['id']} declares an unknown family {family!r}"
        assert metadata.get("cwe") == FAMILY_CWE[family], (
            f"{rule['id']} declares family {family!r} but CWE {metadata.get('cwe')!r}; "
            "the remediation engine derives the family from the CWE, so the two would disagree"
        )

    @pytest.mark.parametrize("rule", [rule for _, rule in COVERAGE_RULES], ids=IDS)
    def test_posting_is_declared_and_a_quarantine_carries_its_reason(self, rule):
        metadata = rule.get("metadata") or {}
        posting = metadata.get("posting")
        assert posting in {POSTING_POST, POSTING_QUARANTINE}, (
            f"{rule['id']} declares posting {posting!r}; it must be 'post' or 'quarantine'"
        )
        if posting == POSTING_QUARANTINE:
            assert str(metadata.get("posting_evidence", "")).strip(), (
                f"{rule['id']} is quarantined with no evidence; a rule is withheld on a "
                "measurement, and the measurement is what lets someone re-enable it"
            )


class TestPolicyLoading:
    def test_quarantined_set_is_what_the_files_declare(self):
        declared = {
            f"opengrep.{rule['id']}"
            for _, rule in COVERAGE_RULES
            if (rule.get("metadata") or {}).get("posting") == POSTING_QUARANTINE
        }
        assert quarantined_rule_ids() == declared

    def test_every_rule_file_is_loaded_into_the_metadata_index(self):
        index = load_rule_metadata()
        for _, rule in COVERAGE_RULES:
            assert f"opengrep.{rule['id']}" in index


class TestCheckIdIsStable:
    """The scanner names a rule after the path it loaded it from, relative to the working
    directory, so the same rule arrives under different ids depending on where the caller
    runs. A rule id that moves cannot key a policy, a suppression or a fingerprint."""

    def test_a_path_prefixed_check_id_resolves_to_the_rule_id(self):
        assert canonical_check_id("opengrep_rules.cwe-78.js-exec-interpolated") == "cwe-78.js-exec-interpolated"
        assert (
            canonical_check_id("services.analysis-service.src.opengrep_rules.cwe-78.js-exec-interpolated")
            == "cwe-78.js-exec-interpolated"
        )

    def test_a_bare_rule_id_is_unchanged(self):
        assert canonical_check_id("cwe-78.js-exec-interpolated") == "cwe-78.js-exec-interpolated"

    def test_an_unknown_id_is_returned_as_it_arrived(self):
        assert canonical_check_id("some.other.tool.rule") == "some.other.tool.rule"
