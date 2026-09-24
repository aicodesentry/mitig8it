"""A `generic` rule with no `paths: include` reads every file in the batch.

The scanner runs one process over a whole batch directory. A rule with a real language
declares its own targets, so `languages: [python]` never sees a `.ts` file. `generic` has
no such protection: it is token matching with no notion of a language, so a generic rule
without an include is handed the `.py`, the `.ts` and the `.java` in the batch alongside
the templates it was written for.

The failure is quiet. `<%- ... %>` finds nothing in a Python file and the rule looks
correct; `innerHTML = ...` finds plenty in JavaScript and reports it under a rule whose
message talks about templates. Neither is visible without reading the output file by file,
so the include is asserted here instead.
"""
from __future__ import annotations

import pytest
import yaml

from opengrep_runner import RULES_DIR, SUPPORTED_EXTENSIONS, TEMPLATE_EXTENSIONS

TEMPLATE_RULES_FILE = "template_coverage.yml"


def _all_rules() -> list[tuple[str, dict]]:
    rules: list[tuple[str, dict]] = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]:
            rules.append((path.name, rule))
    return rules


ALL_RULES = _all_rules()
GENERIC_RULES = [
    (name, rule) for name, rule in ALL_RULES if "generic" in (rule.get("languages") or [])
]
TEMPLATE_RULES = [rule for name, rule in ALL_RULES if name == TEMPLATE_RULES_FILE]


class TestEveryGenericRuleIsScoped:
    def test_there_is_at_least_one_generic_rule(self):
        """Otherwise the rest of this file asserts nothing."""
        assert GENERIC_RULES

    @pytest.mark.parametrize(
        "rule", [rule for _, rule in GENERIC_RULES], ids=[rule["id"] for _, rule in GENERIC_RULES]
    )
    def test_generic_rule_declares_paths_include(self, rule):
        include = ((rule.get("paths") or {}).get("include")) or []
        assert include, (
            f"{rule['id']} is a generic rule with no `paths: include`, so it reads every "
            "file in the batch regardless of language"
        )

    @pytest.mark.parametrize(
        "rule", [rule for _, rule in GENERIC_RULES], ids=[rule["id"] for _, rule in GENERIC_RULES]
    )
    def test_every_included_glob_is_an_extension_the_service_scans(self, rule):
        """An include for an extension tier 2 never fetches is a rule that cannot fire.

        It is also how a generic rule leaks: `*` or `*.py` in this list would put token
        matching back over the languages that have a parser.
        """
        for glob in (rule.get("paths") or {}).get("include") or []:
            assert glob.startswith("*."), f"{rule['id']} includes {glob!r}, which is not an extension glob"
            extension = glob[1:]
            assert extension in TEMPLATE_EXTENSIONS, (
                f"{rule['id']} includes {glob!r}, which is not a template extension; a "
                "generic rule must not be pointed at a language that has a parser"
            )
            assert extension in SUPPORTED_EXTENSIONS, (
                f"{rule['id']} includes {glob!r}, which tier 2 never fetches, so the rule "
                "cannot fire"
            )


class TestTheTemplateFileCoversTheExtensionsItClaims:
    def test_every_template_extension_has_at_least_one_rule(self):
        """An extension in the set with no rule behind it is fetched, scanned and billed
        for nothing. Either a rule covers it or it does not belong in the set."""
        covered = {
            glob[1:]
            for rule in TEMPLATE_RULES
            for glob in (rule.get("paths") or {}).get("include") or []
        }
        assert TEMPLATE_EXTENSIONS - covered == set(), (
            f"no template rule covers {sorted(TEMPLATE_EXTENSIONS - covered)}"
        )

    def test_template_rules_are_generic(self):
        for rule in TEMPLATE_RULES:
            assert rule.get("languages") == ["generic"], rule["id"]
