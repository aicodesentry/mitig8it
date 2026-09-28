"""The rule oracle a static assertion is decided from: one rule, two files, nothing executed.

A static assertion is the weakest verification level the product has
(`services/remediation-service/contracts/repair-v1.md`, "Static assertion"). It answers five
questions about a candidate patch, and four of the five are questions about which rules match
which file text. This module answers exactly those, and nothing else: it takes a rule id, a
path, the original content and the patched content, and returns four match sets.

It lives here rather than in the remediation service because the remediation service cannot run
the scanner. Its image pins `opentelemetry-api==1.44.0` and semgrep requires `~=1.37.0`, which is
why `action/requirements.txt` says the two cannot be satisfied together. The rules and the runner
are this service's, so the assertion is asked of this service.

Two properties this module owes its caller, because the assertion's claim rests on them.

**Nothing is executed.** No file written here is ever run, imported, compiled or loaded. The
scanner parses; the tier 1 rules are regular expressions over text. Neither evaluates the subject.

**Nothing reaches the network.** The tier 2 rules are local files and `_run_semgrep` passes
`--metrics=off --disable-version-check`. Tier 1 opens no socket at all.

**Determinism.** Given the same rule id, path and two file contents, the returned match sets are
the same. Line numbers are the file's own, so a caller can compare them against a finding's line.

**An answer or an error, never an empty answer.** A rule that could not be evaluated never comes
back looking like a rule that was evaluated and matched nothing, because that shape is the thing
the assertion claims. A rule no tier declares and a rule the path is out of scope for come back
as a named `refusal`; a process that has no scanner raises `ScannerUnavailableError`, which the
endpoint returns as a 503 rather than as match sets. `scanner_available` lets a caller ask before
it offers itself as an oracle.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from finding_quality import pattern_match_lines, rule_scan_options, whole_file_patch
from opengrep_runner import (
    RULES_DIR,
    ScannerUnavailableError,
    _build_finding,
    _rule_documents,
    _run_semgrep,
    canonical_check_id,
    contained_scan_path,
    scanner_available,
)
from security_rules import SECURITY_RULES
from test_code_scope import SUPPORTED_EXTENSIONS, is_analyzable_path

# The sentence the evidence has to carry, in these words, wherever a static assertion is
# recorded or rendered. Clause 5 of the contract is a claim about what did not happen, and a
# claim like that is worth nothing unless it is stated rather than implied.
NOTHING_EXECUTED = "No code was executed."

TIER1 = "tier1"
TIER2 = "tier2"

# A rule the assertion cannot run is never silently treated as a rule that found nothing: the
# caller is told which of these it got, and refuses the candidate.
RULE_UNKNOWN = "rule_not_recognized"
RULE_NOT_APPLICABLE = "rule_not_applicable_to_path"


# The third way a rule can fail to be evaluated, and the only one that is not a property of the
# rule or the path: this process has no scanner. `ScannerUnavailableError` and `scanner_available`
# are imported above rather than used only internally, because the remediation service reaches
# this module as an object and asks it both questions through these two names.

MAX_ASSERTION_FILE_BYTES = 2_000_000
MAX_MATCHES_PER_FILE = 500


def tier1_rule(rule_id: str):
    """The tier 1 rule declaring `rule_id`, or None."""
    for rule in SECURITY_RULES:
        if rule.rule_id == rule_id:
            return rule
    return None


def tier2_rule_document(rule_id: str) -> Optional[Dict[str, Any]]:
    """A one-rule YAML document for `rule_id`, or None when no rule file declares it.

    The rule is copied out of the file that declares it, unmodified, so the assertion runs the
    same pattern, the same sanitizers and the same taint configuration that produced the finding.
    A quarantined rule is returned like any other: the quarantine decides whether a finding may
    be *posted*, and an assertion is about the patch rather than about posting, so a candidate
    repairing a quarantined rule's finding is still asserted against that rule.
    """
    bare = rule_id[len("opengrep.") :] if rule_id.startswith("opengrep.") else rule_id
    bare = canonical_check_id(bare)
    for document in _rule_documents():
        for rule in document["rules"]:
            if isinstance(rule, dict) and rule.get("id") == bare:
                return {"rules": [rule]}
    return None


def rule_tier(rule_id: str) -> Optional[str]:
    """Which tier owns `rule_id`, or None when neither does."""
    if tier1_rule(rule_id) is not None:
        return TIER1
    if tier2_rule_document(rule_id) is not None:
        return TIER2
    return None


def _tier1_matches(rule, path: str, content: str) -> List[Dict[str, Any]]:
    options = rule_scan_options(rule, path, content)
    lines = pattern_match_lines(whole_file_patch(content), rule.pattern, **options)
    return [{"rule_id": rule.rule_id, "line": line} for line in lines[:MAX_MATCHES_PER_FILE]]


def tier1_all_matches(path: str, content: str) -> List[Dict[str, Any]]:
    """Every tier 1 rule that matches `content`, with every line it matches.

    Deliberately unlike `pattern_findings`, which emits one finding per rule per file and skips
    a rule whose category the repository does not look like it uses. Clause 4 asks whether the
    patch introduced a match that was not there before, and a scan that stops at the first match
    or skips a rule by repository shape would answer a narrower question than the one asked.
    """
    matches: List[Dict[str, Any]] = []
    for rule in SECURITY_RULES:
        matches.extend(_tier1_matches(rule, path, content))
    return sorted(matches, key=lambda item: (item["line"], item["rule_id"]))[:MAX_MATCHES_PER_FILE]


def tier2_all_matches(path: str, content: str, *, rule_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Tier 2 matches in `content`: every rule, or just `rule_id`.

    Returns an empty list for a path tier 2 does not scan, which is correct rather than
    convenient: a rule that never ran on this file also never matched it, and the caller has
    already established from `rule_tier` whether the rule that produced the finding is a tier 2
    rule at all.
    """
    if not is_analyzable_path(path) or Path(path).suffix.lower() not in SUPPORTED_EXTENSIONS:
        return []
    config: Optional[str] = None
    with tempfile.TemporaryDirectory(prefix="mitig8it_assert_") as workdir:
        scan_dir = Path(workdir) / "tree"
        scan_dir.mkdir()
        target = contained_scan_path(scan_dir, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        if rule_id is not None:
            document = tier2_rule_document(rule_id)
            if document is None:
                return []
            # Beside the scan directory rather than inside it, so the rule file is never itself
            # a scan target.
            config_path = Path(workdir) / "rule.yml"
            config_path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
            config = str(config_path)
        output = _run_semgrep(str(scan_dir), config)
        matches: List[Dict[str, Any]] = []
        for match in output.get("results", []):
            finding = _build_finding(match, str(scan_dir), {path: content})
            matches.append({"rule_id": finding["rule_id"], "line": int(finding["line_start"])})
    return sorted(matches, key=lambda item: (item["line"], item["rule_id"]))[:MAX_MATCHES_PER_FILE]


def rule_matches(rule_id: str, tier: str, path: str, content: str) -> List[Dict[str, Any]]:
    """Where exactly `rule_id` matches `content`."""
    if tier == TIER1:
        rule = tier1_rule(rule_id)
        return [] if rule is None else _tier1_matches(rule, path, content)
    return tier2_all_matches(path, content, rule_id=rule_id)


def all_rule_matches(path: str, content: str) -> List[Dict[str, Any]]:
    """Every rule of either tier that matches `content`.

    Clause 4's input: a repair that closes one vulnerability and opens another is not a repair,
    and both tiers have to answer, because a patch written for a tier 2 finding can introduce a
    shape only tier 1 recognizes.
    """
    matches = tier1_all_matches(path, content) + tier2_all_matches(path, content)
    return sorted(matches, key=lambda item: (item["line"], item["rule_id"]))[:MAX_MATCHES_PER_FILE]


def match_sets(rule_id: str, path: str, original: str, patched: str) -> Dict[str, Any]:
    """The four match sets a static assertion is decided from, for one rule over two files.

    The decision itself is not made here. This service knows which rules match which text; the
    remediation service knows the finding's line, the patch's changed lines and the policy, so
    it is the one that reaches a verdict. Splitting it that way keeps the scanner-side answer
    something a caller can check for itself.
    """
    tier = rule_tier(rule_id)
    if tier is None:
        return {"rule_id": rule_id, "path": path, "tier": None, "refusal": RULE_UNKNOWN, "executed": False, "nothing_executed": NOTHING_EXECUTED}
    if tier == TIER2 and not tier2_scannable(path):
        return {"rule_id": rule_id, "path": path, "tier": tier, "refusal": RULE_NOT_APPLICABLE, "executed": False, "nothing_executed": NOTHING_EXECUTED}
    return {
        "rule_id": rule_id,
        "path": path,
        "tier": tier,
        "refusal": None,
        "original": {
            "rule_matches": rule_matches(rule_id, tier, path, original),
            "all_matches": all_rule_matches(path, original),
        },
        "patched": {
            "rule_matches": rule_matches(rule_id, tier, path, patched),
            "all_matches": all_rule_matches(path, patched),
        },
        # Clause 5, stated by the side that would have had to run something.
        "executed": False,
        "nothing_executed": NOTHING_EXECUTED,
    }


def tier2_scannable(path: str) -> bool:
    return is_analyzable_path(path) and Path(path).suffix.lower() in SUPPORTED_EXTENSIONS
