"""Per-rule precision: the measured prior, the live outcomes, and the number a reviewer sees.

Every rule carries a hand-set `confidence` constant, and until this module that constant was
the only confidence anything saw: triage read it as evidence and the comment printed it as a
percentage. Two better sources already existed and neither was used. A rule's
`precision_evidence` names the corpus measurement behind it ("7 adjudicated, 3 true and 4
false, precision 0.43"), and the api-service's `finding_outcomes` log records what reviewers
did with the rule's findings on real pull requests.

The calculation, in full (docs/validation/fix-placement-and-calibration-2026-10.md has the
same formula with a worked example):

* The prior is the corpus measurement, parsed from `precision_evidence` as `k0` true out of
  `n0` adjudicated. A rule whose evidence states no adjudicated count has no prior counts.
* The outcomes are `p` positive and `q` negative findings of the rule, summed by the
  api-service and sent with the triage request as `rule_stats`. Positive is a fix applied in
  the app or on GitHub, or a thread resolved after the finding was fixed; negative is a
  dismissal for `wrong_rule_match` or `not_exploitable`. Anything else says nothing about
  whether the rule was right and is not counted.
* Below `MINIMUM_OUTCOMES` outcomes (`p + q < 20`) the rule keeps its static constant, and the
  finding says the number is a prior, not a measurement.
* At or above it, the precision is the Wilson lower bound at 95% (z = 1.96) of
  `k0 + p` successes in `n0 + p + q` trials: the corpus counts are pooled with the live ones
  as observations of the same rule, and the lower bound rather than the point estimate is
  used so a rule with few observations cannot look better than it has shown itself to be.

Nothing here runs unless the api-service sends `rule_stats`, which it does only when
`RULE_CALIBRATION_ENABLED` is on.
"""
from __future__ import annotations

import math
import re
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple

MINIMUM_OUTCOMES = 20
WILSON_Z = 1.96

BASIS_MEASURED = "measured"
BASIS_STATIC_PRIOR = "static_prior"

_READ = r"(?:adjudicated|hand-read|read by hand)"
_COUNTED = re.compile(r"(\d+)\s+" + _READ, re.IGNORECASE)
_BOTH_COUNTED = re.compile(r"\bboth\s+" + _READ, re.IGNORECASE)
_FINDINGS_COUNTED = re.compile(r"(\d+)\s+findings?(?:\s+over\s+\d+\s+repositor(?:y|ies))?,\s+" + _READ, re.IGNORECASE)
_PRECISION = re.compile(r"precision\s+(\d(?:\.\d+)?)", re.IGNORECASE)
_TRUE_AND_FALSE = re.compile(r"(\d+)\s+true(?:\s+\([^)]*\))?,?\s+and\s+(\d+)\s+false", re.IGNORECASE)
_ALL_TRUE = re.compile(r"\b(?:all|both)\b[^.;]*?\btrue\b|\band true\b", re.IGNORECASE)


def wilson_lower_bound(successes: float, trials: float, z: float = WILSON_Z) -> Optional[float]:
    """The lower end of the Wilson score interval, or None with no trials."""
    if trials <= 0:
        return None
    successes = min(max(successes, 0.0), trials)
    phat = successes / trials
    z2 = z * z
    centre = phat + z2 / (2 * trials)
    margin = z * math.sqrt((phat * (1 - phat) + z2 / (4 * trials)) / trials)
    return max(0.0, (centre - margin) / (1 + z2 / trials))


def parse_precision_evidence(text: Any) -> Optional[Tuple[int, int]]:
    """`(true, read)` from a rule's evidence line, or None when it states no count.

    The evidence lines are prose written by people, so only the phrasings the rule files use
    are read. How many findings were read: "N adjudicated", "N hand-read", "N read by hand",
    "both adjudicated" (two), or "N findings, adjudicated" (all of them). How many of those
    were true: "K true and F false" (a parenthesis after "true" allowed), else "precision P"
    times the count, else "all true", "both true" or "and true" for every one. A line that
    says something else, such as "all 19 sampled by hand were wrong", is not a count this
    parser will guess at, and a rule with no count has no prior counts.
    """
    value = " ".join(str(text or "").split())
    if not value:
        return None
    n = 0
    anchor = None
    for pattern in (_FINDINGS_COUNTED, _COUNTED):
        match = pattern.search(value)
        if match:
            n, anchor = int(match.group(1)), match
            break
    if not anchor:
        match = _BOTH_COUNTED.search(value)
        if match:
            n, anchor = 2, match
    if not anchor or n <= 0:
        return None
    split = _TRUE_AND_FALSE.search(value)
    if split and int(split.group(1)) + int(split.group(2)) == n:
        return int(split.group(1)), n
    precision = _PRECISION.search(value)
    if precision:
        p = float(precision.group(1))
        if 0.0 <= p <= 1.0:
            return int(round(n * p)), n
    if _ALL_TRUE.search(value[anchor.start():]):
        return n, n
    return None


@lru_cache(maxsize=1)
def rule_priors() -> Dict[str, Dict[str, Any]]:
    """Every rule's static constant and parsed corpus counts, keyed by finding `rule_id`."""
    from opengrep_runner import load_rule_metadata
    from security_rules import SECURITY_RULES

    priors: Dict[str, Dict[str, Any]] = {}
    for rule in SECURITY_RULES:
        priors[rule.rule_id] = {
            "static_confidence": float(rule.confidence),
            "evidence": parse_precision_evidence(rule.precision_evidence),
        }
    for rule_id, metadata in load_rule_metadata().items():
        try:
            static = float(metadata.get("confidence", 0.8))
        except (TypeError, ValueError):
            static = 0.8
        priors[rule_id] = {
            "static_confidence": static,
            "evidence": parse_precision_evidence(metadata.get("precision_evidence")),
        }
    return priors


def _count(value: Any) -> int:
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return 0
    return number if number > 0 else 0


def calibrate(
    rule_id: str,
    static_confidence: float,
    stats: Optional[Dict[str, Any]],
    minimum_outcomes: int = MINIMUM_OUTCOMES,
) -> Dict[str, Any]:
    """The precision a rule has earned, with what it was computed from."""
    prior = rule_priors().get(rule_id, {})
    evidence = prior.get("evidence")
    prior_true, prior_adjudicated = evidence if evidence else (0, 0)
    positives = _count((stats or {}).get("positive"))
    negatives = _count((stats or {}).get("negative"))
    outcomes = positives + negatives
    result: Dict[str, Any] = {
        "rule_id": rule_id,
        "prior_true": prior_true,
        "prior_adjudicated": prior_adjudicated,
        "static_confidence": round(float(static_confidence), 2),
        "positive": positives,
        "negative": negatives,
        "outcomes": outcomes,
        "minimum_outcomes": minimum_outcomes,
    }
    if outcomes < minimum_outcomes:
        result.update(basis=BASIS_STATIC_PRIOR, precision=round(float(static_confidence), 2))
        return result
    bound = wilson_lower_bound(prior_true + positives, prior_adjudicated + outcomes)
    result.update(basis=BASIS_MEASURED, precision=round(bound, 2))
    return result


def apply_rule_stats(findings, rule_stats: Optional[Dict[str, Any]]):
    """Each finding with its rule's calibrated precision, or the findings unchanged.

    `rule_stats` is `{"minimum_outcomes": 20, "rules": {rule_id: {"positive", "negative"}}}`.
    Without a `rules` key the caller did not ask for calibration and nothing is touched.

    `confidence` itself is left alone. It is also what the api-service's inline-comment gate
    reads, against thresholds (0.85 for an AST pattern) tuned to the static constants, and a
    Wilson lower bound sits below them for any rule with few outcomes: 20 positives out of 20
    bound at 0.84. Replacing it would silence rules for being new rather than for being wrong.
    The comment and the dashboard print the measured precision from `rule_precision` instead,
    and whether the gate should read it is a separate decision with its own measurement.
    """
    if not isinstance(rule_stats, dict) or not isinstance(rule_stats.get("rules"), dict):
        return findings
    rules = rule_stats["rules"]
    minimum = _count(rule_stats.get("minimum_outcomes")) or MINIMUM_OUTCOMES
    calibrated = []
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if not rule_id:
            calibrated.append(finding)
            continue
        try:
            static = float(finding.get("confidence", 0.5))
        except (TypeError, ValueError):
            static = 0.5
        precision = calibrate(rule_id, static, rules.get(rule_id), minimum)
        enriched = dict(finding)
        details = dict(enriched.get("evidence_details") or {})
        extra = details.get("extra")
        details["extra"] = {**extra, "rule_precision": precision} if isinstance(extra, dict) else {"rule_precision": precision}
        enriched["evidence_details"] = details
        calibrated.append(enriched)
    return calibrated


def rule_precision_of(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    details = finding.get("evidence_details") or {}
    extra = details.get("extra") if isinstance(details, dict) else None
    value = extra.get("rule_precision") if isinstance(extra, dict) else None
    return value if isinstance(value, dict) else None
