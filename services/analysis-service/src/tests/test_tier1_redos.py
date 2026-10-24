"""One long line must not stall tier 1 past its budgets.

A Python regex cannot be interrupted, and the tier 1 budgets in `pattern_findings` used to be
checked only between rules and between files. `sql.injection.raw_query` is quadratic: a 75 kB
line in one changed file took 27.8 s and stopped tier 1 after 9 of 35 rules, far past the 2 s
per-file and 20 s total budgets. Two defences now hold together:

* `pattern_findings` does not scan a line over `TIER1_MAX_LINE_CHARS` at all, and says so in
  one limitation per file rather than skipping it silently, and
* the per-file budget is also checked between lines inside one rule, so a file of many lines
  just under the cap stops at the budget with a limitation instead of running past it.

The pattern definitions themselves are not changed here. A tier 1 rule publishes only while its
exact definition digest matches the legacy inventory in `benchmarks/rule-quality`, and that
inventory may not be extended to approve a changed rule, so bounding the `.*` in
`sql.injection.raw_query` would withdraw the rule from publication until it has 100 adjudicated
holdout predictions. Its 50 kB timing is a strict xfail that records the defect and fails the
day the definition is fixed, so the marker is removed with it.

The timings are generous ceilings for a slow CI runner, not targets: the quadratic pattern took
about 10 s on the first adversarial line.
"""

import re
import time

import pytest

import secret_detection
from main import TIER1_MAX_LINE_CHARS, ChangedFile, pattern_findings
from security_rules import DEPENDENCY_RISK_PATTERNS, SECURITY_RULES

LINE_CHARS = 50_000
PATTERN_CEILING_SECONDS = 0.2
PATCH_CEILING_SECONDS = 2.0


def _repeat(unit: str, length: int) -> str:
    return (unit * (length // len(unit) + 1))[:length]


ADVERSARIAL_LINES = {
    "fstring_braces": _repeat('f"{', LINE_CHARS),
    "select_keywords": _repeat("select ", LINE_CHARS),
    "quotes": _repeat("\"'", LINE_CHARS),
    "spaces": " " * LINE_CHARS,
}


def _every_pattern():
    patterns = []
    for rule in SECURITY_RULES:
        for attribute in ("pattern", "exclusion", "non_code_text_exclusion"):
            pattern = getattr(rule, attribute, None)
            if pattern is not None:
                patterns.append((f"{rule.rule_id}.{attribute}", pattern))
    for index, (pattern, *_rest) in enumerate(DEPENDENCY_RISK_PATTERNS):
        patterns.append((f"dependency_risk[{index}]", pattern))
    for name, value in sorted(vars(secret_detection).items()):
        if isinstance(value, re.Pattern):
            patterns.append((f"secret_detection.{name}", value))
    for key_format in secret_detection.KEY_FORMATS:
        patterns.append((f"key_format.{key_format.secret_type}", key_format.pattern))
        if key_format.name_hint is not None:
            patterns.append((f"key_format.{key_format.secret_type}.name_hint", key_format.name_hint))
    return patterns


PATTERNS = _every_pattern()


def test_the_pattern_inventory_is_not_empty():
    # A refactor that moved the patterns somewhere this file does not look would otherwise
    # turn every timing test below into a test of nothing.
    assert len([name for name, _ in PATTERNS if not name.startswith(("secret", "key", "dep"))]) >= 35
    assert any(name.startswith("key_format.") for name, _ in PATTERNS)


# Quadratic at 50 kB and kept as they are because their definitions are pinned by digest (see
# the module docstring). The line cap and the per-line deadline are what bound them in tier 1.
KNOWN_QUADRATIC = {
    ("sql.injection.raw_query.pattern", "fstring_braces"),
    ("sql.injection.raw_query.pattern", "select_keywords"),
}


def _pattern_params():
    params = []
    for name, pattern in PATTERNS:
        for line_name in sorted(ADVERSARIAL_LINES):
            marks = []
            if (name, line_name) in KNOWN_QUADRATIC:
                marks.append(pytest.mark.xfail(
                    strict=True,
                    reason="quadratic `.*` in a digest-pinned definition; bounded by the tier 1 line cap",
                ))
            params.append(pytest.param(name, pattern, line_name, id=f"{name}-{line_name}", marks=marks))
    return params


def _time_every_match(pattern, line):
    started = time.perf_counter()
    for _match in pattern.finditer(line):
        pass
    return time.perf_counter() - started


@pytest.mark.parametrize("name,pattern,line_name", _pattern_params())
def test_every_pattern_is_linear_on_a_long_adversarial_line(name, pattern, line_name):
    elapsed = _time_every_match(pattern, ADVERSARIAL_LINES[line_name])
    assert elapsed < PATTERN_CEILING_SECONDS, f"{name} took {elapsed:.3f} s on {line_name}"


@pytest.mark.parametrize("line_name", sorted(ADVERSARIAL_LINES))
@pytest.mark.parametrize("name,pattern", PATTERNS, ids=[name for name, _ in PATTERNS])
def test_every_pattern_is_fast_on_the_longest_line_tier1_scans(name, pattern, line_name):
    # No exception here: this is the length the line cap lets through to a rule.
    elapsed = _time_every_match(pattern, ADVERSARIAL_LINES[line_name][:TIER1_MAX_LINE_CHARS])
    assert elapsed < PATTERN_CEILING_SECONDS, f"{name} took {elapsed:.3f} s on {line_name}"


def test_a_file_of_lines_just_under_the_cap_stops_at_the_per_file_budget():
    # 48 lines of 4 kB that each cost the quadratic rule about 0.07 s: 7.7 s on one rule when
    # the budget was only checked between rules.
    line = _repeat('f"{', TIER1_MAX_LINE_CHARS)
    patch = "@@ -0,0 +1,48 @@\n" + "".join(f"+{line}\n" for _ in range(48))
    limitations = []

    started = time.perf_counter()
    pattern_findings([ChangedFile(path="app.py", patch=patch)], limitations)
    elapsed = time.perf_counter() - started

    assert elapsed < 3.0, f"pattern_findings took {elapsed:.3f} s"
    assert [item["kind"] for item in limitations] == ["budget"]
    assert limitations[0]["path"] == "app.py"


def _single_line_patch(line: str) -> str:
    return f"@@ -1,1 +1,2 @@\n context = 1\n+{line}\n"


@pytest.mark.parametrize("line_name", sorted(ADVERSARIAL_LINES))
def test_a_200_kb_line_is_skipped_with_one_limitation(line_name):
    # Just under the 200 kB patch cap, so the line reaches the rules rather than the cap.
    line = _repeat(ADVERSARIAL_LINES[line_name][:64], 199_000)
    patch = _single_line_patch(line)
    assert len(patch) < 200_000
    limitations = []

    started = time.perf_counter()
    pattern_findings([ChangedFile(path="app.py", patch=patch, content="context = 1\n" + line + "\n")], limitations)
    elapsed = time.perf_counter() - started

    assert elapsed < PATCH_CEILING_SECONDS, f"pattern_findings took {elapsed:.3f} s"
    long_line = [item for item in limitations if item.get("path") == "app.py"]
    assert len(long_line) == 1, limitations
    assert long_line[0]["message"] == "Tier 1 skipped 1 line over 4 kB"
    assert long_line[0]["line"] == 2


def test_several_long_lines_in_one_file_record_one_limitation():
    line = "x = 1  # " + "a" * (TIER1_MAX_LINE_CHARS + 10)
    patch = "@@ -1,0 +1,3 @@\n+" + line + "\n+" + line + "\n+eval(user_input)\n"
    limitations = []

    findings = pattern_findings([ChangedFile(path="app.py", patch=patch)], limitations)

    assert [item["message"] for item in limitations] == ["Tier 1 skipped 2 lines over 4 kB"]
    assert limitations[0]["line"] == 1
    # The lines around a skipped one are still scanned, at their own line numbers.
    eval_findings = [finding for finding in findings if finding["rule_id"] == "code.injection.eval"]
    assert [finding["line_start"] for finding in eval_findings] == [3]


def test_a_finding_on_a_long_line_is_not_reported_and_the_line_at_the_cap_still_is():
    at_cap = "eval(user_input)  # " + "a" * (TIER1_MAX_LINE_CHARS - 20)
    over_cap = at_cap + "a"
    assert len(at_cap) == TIER1_MAX_LINE_CHARS
    limitations = []

    kept = pattern_findings([ChangedFile(path="a.py", patch=f"@@ -0,0 +1,1 @@\n+{at_cap}\n")], limitations)
    assert any(finding["rule_id"] == "code.injection.eval" for finding in kept)
    assert limitations == []

    skipped = pattern_findings([ChangedFile(path="b.py", patch=f"@@ -0,0 +1,1 @@\n+{over_cap}\n")], limitations)
    assert not any(finding["rule_id"] == "code.injection.eval" for finding in skipped)
    assert [item["path"] for item in limitations] == ["b.py"]


def test_a_long_removed_line_is_not_a_limitation():
    # Tier 1 never scans removed lines, so skipping one hides nothing.
    patch = "@@ -1,1 +1,1 @@\n-" + "a" * (TIER1_MAX_LINE_CHARS + 1) + "\n+short = 1\n"
    limitations = []
    pattern_findings([ChangedFile(path="a.py", patch=patch)], limitations)
    assert limitations == []


def test_a_patch_over_the_cap_is_a_limitation_not_a_silent_skip():
    patch = "@@ -0,0 +1,1 @@\n+" + "a = 1; " * 30_000 + "\n"
    limitations = []
    assert pattern_findings([ChangedFile(path="big.py", patch=patch)], limitations) == []
    assert [(item["kind"], item["path"]) for item in limitations] == [("not_analyzed", "big.py")]
