# Tier 1 precision benchmark

A labelled set of lines with a known verdict, and the gate a tier 1 rule change has to
pass before it can post.

## What is in it

`cases.json` holds two lists.

**`false_positives`** is every line the September 2026 real-repository replay read by hand
and judged wrong, as far as the report reproduces them. The replay read 30 findings across
165 merged pull requests from 11 public repositories and found 29 of them false; its raw
results are not committed (`scripts/replay/.gitignore` ignores `results/`), so the 18 lines
quoted in `docs/validation/real-repo-replay-2026-09.md` are the ones that can be rebuilt.
Each case names the rule that fired and, in `suppressed_by`, the mechanism that stops it
now:

| `suppressed_by` | Meaning |
| --- | --- |
| `quarantine` | The rule is quarantined, so nothing it produces is posted. |
| `word_boundary` | The rule's own pattern no longer matches after the pattern fix. |
| `exclusion` | The pattern still matches; the exclusion pass drops it. |
| `comment_stripping` | The line is a comment, so the rule never sees it. |

A case with a `known_gap` key reproduces today and is expected to. The gate asserts it
still reproduces, so when the gap closes the test fails and the key has to come out.

**`true_positives`** is 20 lines drawn from
`services/analysis-service/src/tests/test_security_rules.py`, one per rule family that
posts. They are the floor: a precision change that also removes these has narrowed the
product, not improved it.

## Running it

```sh
cd services/analysis-service/src
python -m pytest tests/test_tier1_precision_benchmark.py -q
```

The gate asserts three things:

1. no posted finding on any case comes from a quarantined rule;
2. no false-positive case produces a posted finding for its rule;
3. every true-positive case still produces its finding.

It also asserts, for the cases not carried by the quarantine, that the rule's own pattern
no longer matches. That is the difference between a rule that was fixed and a rule that
was merely silenced.

## Adding a case

Add a line with a verdict you can defend, and say where the verdict comes from. A case
without provenance is an opinion. Re-enabling a quarantined rule means adding its
false-positive cases here first and showing they pass.
