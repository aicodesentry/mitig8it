# Tier 2 precision benchmark

One fixture per tier 2 coverage rule, plus every line a rule was narrowed away from, so a
rule cannot stop matching or start matching again without a test failing.

`cases.json` is the whole benchmark. `services/analysis-service/src/tests/test_tier2_precision_benchmark.py`
runs it:

```sh
cd services/analysis-service/src && python -m pytest tests/test_tier2_precision_benchmark.py -q
```

Every fixture is written to a temporary tree and scanned in **one** scanner pass, because a
pass costs about a second and there are ninety of them.

## Why it exists

A rule that posts is a claim about real code, and the claim decays silently. Two ways:

* A pattern edited to remove a false positive removes the true positive with it. Nothing
  fails: the rule simply stops finding anything, and tier 2 finding nothing is exactly the
  state this work started from.
* A pattern widened for coverage starts matching the shape it was narrowed away from. Again
  nothing fails, and the rule's measured precision quietly stops describing it.

The replay would catch neither, because the replay is not run in CI and reads GitHub.

## What is in `cases.json`

Each case is one file's worth of code and what must happen to it.

| Field | Meaning |
| --- | --- |
| `id` | The case name; for a true positive it is the rule id. |
| `expect` | `finding` or `no-finding`. |
| `rule` | True positives: the rule that must fire. |
| `rules` | No-finding cases: the rules that must all stay silent. |
| `path` | The path the fixture is scanned at; the extension picks the language. |
| `code` | The fixture source. |
| `note` | No-finding cases: what was measured and what the narrowing was. |

Three tests run over it:

1. **Every case names a rule that exists.** A renamed rule leaves a case behind that asserts
   nothing; this catches it.
2. **Every posting coverage rule has a true-positive fixture.** Adding a rule to
   `javascript_coverage.yml` or `python_coverage.yml` without a fixture fails here. A
   quarantined rule is exempt, because it posts nothing; several still carry fixtures, which
   is deliberate: a quarantined rule is expected to be re-enabled, and the fixture is what
   the re-enabling is measured against.
3. **Every no-finding line stays silent.**

The pre-existing rules in `javascript.yml` and `python.yml` are out of scope. They were in
the tree before the coverage set; their measurement is the replay, recorded in
`docs/validation/tier2-coverage-2026-09.md`.

## Adding a case

A true positive is the smallest code that the rule should fire on and that a reviewer would
agree is the vulnerability. Not the smallest code that happens to match: a fixture written
backwards from the pattern proves only that the pattern matches itself.

A no-finding case is a line that actually appeared in the replay, with `note` naming the
repository, the pull request and what the narrowing was. Do not invent one: a hypothetical
false positive is an opinion, and this file is for measurements.
