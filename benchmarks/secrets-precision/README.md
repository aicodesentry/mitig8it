# Secrets precision benchmark

One fixture per key format and per entropy shape the secrets detector claims, and every line
the September 2026 measurement read by hand and judged wrong, so neither half of the claim can
decay in silence.

`cases.json` is the whole benchmark. `services/analysis-service/src/tests/test_secrets_precision_benchmark.py`
runs it:

```sh
cd services/analysis-service/src && python -m pytest tests/test_secrets_precision_benchmark.py -q
```

It runs in the same suite and the same CI job as the tier 1 and tier 2 precision gates, so it
is the same gate. It has its own case file because the detector is Python rather than an
OpenGrep rule, and because its cases are single lines rather than whole files to scan: the
detector reads the added lines of a diff, so a case is a one-line hunk.

## Why it exists separately from the tier 1 set

`benchmarks/tier1-precision/cases.json` is keyed on `rule_id` from `security_rules.py`, and
every case is a whole-snippet run through `analyze_tier1_payload`. Neither fits here. A
secrets case has to say **which signal** fired and **which key format**, because the detector
declares two rule ids and records the format in `evidence_details.extra.secret_type`; and a
no-finding case has to name **which exclusion** refused it, because the exclusions are the
precision control and "it did not fire" is not a measurement of anything.

## What is in `cases.json`

Each case is one line, its path, and what must happen to it.

| Field | Meaning |
| --- | --- |
| `id` | `tp.` for a true positive, `fp.` for a line that must stay silent. |
| `expect` | `finding` or `no-finding`. |
| `path` | The file the line is in. The path decides the entropy signal's scope and whether the finding is informational. |
| `line` | The line itself, added by the case's hunk. |
| `signal` | On a `finding` case: the rule id that must fire, `secret.format.known_key` or `secret.entropy.credential_assignment`. |
| `secret_type` | On a `finding` case: the format, from `secret_detection.KEY_FORMATS` or `dotenv_file` or `high_entropy_assignment`. |
| `reason` | On a `no-finding` case: which of the recorded reasons refuses it. |
| `silent_signal` | On a `no-finding` case where one signal is wrong and the other is not: only that signal is asserted silent. |
| `as_context_line` | `true` puts the line in the hunk as context rather than as an addition. |
| `evidence` | Why the verdict is what it is. A case without this is an opinion. |

The gate asserts six things:

1. every case is well formed, and every recorded no-finding reason is exercised by at least
   one case;
2. every format in `secret_detection.KEY_FORMATS` has a true-positive fixture, so adding a
   format forces adding its case;
3. every true-positive case still produces its finding;
4. every true-positive finding reaches a reviewer, which is the posting policy's half of the
   claim: a finding the policy withholds is not a true positive yet;
5. every no-finding case produces nothing, or nothing from its `silent_signal`;
6. every finding says the credential must be rotated, and the shapes no template can rewrite
   offer no fix at all.

## No case in this file is a live credential

Every positive fixture body is a locally generated random string or a value the vendor
publishes in its own documentation. The negative fixtures are quoted from the corpora, and
four of them are the lines this repository's own `.gitleaksignore` records: gitleaks caught
them in our fixtures, a human cleared them, and they are here so this detector can never
regress onto the same lines.

## Adding a case

Say where the verdict came from. For a true positive, name the structure the format verifies.
For a false positive, name the exclusion that refuses it and where the line was read: a clean
repository's pull request, a corpus tree, or our own `.gitleaksignore`. A no-finding case with
no named reason cannot tell a fixed detector from a silenced one.
