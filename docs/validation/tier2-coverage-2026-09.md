# Tier 2 coverage, September 2026

The real-repository replay (`docs/validation/real-repo-replay-2026-09.md`) ran 165 merged pull
requests from 11 public repositories through the pipeline and tier 2 produced **zero** findings
over 816 changed files. The AST scanner covered 25 rules for JavaScript, TypeScript and Python,
in five families, and none of their shapes occurs in ordinary library code.

This is the measurement of the widened rule set: what was added, what it found on the same
corpus, which findings were read by hand, and which rules are allowed to post as a result.

> **Superseded in part.** The XSS and path-traversal sections below describe the rule set as it
> stood on 24 September 2026, before the recall change recorded in the second half of
> `docs/validation/vulnerable-corpus-2026-09.md`. That change added `template_coverage.yml`
> (9 generic rules over 16 template extensions), 5 rules to the JavaScript and Python coverage
> files, and widened 2 path rules, taking the coverage set from 116 to 130. The rule counts and
> the XSS numbers here are the earlier state.

## The rule set

116 rules now cover JavaScript, TypeScript and Python: the 25 that were already in the tree and
91 added here, in `opengrep_rules/javascript_coverage.yml` (48) and
`opengrep_rules/python_coverage.yml` (43).

Every added rule is written in this repository. Both obvious sources were checked and both are
excluded: `opengrep-rules` is LGPL-2.1 **plus the Commons Clause**, which bars a paid service
whose value derives from the rules, and `semgrep-rules` is under the Semgrep Rules License v1.0,
which is internal-use only and forbids making the rules available as a service. The reading is
recorded in `docs/legal/third-party-rules.md`.

### By class

| Class | Rules | | Class | Rules |
| --- | ---: | --- | --- | ---: |
| Security misconfiguration | 11 | | NoSQL injection | 4 |
| SQL injection | 8 | | SSRF | 4 |
| XSS | 7 | | Open redirect | 3 |
| Hardcoded credentials | 7 | | Prototype pollution | 3 |
| Command injection | 6 | | Session management | 3 |
| Code injection | 6 | | Weak password hashing | 2 |
| Path traversal | 6 | | Insecure randomness | 2 |
| Weak cryptography | 6 | | Template injection | 1 |
| Insecure deserialization | 5 | | XXE | 1 |
| JWT misuse | 5 | | Information disclosure | 1 |

By language: 48 JavaScript and TypeScript, 43 Python. 33 carry one of the five remediation
families: `sql_parameterization` 8, `hardcoded_credential` 7, `command_arguments` 6,
`code_injection_eval` 6, `path_containment` 6. Every rule carries a canonical `internal_type`
from `taxonomy.py`; `tests/test_tier2_rule_metadata.py` refuses a rule that passes its own check
id, declares a type outside the canonical set, or declares a family its CWE does not produce.

## A rule id that moved with the working directory

The measurement found this before it found anything about precision. Pointed at a directory,
the scanner names a rule after the path it loaded it from **relative to the working directory**.
The same rule therefore arrived as `opengrep.opengrep_rules.cwe-78.js-exec-interpolated` when
the service ran from `src/` and as
`opengrep.services.analysis-service.src.opengrep_rules.cwe-78.js-exec-interpolated` when the
replay ran from the repository root.

A rule id that depends on the caller's working directory cannot key a posting policy, a
suppression, or a fingerprint, and fingerprints are what deduplicate a finding across runs of
the same pull request. `canonical_check_id` in `opengrep_runner.py` resolves the id back to the
one the rule file declares. This was a pre-existing defect that the posting policy made visible;
it is fixed here because the policy cannot work without it.

## The measurement

The replay was run three times over the same cached GitHub responses, so all three passes saw
byte-identical input:

| Pass | Rule set | Tier 2 findings |
| --- | --- | ---: |
| Baseline | the branch as it was | 0 |
| Measurement | 91 new rules, none narrowed | 6 |
| Final | the same rules with one narrowed and four quarantined | 0 |

165 pull requests, 847 changed files, 9.5 MB of patch and head content. No exceptions, no
timeouts and no worker crashes in any pass. Tier 1 is unchanged at 135 findings throughout.

### Per-rule table

Only one of the 91 rules fired on the corpus. Every finding it produced was read.

| Rule | Findings | Read | True | False | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| `cwe-78.js-exec-interpolated` | 6 | 6 | 0 | 6 | **Narrowed**, then posts |
| the other 87 posting rules | 0 | n/a | n/a | n/a | Posts: zero findings, sink-only pattern, clear taxonomy |
| `cwe-79.js-dangerously-set-dynamic` | 0 | n/a | n/a | n/a | **Quarantined**: needs a data-flow answer |
| `cwe-1275.js-cookie-samesite-none` | 0 | n/a | n/a | n/a | **Quarantined**: matches an object, not a cookie |
| `cwe-79.py-jinja-autoescape-off` | 0 | n/a | n/a | n/a | **Quarantined**: not XSS unless the template is HTML |
| `cwe-489.py-debug-constant-true` | 0 | n/a | n/a | n/a | **Quarantined**: not a settings module |

87 post, 4 are quarantined. Nothing posts on a precision claim nobody measured: the 87 post
under the second clause of the policy, which is that a rule that found nothing on the corpus may
post when its pattern is a sink-only match with a clear taxonomy and makes no data-flow
assumption. That clause is doing real work here, and it is worth naming what it costs: it is an
argument about the pattern, not a measurement of it, so the first corpus that contains these
shapes is the first real test of these 87 rules.

### The six findings, read

All six are the same line of the same file, seen in six different pull requests of
`sindresorhus/got` (#2454, #2462, #2463, #2464, #2465, #2466):

```
source/core/options.ts
unixSocketGroups = /^(?<socketPath>[^:]+):(?<path>.+)$/v.exec(`${url.pathname}${url.search}`)?.groups as typeof unixSocketGroups;
```

This is `RegExp.prototype.exec`, not `child_process.exec`. Labelled precision 0.00 over six
findings.

The rule matched `$X.exec(template)` for any `$X`, and in JavaScript the overwhelmingly common
`.exec` is the regex one. It now names the receiver (`child_process`, `childProcess`,
`node_child_process`, `cp`, or an inline `require("child_process")`), and keeps the unqualified
`exec(...)` and `execSync(...)` forms, where no regex method shares the name: a regex `exec` is
always a method call, so a bare one is a destructured `child_process` import.

That exact line is checked in as a no-finding case in `benchmarks/tier2-precision/cases.json`,
so the narrowing cannot be undone silently. The rule's true-positive fixture is checked in
beside it, so the narrowing cannot have silently removed the rule either.

## Why the corpus is nearly silent

Zero tier 2 findings over 847 changed files is not a harness artifact: `scripts/replay/selftest.py`
puts an obvious SQL injection through the same worker and gets a finding, a candidate and a
passing sandbox check, and `benchmarks/tier2-precision` proves all 87 posting rules fire on a
fixture in one scanner pass.

The corpus is 165 merged pull requests of mature, widely reviewed libraries. Most of what
changes in them is tests, documentation and refactoring. A rule set four and a half times larger
found one shape, six times, and it was wrong. Two things follow, and only the first is
comfortable:

* The widened set adds no noise. A reviewer's experience of these 165 pull requests is unchanged.
* The widened set is also unmeasured on real true positives. This corpus cannot tell a good rule
  from a rule that never matches. The next measurement this needs is a corpus that contains
  vulnerabilities: security advisories with fixing commits, or the pre-fix side of CVE patches.

## Remediation family reach

`hardcoded_credential` was a Python-only family, which is why the baseline replay repaired
nothing: both `secret.hardcoded.credential` findings were in TypeScript. The family now covers
JavaScript and TypeScript, and the two findings reach it.

| | Baseline | Final |
| --- | ---: | ---: |
| Findings in a supported family and language | 0 | 2 |
| Candidates produced | 0 | 0 |
| Verified | 0 | 0 |

Both are `password: 'old-password'` in got test files (`test/hooks.ts:893`,
`test/pagination.ts:1294`), and the engine declines to repair them: `test/` is in
`forbidden_path_prefixes`, so the patch bundle is rejected as `protected_path`. That is the
right answer. A password in a test fixture is not a credential, and the replay's own hand-read
sample already called this finding "a correct pattern match on a value that is not a secret".

So the corpus proves the family is now reached and does not prove the repair. The repair is
proven by `benchmarks/remediation/fixtures/js-hardcoded-secret` and
`js-hardcoded-config-secret`, which both produce a verified template candidate identical to the
reviewed repair with no provider call, under the reference and `engine-local` adapters.

## Suites

| Suite | Command | Result |
| --- | --- | --- |
| analysis-service | `python -m pytest tests -q` in `services/analysis-service/src` | 890 passed |
| remediation-service | `python -m pytest tests -q` in `services/remediation-service` | 336 passed, 1 failed (`test_python_harness.py`, pre-existing, fails because Flask is installed in this interpreter) |
| tier 2 precision benchmark | `python -m pytest tests/test_tier2_precision_benchmark.py -q` | 94 passed |
| remediation benchmark | `benchmarks/remediation/evaluate.py --suite seed` and `--adapter engine-local` | 13 cases, 9 repairs verified, 4 safe abstentions, no failures |
| replay self-test | `scripts/replay/selftest.py` | ok: findings=1 candidates=1 verified=1 agent_needed=0 |
