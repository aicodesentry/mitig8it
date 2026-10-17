# Fix placement and calibrated confidence, October 2026

Three changes on `feat/fix-anchors-and-calibrated-confidence`, each answering a line of the
September action trial ([action-trial-2026-09.md](action-trial-2026-09.md), "What is still
wrong"):

* **Anchors.** Item 7: three findings sat on `module.exports = {` or `app.use(session({`
  instead of the property that was the defect.
* **Placement.** Item 9: no fix on any of the four JavaScript and TypeScript repositories. The
  shape those repairs take, an `execFile` added to a `require` line the pull request never
  touched plus the call site that uses it, was published as a suggestion of the call site
  alone, with the import folded into a note. Clicking it commits code that does not build.
* **Calibration.** Every rule's confidence is a hand-set constant. The corpus measurement
  behind each rule (`precision_evidence`) and the reviewers' own decisions (`finding_outcomes`)
  both existed and neither was used.

Nothing here has been run against a real repository or a real outcome log. What is measured is
stated per section, with the command; what is not is stated with the command that would
measure it.

## Anchors

`cwe-798.js-credential-config-key` matched the whole object literal and
`cwe-614.js-session-cookie-insecure` matched the whole `session({ ... })` or
`cookieSession({ ... })` call, so the scanner reported the first line of the construct. Both now
use `pattern-inside` for the container and match the property, the change item 13 made to
`cwe-798.js-session-secret-literal`.

Measured by running the scanner over the anchored cases of
`benchmarks/tier2-precision/cases.json` with the rule file from `origin/main` and from this
branch (opengrep, 2026-10-17):

| Case | Defect on line | `origin/main` | This branch |
| --- | ---: | ---: | ---: |
| `anchor.cwe-798.js-credential-config-key.nested-call` | 3 | 1 | 3 |
| `corpus.cwe-798.js-credential-config-key` (NodeGoat `config/env/all.js`) | 4 | 1 | 4 |
| `anchor.cwe-614.js-session-cookie-insecure.nested-call` | 6 | 1 | 6 |
| `anchor.cwe-614.js-session-cookie-insecure.object-literal` | 4 | 1 | 4 |
| `corpus.cwe-614.js-session-cookie-insecure` (dvna `server.js`) | 5 | 1 | 5 |
| `cwe-798.js-credential-config-key` (`module.exports` object) | 3 | 1 | 3 |
| `cwe-614.js-session-cookie-insecure` (one-line call) | 1 | 1 | 1 |

The two corpus rows are the trial's own lines: NodeGoat `config/env/all.js:5` becomes `:8` and
dvna `server.js:23` becomes `:27`.

A case that names a `line` is now an assertion: `TestAnchorLine` in
`services/analysis-service/src/tests/test_tier2_precision_benchmark.py` fails when the rule
does not report that line. `make bench-tier2` runs it: 176 passed.

One consequence to know about. A match is now a property, so an object with two credential
properties, or a `cookie: { secure: false, httpOnly: false }`, yields two findings where it
used to yield one. The fold in `cluster_findings` keys on adjacent lines and internal type and
will usually join them; where it does not, the two comments are on the two lines that are
wrong, which is the point.

### Rules with the same shape, not changed

Each of these matches an object or call and reports its first line, while the defect is one
property inside it. None is a one-line change (each needs the `pattern-inside` restructure
and a fixture), so they are listed rather than fixed:

| Rule | File | The property |
| --- | --- | --- |
| `cwe-943.js-mongo-where-operator` | `javascript_coverage.yml` | `$where` |
| `cwe-78.js-spawn-shell-true` | `javascript_coverage.yml` | `shell: true` |
| `cwe-502.js-yaml-load-unsafe` | `javascript_coverage.yml` | `schema:` |
| `cwe-798.js-basic-auth-literal` | `javascript_coverage.yml` | `Authorization:` |
| `cwe-347.js-jwt-none-algorithm` | `javascript_coverage.yml` | `algorithm(s):` |
| `cwe-613.js-jwt-ignore-expiration` | `javascript_coverage.yml` | `ignoreExpiration`, `ignoreNotBefore` |
| `cwe-295.js-agent-reject-unauthorized-false` | `javascript_coverage.yml` | `rejectUnauthorized: false` |
| `cwe-326.js-tls-min-version-legacy` | `javascript_coverage.yml` | `minVersion`, `secureProtocol` |
| `cwe-295.js-checkserveridentity-disabled` | `javascript_coverage.yml` | `checkServerIdentity` |
| `cwe-1275.js-cookie-samesite-none` | `javascript_coverage.yml` | `sameSite` |
| `cwe-942.js-cors-credentials-reflected` | `javascript_coverage.yml` | `origin` and `credentials` (two properties; which line is the defect is a choice) |
| `cwe-693.js-helmet-protection-disabled` | `javascript_coverage.yml` | the disabled protection |
| `cwe-489.js-express-error-stack-exposed` | `javascript_coverage.yml` | `stack:` |
| `cwe-295.tls-disabled` | `javascript.yml` | `rejectUnauthorized: false` |
| `cwe-943.py-pymongo-where-operator` | `python_coverage.yml` | `"$where"` |
| `cwe-347.py-jwt-verification-disabled` | `python_coverage.yml` | `"verify_signature"`, `"verify_exp"` |

On a one-line call all of these already report the right line. They are wrong only when the
options object is spread over several lines.

## Placement

A suggestion is the lines a reviewer commits by pressing **Commit suggestion**, and GitHub
accepts one only on lines the pull request diff shows. The question for a fix with several
regions is therefore which fix that click would commit. The decision is made once, in
`planSection` in `services/github-service/src/services/githubInternalOperations.js`, which the
App reaches through the api-service publication (`remediationInlineFixes.js`) and the Action
reaches through `action/publisher/publish.js`.

Whether a region outside the diff can be left out is decided where the regions are computed:
`isDispensableRegion` in `services/api-service/src/services/remediationInlineFixes.js` and its
port `is_dispensable_region` in `action/orchestrator/inline_fixes.py` mark every region
`dispensable` when every line it adds or removes is blank or a whole-line comment. github-service
reads only a literal `true`; a missing or malformed flag is a region the fix needs.

| The fix | What is published |
| --- | --- |
| The finding's line is outside the diff | No inline comment is possible. A pull request comment with the diff, the reason, and the apply link. |
| No hunk: several files, another file, or nothing line-shaped | The diff, the reason, and the apply link. |
| A region contains a code fence | The diff, "the fixed lines contain a code fence", and the apply link. |
| Every region in the diff | One suggestion per contiguous region: the finding's region in the finding comment (or in a comment on its own lines when the finding comment cannot carry it), each other region in its own comment. |
| A region outside the diff that changes only comments or blank lines | The in-diff regions as suggestions, and a note: "Left out: line N, outside the pull request diff, changes only comments or blank lines; the fix is complete without it." |
| Any other region outside the diff, an added import included | No suggestion anywhere. The fenced unified diff, one sentence ("the fix also changes line N, outside the pull request diff, and a suggestion without that change would commit half of the verified fix"), and the apply link. |
| The finding's own region outside the diff and the comment cannot carry it | The diff, the reason, and the apply link. |

The apply link is `Apply the whole change with Apply this fix in [Mitig8it](...)` for the App.
The Action has no app behind it, so it says `Apply the whole change with git apply on a
checkout of this branch.`

The previous behaviour for the import case was the opposite of the last-but-two row: the call
site was suggested and the import was a note ("Also add `const { execFile } = ...` at line 2").
That note is gone.

Tests, one per row:

* `services/github-service/src/__tests__/remediationOperations.test.js`: the finding line
  outside the diff; several files; the code fence; every region in the diff (two tests, the
  extra-comment one and the separate-comment one); the comment-only region left out; the import
  outside the diff; two needed regions outside the diff; a `dispensable` flag that is not
  literally `true`; the Action's `git apply` sentence; the comment that cannot carry the hunk.
  44 passed.
* `services/api-service/tests/remediationInlineFixes.test.js`: four comment-only regions are
  dispensable; eight needed ones are not, including the trial's `require`, a JavaScript private
  field (`#count`), a generator method (`*items()`) and a comment plus one statement; and
  `buildSections` marks every region it sends. 37 passed.
* `action/tests/test_inline_fix_parity.py` runs the Node `isDispensableRegion` and the Python
  port on the same twelve regions and requires the same answers;
  `action/tests/test_fix_sections.py` checks that the Action's sections carry the flag. The
  whole Action suite: 300 passed.

What this does not do: produce a fix. Item 9's zero comes first from the repair engine, and this
change only decides what happens once a JavaScript fix exists. A re-run of the trial on
nodegoat, juice-shop, nodejs-goof and dvna would show it, if the engine produces a two-region
`command_arguments` fix: the comment should carry the diff and the `git apply` sentence, and
no suggestion block.

## Calibration

### The formula

For a rule with corpus prior `k0` true out of `n0` read, and `p` positive and `q` negative
outcomes:

```
m = p + q
if m < 20:   precision = the rule's static confidence constant   (basis: static_prior)
else:        precision = WilsonLower(k0 + p, n0 + m, z = 1.96)    (basis: measured)

WilsonLower(k, n, z) = ( phat + z^2/(2n) - z * sqrt( (phat (1 - phat) + z^2/(4n)) / n ) ) / (1 + z^2/n)
phat = k / n
```

* **Prior.** `parse_precision_evidence` in
  `services/analysis-service/src/rule_precision.py` reads the rule's `precision_evidence` line.
  It reads how many findings were read ("N adjudicated", "N hand-read", "N read by hand",
  "both adjudicated", "N findings, adjudicated") and how many were true ("K true and F
  false", else "precision P" times the count, else "all true", "both true", "and true"). 22 of
  the 33 evidence lines in the tree parse. The eleven that do not are five tier 1 replay notes
  with no count ("all 19 sampled by hand were wrong", "2 findings, both wrong") and six
  workflow rules measured at zero findings or described in prose, and a rule with no count has
  no prior counts. The static `confidence` constant is not presented as measured
  anywhere.
* **Positive outcome.** A fix applied in the app (`applied_in_app`) or on GitHub
  (`applied_on_github`), or a review thread resolved (`thread_resolved`) after the finding was
  fixed and never applied by us. A thread resolved after an applied fix is the same positive,
  not a second one.
* **Negative outcome.** `dismissed` with reason `wrong_rule_match` or `not_exploitable`.
* **Neither.** A test-code dismissal, `other`, an accepted risk, a suppression, a thread
  resolved with no fix. They do not say whether the rule matched a real defect.
* **Minimum.** 20 outcomes, `MINIMUM_OUTCOMES` in `rule_precision.py` and
  `MINIMUM_RULE_OUTCOMES` in `services/api-service/src/services/qualityMetrics.js`.

The corpus counts are pooled with the live ones as observations of the same rule, and the
lower bound rather than the point estimate is used, so a rule with few observations cannot
look better than it has shown itself to be.

### A worked example

`opengrep.cwe-798.js-credential-config-key`: static constant 0.80; `precision_evidence` reads
"3 adjudicated by label, all true", so `k0 = 3, n0 = 3`. Suppose an installation has 18
positive and 4 negative outcomes for it.

```
m = 22                      (at least 20, so measured)
k = 3 + 18 = 21, n = 3 + 22 = 25, phat = 0.84, z^2 = 3.8416
centre = 0.84 + 3.8416/50                        = 0.916832
margin = 1.96 * sqrt((0.84*0.16 + 3.8416/100)/25) = 0.162958
lower  = (0.916832 - 0.162958) / (1 + 3.8416/25) = 0.753874 / 1.153664 = 0.6535
```

The comment reads `**Confidence:** 65% (this rule's measured precision, lower bound over 22
reviewed findings)`. With 15 positive and 4 negative it would read `**Confidence:** 80% (this
rule's prior, not yet measured: 19 of 20 reviewed findings)`. Both shapes are asserted in
`test_rule_precision.py` and `orchestrator.test.js`, and the four Wilson values the two
languages share (21 of 25, 20 of 20, 0 of 20, 3 of 3) are asserted in both.

### Where it is used

* **api-service.** Migration `0029_rule_precision_outcomes.sql` adds `outcome_positive` and
  `outcome_negative` to `quality_metrics_daily`, recomputed by the existing roll-up.
  `GET /api/reports/quality` returns them per rule with `outcomes` and
  `outcome_precision_lower_bound` (the outcomes alone, null below 20). Before tier 3, with
  `RULE_CALIBRATION_ENABLED=true`, the orchestrator reads the installation's per-rule sums over
  365 days and sends them as `rule_stats` beside `repo_profile`, over HTTP or gRPC
  (`TriageFindingsRequest.rule_stats`, a `google.protobuf.Struct`; stubs regenerated with
  grpcio-tools 1.71.2, the version the checked-in stubs were built with, so the only diff is
  the new field).
* **analysis-service.** `apply_rule_stats` records the result on each finding as
  `evidence_details.extra.rule_precision` (basis, precision, the prior and outcome counts, the
  minimum). `_evidence_strength` reads it: a measured precision of 0.80 or more raises the
  strength one step, below 0.50 makes it `light` whatever the scope, between the two the scope
  decides, and a static prior moves nothing. The triage prompt carries `rule_precision` beside
  `confidence`.
* **What a reader sees.** The review comment's `**Confidence:**` line and the finding pages
  (`frontend/src/lib/confidence.js`) print the measured precision with its count, or the static
  constant marked as a prior.

`finding.confidence` is deliberately not replaced. `explainInlineCommentDecision` gates inline
comments on it at 0.85 for an AST pattern, a threshold tuned to the static constants, and a
Wilson lower bound sits below that for any rule with few outcomes: a perfect 20 of 20 bounds at
0.84. Replacing it would stop a rule posting for being new rather than for being wrong. Whether
the gate should read the measured precision is a separate change that needs its own
measurement.

### Gating

`RULE_CALIBRATION_ENABLED` on the api-service, off by default. Off, no outcome counts are read,
`rule_stats` is empty, the analysis service touches nothing and every comment is byte for byte
what it was. A failed read is logged and the review goes on without counts. The Action has no
outcome store and never sends `rule_stats`.

### Measured and not

Measured: the roll-up SQL against a disposable Postgres 14 database with all migrations applied
(0029 included), seeded with eleven outcomes over two rules. It produced 4 positive and 3
negative for the rule that had them (three applies, one of them later thread-resolved and
counted once; one fix by re-analysis then thread-resolved; two `wrong_rule_match`, one
`not_exploitable`), excluded the test-code dismissal, the unfixed thread and the `other`
dismissal, and a second recompute changed nothing.

Not measured: any real rule's measured precision. No installation has 20 outcomes for any rule
in this environment, and rows before migration 0029 read zero until the trailing 35-day window
recomputes them; older days stay at zero. To measure, with the flag on in an environment that
has outcomes:

```sh
curl -s -H "Authorization: Bearer $TOKEN" "$API/api/reports/quality?window=30" \
  | jq '.by_rule[] | {rule_id, outcome_positive, outcome_negative, outcome_precision_lower_bound}'
```

or directly:

```sql
SELECT rule_id, SUM(outcome_positive) AS positive, SUM(outcome_negative) AS negative
  FROM quality_metrics_daily
 WHERE repository_id IS NULL AND rule_id IS NOT NULL
 GROUP BY rule_id
HAVING SUM(outcome_positive) + SUM(outcome_negative) >= 20;
```

The number that would say whether calibration helps is the dismiss rate on rules whose measured
precision falls below 0.50, before and after, on the same installation. It has not been run.

## Commands

```sh
make bench-tier2
cd services/github-service && npx jest src/__tests__/remediationOperations.test.js
cd services/api-service && npx jest tests/remediationInlineFixes.test.js tests/qualityMetrics.test.js \
  tests/orchestrator.test.js tests/grpcRequestSerialization.test.js
cd action && python -m pytest tests -q
cd services/analysis-service/src && python -m pytest tests/test_rule_precision.py tests/test_llm_triage.py \
  tests/test_grpc_contracts.py -q
cd frontend && npx vitest run src/lib
```
