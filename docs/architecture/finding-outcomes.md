# Finding outcomes and quality metrics

Two tables. `finding_outcomes` is the append-only record of what happened to every
finding and to every fix the app published. `quality_metrics_daily` is a roll-up of it,
recomputed on a schedule and holding no fact of its own.

## The outcome log

`finding_outcomes` is written by one helper, `recordOutcome` in
`services/api-service/src/db/findingOutcomes.js`. Nothing inserts into the table inline.
The insert is `ON CONFLICT DO NOTHING` against a replay key of
`(coalesce(finding_id, sentinel), fingerprint, outcome, source, coalesce(external_id, ''))`,
so a redelivered webhook, a retried reconciler step, or a re-run analysis records the same
fact once. The helper takes an optional transaction client, so an outcome commits with the
state change it describes.

The fingerprint, rule id, CWE, severity, confidence and family are copied onto the row
rather than joined for. A finding row is deleted when a repository is disconnected; the
outcome survives it.

Outcomes: `fix_published`, `applied_in_app`, `applied_on_github`, `dismissed`,
`accepted_risk`, `suppressed`, `thread_resolved`, `thread_unresolved`,
`fixed_by_reanalysis`, `reopened`, `marked_fixed`, `residual_after_apply`.

Sources: `workspace`, `github_thread`, `github_push`, `reanalysis`, `remediation`,
`suppression`.

A dismissal carries one of four reasons: `not_exploitable`, `test_or_sample_code`,
`wrong_rule_match`, `other`. The workspace's older `false_positive` maps to
`not_exploitable`; anything unrecognised becomes `other` rather than being stored as free
text.

### Writers

| Where | Outcome |
| --- | --- |
| `PATCH /api/findings/:id/status`, through `db/findings.js` `updateStatus` | `dismissed`, `accepted_risk`, `reopened`, `marked_fixed` |
| `POST /api/suppressions` | `suppressed` for every finding carrying the fingerprint |
| `db/findings.js` `markFixed`, called by the analysis orchestrator | `fixed_by_reanalysis` |
| `services/remediationInlineFixes.js`, on a successful publication | `fix_published` per finding the published candidate covers |
| `db/remediation.js` `recordAppliedOutcomes`, on an action reaching `applied` and again on completion | `applied_in_app` |
| `services/remediationResidualReport.js`, when the residual comment is published | `residual_after_apply` per blocking finding |
| `services/findingThreadEvents.js` `handleReviewThread` | `thread_resolved`, `thread_unresolved` |
| `services/findingThreadEvents.js` `handleReviewComment` | `dismissed` |
| `services/findingThreadEvents.js` `handleCommitSuggestions` | `applied_on_github` |

The three webhook handlers run inside the delivery transaction the webhook route already
holds, so a redelivery rolls back with the delivery marker.

### Decisions made on GitHub

A reviewer who never opens the workspace still decides things, and the app has to see it.

- Resolving or unresolving the bot's review thread. The thread's root comment carries a
  `<!-- mitig8it-finding:<fingerprint> -->` marker; a thread without one is not ours and
  is ignored. The root comment id is remembered on the finding the first time it is seen,
  because a reply carries only that id and never the root's body.
- Replying to that thread with `not an issue`, `false positive` or `/mitig8it dismiss`.
  The finding is dismissed with the reason the reply names, or `wrong_rule_match` when it
  names none.
- Pressing "Commit suggestion" on a published fix. GitHub commits on the reviewer's behalf
  and credits the comment's author in a `Co-authored-by:` trailer. A push whose commit
  carries that trailer for the app's own bot login, and whose modified files contain the
  path of a finding with a `fix_published` outcome, records `applied_on_github` for that
  finding. It is not recorded as fixed: the re-analysis of the new head establishes that.

The bot login comes from `resolveGithubAppSlug` in
`services/api-service/src/services/githubAppIdentity.js`, which reads `GITHUB_APP_SLUG`.
It is never a literal: an installation of a differently named app must recognise its own
commits, not ours.

Two GitHub App event subscriptions are required for this and are listed in
[the GitHub App setup guide](../getting-started/github-app.md): **Pull request review
thread** and **Pull request review comment**.

## The daily roll-up

`quality_metrics_daily` holds counts of distinct findings per day, at four grains
distinguished by which key columns are NULL: the installation total, the installation per
rule, one repository's total, and one repository per rule. A finding belongs to one
repository and carries one rule, so the coarser grains are exact sums of the base grain.

`applied_in_app` and `applied_on_github` are disjoint by construction: a finding counted
as applied in the app on a day is not counted again under `applied_on_github` that day, so
their sum is an exact count of distinct findings applied.

`thread_resolved_without_fix` is the subset of `thread_resolved` for findings that were
never applied and never re-analysed away. The reviewer closed the thread and nothing was
fixed, which is a rejection.

The SQL is in `services/api-service/src/db/qualityMetrics.js`. One statement rebuilds all
four grains through `GROUPING SETS` and upserts on the unique index; a second statement
prunes any window row the pass did not touch. Running it twice changes nothing.

### The three rates

Pure functions in `services/api-service/src/services/qualityMetrics.js`:

- **apply rate** = distinct findings applied (in the app or on GitHub) / distinct findings
  a fix was published for.
- **dismiss rate** = (dismissed + suppressed + threads resolved without a fix) / findings
  raised.
- **residual rate** = findings still blocking after an apply / distinct findings applied.

A rate is `null`, never zero, when its denominator is zero. Zero would read as "nobody
applied our fixes"; null reads as "we published nothing to apply". The frontend renders
null as `n/a`.

Rates are computed from the sum of a window's rows, never averaged across days.

### Where it runs and where it is read

The `quality_metrics` step of `services/api-service/src/services/remediationReconciler.js`
recomputes a trailing 35 days per installation and republishes the gauges. It runs at most
once per `QUALITY_METRICS_INTERVAL_MS` (default 3600000), whatever the reconciler's own
period is. One failing installation does not stop the rest.

Gauges, labelled `installation_id` and `window`: `mitig8it_quality_apply_rate`,
`mitig8it_quality_dismiss_rate`, `mitig8it_quality_residual_rate`. A rate with no
denominator is removed rather than set, so a dashboard shows a gap instead of a confident
and wrong number.

`GET /api/reports/quality?window=7|30&repository_id=` returns `overall` and `by_rule` (the
top 20 rules by dismiss rate, then by how often the rule fired), scoped to the
installations the caller can reach. The route reads rows and sums them; it never touches
the raw log, so a large log cannot make the dashboard slow. A repository the caller cannot
reach is refused with 404 rather than answered with an empty roll-up.

The dashboard shows the three rates over 30 days; the reports page shows the rule table.
