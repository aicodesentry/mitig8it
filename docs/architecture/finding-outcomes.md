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

