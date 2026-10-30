# Production readiness

This is the working checklist for taking Mitig8it from a system that works on
friendly repositories to one that behaves correctly on repositories it has
never seen, and that tells its operators when it does not. Each item states
the bar, the current state, and the evidence. Items move to "done" only with a
merged pull request or a recorded live check.

States: done, in progress, open.

The machine-enforced quality decision is `python -m benchmarks.production_readiness`
or `make production-readiness`. It emits JSON and exits 2 when production quality
evidence is missing. Current result: **not ready** — 201 posting rules are legacy
exceptions, no posting rule has qualifying holdout evidence, and remediation has
no configured independent review signature verifier. Passing unit tests or
`make bench-rule-quality` does not change that decision. `make quality-report`
only writes the report and must not be used as a shipping gate.

The [exact quality criterion and path audit](../benchmarks/rule-quality/README.md)
covers rule admission, runtime filtering, fix publication, image release, and all
Cloud Run/Firebase production workflows. This check covers analysis and remediation
quality; the operational, trust, and distribution items below remain separate work.

## Live rollout blockers (read-only inspection, 2026-10-20)

- The GCP project has the legacy `codesentry-database-url`, but not
  `codesentry-database-runtime-url` or `codesentry-internal-secret`; the current API
  revision still mounts the legacy database credential and a plain internal value.
- The repository has no protected `production` or `staging` GitHub Environment matching
  the workflows. Create them, scope their variables, and require production approval.
- The Cloud Run Job sandbox Terraform and its IAM/private-egress controls have not been
  applied and proven by the new signed live-release smoke.
- Strict AI readiness exits 2: 201 rules are frozen legacy, 14 are quarantined, zero
  have qualifying holdout evidence, and remediation lacks an approved cryptographic
  external-review verifier and independently reviewed release corpus.

Until those owner actions and evidence checks pass, use the staging compatibility path.
Do not weaken the production gate to make a deployment green.

## 1. Correctness on unfamiliar input

| Item | Bar | State | Evidence |
| --- | --- | --- | --- |
| Tolerant scanning | A parse warning or per-file timeout records a limitation and keeps every other result. Only configuration errors fail closed, with details in the log. | in progress | PR 437: warnings and per-file timeouts become limitations; reproduced on nebullii/test-only#135 where one lexical error had discarded 97 results. |
| File caps degrade, not fail | A pull request over the 200-file cap is reviewed up to the cap with a limitation line, not failed. | in progress | PR 442. |
| One finding per vulnerable line | Findings from both analysis tiers cluster; one suggestion per line. | in progress | PR 429. |
| Unsupported families are skipped, not fatal | A finding outside the supported families never blocks fixes for the others. | done | Residual report lists skipped findings. |
| Real-repository validation | Analysis and remediation replayed over recent pull requests of at least ten public repositories (JavaScript and Python, monorepos, vendored and generated code, non-UTF-8 content) with every crash, timeout, and limitation triaged. | in progress | PR 440: 165 merged pull requests from 11 repositories, four robustness bugs fixed; 29 of 30 sampled tier 1 findings were false positives. PR 447: 171 labelled vulnerabilities in 23 repositories; precision of posted findings 0.97 with PR 441, recall 0.40. PR 449: recall 0.58, XSS 26 of 32. |
| Rule publication policy | New, changed, and re-enabled rules require at least 100 reviewed holdout predictions, no unresolved judgments, and a 95% Wilson lower precision bound of at least 0.95. | in progress | Gate and runtime admission implemented; 201 frozen legacy exceptions remain unvalidated and 14 rules are quarantined. Production readiness stays false until posting rules have qualifying evidence. |
| Tier 2 coverage | Rules for the OWASP classes across JavaScript, TypeScript, Python, and template languages, written in-house after the public rule libraries were found to forbid use in a paid service. | in progress | PR 445: 25 to 116 rules; PR 449: template files and XSS. |
| Evaluation corpus | At least 40 authored fixtures across the five families, both languages, with negatives and adversarial cases, run on every change. | in progress | PR 446: 42 fixtures; PR 448: 44, all passing under both adapters with an empty known-failures list. |

## 2. Trust

| Item | Bar | State | Evidence |
| --- | --- | --- | --- |
| Isolated verification | Every published fix is verified in a fresh, network-denied container, with the level stated in the comment. | in progress | PR 438: Cloud Run Job driver with network probes and an isolated_job level; the smoke test decides whether Cloud Run permits the user namespace it depends on. |
| No write access to code | The GitHub App requests no `contents: write`. Fixes are applied through GitHub's own suggestion button under the developer's identity. | in progress | PR 442: apply commit path and merge controller removed; grep shows no createCommitOnBranch, no git/refs, no contents PUT, no merge call. Owner sets Contents to read-only after merge. |
| Uninstall deletes data | `installation.deleted` purges findings, runs, jobs, and evidence for that installation within 24 hours. | in progress | PR 442: purge across 25 tables 24 hours after installation.deleted, integration-tested against Postgres under row-level security. |
| Outcome record | Every published fix, apply, dismissal, suppression, thread resolution, re-analysis result, and residual is recorded append-only with a reason. | in progress | PR 436. |
| Three product numbers | Apply rate, dismiss rate, residual rate per installation and per rule, on the dashboard and in Prometheus. | in progress | PR 436: hourly roll-up, GET /api/reports/quality, three gauges, dashboard tiles. |
| Security page states facts only | Every claim on mitig8it.com/security is sourced from code or docs. | done | PR 428. |
| Secrets handling | Model key rotated; secret paths excluded from model context; keys stripped from logs. | in progress | Rotation is an owner action. |

## 3. Operations

| Item | Bar | State | Evidence |
| --- | --- | --- | --- |
| First review latency | Under 20 seconds after a pull request opens during working hours. | open | Deliberately deferred. Production now deploys cold (`api_min_instances: '0'`), because the target was never demonstrated and a warm instance bills whether or not anybody uses it. The start-up warm-up from PR 444 remains. Re-open this when there are hosted users: the mechanism is one value in `deploy-production.yml`, and the number still has to be measured rather than assumed. |
| Metrics reach a dashboard | Request, queue, analysis, and remediation metrics visible in Grafana. | in progress | PR 444: Managed Prometheus sidecar scraping a loopback listener; ten product metrics. |
| One alert that matters | Page when reviews fail or stall for 15 minutes. | in progress | PR 444: reviews failing and reviews stalled, as Grafana rules and Cloud Monitoring policies; eleven unfirable rules deleted. |
| Structured logs with correlation | Every log line carries the delivery id or analysis run id across the three services. | in progress | PR 444: delivery, run, and job ids over headers, gRPC metadata, and the queue in all three services. |
| Staging environment | Same workflows deploy a staging set of services from a branch before main. | in progress | PR 444: environment input on every deploy workflow and a staging branch workflow; owner one-time steps in docs/deployment/staging.md. |
| Database backup and restore drill | Restore to a point in time exercised once and documented. | open | |
| Runbooks exercised | Each runbook under docs/runbooks run end to end once by someone other than the author. | open | |
| Row-level security enforced | Runtime database role without BYPASSRLS. | operator rollout pending | Production startup/deploy verification, separate runtime credential, and real-login integration tests cover all 12 forced-RLS tables. [Runtime-role runbook](runbooks/runtime-database-role.md); live cutover remains unverified. |

## 4. Distribution

| Item | Bar | State | Evidence |
| --- | --- | --- | --- |
| Public dogfood | The App reviews every pull request on aicodesentry/mitig8it. | in progress | The Action branch adds a self-review workflow on this repository. |
| Public sandbox | Anyone can open a pull request against a public repository and watch the review land without installing anything. | open | |
| GitHub Action | `uses: mitig8it/review` with the workflow's own token, no App install. | in progress | Branch feat/github-action-mode: container action with the workflow token, nothing leaves the runner. |
| Marketplace listing | Listed with the verified creator badge. | open | Owner action. |
| Free for public repositories | Stated on the site and enforced in billing. | open | |

## Order of work

1. Tolerant scanning and file caps.
2. Outcome record and the three numbers.
3. Isolated verification.
4. Real-repository validation, then the corpus.
5. Remove write access, uninstall purge.
6. Latency, metrics, alert, staging.
7. Dogfood, sandbox, Action, Marketplace.
