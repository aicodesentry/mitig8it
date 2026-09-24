# Production readiness

This is the working checklist for taking Mitig8it from a system that works on
friendly repositories to one that behaves correctly on repositories it has
never seen, and that tells its operators when it does not. Each item states
the bar, the current state, and the evidence. Items move to "done" only with a
merged pull request or a recorded live check.

States: done, in progress, open.

## 1. Correctness on unfamiliar input

| Item | Bar | State | Evidence |
| --- | --- | --- | --- |
| Tolerant scanning | A parse warning or per-file timeout records a limitation and keeps every other result. Only configuration errors fail closed, with details in the log. | in progress | PR 437: warnings and per-file timeouts become limitations; reproduced on nebullii/test-only#135 where one lexical error had discarded 97 results. |
| File caps degrade, not fail | A pull request over the 200-file cap is reviewed up to the cap with a limitation line, not failed. | in progress | PR 442. |
| One finding per vulnerable line | Findings from both analysis tiers cluster; one suggestion per line. | in progress | PR 429. |
| Unsupported families are skipped, not fatal | A finding outside the supported families never blocks fixes for the others. | done | Residual report lists skipped findings. |
| Real-repository validation | Analysis and remediation replayed over recent pull requests of at least ten public repositories (JavaScript and Python, monorepos, vendored and generated code, non-UTF-8 content) with every crash, timeout, and limitation triaged. | in progress | PR 440: 165 merged pull requests from 11 repositories, four robustness bugs fixed; 29 of 30 sampled tier 1 findings were false positives. PR 447: 171 labelled vulnerabilities in 23 repositories; precision of posted findings 0.97 with PR 441, recall 0.40. PR 449: recall 0.58, XSS 26 of 32. |
| Tier 1 posting policy | A rule posts only with measured precision; five rules with near-total false positives are quarantined with evidence, a static check catches the regex shape, comments are stripped before matching, and a labelled benchmark gates every rule change. | in progress | PR 441, confirmed independently by PR 447 (the same five rules produce 50 of 57 false positives). |
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
| First review latency | Under 20 seconds after a pull request opens during working hours. | in progress | PR 444: min-instances 1 on the API behind a workflow input, start-up warm-up. |
| Metrics reach a dashboard | Request, queue, analysis, and remediation metrics visible in Grafana. | in progress | PR 444: Managed Prometheus sidecar scraping a loopback listener; ten product metrics. |
| One alert that matters | Page when reviews fail or stall for 15 minutes. | in progress | PR 444: reviews failing and reviews stalled, as Grafana rules and Cloud Monitoring policies; eleven unfirable rules deleted. |
| Structured logs with correlation | Every log line carries the delivery id or analysis run id across the three services. | in progress | PR 444: delivery, run, and job ids over headers, gRPC metadata, and the queue in all three services. |
| Staging environment | Same workflows deploy a staging set of services from a branch before main. | in progress | PR 444: environment input on every deploy workflow and a staging branch workflow; owner one-time steps in docs/deployment/staging.md. |
| Database backup and restore drill | Restore to a point in time exercised once and documented. | open | |
| Runbooks exercised | Each runbook under docs/runbooks run end to end once by someone other than the author. | open | |
| Row-level security enforced | Runtime database role without BYPASSRLS. | open | Recorded in known debt. |

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
