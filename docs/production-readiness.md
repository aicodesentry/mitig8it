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
| Tolerant scanning | A parse warning or per-file timeout records a limitation and keeps every other result. Only configuration errors fail closed, with details in the log. | in progress | Reproduced on nebullii/test-only#135: one lexical error discarded 97 results. |
| File caps degrade, not fail | A pull request over the 200-file cap is reviewed up to the cap with a limitation line, not failed. | open | |
| One finding per vulnerable line | Findings from both analysis tiers cluster; one suggestion per line. | in progress | PR 429. |
| Unsupported families are skipped, not fatal | A finding outside the supported families never blocks fixes for the others. | done | Residual report lists skipped findings. |
| Real-repository validation | Analysis and remediation replayed over recent pull requests of at least ten public repositories (JavaScript and Python, monorepos, vendored and generated code, non-UTF-8 content) with every crash, timeout, and limitation triaged. | open | |
| Evaluation corpus | At least 40 authored fixtures across the five families, both languages, with negatives and adversarial cases, run on every change. | in progress | 11 today; branch feat/eval-corpus-40. |

## 2. Trust

| Item | Bar | State | Evidence |
| --- | --- | --- | --- |
| Isolated verification | Every published fix is verified in a fresh, network-denied container, with the level stated in the comment. | in progress | Branch feat/cloud-run-job-sandbox. |
| No write access to code | The GitHub App requests no `contents: write`. Fixes are applied through GitHub's own suggestion button under the developer's identity. | open | Requires removing the in-app apply route and the merge controller path, then changing the App permissions. |
| Uninstall deletes data | `installation.deleted` purges findings, runs, jobs, and evidence for that installation within 24 hours. | open | |
| Outcome record | Every published fix, apply, dismissal, suppression, thread resolution, re-analysis result, and residual is recorded append-only with a reason. | in progress | Branch feat/finding-outcomes-and-quality-metrics. |
| Three product numbers | Apply rate, dismiss rate, residual rate per installation and per rule, on the dashboard and in Prometheus. | in progress | Same branch. |
| Security page states facts only | Every claim on mitig8it.com/security is sourced from code or docs. | done | PR 428. |
| Secrets handling | Model key rotated; secret paths excluded from model context; keys stripped from logs. | in progress | Rotation is an owner action. |

## 3. Operations

| Item | Bar | State | Evidence |
| --- | --- | --- | --- |
| First review latency | Under 20 seconds after a pull request opens during working hours. | open | Requires a minimum instance on the API and warm dependencies. |
| Metrics reach a dashboard | Request, queue, analysis, and remediation metrics visible in Grafana. | open | Prometheus endpoint exists; nothing scrapes it on Cloud Run. |
| One alert that matters | Page when reviews fail or stall for 15 minutes. | open | Existing rules are noisy or no-data. |
| Structured logs with correlation | Every log line carries the delivery id or analysis run id across the three services. | open | |
| Staging environment | Same workflows deploy a staging set of services from a branch before main. | open | |
| Database backup and restore drill | Restore to a point in time exercised once and documented. | open | |
| Runbooks exercised | Each runbook under docs/runbooks run end to end once by someone other than the author. | open | |
| Row-level security enforced | Runtime database role without BYPASSRLS. | open | Recorded in known debt. |

## 4. Distribution

| Item | Bar | State | Evidence |
| --- | --- | --- | --- |
| Public dogfood | The App reviews every pull request on aicodesentry/mitig8it. | open | Owner installs the App on the repository. |
| Public sandbox | Anyone can open a pull request against a public repository and watch the review land without installing anything. | open | |
| GitHub Action | `uses: mitig8it/review` with the workflow's own token, no App install. | open | |
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
