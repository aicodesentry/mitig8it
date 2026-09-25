# Roadmap

The open items only. This is derived from [docs/production-readiness.md](docs/production-readiness.md),
which holds the full list with the bar each item has to clear and the evidence behind it. Of the
23 items there, 2 are done, 16 are in progress and 5 have not been started.

An item moves off this page only with a merged pull request or a recorded live check.

## Correctness on unfamiliar input

| Item | What is left |
| --- | --- |
| Tolerant scanning | A parse warning or a per-file timeout becomes a limitation rather than a failure. Landed; not yet certified that only configuration errors fail closed. |
| File caps degrade, not fail | A pull request over the 200-file cap is reviewed to the cap with a limitation line. Landed; not yet certified. |
| One finding per vulnerable line | Cross-tier clustering to one suggestion per line. Landed; not yet confirmed complete. |
| Real-repository validation | Precision is there, recall is not: 0.58 of labelled lines, and lower again for what actually posts. The gap by class is in [docs/validation/vulnerable-corpus-2026-09.md](docs/validation/vulnerable-corpus-2026-09.md). |
| Tier 1 posting policy | Five rules producing almost all false positives are quarantined. The measured-precision gate that decides posting generally is not finished. |
| Tier 2 coverage | 25 rules to 130, all written in-house. Full OWASP-class coverage across JavaScript, TypeScript, Python and templates is not reached. |
| Evaluation corpus | 59 fixtures passing under both adapters, against a release manifest asking for 120 externally reviewed cases, 20 supported per family, 30 negatives, 30 adversarial. No family reaches 20 and there are no external review signatures. |

## Trust

| Item | What is left |
| --- | --- |
| Isolated verification | The Cloud Run Job driver and the `isolated_job` level exist. Whether Cloud Run permits the user namespace they depend on is decided by a smoke test that has not run. Until it does, every candidate is `development_unverified`. |
| No write access to code | The apply-commit path and the merge controller are removed and the greps are clean. The App's Contents permission still has to be set to read-only in the App settings, which is an owner action. |
| Uninstall deletes data | 25 tables purged 24 hours after `installation.deleted`, integration-tested against Postgres under row-level security. Not signed off. |
| Outcome record | Append-only recording of every publish, apply, dismissal, suppression, thread resolution, re-analysis and residual, each with a reason. Partly shipped. |
| Three product numbers | Apply rate, dismiss rate and residual rate per installation and per rule. The roll-up, the endpoint and the dashboard tiles exist; the per-rule breakdown is not certified. |
| Secrets handling | Blocked on an owner action: the model key rotation. |

## Operations

| Item | What is left |
| --- | --- |
| First review latency | Under 20 seconds to the first review. Min-instances and a start-up warm-up are in place behind a workflow input; the number has not been demonstrated. |
| Metrics reach a dashboard | A Managed Prometheus sidecar and ten product metrics exist. Request, queue, analysis and remediation visibility in Grafana is not confirmed. |
| One alert that matters | "Reviews failing" and "reviews stalled" rules exist in Grafana and Cloud Monitoring. The 15-minute page has not been validated. |
| Structured logs with correlation | Delivery, run and job ids propagate over headers, gRPC metadata and the queue across all three services. Not signed off. |
| Staging environment | Deploy workflows take an environment input and a staging branch workflow exists. The one-time owner steps in [docs/deployment/staging.md](docs/deployment/staging.md) remain. |
| Database backup and restore drill | Not started. A point-in-time restore has never been exercised or documented. |
| Runbooks exercised | Not started. No runbook under `docs/runbooks/` has been run end to end by someone other than its author. |
| Row-level security enforced | Not started. The runtime database role has `BYPASSRLS`, so the forced policies are defined and never enforced. A non-bypass role is needed before a second tenant. Recorded in [docs/architecture/known-debt.md](docs/architecture/known-debt.md). |

## Distribution

| Item | What is left |
| --- | --- |
| Public dogfood | The Action reviews this repository's own pull requests. The App does not yet review every pull request on `aicodesentry/mitig8it`. |
| GitHub Action | Shipped as `aicodesentry/mitig8it/action@main`. A short, stable `uses:` name is not. The defects the ten-repository trial found are open: [docs/validation/action-trial-2026-09.md](docs/validation/action-trial-2026-09.md). |
| Public sandbox | Not started. There is nowhere a stranger can open a pull request and watch a review land without installing anything. |
| Marketplace listing | Not started. Owner action. |
| Free for public repositories | Not started. Not stated on the site and not enforced in billing. |

## Order of work

The production readiness document sequences the remaining work like this:

1. Tolerant scanning and file caps.
2. The outcome record and the three numbers.
3. Isolated verification.
4. Real-repository validation, then the corpus.
5. Remove write access, uninstall purge.
6. Latency, metrics, alert, staging.
7. Dogfood, sandbox, Action, Marketplace.

Known engineering debt that was deliberately deferred is a separate list:
[docs/architecture/known-debt.md](docs/architecture/known-debt.md). Eight bounded pieces of it are
written up as starting points in
[docs/contributing/good-first-issues.md](docs/contributing/good-first-issues.md).
