# Agentic remediation implementation ledger

Branch: `feat/agentic-remediation`
Base commit: `6b02c870a3b1196103233876c94b09cf4ee77246`
Started: 2026-09-15. Last updated: 2026-09-18.

This document records observed evidence, not intended completion. Every result below was produced on a developer workstation with mocked providers, a local subprocess sandbox, or a disposable PostgreSQL 14 database. No result here is a real model, real GKE Sandbox, staging GitHub, or production observation.

## Baseline and ownership

Existing unstaged hardening changes and untracked documents were preserved and are committed on this branch alongside the remediation work. Implementation was delegated by component (API control plane, Python repair service, GitHub adapter, frontend, infrastructure and docs, merge controller) with an orchestrator owning interface review, seam alignment, verification, and this ledger.

## Verification on 2026-09-18

All commands run from the named service directory unless stated. Disposable databases were dropped and recreated before each integration run.

| Check | Command | Result |
| --- | --- | --- |
| API unit | `npm test -- --runInBand` | 27 suites, 316 passed |
| API lint | `npm run lint` | clean |
| API access integration | `npm run test:integration:access` | 6 passed |
| API lifecycle integration | `npm run test:integration:lifecycle` | 8 passed |
| API remediation integration | `npm run test:integration:remediation` | 16 passed |
| API migrations | `npm run db:migrate` then `db:verify` then `db:migrate` on a fresh database | 0001 to 0016 applied once, verify clean, reapply applied nothing |
| GitHub adapter unit | `npm test -- --runInBand` | 6 suites, 104 passed |
| GitHub adapter remediation subset | `npm run test:remediation` | 54 passed |
| GitHub adapter lint | `npm run lint` | clean |
| Frontend unit | `npm test` | 15 files, 73 passed |
| Frontend lint and build | `npm run lint`, `npm run build` | clean, built |
| Frontend browser | `npm run test:remediation-browser` | 3 scenarios passed against the real Vite app with fixture API responses (system Chrome via `PLAYWRIGHT_CHROME_PATH`) |
| Repair service | `pytest tests -q` (Python 3.11) | 90 passed |
| Benchmark harness | `python -m unittest benchmarks.remediation.tests.test_evaluate` | 19 passed |
| Seed suite, reference oracle | `evaluate.py --suite seed` | exit 0 |
| Seed suite, real engine, local mode | `evaluate.py --suite seed --adapter engine-local` | exit 0; 7 cases, 4 verified repairs, 3 abstentions; `results_kind=pipeline_integrity`, `provider_kind=scripted-provider`, level `development_unverified` |
| Release gate | `evaluate.py --suite release` | exit 2 as expected: corpus is 7 of 120 fixtures, no review signatures, no signature trust root |
| Compose | `docker compose config`; `docker compose build` of repair service, worker, broker | valid; images built; repair service container answered `/health` 200 |
| Kubernetes | `render_kubernetes.py` with non-production values, then `kubectl kustomize` | 26 documents rendered |
| Terraform | `fmt -check`; `init -backend=false` and `validate` under Terraform 1.11.3 | clean; valid |
| Analysis service Python tests | `python -m pytest src/tests -q` (Python 3.11, native Semgrep on PATH) | 274 passed, zero skipped |

## Work package status

| ID | Status | Evidence and limits |
| --- | --- | --- |
| W00 | done | Baseline preserved, reviewed, rerun above |
| W01 | partial | Fixture schema, 7 fixtures (4 supported including one two-file batch, 2 negative, 1 adversarial), reference and engine-local adapters, release gate that refuses to pass without 120 reviewed fixtures and signatures. The plan's full corpus and adversarial operational cases do not exist |
| W02 | done | Migrations 0013 to 0016, all ten planned tables plus writer leases, forced RLS, composite tenant keys, tested by upgrade and reapply |
| W03 | done for in-process dispatch | Outbox handler registry with delivery recorded only after handler success, backoff, dead letter after 5 attempts; reconciler for leases, stuck outbox rows, ambiguous writes, quarantine, intent expiry. `REMEDIATION_DISPATCH_MODE=cloud_tasks` throws not-implemented; Terraform gates the queue behind `enable_cloud_tasks_dispatch=false` |
| W04 | partial | Node OpenTelemetry with allowlisted attributes and log injection stripping; Python tracer with allowlist, redaction guard, and span links, tested with a secret canary. Dashboards and alert rules exist; panels for metrics not yet emitted say so. No collector has been exercised against a backend |
| W05 | code complete, unproven | Real Kubernetes Job driver with gVisor, no token mount, dropped capabilities, and HMAC-attested broker evidence; local subprocess driver for development only. No isolation has been demonstrated on a real cluster; both attestation gates stay false |
| W06 | partial | Exact-commit snapshot from the GitHub adapter with blob SHA verification, tree identity re-bound in the repair service. Retrieval is literal search plus filename heuristics; no symbol parsing, ranking, or repair memory reads |
| W07 | done for the scripted path | Nine schema-validated tools, budgets, checkpoint resume, one agent per connected finding group. The OpenAI-compatible provider adapter has never been exercised against a real model in this repository |
| W08 | partial | Baseline and candidate runs, exploit-must-fail-on-baseline, patch policy with syntax and dependency checks, scanner findings regression, honest limitations, verification levels. Advisory security review (plan section 8 step 7) is not implemented |
| W09 | done | Combined tree from the union of candidate patches, overlap rejection, combined verification, immutable manifest |
| W10 | done | All public routes plus feedback; live actor authorization, branch policy, budget, writer lease, idempotency, revalidation with machine-readable rejections, checking and completed states, development verification refused unless `REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION=true`; nine GitHub adapter operations with HTTP and gRPC parity |
| W11 | done | Per-finding and PR-level panel, unified diffs, coverage sentence, stale head, blocked reasons, capability-driven buttons, merge intent states, feedback control |
| W12 | done against mocks | Merge controller with ordered live re-checks, CAS transitions, bounded attempts, reconciling settlement, app verification check publication, GitHub-side cancel. Never exercised against a real repository with branch protection |
| W13 | partial | Feedback persists observation rows in `repair_memory`; nothing promotes or reads them. Retention and deletion jobs do not exist |
| W14 | not done | No load, chaos, or security acceptance suites |
| W15 | partial | CI runs every suite above; compose runs the whole stack locally; runbook covers all listed incidents. No staging deployment, no real GitHub PR lifecycle, no restore drill |

## Live evidence on the deployed app, 2026-09-19 to 2026-09-20

Staging repository: nebullii/test-only. Deployment: Cloud Run, single instance per service, scale to zero, CPU always allocated; repair service with the local execution backend, in-process worker and sandbox, gpt-4o; every result labelled `development_unverified`.

| Observation | Evidence |
| --- | --- |
| Analysis on a multi-file PR | PR 124: check run failure "5 critical/high findings"; 19 inline comments (3 blocking, 16 informational in test code); summary reports 3 test files scanned and 33 informational findings; one scanner batch, no memory events |
| Generation | PR 124 job 8b27a35b: ready in about one minute, 6,318 input and 471 output tokens, one candidate proven by a generated regression test that fails on baseline and passes on the candidate |
| Honest partial coverage | Two findings skipped as unsupported families, three as not repaired (no reproducing test); none claimed |
| Apply | Action c002de2b completed; commit e6593394 by the app on the PR branch changing one line (parameterized SQL query); exact head and manifest bound |
| Post-apply | Fresh analysis on the applied head shows the SQL finding gone (5 open, was 6); the app's remediation verification check reports failure because blocking findings remain |
| Defects fixed on the way | Cloud Run billing and CPU throttling, metadata token retry, protobuf map serialization, GitHub identity token on HTTP and gRPC transport for remediation calls, repair service secret precedence, request contract (attempt, platform, tree entries), partial coverage, budget estimation and overage settlement, checkpoint resume, lease heartbeat, reservation leak, sandbox workspace root, per-finding proof, full-file manifests, sandbox test harness |

Not yet exercised live: merge-when-ready (flag off; the installation lacks push and pull request review event subscriptions), and coverage of more than one finding per run.

## Definition of done, honestly

Unmet items from plan section 15: a real staging PR lifecycle, real sandbox isolation evidence, evaluation against real baselines with a reviewed corpus, dashboards and alerts exercised, retention and deletion, and load testing. Everything the feature flags guard remains off by default, and the local compose stack labels its results `development_unverified`.

## External acceptance prerequisites

A disposable staging GitHub repository with branch protection and the app's verification check required, a GCP project and region with GKE Sandbox, a repair model account with pricing configuration, and a budget for real-model and sandbox evaluation. Until those exist, this branch is a complete local implementation, not a release.

Full specification: [implementation plan](agentic-remediation-implementation-plan.md).
