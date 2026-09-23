# Architecture Overview

Mitig8it is a multi-service GitHub App system. The active runtime path is:

```mermaid
flowchart LR
  GitHub[GitHub App] --> API[API Service]
  UI[Frontend] --> API
  API --> DB[(PostgreSQL)]
  API --> GH[GitHub Service]
  API --> Analysis[Analysis Service]
  API --> Repair[Remediation Service]
  Repair --> Broker[Sandbox Broker]
  GH --> GitHub
  Prom[Prometheus] --> API
  Prom --> GH
  Prom --> Analysis
```

The remediation path is on by capability, not by default. The API calls the repair service with a snapshot the GitHub service fetched at an exact commit; the repair service proposes patches and never touches GitHub. Every GitHub write, including a fix a developer applies, goes through the GitHub service.

The repository still uses the `codesentry` namespace in database names, metrics, package metadata, and Cloud Run resources.

## Services

| Service | Path | Local port | Responsibility |
|---|---|---:|---|
| Frontend | `frontend/` | `5173` | React dashboard, onboarding, repositories, PR reports, findings, suppressions, account/settings pages. |
| API service | `services/api-service/` | `3000` | Auth/session, GitHub OAuth, webhook ingest, PostgreSQL persistence, analysis orchestration, dashboard REST APIs. |
| GitHub service | `services/github-service/` | `3002` inside Compose | GitHub App auth, PR changed-file fetch, summary comments, inline comments, check runs, optional notifications. |
| Analysis service | `services/analysis-service/` | `8001` inside Compose | Changed-file security analysis using regex rules, dependency checks, OpenGrep, remediation patch metadata, optional LLM triage. |
| Remediation service | `services/remediation-service/` | `8002` | Turns an exact-commit snapshot and confirmed findings into verified repair candidates. Proposes patches only. |
| Remediation worker | Same image, `python -m src.worker` | none | Durable repair job execution, leases, fencing, spend accounting. |
| Sandbox broker | `Dockerfile.broker` | `8003` | One-use isolated verification jobs returning authenticated evidence. |
| API worker | API image, `node src/workers/index.js` | none | Control-plane job stages, outbox dispatch, reconciliation. |
| OTel collector | Compose service | `4317`, `4318` | Local remediation trace sink. No upstream exporter in the development config. |
| Postgres | Compose service | `5432` | Canonical relational data store. |
| Prometheus | Compose service | `9090` | Local scrape target for service metrics. Nothing scrapes the deployed services. |

## Control Plane

`services/api-service` owns the main application state and user-facing API:

- `GET /health` validates API and Postgres health.
- `/auth/*` handles GitHub OAuth, session cookies, logout, and current-user lookup.
- `POST /webhooks/github` verifies GitHub signatures and ingests installation/repository/PR events.
- `/api/installations/*` syncs GitHub App installations and repositories.
- `/api/repositories/*` lists repositories, connects/disconnects them, requeues profiling, and toggles baseline mode.
- `/api/reports/*` exposes analysis reports and summary counts.
- `/api/findings/*`, `/api/pull-requests/:id/findings`, and `/api/suppressions/*` expose finding lifecycle and suppression APIs.
- `/api/webhooks/events` surfaces recent PR/webhook-derived events for the dashboard.
- `GET /metrics` exposes Prometheus metrics.

The API runs schema bootstrap locally on startup and production migrations through the Cloud Run deploy workflow before deployment.

## GitHub Integration Plane

`services/github-service` is the GitHub API adapter. It exposes:

- `GET /health`
- `GET /health/github-app`
- `GET /metrics`
- `POST /webhooks/github` for direct webhook testing
- `/internal/*` endpoints used by the API service for changed files, comments, and check runs

Internal routes are protected with `GITHUB_SERVICE_INTERNAL_SECRET`. The service accepts `WEBHOOK_SECRET`; local Compose maps this from the root `GITHUB_WEBHOOK_SECRET`.

## Analysis Plane

`services/analysis-service` exposes:

- `GET /health`
- `GET /metrics`
- `POST /analyze/pr`
- `POST /analyze/pr/tier1`
- `POST /analyze/pr/tier2`
- `POST /analyze/pr/tier3`

Analysis requests and metrics require `x-internal-secret`. The expected value is `ANALYSIS_SERVICE_INTERNAL_SECRET` when set, otherwise `GITHUB_SERVICE_INTERNAL_SECRET`.

The combined `/analyze/pr` route:

1. Filters OpenGrep rule fixtures. Test code is scanned; its findings are marked `in_test_code`, keep their `original_severity` in evidence, and are reported as `info` so they do not fail a check run.
2. Runs Tier 1 regex and dependency checks and Tier 2 OpenGrep rules from `src/opengrep_rules/` concurrently, merging by tier so ordering is stable. Tier 2 scans in bounded batches.
3. Runs Tier 3 LLM triage when configured.
4. Clusters findings and returns normalized finding objects.

Tier 3 failures are non-blocking. Tier 2 is not: a batch failure raises and the tier fails closed, because a partial scan that looks clean is worse than no scan.

## Remediation Plane

`services/remediation-service` turns an exact-commit snapshot and confirmed findings into candidates that carry their own verification evidence. It has no GitHub, database, cloud, or shell tool available to the model, and it never executes repository code in its API process: checks run through the sandbox broker.

The control plane in the API service owns everything durable: the job and action tables, leases and fencing, idempotency, spend reservations, the outbox, and reconciliation. It decides what may be presented and applied through the policy in `src/services/remediationPolicy.js`, and it is the only component that asks the GitHub service to write.

Capabilities are `generate`, `publish`, `apply`, `merge`, and `auto_generate`, each requiring the global kill switch, its own flag, and its real dependencies. `auto_generate` is what queues a job after an analysis; it requires generation and publication together, because generating a fix that cannot be published under its finding is not useful.

See the [README](../../README.md) for the flag table and the repair families, and the [remediation runbook](../runbooks/remediation.md) for operations.

## Data Model

PostgreSQL is the source of truth. Core tables include:

- `installations`
- `users`
- `user_installations`
- `repositories`
- `repository_access`
- `pull_requests`
- `analysis_runs`
- `findings`
- `suppressions`
- `audit_logs`
- `webhook_deliveries`

Key behaviors:

- Webhook delivery idempotency uses `webhook_deliveries.delivery_id`.
- Repository authorization is mediated through `repository_access`.
- Findings are fingerprinted for dedupe and fixed-state transitions.
- Suppressions can target a finding or fingerprint and write audit logs.
- Baseline mode is tracked on repositories and findings.

## Security Boundaries

- GitHub webhooks are HMAC-verified with `GITHUB_WEBHOOK_SECRET`.
- Dashboard auth uses an `HttpOnly` `__session` cookie signed with `JWT_SECRET`.
- Mutating dashboard requests require `X-CSRF-Protection: 1`.
- API CORS allows configured frontend origins, CodeSentry Firebase hosting URLs, and Mitig8it production domains.
- API-to-GitHub-service and API-to-analysis-service calls use shared internal secrets.
- Production metrics endpoints require `x-internal-secret`.
- GitHub OAuth tokens are encrypted with `ENCRYPTION_KEY`.

## Local Infrastructure

Primary local infrastructure is [docker-compose.yml](../../docker-compose.yml):

- `postgres:15-alpine`
- Backend service containers built from local Dockerfiles
- Frontend Vite container
- `prom/prometheus:v2.54.1`
- Named volumes for Postgres and Prometheus data
- One bridge network: `mitig8it-net`

## Production Infrastructure

Production is deployed by GitHub Actions:

- `frontend` -> Firebase Hosting
- `api-service` -> Cloud Run service `codesentry-api`
- `github-service` -> Cloud Run service `codesentry-github`
- `analysis-service` -> Cloud Run service `codesentry-analysis`
- Container images -> Google Artifact Registry
- Runtime secrets -> GCP Secret Manager
- Database -> managed PostgreSQL connection exposed through `codesentry-database-url`

See [cloud-run-firebase.md](../deployment/cloud-run-firebase.md).
