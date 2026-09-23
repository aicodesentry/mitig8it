# Deployment Guide

Production deployment is driven by GitHub Actions. The deploy workflows run after the `CI` workflow succeeds on `main`, or manually through `workflow_dispatch`.

## Targets

| Component | Target | Workflow |
|---|---|---|
| Frontend | Firebase Hosting | `.github/workflows/deploy-frontend-firebase.yml` |
| API service | Cloud Run `codesentry-api` | `.github/workflows/deploy-api-cloudrun.yml` |
| GitHub service | Cloud Run `codesentry-github` | `.github/workflows/deploy-github-cloudrun.yml` |
| Analysis service | Cloud Run `codesentry-analysis` | `.github/workflows/deploy-analysis-cloudrun.yml` |
| Remediation service | Cloud Run `codesentry-remediation` | `.github/workflows/deploy-remediation-cloudrun.yml` |

Backend images are pushed to Google Artifact Registry. Runtime secrets are injected from GCP Secret Manager and GitHub Actions secrets.

The remediation workflow is the one exception to the CI gate: it triggers on a push to `main` touching `services/remediation-service/**` or the workflow file, plus `workflow_dispatch`. It deploys a single service in the single-instance development mode and grants no IAM; `roles/run.invoker` for the API runtime service account must be granted out of band.

## Release Flow

1. A push lands on `main`.
2. `CI` runs security scans, tests, audits, and Docker builds.
3. Each deploy workflow starts only if `CI` succeeded.
4. Each workflow path-filters changes and skips if its component did not change.
5. Backend workflows authenticate to Google Cloud with Workload Identity Federation.
6. Backend workflows build and push service images to Artifact Registry.
7. The API workflow runs database migrations from the release image.
8. Cloud Run or Firebase Hosting is deployed.
9. Each workflow verifies the deployed service or public frontend URL.

Each Cloud Run workflow has its own `cloudrun-deploy-${{ github.workflow }}` concurrency group with `cancel-in-progress: false`, so repeat deploys for the same component are serialized.

## Required GitHub Repository Variables

Shared Google Cloud variables:

- `GCP_WORKLOAD_IDENTITY_PROVIDER`
- `GCP_SERVICE_ACCOUNT_EMAIL`
- `GCP_PROJECT_ID`
- `GCP_REGION`
- `GAR_REPOSITORY`

Application URL variables:

- `CODESENTRY_FRONTEND_URL`
- `CODESENTRY_GH_SERVICE_URL`
- `CODESENTRY_ANALYSIS_URL`

Frontend variables:

- `FIREBASE_PROJECT_ID`

## Required GitHub Repository Secrets

- `FIREBASE_TOKEN`
- `CODESENTRY_INTERNAL_SECRET`
- `CODESENTRY_WEBHOOK_SECRET`

`CODESENTRY_INTERNAL_SECRET` is deployed as:

- `GITHUB_SERVICE_INTERNAL_SECRET` on the API and GitHub service.
- `ANALYSIS_SERVICE_INTERNAL_SECRET` on the analysis service.

## Required GCP Secret Manager Secrets

API service:

- `codesentry-jwt-secret`
- `codesentry-encryption-key`
- `codesentry-database-url`
- `codesentry-github-app-id`
- `codesentry-github-app-private-key`
- `codesentry-webhook-secret`
- `codesentry-github-client-id`
- `codesentry-github-client-secret`

GitHub service:

- `codesentry-database-url`
- `codesentry-github-app-id`
- `codesentry-github-app-private-key`

Analysis service:

- `codesentry-gemini-api-key`

Remediation service, the four repair secrets:

- `codesentry-remediation-internal-secret`
- `codesentry-repair-llm-base-url`
- `codesentry-repair-llm-api-key`
- `codesentry-repair-llm-model`

`codesentry-remediation-internal-secret` is also attached to the API service as `REMEDIATION_SERVICE_INTERNAL_SECRET`, because both ends must hold the same value. The three `REPAIR_LLM_*` secrets belong only to the repair service.

The API deploy workflow also reads `codesentry-database-url` before deployment so it can run `npm run db:migrate` from the release image.

## Cloud Run Runtime Env

API service deploys with:

- `NODE_ENV=production`
- `FRONTEND_URL=${CODESENTRY_FRONTEND_URL}`
- `GITHUB_SERVICE_URL=${CODESENTRY_GH_SERVICE_URL}`
- `ANALYSIS_SERVICE_URL=${CODESENTRY_ANALYSIS_URL}`
- `GITHUB_CALLBACK_URL=${CODESENTRY_FRONTEND_URL}/auth/github/callback`
- `GITHUB_APP_SLUG=mitig8it`
- `GITHUB_SERVICE_INTERNAL_SECRET=${CODESENTRY_INTERNAL_SECRET}`

GitHub service deploys with:

- `NODE_ENV=production`
- `FRONTEND_URL=${CODESENTRY_FRONTEND_URL}`
- `GITHUB_SERVICE_INTERNAL_SECRET=${CODESENTRY_INTERNAL_SECRET}`
- `WEBHOOK_SECRET=${CODESENTRY_WEBHOOK_SECRET}`

Analysis service deploys with:

- `FRONTEND_URL=${CODESENTRY_FRONTEND_URL}`
- `ANALYSIS_SERVICE_INTERNAL_SECRET=${CODESENTRY_INTERNAL_SECRET}`

Remediation service deploys in single-instance development mode with `--max-instances 1`, `--min-instances 0`, `--concurrency 1`, `--memory 1Gi`, `--cpu 1`, `--timeout 900`, `--port 8002`, `--no-allow-unauthenticated`, and:

- `REMEDIATION_EXECUTION_BACKEND=local`
- `REMEDIATION_LOCAL_STATE_DIR=/tmp/remediation`
- `REMEDIATION_WORKER_INPROCESS=true`
- `REMEDIATION_WORKER_POLL_SECONDS=2`
- `SANDBOX_BROKER_MODE=inprocess`
- `SANDBOX_DRIVER=local`
- `SANDBOX_LOCAL_WORKSPACE_ROOT=/tmp/sandbox`
- `SANDBOX_NETWORK_POLICY_ATTESTED=false`
- `SANDBOX_NODE_LIMITS_ATTESTED=false`
- `OTEL_SERVICE_NAME=remediation-service`

There is no separate worker Deployment and no separate broker in this mode; the durable worker runs as an asyncio task in the same process and the broker is in-process over the local subprocess driver. No `OTEL_EXPORTER_OTLP_ENDPOINT` is set, so tracing is inert. The execution store is a per-instance SQLite file under `/tmp` and does not survive a revision or an instance replacement. Every result carries `development_unverified`, which the API presents only when `REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION=true`.

The remediation feature flags (`REMEDIATION_ENABLED`, `REMEDIATION_GENERATE_ENABLED`, `REMEDIATION_PUBLISH_ENABLED`, `REMEDIATION_APPLY_ENABLED`, `REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION`, `REMEDIATION_SERVICE_URL`, `REMEDIATION_SERVICE_AUDIENCE`) are set on the API service out of band, not by any workflow. The full list is in [the remediation runbook](../runbooks/remediation.md).

## Database Migrations

The API deployment is responsible for production database migrations:

```text
docker run --rm \
  -e DATABASE_URL="$DATABASE_URL" \
  -e NODE_ENV=production \
  "$IMAGE" \
  npm run db:migrate
```

Do not rely on service startup to mutate production schema. Keep schema changes in the API migration path and verify them before deployment.

## Path Filters

Deploy workflows skip unchanged components:

- API deploys for changes under `services/api-service/`, `proto/`, or its workflow file.
- GitHub service deploys for changes under `services/github-service/`, `proto/`, or its workflow file.
- Analysis service deploys for changes under `services/analysis-service/`, `proto/`, or its workflow file.
- Frontend deploys for changes under `frontend/`, `firebase.json`, or its workflow file.

Manual `workflow_dispatch` bypasses these filters and deploys the selected component.

## Smoke Checks

- API: Cloud Run service URL + `/health`
- GitHub service: Cloud Run gRPC startup/liveness probes plus service URL verification
- Analysis service: Cloud Run gRPC startup/liveness probes plus service URL verification
- Frontend: `CODESENTRY_FRONTEND_URL` when configured

## Analysis Queue Wakeup

The API uses a DB-backed analysis queue. Because the API service can scale to zero, configure Cloud Scheduler to periodically wake the queue worker through the authenticated internal tick endpoint:

```bash
API_URL="$(gcloud run services describe codesentry-api \
  --project "$GCP_PROJECT_ID" \
  --region "$GCP_REGION" \
  --format='value(status.url)')"

gcloud scheduler jobs create http mitig8it-analysis-queue-tick \
  --project "$GCP_PROJECT_ID" \
  --location "$GCP_REGION" \
  --schedule="* * * * *" \
  --uri="${API_URL}/internal/analysis-queue/tick" \
  --http-method=POST \
  --headers="x-internal-secret=${CODESENTRY_INTERNAL_SECRET}"
```

The endpoint returns current queue stats and requires `x-internal-secret`. Keep the scheduler secret aligned with `GITHUB_SERVICE_INTERNAL_SECRET` on the API service.

## Operational Notes

- Keep Cloud Run service URLs aligned with the GitHub App callback and webhook configuration.
- Keep `CODESENTRY_INTERNAL_SECRET` consistent across API, GitHub service, and analysis service.
- Metrics endpoints require `x-internal-secret` in production, but nothing scrapes them. `infrastructure/prometheus/prometheus.yml` targets Docker Compose hostnames only, and the Grafana Agent config under `infrastructure/grafana-agent/` is referenced by no workflow and no compose service. There is no metrics collection and no trace export in the deployment today.
- Every Cloud Run service scales to zero. No deploy workflow passes `--no-cpu-throttling` or a non-zero `--min-instances`, so CPU is allocated during request handling only and a cold start precedes the first request after an idle period. Cloud Scheduler wakes the analysis queue, which is what keeps queued work moving despite this.
- The API and frontend are public; GitHub, analysis, and remediation Cloud Run services use `--no-allow-unauthenticated`. The GitHub and analysis workflows grant the API runtime service account `roles/run.invoker` themselves; the remediation workflow does not, so that binding must be created out of band.
- Rotate GitHub App private keys, OAuth secrets, webhook secrets, JWT secret, encryption key, and internal service secret through GitHub/GCP secret stores, not code.
