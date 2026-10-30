# Deployment Guide

Production deployment is driven by the manual `Deploy production` workflow. It refuses
to start unless the exact selected commit already has a successful `CI` run, then deploys
the API, internal services, an authenticated cross-service smoke, and the frontend in
that order. The component workflows remain available for deliberate manual recovery.

## Targets

| Component | Target | Workflow |
|---|---|---|
| Frontend | Firebase Hosting | `.github/workflows/deploy-frontend-firebase.yml` |
| API service | Cloud Run `codesentry-api` | `.github/workflows/deploy-api-cloudrun.yml` |
| GitHub service | Cloud Run `codesentry-github` | `.github/workflows/deploy-github-cloudrun.yml` |
| Analysis service | Cloud Run `codesentry-analysis` | `.github/workflows/deploy-analysis-cloudrun.yml` |
| Remediation service | Cloud Run `codesentry-remediation` | `.github/workflows/deploy-remediation-cloudrun.yml` |

Backend images are pushed to Google Artifact Registry. Runtime secrets are injected from
GCP Secret Manager. GitHub Actions holds deployment credentials only.

## Release Flow

1. A commit lands and `CI` runs security scans, tests, audits, and image builds.
2. An operator dispatches `Deploy production` for that exact commit.
3. The workflow verifies that commit has a successful `CI` run.
4. The API deploy runs migrations with the migration credential, provisions and verifies
   the restricted runtime role, and deploys with only the runtime credential.
5. GitHub, analysis, and remediation deploy from the same commit. Production remediation
   selects the isolated Cloud Run Job driver and must pass its signed live-release check.
6. `/internal/dependencies` proves authenticated API-to-analysis and API-to-GitHub
   application RPCs against the deployed revisions.
7. Only after all backend gates pass is the frontend deployed and smoke-tested.

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
- `GCP_SA_KEY` only when Workload Identity Federation is unavailable

Application credentials do not belong in GitHub Actions secrets.

## Required GCP Secret Manager Secrets

API service:

- `codesentry-jwt-secret`
- `codesentry-encryption-key`
- `codesentry-database-url` (migration/provisioning identity; never mounted at runtime)
- `codesentry-database-runtime-url` (restricted API runtime identity)
- `codesentry-github-app-id`
- `codesentry-github-app-private-key`
- `codesentry-webhook-secret`
- `codesentry-github-client-id`
- `codesentry-github-client-secret`
- `codesentry-internal-secret`

GitHub service:

- `codesentry-github-app-id`
- `codesentry-github-app-private-key`
- `codesentry-internal-secret`
- `codesentry-webhook-secret`

Analysis service:

- `codesentry-gemini-api-key`
- `codesentry-internal-secret`

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
- `DEPLOY_ENVIRONMENT=production` or `staging`
- `METRICS_LOOPBACK_ENABLED=true` and `METRICS_LOOPBACK_PORT=9091`
- `FRONTEND_URL=${CODESENTRY_FRONTEND_URL}`
- `GITHUB_SERVICE_URL=${CODESENTRY_GH_SERVICE_URL}`
- `ANALYSIS_SERVICE_URL=${CODESENTRY_ANALYSIS_URL}`
- `GITHUB_CALLBACK_URL=${CODESENTRY_FRONTEND_URL}/auth/github/callback`
- `GITHUB_APP_SLUG=mitig8it`
- `DATABASE_URL` from `codesentry-database-runtime-url`
- `GITHUB_SERVICE_INTERNAL_SECRET` and `ANALYSIS_SERVICE_INTERNAL_SECRET` from
  `codesentry-internal-secret`

The API is a two-container service. Alongside the application container (`app`) runs
the Google Managed Service for Prometheus sidecar (`collector`), which scrapes the
loopback metrics listener every 30 seconds. See
[runbooks/observability.md](../runbooks/observability.md) for the one-time setup the
sidecar needs and what it costs to skip it.

### Keeping the API warm

**Production deploys cold.** `deploy-production.yml` passes `api_min_instances: '0'`, so the
API scales to zero and the first request after an idle period pays a cold start. The input
default in `deploy-api-cloudrun.yml` is still `1`, so a direct `workflow_dispatch` of that
workflow gets a warm instance unless it says otherwise.

It is cold because a warm instance is the only line item here that bills whether or not anybody
uses it, and the target it buys, under 20 seconds to a first review, has never been demonstrated.
The Action runs in the caller's own runner and never reaches this service, so the cold start is
paid only by hosted App users. Set `api_min_instances: '1'` in `deploy-production.yml` when there
are hosted users whose first review is worth fifty dollars a month.

The API also warms itself at start-up: it opens the database pool with a real query and,
in parallel, pings the github and analysis services and pre-mints their Cloud Run
identity tokens. Without that, the first webhook after an idle period paid for each of
those cold starts one after another. The warm-up is not awaited and never fails
start-up; where a downstream is still cold, the orchestrator's existing retry on a
transient failure still covers it.

**What the warm instance costs.** Order of magnitude, not a quote. The API runs with
Cloud Run's default 1 vCPU and 512 MiB and deploys with `--no-cpu-throttling`, so a
minimum instance is billed for CPU and memory continuously, about 730 hours a month:

| Resource | Rate (us-central1, tier 1) | Month at 1 instance |
| --- | --- | --- |
| vCPU, always allocated | ~$0.0000180 per vCPU-second | ~$47 |
| Memory, always allocated | ~$0.0000020 per GiB-second | ~$3 |
| | | **~$50/month** |

Call it fifty dollars a month, and treat anything between forty and sixty as the same
answer, and it is what production stops paying by deploying cold. Two minimum instances double
it. Staging also deploys with `api_min_instances: 0`, so an idle staging environment adds
nothing either.

Check the current rates before budgeting: Cloud Run pricing changes, the free tier
covers part of this, and committed-use discounts apply.

GitHub service deploys with:

- `NODE_ENV=production`
- `FRONTEND_URL=${CODESENTRY_FRONTEND_URL}`
- `GITHUB_SERVICE_INTERNAL_SECRET` from `codesentry-internal-secret`
- `WEBHOOK_SECRET` from `codesentry-webhook-secret`

Analysis service deploys with:

- `FRONTEND_URL=${CODESENTRY_FRONTEND_URL}`
- `ANALYSIS_SERVICE_INTERNAL_SECRET` from `codesentry-internal-secret`

Remediation control-plane service deploys as a single instance with `--max-instances 1`,
`--min-instances 0`, `--memory 1Gi`, `--cpu 1`, `--timeout 900`, `--port 8002`, and
`--no-allow-unauthenticated`. Production releases select `SANDBOX_DRIVER=cloud_run_job`;
direct manual recovery defaults to preserving the currently deployed driver. See the
[sandbox release runbook](../runbooks/sandbox-cloud-run-job.md) for its live evidence gate.

- `REMEDIATION_EXECUTION_BACKEND=local`
- `REMEDIATION_LOCAL_STATE_DIR=/tmp/remediation`
- `REMEDIATION_WORKER_INPROCESS=true`
- `REMEDIATION_WORKER_POLL_SECONDS=2`
- `SANDBOX_BROKER_MODE=inprocess`
- `SANDBOX_DRIVER=cloud_run_job` for the ordered production release
- `SANDBOX_LOCAL_WORKSPACE_ROOT=/tmp/sandbox`
- `SANDBOX_NETWORK_POLICY_ATTESTED=false`
- `SANDBOX_NODE_LIMITS_ATTESTED=false`
- `OTEL_SERVICE_NAME=remediation-service`

There is no separate worker Deployment or broker: the durable worker runs in the service
process and the broker is in-process. The execution store remains per-instance SQLite
under `/tmp`, so control-plane durability and a separate broker trust boundary are still
known production gaps. Publication remains blocked by the quality gate until independent
repair-verification evidence is present.

The remediation feature flags (`REMEDIATION_ENABLED`, `REMEDIATION_GENERATE_ENABLED`, `REMEDIATION_PUBLISH_ENABLED`, `REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION`, `REMEDIATION_SERVICE_URL`, `REMEDIATION_SERVICE_AUDIENCE`) are set on the API service out of band, not by any workflow. The full list is in [the remediation runbook](../runbooks/remediation.md).

## Database Migrations

The API deployment uses `codesentry-database-url${SECRET_SUFFIX}` only for migrations
and role provisioning. It then verifies a separate runtime login from
`codesentry-database-runtime-url${SECRET_SUFFIX}` and mounts only that credential into
the API. The GitHub gRPC deployment does not mount a database credential.

The equivalent administrative sequence is:

```text
DATABASE_URL="$DATABASE_MIGRATION_URL" npm run db:migrate
npm run db:provision-runtime
npm run db:verify-runtime
```

Do not rely on service startup to mutate production schema. Keep schema changes in the API migration path and verify them before deployment.
Both URLs must be supplied securely to the deployment runner; `DATABASE_URL` is the
restricted login for the latter two commands. See the [runtime-role runbook](../runbooks/runtime-database-role.md)
before the first deployment: missing or elevated runtime credentials stop deployment
and production startup.

## Release scope

An ordered environment release deploys every component from one exact commit. This costs
more than path filtering, but prevents a mixed-version release across RPC contracts,
secrets, migrations, and the public frontend. Component workflows are manual escape
hatches and should be used only for reviewed recovery.

## Smoke Checks

- API: Cloud Run service URL + `/health`
- GitHub service: Cloud Run gRPC startup/liveness probes plus service URL verification
- Analysis service: Cloud Run gRPC startup/liveness probes plus service URL verification
- Internal boundary: API `/internal/dependencies` calls authenticated application-level
  health RPCs on both gRPC services and must report both `ok`
- Frontend: `CODESENTRY_FRONTEND_URL` when configured

## Analysis Queue Wakeup

The API uses a DB-backed analysis queue. Because the API service can scale to zero, configure Cloud Scheduler to periodically wake the queue worker through the authenticated internal tick endpoint:

```bash
API_URL="$(gcloud run services describe codesentry-api \
  --project "$GCP_PROJECT_ID" \
  --region "$GCP_REGION" \
  --format='value(status.url)')"

INTERNAL_SECRET="$(gcloud secrets versions access latest \
  --project "$GCP_PROJECT_ID" --secret codesentry-internal-secret)"

gcloud scheduler jobs create http mitig8it-analysis-queue-tick \
  --project "$GCP_PROJECT_ID" \
  --location "$GCP_REGION" \
  --schedule="* * * * *" \
  --uri="${API_URL}/internal/analysis-queue/tick" \
  --http-method=POST \
  --headers="x-internal-secret=${CODESENTRY_INTERNAL_SECRET}"
```

The endpoint returns current queue stats and requires `x-internal-secret`. The scheduler
must read the same Secret Manager value mounted as `GITHUB_SERVICE_INTERNAL_SECRET`.

## Operational Notes

- Keep Cloud Run service URLs aligned with the GitHub App callback and webhook configuration.
- Keep `codesentry-internal-secret` consistent across API, GitHub, analysis, the internal
  smoke, and any scheduler that calls an internal API route.
- The API's metrics are collected. A managed Prometheus sidecar in the same instance scrapes a loopback listener every 30 seconds and writes to Cloud Monitoring, where the alert policies in `infrastructure/monitoring/` read them; the public `/metrics` route still requires `x-internal-secret`. The github and analysis services are still unscraped, and there is still no trace export: no deploy workflow sets `OTEL_EXPORTER_OTLP_ENDPOINT`.
- The API keeps one instance warm by default and runs with `--no-cpu-throttling`. The github, analysis and remediation services still scale to zero, so the first call into them after an idle period pays a cold start; the API's start-up warm-up pings them so that cost is paid before the first webhook rather than during it. Cloud Scheduler still wakes the analysis queue.
- A staging environment exists in the workflows but not in the cloud. `deploy-staging.yml` deploys every service to a `-staging` name on a push to the `staging` branch; the secrets, database branch, GitHub App and Firebase site it needs are one-time owner steps in [staging.md](staging.md).
- The API and frontend are public; GitHub, analysis, and remediation Cloud Run services use `--no-allow-unauthenticated`. The GitHub and analysis workflows grant the API runtime service account `roles/run.invoker` themselves; the remediation workflow does not, so that binding must be created out of band.
- Rotate GitHub App private keys, OAuth secrets, webhook secrets, JWT secret, encryption key, and internal service secret through GitHub/GCP secret stores, not code.
