# Environment Variables Setup

Mitig8it uses a single root `.env` file for local development. `docker-compose.yml` passes that file to every service with `env_file: [.env]`, then overrides Docker-specific hostnames and ports in each service `environment:` block.

The product is Mitig8it, but several variable names still use the `CODESENTRY` or `GITHUB_SERVICE` namespace because that is what the current code and deployment workflows expect.

## Quick Start

```bash
./scripts/setup-local-dev.sh
./scripts/validate-env.sh
docker-compose up --build
```

`setup-local-dev.sh` copies `.env.example` to `.env` when needed and generates local values for:

- `JWT_SECRET`
- `ENCRYPTION_KEY`
- `GITHUB_WEBHOOK_SECRET`
- `GITHUB_SERVICE_INTERNAL_SECRET`

You still need real GitHub OAuth/App credentials for the full webhook and dashboard flow.

## Required For Full Local Flow

| Variable | Used by | Description |
|---|---|---|
| `DATABASE_URL` | API, GitHub service | PostgreSQL connection string for standalone runs; Compose overrides it to use `postgres:5432`. |
| `JWT_SECRET` | API | Signs dashboard session JWTs and OAuth state. |
| `ENCRYPTION_KEY` | API | 64 hex characters; encrypts stored GitHub OAuth tokens. |
| `GITHUB_CLIENT_ID` | API | GitHub OAuth App client ID. |
| `GITHUB_CLIENT_SECRET` | API | GitHub OAuth App client secret. |
| `GITHUB_CALLBACK_URL` | API | OAuth callback. Local default: `http://localhost:3000/auth/github/callback`. |
| `GITHUB_APP_ID` | API, GitHub service | GitHub App ID. |
| `GITHUB_APP_PRIVATE_KEY` | API, GitHub service | GitHub App PEM private key. Newlines should be escaped as `\n` in `.env`. |
| `GITHUB_APP_SLUG` | API | GitHub App slug. Current local default in `.env.example`: `mitig8it`. |
| `GITHUB_WEBHOOK_SECRET` | API, GitHub service | Webhook HMAC secret. Compose aliases this to `WEBHOOK_SECRET` for the GitHub service. |
| `GITHUB_SERVICE_INTERNAL_SECRET` | API, GitHub service, analysis service | Shared internal auth secret for service-to-service calls and production metrics. |
| `FRONTEND_URL` | API, GitHub service, analysis service | CORS and redirect origin. Local default: `http://localhost:5173`. |
| `VITE_API_URL` | Frontend | API base URL used by the Vite build. Local default: `http://localhost:3000`. |

`./scripts/validate-env.sh` checks the required full-flow variables above.

## Optional Variables

| Variable | Used by | Description |
|---|---|---|
| `METRICS_AUTH_TOKEN` | API, GitHub service | Dedicated production token for `/metrics`; falls back to `GITHUB_SERVICE_INTERNAL_SECRET`. |
| `ANALYSIS_SERVICE_INTERNAL_SECRET` | Analysis service | Dedicated analysis auth token; falls back to `GITHUB_SERVICE_INTERNAL_SECRET`. |
| `ANALYSIS_SERVICE_URL` | API | Analysis service base URL. Compose overrides this to `http://analysis-service:8001`. |
| `GITHUB_SERVICE_URL` | API | GitHub service base URL. Compose overrides this to `http://github-service:3002`. |
| `LLM_PROVIDER` | Analysis service | Optional Tier 3 provider selector. Supported values: `openai`, `gemini`, `openai_compatible`. |
| `LLM_MODEL` / `LLM_TRIAGE_MODEL` | Analysis service | Optional Tier 3 model name. Defaults to `gemini-2.5-flash-lite` for `gemini` and `gpt-4o-mini` otherwise. |
| `LLM_API_KEY` | Analysis service | Generic Tier 3 LLM API key. Preferred for production Secret Manager wiring. |
| `LLM_BASE_URL` | Analysis service | Required only for `openai_compatible` providers. |
| `GEMINI_API_KEY` / `OPENAI_API_KEY` | Analysis service | Provider-specific fallback keys for local development. |
| `ANALYSIS_CACHE_TTL_DAYS` | Analysis service | Cache retention setting used by analysis cache helpers. |
| `REDIS_URL` | Analysis service | Reserved for cache-backed analysis behavior; the current local Compose stack does not start Redis. |
| `EMAIL_USER` | GitHub service | Optional SMTP user for email notifications. |
| `EMAIL_PASSWORD` | GitHub service | Optional SMTP password. |
| `EMAIL_SERVICE` | GitHub service | Optional SMTP provider, default `gmail`. |
| `EMAIL_FROM_NAME` | GitHub service | Display name for outbound email. |
| `WEBHOOK_URL` | GitHub service / local ops | Public URL for local webhook testing, usually an ngrok URL. |
| `FIREBASE_HOSTING_URL` | API | Additional allowed frontend origin. |

## Compose Overrides

The root `.env` should use localhost-friendly values for standalone development:

```env
DATABASE_URL=postgresql://dev:devpass123@localhost:5432/codesentry
ANALYSIS_SERVICE_URL=http://localhost:8001
GITHUB_SERVICE_URL=http://localhost:3002
VITE_API_URL=http://localhost:3000
```

Compose overrides the service-to-service values inside Docker:

- API `DATABASE_URL` -> `postgres:5432`
- API `ANALYSIS_SERVICE_URL` -> `http://analysis-service:8001`
- API `GITHUB_SERVICE_URL` -> `http://github-service:3002`
- GitHub service `DATABASE_URL` -> `postgres:5432`
- GitHub service `WEBHOOK_SECRET` -> `GITHUB_WEBHOOK_SECRET`

## Standalone Service Notes

Node services load both their local environment and the root `.env`:

- `services/api-service/src/index.js`
- `services/github-service/src/index.js`

For the Python analysis service, export the root env values manually when running outside Docker:

```bash
set -a
source .env
set +a
cd services/analysis-service
uvicorn src.main:app --reload --port 8001
```

## Remediation Variables

Remediation has its own variable set, which is not needed for analysis. The API service reads the feature flags, the repair service URL, audience, internal secret, sandbox image digest, token prices, and policy JSON; the repair service reads its execution backend, sandbox driver, worker mode, and the three `REPAIR_LLM_*` provider settings; the broker reads its token and attestation settings. Compose supplies development defaults for all of them and leaves `REMEDIATION_ENABLED` false.

The authoritative list, with the values used by the single-instance development deployment, is in [the remediation runbook](../runbooks/remediation.md). The capability rules, including why `auto_generate` requires generation and publication together, are in the [README](../../README.md).

## Production

Production values are injected by GitHub Actions and Cloud Run:

- GitHub Actions repository variables provide project IDs, region, frontend/API URLs, and service account metadata.
- GitHub Actions secrets provide deploy-time tokens such as `FIREBASE_TOKEN`, `CODESENTRY_INTERNAL_SECRET`, and `CODESENTRY_WEBHOOK_SECRET`.
- GCP Secret Manager provides runtime secrets such as `codesentry-database-url`, `codesentry-jwt-secret`, GitHub App credentials, `codesentry-gemini-api-key`, and the four repair secrets `codesentry-remediation-internal-secret`, `codesentry-repair-llm-base-url`, `codesentry-repair-llm-api-key`, and `codesentry-repair-llm-model`.
- The remediation feature flags themselves are set on the API service out of band, not by any workflow.

See [cloud-run-firebase.md](../deployment/cloud-run-firebase.md).

## Troubleshooting

| Problem | Fix |
|---|---|
| `Missing required env vars` | Run `./scripts/validate-env.sh` and replace placeholders in `.env`. |
| API cannot reach Postgres in Docker | Use `docker-compose up --build`; Compose injects the container hostname automatically. |
| API cannot reach Postgres standalone | Make sure `DATABASE_URL` uses `localhost:5432` and Postgres is running. |
| GitHub service exits on missing `WEBHOOK_SECRET` | Set `GITHUB_WEBHOOK_SECRET`; Compose and `src/index.js` alias it to `WEBHOOK_SECRET`. |
| Analysis calls return `401` | Ensure `x-internal-secret` matches `ANALYSIS_SERVICE_INTERNAL_SECRET` or `GITHUB_SERVICE_INTERNAL_SECRET`. |
| Metrics return `401` in production | Send `x-internal-secret: $METRICS_AUTH_TOKEN` or `x-internal-secret: $GITHUB_SERVICE_INTERNAL_SECRET`. |
| OAuth callback fails | Confirm `GITHUB_CALLBACK_URL` matches the GitHub OAuth App callback URL. |
| Webhooks are not received locally | Set your GitHub App webhook URL to a public tunnel that forwards to `http://localhost:3000/webhooks/github`. |
