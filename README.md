# Mitig8it

Mitig8it is a GitHub-native security reviewer for pull requests. It receives GitHub App webhooks, analyzes changed PR files with a three-tier detection pipeline, stores results in PostgreSQL, and posts review feedback back to GitHub.

The repository is still named `codesentry` and some environment variables, package names, metrics, and Cloud Run resources still use the CodeSentry name. Treat Mitig8it as the product name and CodeSentry as the current infrastructure/code namespace.

## Runtime Components

- `frontend/` - React 18 + Vite dashboard served locally on port `5173`.
- `services/api-service/` - Node.js/Express control plane on port `3000`; handles auth, webhooks, repository/PR/finding APIs, orchestration, and migrations.
- `services/github-service/` - Node.js/Express GitHub adapter on port `3002`; fetches PR files and posts comments/check runs through the GitHub App.
- `services/analysis-service/` - FastAPI analysis engine on port `8001`; runs regex rules, dependency checks, OpenGrep rules, and optional LLM triage.
- `services/remediation-service/` - FastAPI repair service on port `8002`; turns an exact-commit snapshot and a confirmed finding into a bounded candidate. It proposes patches only and never writes to GitHub.
- `remediation-worker` - The same image as the repair service running `python -m src.worker`; owns durable job execution, leases, and spend accounting.
- `sandbox-broker` - Sandbox broker on port `8003` (`Dockerfile.broker`); creates one-use isolated verification jobs and returns authenticated evidence. Deployed it terminates TLS itself; the local stack runs it as plain HTTP.
- `api-worker` - The api-service image running `node src/workers/index.js`; background remediation progress lives here instead of in the API request path.
- `otel-collector` - OpenTelemetry Collector for remediation traces, metrics, and logs, with source, prompts, completions, and patches stripped before export.
- `postgres` - PostgreSQL 15 system of record.
- `prometheus` - Local metrics scrape target on port `9090`.

Primary local wiring lives in [docker-compose.yml](docker-compose.yml). Production deployment wiring lives in `.github/workflows/`.

## How PR Analysis Flows

1. GitHub sends `pull_request`, `installation`, or `installation_repositories` events to `POST /webhooks/github` on the API service.
2. The API verifies the webhook signature with `GITHUB_WEBHOOK_SECRET` and deduplicates deliveries by `webhook_deliveries.delivery_id`.
3. For PR events, the API persists repository/PR state, creates an `analysis_runs` row, and starts orchestration.
4. The API calls the GitHub service with `GITHUB_SERVICE_INTERNAL_SECRET` to fetch changed files and publish GitHub feedback.
5. The API calls the analysis service with an internal secret to analyze changed files.
6. Findings are normalized, clustered, fingerprinted, stored in PostgreSQL, filtered by suppressions/baseline state, and surfaced in the dashboard.
7. High-confidence findings can be posted inline; summaries/check runs are posted through the GitHub service.

## Detection Pipeline

- Tier 1: deterministic regex and dependency-risk checks in `services/analysis-service/src/security_rules.py`.
- Tier 2: OpenGrep AST rules in `services/analysis-service/src/opengrep_rules/`.
- Tier 3: optional provider-agnostic LLM triage through `LLM_PROVIDER` + `LLM_API_KEY`; failures are non-blocking.

The combined production path is `POST /analyze/pr`. Tier-specific endpoints also exist for focused testing: `/analyze/pr/tier1`, `/analyze/pr/tier2`, and `/analyze/pr/tier3`.

## Quick Start

```bash
./scripts/setup-local-dev.sh
./scripts/install-git-hooks.sh
```

Then fill in real GitHub values in `.env`:

- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `GITHUB_APP_ID`
- `GITHUB_APP_PRIVATE_KEY`
- `GITHUB_WEBHOOK_SECRET` if you do not want the generated local value

Validate and start:

```bash
./scripts/validate-env.sh
docker-compose up --build
```

Local URLs:

- Frontend: `http://localhost:5173`
- API: `http://localhost:3000`
- GitHub service: internal Docker service on `github-service:3002`; expose manually for standalone development
- Analysis: internal Docker service on `analysis-service:8001`; expose manually for direct local calls
- Prometheus: `http://localhost:9090`

## Standalone Development

```bash
# API
cd services/api-service
npm install
npm run dev

# GitHub service
cd services/github-service
npm install
npm run dev

# Analysis service
cd services/analysis-service
pip install -r src/requirements.txt
uvicorn main:app --app-dir src --reload --port 8001

# Frontend
cd frontend
npm install
npm run dev
```

The Node services load the root `.env` automatically as a fallback. For standalone Python runs, export the needed values from the root `.env` before starting Uvicorn.

## Test and Verification

```bash
# Frontend lint, tests, and build
cd frontend
npm run lint
npm test
npm run build

# API tests
cd services/api-service
npm test

# GitHub service tests
cd services/github-service
npm test

# Analysis tests
cd services/analysis-service/src
pytest tests -q

# Environment validation
./scripts/validate-env.sh
```

CI also runs Gitleaks, dependency review on PRs, npm audits, Python `pip-audit`, Bandit, and Docker image builds for the backend services.

## Remediation

Agentic PR remediation turns a confirmed finding into a repository-aware repair, verifies it in an isolated sandbox, and presents it below the finding for an authorized developer to apply.

Status: behind feature flags and off by default. The only verification available in this repository today is `development_unverified`. Local Docker Compose results, fixture suites, and scripted-provider benchmark runs are pipeline integrity checks. They are not repair quality measurements and they are not release evidence. Promotion requires the staging gates recorded in [docs/runbooks/remediation.md](docs/runbooks/remediation.md), including an exploit and behavior check through a real GKE Sandbox runner with signed broker evidence.

Services: `remediation-service` (port 8002), `remediation-worker`, `sandbox-broker` (port 8003), `api-worker`, and `otel-collector`. Deployment definitions live in `infrastructure/remediation/`; nothing there has been applied.

Flags on the API service, all false unless set:

| Flag | Effect |
| --- | --- |
| `REMEDIATION_ENABLED` | Global kill switch. Every capability below stays off while it is false. |
| `REMEDIATION_GENERATE_ENABLED` | Generate repair candidates. Defaults to true in the local compose stack. |
| `REMEDIATION_PUBLISH_ENABLED` | Show candidates and evidence to developers. |
| `REMEDIATION_APPLY_ENABLED` | Apply a verified batch through an expected-head write. |
| `REMEDIATION_MERGE_ENABLED` | Record merge intent and merge after checks and approvals. |
| `REMEDIATION_DISPATCH_MODE` | `inprocess` (outbox polling) or `cloud_tasks`. The Cloud Tasks control-plane endpoints are not implemented. |
| `REMEDIATION_WORKER_ENABLED` | Runs the control-plane polling worker. Set on `api-worker`, not on `api-service`. |

The repair service takes `REMEDIATION_EXECUTION_BACKEND=local|postgres` and the broker takes `SANDBOX_DRIVER=local|kubernetes`. `local` is development only.

Local flow:

```bash
docker compose build remediation-service remediation-worker sandbox-broker
docker compose up api-service api-worker remediation-service remediation-worker sandbox-broker otel-collector
```

The compose stack runs without a gVisor runtime class, without NetworkPolicy, without CMEK artifact storage, and with both sandbox attestation gates false. `SANDBOX_NETWORK_POLICY_ATTESTED` and `SANDBOX_NODE_LIMITS_ATTESTED` must not be set to true based on anything it reports. Provider credentials are passed through from the host environment and are unset by default, so the repair loop abstains rather than calling a model.

Remediation tests:

```bash
cd services/api-service && npm run test:integration:remediation   # needs a disposable _test database
cd services/github-service && npm run test:remediation
cd frontend && npm run test:remediation-browser                   # Playwright, fixtures only
cd services/remediation-service && python -m pytest tests
python benchmarks/remediation/evaluate.py --suite seed
```

## Deployment

Deployments are performed by GitHub Actions after the `CI` workflow succeeds on `main`, or manually via `workflow_dispatch`.

- Frontend deploys to Firebase Hosting.
- API, GitHub service, and analysis service deploy to Cloud Run.
- Images are pushed to Google Artifact Registry.
- API migrations run from the release image before the API Cloud Run revision is deployed.
- Secrets are read from GCP Secret Manager and GitHub Actions secrets/variables.

See [cloud-run-firebase.md](docs/deployment/cloud-run-firebase.md).

## Documentation

All project documentation lives under [docs/](docs/README.md), organized by workflow:

```text
docs/
  getting-started/   local setup, environment variables, GitHub App setup
  architecture/      system overview, guardrails, known limitations
  deployment/        CI/CD, Cloud Run/Firebase deployment, rollout notes
  services/          frontend, API, GitHub service, analysis service
  operations/        scripts, benchmarks, observability
  contributors/      contributor guidelines
```

Start with the [Documentation Index](docs/README.md). Common entry points:

- [Local Development](docs/getting-started/local-dev.md)
- [Environment Setup](docs/getting-started/environment.md)
- [Architecture Overview](docs/architecture/overview.md)
- [CI/CD Pipeline](docs/deployment/ci-cd-pipeline.md)
- [Cloud Run and Firebase Deployment](docs/deployment/cloud-run-firebase.md)
