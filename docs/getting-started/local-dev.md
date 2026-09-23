# Local Development

This repository is optimized for Docker Compose local development with a single root `.env` file.

## Prerequisites

- Docker Desktop or another Docker engine with Compose support.
- Node.js 20 for standalone frontend/API/GitHub service work.
- Python 3.11 for standalone analysis-service work.
- GitHub OAuth App and GitHub App credentials for end-to-end auth/webhook flows.

## Bootstrap

```bash
./scripts/setup-local-dev.sh
./scripts/install-git-hooks.sh
./scripts/validate-env.sh
docker-compose up --build
```

`setup-local-dev.sh` creates `.env` from `.env.example` if needed and fills local-only secrets. You must still add real GitHub credentials before the full OAuth/App flow works.

## Local URLs

| Component | URL |
|---|---|
| Frontend | `http://localhost:5173` |
| API service | `http://localhost:3000` |
| API health | `http://localhost:3000/health` |
| Prometheus | `http://localhost:9090` |

In Compose, `github-service` and `analysis-service` are exposed only to the Docker network:

- `http://github-service:3002`
- `http://analysis-service:8001`

Run those services standalone or add temporary port mappings if you need direct browser/curl access from the host.

## Compose Stack

`docker-compose.yml` starts eleven services:

- `postgres` from `postgres:15-alpine`, initialized by `infrastructure/docker/postgres/init.sql`.
- `api-service` on host port `3000`.
- `api-worker`, the same image running `node src/workers/index.js`, with `REMEDIATION_WORKER_ENABLED=true`.
- `github-service` on Docker port `3002`.
- `analysis-service` on Docker port `8001`.
- `remediation-service` on host port `8002`.
- `remediation-worker`, the same image running `python -m src.worker`.
- `sandbox-broker` on host port `8003`.
- `otel-collector` on `4317` and `4318`, configured by `infrastructure/remediation/otel/collector-dev.yaml`.
- `frontend` on host port `5173`.
- `prometheus` on host port `9090`.

The API waits for Postgres health and starts after the GitHub and analysis containers are started. The API service bootstraps schema locally via `ensureDatabaseSchema()`.

`docker compose up --build` with no service list starts all of them. To work on analysis only, name the services you need. The remediation services are useful on their own:

```bash
docker compose build remediation-service remediation-worker sandbox-broker
docker compose up api-service api-worker remediation-service remediation-worker sandbox-broker otel-collector
```

Compose leaves `REMEDIATION_ENABLED` false, so every remediation capability is off until a developer opts in, and `REPAIR_LLM_BASE_URL`, `REPAIR_LLM_API_KEY`, and `REPAIR_LLM_MODEL` are empty by default, so the repair loop abstains rather than calling a model. Both sandbox attestation gates are false and must stay false: nothing this stack reports can justify setting either to true. See [the remediation runbook](../runbooks/remediation.md) for the rest.

## Common Commands

```bash
# Start or rebuild the full stack
docker-compose up --build

# Stop containers
docker-compose down

# Stop containers and remove DB/Prometheus volumes
docker-compose down -v

# Validate required root env vars
./scripts/validate-env.sh

# Check app/service health helpers
./scripts/health-check.sh
./scripts/monitor-services.sh

# Run local happy-path smoke script
./scripts/e2e-happy-path.sh
```

## Standalone Services

Use standalone mode when you are iterating on one service and want faster restarts.

```bash
# Frontend
cd frontend
npm install
npm run dev

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
uvicorn src.main:app --reload --port 8001
```

The API and GitHub service load the root `.env` automatically. For analysis-service standalone runs:

```bash
set -a
source .env
set +a
cd services/analysis-service
uvicorn src.main:app --reload --port 8001
```

## Tests

```bash
# Frontend
cd frontend
npm run lint
npm test
npm run build

# API service
cd services/api-service
npm run lint
npm test

# GitHub service
cd services/github-service
npm run lint
npm test

# Analysis service
cd services/analysis-service/src
pip install -r requirements-test.txt
pytest tests -q

# Remediation service
cd services/remediation-service
pip install -r requirements-test.txt
python -m pytest tests
```

Suites that need a disposable database, a browser, or the benchmark harness:

```bash
cd services/api-service && npm run test:integration:remediation
cd services/api-service && npm run test:integration:access
cd services/api-service && npm run test:integration:lifecycle
cd services/api-service && npm run test:integration:transport
cd services/github-service && npm run test:remediation
cd frontend && npm run test:remediation-browser
python benchmarks/remediation/evaluate.py --suite seed
python -m unittest benchmarks.remediation.tests.test_evaluate
```

## Observability

Prometheus config lives in [infrastructure/prometheus/prometheus.yml](../../infrastructure/prometheus/prometheus.yml).

Local Prometheus scrapes:

- `api-service:3000/metrics`
- `github-service:3002/metrics`
- `analysis-service:8001/metrics`

Those three targets are Docker Compose hostnames. Nothing scrapes the deployed services, and no deploy workflow sets an OTLP endpoint, so metrics and traces exist locally only.

In production, metrics endpoints require `x-internal-secret`. Locally, the API and GitHub service only enforce metrics auth when `NODE_ENV=production`; the analysis service always requires internal auth for `/metrics`.

The compose `otel-collector` receives remediation traces from the API, the API worker, and the repair service over `http://otel-collector:4318`. Its development config has no upstream exporter, no tail sampling, and no persistence: it prints redacted telemetry to stdout and keeps nothing.

## Webhook Testing

For real GitHub webhook testing:

1. Start the API locally.
2. Create a public tunnel to `http://localhost:3000`.
3. Set the GitHub App webhook URL to `<public-url>/webhooks/github`.
4. Set the same secret in GitHub and `GITHUB_WEBHOOK_SECRET`.
5. Trigger installation or pull request events.

The local validation helper can create a temporary branch/PR and poll for Mitig8it feedback:

```bash
TARGET_REPO=owner/repo ./scripts/live-suggestion-validation.sh
```
