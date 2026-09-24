# Mitig8it

Mitig8it is a GitHub-native security reviewer for pull requests. It receives GitHub App webhooks, analyzes the changed files of a pull request with a three-tier detection pipeline, stores findings in PostgreSQL, and posts inline comments and a check run back to GitHub. When remediation is enabled it also generates repairs for the findings it supports, verifies each one against a generated regression test that must fail on the original code and pass on the patched code, and publishes the verified fix under its finding as a GitHub suggestion block. Applying a fix and merging a pull request are human actions on GitHub: the App holds no write access to repository contents, so it cannot commit to a branch or merge a pull request.

The repository is still named `codesentry` and some environment variables, package names, metrics, and Cloud Run resources still use the CodeSentry name. Treat Mitig8it as the product name and CodeSentry as the current infrastructure and code namespace.

## Components

| Component | Path or command | Local port | Role |
| --- | --- | --- | --- |
| Frontend | `frontend/` | 5173 | React 18 and Vite dashboard: onboarding, repositories, pull request reports, findings, suppressions, remediation panel. |
| API service | `services/api-service/` | 3000 | Control plane. Auth, GitHub OAuth, webhook ingest, PostgreSQL persistence, analysis orchestration, remediation policy and job control, dashboard REST APIs, migrations. |
| API worker | `services/api-service/`, `node src/workers/index.js` | none | Control-plane polling worker: remediation job stages, outbox dispatch, reconciliation. Refuses to start without `REMEDIATION_WORKER_ENABLED=true`. |
| GitHub service | `services/github-service/` | 3002 | GitHub App adapter. Fetches changed files and repair snapshots, publishes comments, reviews, check runs, and remediation commits. Reads and writes are split: reads retry with jittered backoff, writes are sent once and an ambiguous outcome is settled by reading history. |
| Analysis service | `services/analysis-service/` | 8001 | FastAPI detection engine: regex and dependency rules, OpenGrep, optional LLM triage. |
| Remediation service | `services/remediation-service/` | 8002 | FastAPI repair service. Turns an exact-commit snapshot and confirmed findings into verified candidates. It proposes patches only and never writes to GitHub. |
| Remediation worker | `services/remediation-service/`, `python -m src.worker` | none | Durable repair job execution, leases, fencing, spend accounting. |
| Sandbox broker | `services/remediation-service/Dockerfile.broker` | 8003 | Creates one-use isolated verification jobs and returns authenticated evidence. Deployed it terminates TLS itself; the local stack runs it as plain HTTP. |
| OpenTelemetry collector | `infrastructure/remediation/otel/` | 4317, 4318 | Local collector for remediation traces. The development config has no upstream exporter and keeps nothing. |
| PostgreSQL | Compose service | 5432 | System of record. |
| Prometheus | Compose service | 9090 | Local scrape target for service metrics. |

Local wiring lives in [docker-compose.yml](docker-compose.yml). Deployment wiring lives in `.github/workflows/`.

## The Pull Request Flow

1. GitHub sends `pull_request`, `installation`, or `installation_repositories` events to `POST /webhooks/github` on the API service. The API verifies the signature with `GITHUB_WEBHOOK_SECRET` and deduplicates deliveries by `webhook_deliveries.delivery_id`.
2. The API persists repository and pull request state, creates an `analysis_runs` row, and starts orchestration. It calls the GitHub service to fetch the changed files at the queued commit SHA, and the analysis service to analyze them.
3. Findings are normalized, clustered, fingerprinted, stored in PostgreSQL, and filtered by suppressions and baseline state. Findings in test code keep their original severity in evidence but are recorded as `info` and do not fail the check run.
4. Inline comments and a check run are published through the GitHub service.
5. If the `auto_generate` capability is on, the API queues one remediation job for that head's open, non-informational findings as soon as the analysis is published. At most one automatic job exists per head, the job is bounded by the policy file limit and the installation budget, and a queue failure never delays or fails the analysis.
6. The repair service returns one candidate per finding it proved. Each verified fix is published under its own finding's inline comment: a GitHub suggestion block when the change is one contiguous region the comment can carry, otherwise the unified diff with the reason it could not be a suggestion; then a `Verified:` line stating that the regression test failed on the original code and passed with the change, then a collapsed `Details` block with the stated intent, the proof, the evidence, the limitations, and the human-in-the-loop sentence. A finding the repair service skipped gets one `No automatic fix: <reason>` line. Sections are keyed by candidate and updated in place, so a redelivery or a regeneration rewrites them rather than adding a second copy.
7. A human applies a fix with GitHub's own "Commit suggestion" button, which commits the suggestion under the developer's identity. Mitig8it cannot push to the repository: the App does not hold write access to code, and there is no in-app apply.
8. The push webhook sees the resulting commit, which GitHub co-authors to the app, and records it as an observed apply. The commit is analyzed afresh. One residual report comment per observed apply, updated in place, lists what was applied, what is still open by file and severity, and what was not repaired and why. The app's verification check is published; it is green only when no blocking finding remains in the changed files.
9. Merging is a human action on GitHub. The product cannot request a merge and the panel offers no merge button.

## Detection Pipeline

- Tier 1: deterministic regex and dependency-risk checks in `services/analysis-service/src/security_rules.py`.
- Tier 2: OpenGrep AST rules in `services/analysis-service/src/opengrep_rules/`. Files are scanned in batches bounded by `OPENGREP_BATCH_MAX_FILES` and `OPENGREP_BATCH_MAX_BYTES`; any batch failure fails the tier closed, so partial results are never returned.
- Tier 3: optional provider-agnostic LLM triage through `LLM_PROVIDER` and `LLM_API_KEY`. The Gemini default model is `gemini-2.5-flash-lite`; the OpenAI default is `gpt-4o-mini`. Triage failures are non-blocking, and every log line and error body on those paths is passed through a redaction helper that strips API keys and Authorization values.

The blocking analysis routes are synchronous handlers that FastAPI runs in its threadpool, and the combined route runs tier 1 and tier 2 concurrently with a fixed merge order, so a long scan does not block `/health` and fingerprints stay stable.

The combined production path is `POST /analyze/pr`. Tier-specific endpoints exist for focused testing: `/analyze/pr/tier1`, `/analyze/pr/tier2`, and `/analyze/pr/tier3`.

## Repairs

### Supported families by language

The repair service classifies a finding into one of five families from its CWE and rule text. Language follows the affected file's extension: `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs` are JavaScript, `.py` is Python. A group that mixes both is split by language.

| Family | JavaScript | Python |
| --- | --- | --- |
| `sql_parameterization` | yes | yes |
| `command_arguments` | yes | yes |
| `path_containment` | yes | yes |
| `hardcoded_credential` | no | yes |
| `code_injection_eval` | no | yes |

The two Python-only families are limited by the Node harness, which records no environment reads and stubs no `eval`.

For every supported finding the service first writes both halves of the repair itself, before any model call. `src/sites.py` derives the enclosing Express route or Python function or Flask view over the exact snapshot, `src/proofs.py` emits one harness regression test from that site, and `src/templates.py` attempts a deterministic hunk for the family. Template hunks are verified exactly like a model proposal and are charged zero input and output tokens. Only findings the template pass did not prove reach the model, which receives the same service-written proof.

### When the service abstains

Per-finding skips are reported in the job's `skipped` list and surface as the `No automatic fix` line on the pull request:

| Reason code | Meaning |
| --- | --- |
| `unsupported_rule_family` | The finding is outside the five families, or the family is not repaired for that language yet. |
| `rule_family_disabled` | The family is not in `REMEDIATION_ALLOWED_RULE_FAMILIES_JSON`. |
| `affected_source_missing` | The affected file is absent from the snapshot. |
| `unsupported_language` | The file extension is neither JavaScript nor Python. |
| `pg_dependency_not_proven` | A JavaScript SQL repair whose snapshot has no `package.json` declaring `pg`. |
| `shell_pipeline_unsupported` | The process call carries a pipe or `shell: true`. |
| `ambiguous_query_api` | A Python query that reaches no known driver `execute()`, so the placeholder style cannot be determined. |
| `not_repaired` | No regression test reproduced the finding, so no candidate claims it. |
| `regression_test_not_reproducing` | A test also passed on the baseline, so it proves nothing. |
| `dependent_hunk_unproven` | Every proven finding depended on a hunk owned by an unproven finding. |
| `overlapping_candidates` | A later group's patch changes a line range an accepted candidate already changes. |
| `budget_exhausted` | The group's share of the job budget falls below the per-group floor. |

A candidate never carries a hunk its evidence does not cover, so a reviewer can apply one finding's fix without the others.

### Verification levels

Broker evidence carries an explicit level, and the API refuses to present a level its policy does not permit.

| Level | Produced by | Meaning |
| --- | --- | --- |
| `independent_sandbox` | The Kubernetes and gVisor driver | The verifier required a digest-pinned runner image, denied network, and a read-only root filesystem. |
| `development_unverified` | The local subprocess driver | The checks ran as ordinary subprocesses with no network, kernel, or filesystem isolation and no resource limit beyond a wall-clock timeout. It is a pipeline integrity signal, not repair quality and not release evidence. The API accepts it only when `REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION=true`. |
| `none` | Refusals and jobs with no candidate | Nothing was verified. |

`development_unverified` is the only level this repository has produced to date. Every deployed result carries it.

### Flags

All are read on the API service, all are false unless the value is exactly `true`, and each capability additionally requires its dependencies to be configured.

| Flag | Effect |
| --- | --- |
| `REMEDIATION_ENABLED` | Global kill switch. Every capability below stays off while it is false. |
| `REMEDIATION_GENERATE_ENABLED` | Generate repair candidates. The `generate` capability also requires `REMEDIATION_SERVICE_URL`, `REMEDIATION_SERVICE_INTERNAL_SECRET`, `GITHUB_SERVICE_URL`, `GITHUB_SERVICE_INTERNAL_SECRET`, `REMEDIATION_SANDBOX_IMAGE_DIGEST`, both token price variables, and parseable checks and family JSON. Defaults to true in the local compose stack. |
| `REMEDIATION_PUBLISH_ENABLED` | Show candidates and evidence in the app, and publish each verified fix under its finding's inline review comment on GitHub. |
| `REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION` | Permit `development_unverified` candidates to be presented. Required by any stack using the local sandbox driver. |
| `REMEDIATION_DISPATCH_MODE` | `inprocess` (outbox polling) or `cloud_tasks`. The Cloud Tasks control-plane endpoints are not implemented. |
| `REMEDIATION_WORKER_ENABLED` | Guards the standalone `node src/workers/index.js` process. Set it on `api-worker`, not on `api-service`. |
| `REMEDIATION_WORKER_INPROCESS` | Runs the control-plane loop inside the API process. It is the API's own switch and does not read `REMEDIATION_WORKER_ENABLED`. |

The `auto_generate` capability, which is what queues a job automatically after an analysis, requires `REMEDIATION_ENABLED`, `REMEDIATION_GENERATE_ENABLED`, and `REMEDIATION_PUBLISH_ENABLED` together with both the repair service and GitHub write dependencies. Generation is only useful when the result can be published under the findings.

The repair service takes `REMEDIATION_EXECUTION_BACKEND=local|postgres` (default `postgres`) and the broker takes `SANDBOX_DRIVER=local|kubernetes` (default `kubernetes`). Both `local` values are development only and log a warning when selected.

`GET /api/pull-requests/:id/remediations` and `GET /api/remediations/:id` return a capability report that names, per capability, whether it is enabled and which of `global_kill_switch_off`, `feature_flag_off`, or `dependency_not_configured` is the reason it is not.

### Diagnosing a job

`GET /api/remediations/:id/evidence` returns the durable evidence for a job in any state, including a job that repaired nothing. It carries the job state, stage, head and base SHA, attempt count, reason, and the persisted `agent_trace`, `usage`, `budget_reservation`, `groups`, `verification`, and `candidates` records, with an index of what was recorded on which attempt. Nothing it returns can be applied.

## Local Development

```bash
./scripts/setup-local-dev.sh
./scripts/install-git-hooks.sh
```

Then fill in real GitHub values in `.env`: `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, and `GITHUB_WEBHOOK_SECRET` if you do not want the generated local value.

```bash
./scripts/validate-env.sh
docker compose up --build
```

Local URLs: frontend `http://localhost:5173`, API `http://localhost:3000`, Prometheus `http://localhost:9090`. The GitHub service (`github-service:3002`) and analysis service (`analysis-service:8001`) are reachable only on the Docker network; expose them manually for direct calls.

To bring up the remediation services as well:

```bash
docker compose build remediation-service remediation-worker sandbox-broker
docker compose up api-service api-worker remediation-service remediation-worker sandbox-broker otel-collector
```

The compose defaults set `REMEDIATION_GENERATE_ENABLED=true` and leave publish false, and `REMEDIATION_ENABLED` is false, so every capability stays off until a developer opts in. The stack runs without a gVisor runtime class, without NetworkPolicy, without CMEK artifact storage, and with both sandbox attestation gates false. `SANDBOX_NETWORK_POLICY_ATTESTED` and `SANDBOX_NODE_LIMITS_ATTESTED` must not be set to true based on anything it reports. Provider credentials pass through from the host environment and are unset by default, so the repair loop abstains rather than calling a model.

For standalone service runs, environment variables, and the GitHub App setup, see [docs/getting-started/](docs/getting-started/local-dev.md).

## Tests

```bash
# Frontend: lint, unit tests, build
cd frontend && npm run lint && npm test && npm run build

# API service
cd services/api-service && npm run lint && npm test

# GitHub service
cd services/github-service && npm run lint && npm test

# Analysis service (Python 3.11)
cd services/analysis-service/src && pip install -r requirements-test.txt && pytest tests -q

# Remediation service (Python 3.11)
cd services/remediation-service && pip install -r requirements-test.txt && python -m pytest tests

# Environment validation
./scripts/validate-env.sh
```

Remediation suites that need a disposable database, a browser, or the benchmark harness:

```bash
cd services/api-service && npm run test:integration:remediation   # needs a disposable _test database
cd services/api-service && npm run test:integration:access
cd services/api-service && npm run test:integration:lifecycle
cd services/github-service && npm run test:remediation
cd frontend && npm run test:remediation-browser                   # Playwright, fixtures only
python benchmarks/remediation/evaluate.py --suite seed
python -m unittest benchmarks.remediation.tests.test_evaluate
```

CI runs Gitleaks, dependency review on pull requests, npm audits, `pip-audit`, Bandit, every suite above, and Docker image builds for the backend services. A separate `remediation.yml` workflow runs the repair service tests, the offline fixture and release evaluator gate, `terraform fmt` and `validate`, and a Kustomize render. It deploys nothing.

## Deployment

Deploys run from GitHub Actions after the `CI` workflow succeeds on `main`, or manually through `workflow_dispatch`. Each workflow path-filters its component, authenticates to Google Cloud with Workload Identity Federation, and ends with a smoke check.

| Component | Target | Workflow |
| --- | --- | --- |
| Frontend | Firebase Hosting | `deploy-frontend-firebase.yml` |
| API service | Cloud Run `codesentry-api` | `deploy-api-cloudrun.yml` |
| GitHub service | Cloud Run `codesentry-github` | `deploy-github-cloudrun.yml` |
| Analysis service | Cloud Run `codesentry-analysis` | `deploy-analysis-cloudrun.yml` |
| Remediation service | Cloud Run `codesentry-remediation` | `deploy-remediation-cloudrun.yml` |

Backend images go to Google Artifact Registry. Runtime secrets come from GCP Secret Manager; the database is managed PostgreSQL supplied as `codesentry-database-url`. The API workflow runs `npm run db:migrate` from the release image before the new revision is deployed. The API and the frontend are public; the GitHub, analysis, and remediation services deploy with `--no-allow-unauthenticated` and grant the API runtime service account `roles/run.invoker`.

Every Cloud Run service scales to zero and none of the deploy workflows passes `--no-cpu-throttling` or `--min-instances` above zero, so CPU is allocated during request handling only. The remediation service is deployed with `--max-instances 1`, `--concurrency 1`, `--timeout 900`, the local execution backend, an in-process worker and sandbox, and both attestation gates false.

See [docs/deployment/cloud-run-firebase.md](docs/deployment/cloud-run-firebase.md).

### Single-instance development deployment

One Cloud Run instance per service, no separate worker and no separate broker. It exists so the feature can be enabled on a repository the operator owns, in development-verification mode. It is not a production configuration and produces no release evidence. The full variable list for the API and the repair service, the authentication layout, and the limits of the mode are in [docs/runbooks/remediation.md](docs/runbooks/remediation.md).

Its limits, in short: every result is `development_unverified`; repository checks run as ordinary subprocesses inside the repair container with no isolation; the execution store is a per-instance SQLite file on ephemeral storage that does not survive a revision or an instance replacement; and it must only be enabled on repositories whose contents the operator controls, because the repository's own commands execute inside the service container.

## Status

Production-grade today:

- Webhook ingest, signature verification, and delivery deduplication.
- The three-tier detection pipeline, finding persistence, clustering, fingerprinting, suppressions, and baseline state.
- Inline comment, review, and check run publication, including reuse of the app's own existing threads.
- Repository access derived from the intersection of the user's GitHub access and the app installation, with revocation on membership removal or suspension.
- Least privilege on GitHub: the App asks for Contents read, Pull requests read and write, Checks read and write, and Metadata read. It cannot commit to a branch or merge a pull request, and no code path exists that would.
- Explicit migrations run from the release image, with startup refusing to mutate the schema.
- The GitHub reader and writer split: reads retry with jittered backoff and honour `Retry-After`; writes are sent once and an ambiguous outcome is settled by reading authoritative history, never by writing again.

Development-grade today:

- All repair verification. `development_unverified` is the only level produced so far, on the local subprocess driver with no isolation.
- The single-instance deployment: one instance, one concurrent request, per-instance SQLite state on ephemeral storage.
- The evaluation corpus: 11 authored fixtures against the release manifest's requirement of 120 externally reviewed cases.
- Observability. Traces, metrics, and alert rules are written and redacted, but no collector endpoint, scrape target, or alert rule is wired to a backend in any deploy workflow.
- Retention, deletion, and restore procedures, which are documented but have never been exercised.

The full record of what has been observed, with each number traceable to a pull request or a run, is the ledger: [docs/architecture/agentic-remediation-progress.md](docs/architecture/agentic-remediation-progress.md). Known engineering debt that was deliberately deferred is listed in [docs/architecture/known-debt.md](docs/architecture/known-debt.md).

## Documentation

All project documentation lives under [docs/](docs/README.md):

```text
docs/
  getting-started/   local setup, environment variables, GitHub App setup
  architecture/      system overview, guardrails, limitations, remediation ledger, known debt
  deployment/        CI/CD, Cloud Run and Firebase deployment, rollout notes
  services/          frontend, API, GitHub service, analysis service
  runbooks/          remediation operations
  operations/        scripts, benchmarks, observability
  contributors/      contributor guidelines
```

Common entry points:

- [Local Development](docs/getting-started/local-dev.md)
- [Environment Setup](docs/getting-started/environment.md)
- [Architecture Overview](docs/architecture/overview.md)
- [Remediation Runbook](docs/runbooks/remediation.md)
- [CI/CD Pipeline](docs/deployment/ci-cd-pipeline.md)
- [Cloud Run and Firebase Deployment](docs/deployment/cloud-run-firebase.md)

The dated documents in the repository root (`BUG-REVIEW-2026-09-05.md`, `PRODUCT-ANALYSIS-2026-08-08.md`, `DEVELOPER-READINESS-REVIEW-2026-08-14.md`, `EXECUTION-PLAN-2026-08-17.md`, `HARDENING-HANDOFF.md`, `HARDENING-TRACKER.md`, and the `TASK-0*.md` files) are historical records of reviews and work packages as they stood on their dates. They are kept as written and are not maintained against the current code.
