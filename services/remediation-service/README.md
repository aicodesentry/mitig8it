# Mitig8it remediation service

This service turns an authorized exact-commit JavaScript/TypeScript snapshot and confirmed SQL-injection, command-injection, or path-traversal findings into a bounded candidate. It is intentionally only a proposer: a candidate is `ready` only after a separate sandbox broker returns authenticated baseline/candidate evidence. The service has no GitHub, database, cloud, or shell tool available to the model and never executes repository code in its API process.

## Components

- `src/retrieval`: validates bounded flat snapshots, rejects path traversal/control characters/duplicates, verifies file hashes, and returns provenance-bound scoped reads/searches.
- `src/agent`: a real configurable OpenAI-compatible provider adapter and a schema-constrained loop capped by tool and candidate-attempt budgets.
- `src/grouping.py`: connected components of findings over shared file paths, so one bounded agent loop runs per group.
- `src/telemetry.py`: OpenTelemetry spans for the repair stages, with an attribute allowlist and a redaction guard.
- `src/patches.py` and `src/git_tree.py`: exact whole-file replacement validation, protected-path enforcement, immutable SHA-256 artifacts, and real Git tree OID calculation with original modes preserved.
- `src/verification`: constructs baseline/candidate verification work and accepts only authenticated, complete broker evidence.
- `src/sandbox`: HTTPS broker client, executable Kubernetes/gVisor broker driver, a development-only local subprocess driver, and the trusted materializer shared by both.
- `src/executions.py`: the durable PostgreSQL/GCS backend and a development-only SQLite/file backend with the same lease, fencing, retry, and dead-letter semantics.
- `src/fixtures.py`: converts a `benchmarks/remediation` fixture directory into a complete RepairRequest for development and evaluation runs. It fabricates revision identifiers and must never describe a real repository.

## Finding grouping and multiple candidates

One job may carry several findings. They are grouped into connected components before any agent runs: two findings are connected when they name any file in common, counting each finding's affected file and every repository path its scanner trace names. One bounded agent loop runs per group, sequentially, and each group produces at most one candidate. Grouping shared files before execution is what keeps two agents from proposing conflicting edits to the same file.

The job's tool-call, token, and USD budgets are split evenly across the groups with a per-group floor. A group whose share would fall below the floor is not launched at all: its findings are reported `unsupported` with reason `budget_exhausted`, which is attributable, instead of a half-funded loop that burns budget and abstains. The first group always runs, so a single-finding job behaves exactly as it did before grouping existed. Durable spend reservations remain job-wide, so a resumed multi-group job can never exceed the job budget.

Candidates are then combined into one tree and that union is verified again, because per-candidate evidence never covers candidate interaction. A later group whose patch changes a line range an already accepted candidate changes is reported `unsupported` with reason `overlapping_candidates` and is left out of the batch; the earlier candidates still ship. Every candidate's `finding_ids` are exactly its own group's findings, and `evidence.groups` records each group's finding IDs, state, and reason, so partial coverage is visible rather than silent.

## Telemetry

Tracing is configured only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Unset means every tracing helper is inert and nothing is exported.

```text
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318   # unset disables tracing entirely
OTEL_SERVICE_NAME=remediation-service                    # optional resource name
REMEDIATION_SERVICE_VERSION=...                          # optional resource version
```

The intake request continues the caller's W3C trace context and persists the resulting `traceparent` on the execution row. The worker starts its span with a *link* to that context rather than reparenting itself, because the intake request finished long before the worker resumed. Spans cover the `snapshot_bind`, `retrieval`, `agent_attempt`, `verification`, and `batch` stages.

Only an allowlist of attributes is exported: job id, stage, attempt, model version, prompt version, policy version, outcome, error category, token counts, and cost estimate. Everything else is dropped. A redaction guard additionally rejects any value longer than 256 characters and any value matching a secret-like pattern (bearer tokens, `sk-` keys, `ghp_`/`ghs_` GitHub tokens, private key headers). Source, prompts, completions, patches, and tool output never reach a span; detailed evidence belongs in the artifact store. Exporter setup failure is logged and downgraded to no-op tracing, never raised into the workflow.

Apply `migrations/0002_remediation_trace_context.sql` with the migration role to add the `trace_context` column.

## Run the API

Install `requirements-test.txt` for development, then:

```sh
export REMEDIATION_SERVICE_INTERNAL_SECRET='...'
export REPAIR_LLM_BASE_URL='https://api.openai.com/v1'
export REPAIR_LLM_API_KEY='...'
export REPAIR_LLM_MODEL='evaluated-model-id'
export SANDBOX_BROKER_URL='https://sandbox-broker.internal'
export SANDBOX_BROKER_TOKEN='...'
export SANDBOX_BROKER_ATTESTATION_SECRET='...'
export SANDBOX_BROKER_ATTESTATION_KEY_ID='repair-attestation-2026-09'
export REMEDIATION_DATABASE_URL='postgresql://...'
export REMEDIATION_ARTIFACT_BUCKET='...'
export REMEDIATION_ARTIFACT_KMS_KEY='projects/.../cryptoKeys/...'
uvicorn src.main:app --host 127.0.0.1 --port 8002
```

The production defaults are unchanged: `REMEDIATION_EXECUTION_BACKEND=postgres` and `SANDBOX_DRIVER=kubernetes` apply when the variables are unset.

Run `migrations/0001_remediation_executions.sql` with the migration role, and run the durable worker separately with `python -m src.worker`. Intake stores content-addressed request/result and agent-checkpoint JSON in KMS-encrypted GCS, while PostgreSQL holds workflow metadata, artifact pointers, checkpoint CAS version, and job-level token/USD accounting. The worker uses short expiring leases and heartbeats; an expired worker cannot publish a result. POST is idempotent for the same job/fencing/request digest and conflicts closed on a reused fence with different input. Before every provider request the worker atomically charges a worst-case input/output reservation. It then settles to authenticated provider usage while persisting the normalized pending tool action, and checkpoints the completed trajectory after tool execution. A crash with an ambiguous provider outcome retains the full reservation and resumes from the last completed step, so reclaim never resets the job budget.

The request `versions.repair_model` must match `REPAIR_LLM_MODEL`, preventing a silent model fallback. Provider errors never become verified results. The model API must implement OpenAI-compatible chat completions with strict function tools.

## Run the broker

Build and push `Dockerfile.runner`; configure the exact full digest-pinned reference (`registry/image@sha256:<64 hex>`, never a tag or bare digest) in both the repair policy's `sandbox_image_digest` and `SANDBOX_ALLOWED_IMAGE_DIGESTS`. Deploy `Dockerfile.broker` inside the cluster with a narrowly scoped service account able to create/get/list/delete Jobs, Pods, logs, and Secrets only in the sandbox namespace. Required settings include:

```text
SANDBOX_BROKER_TOKEN
SANDBOX_BROKER_ATTESTATION_SECRET
SANDBOX_BROKER_ATTESTATION_KEY_ID
SANDBOX_BROKER_ID
SANDBOX_K8S_NAMESPACE
SANDBOX_K8S_SERVICE_ACCOUNT=sandbox-no-access
SANDBOX_K8S_RUNTIME_CLASS=gvisor
SANDBOX_ALLOWED_IMAGE_DIGESTS=sha256:...
SANDBOX_NETWORK_POLICY_ATTESTED=true
SANDBOX_NODE_LIMITS_ATTESTED=true
```

Do not set the two attestation variables until a deployed default-deny policy and node-level process/log/ephemeral-storage limits have been exercised against fork bombs, output floods, internet, metadata, Kubernetes API, and private-network canaries. The runner pod's service account must have zero API permissions. Broker credentials and attestation keys belong only to the trusted broker/API containers and are never mounted in a workload pod.

## Development mode without cloud services

Two environment switches replace the managed dependencies for local work. Both default to the production implementation, and both log a warning when the development implementation is selected.

```text
REMEDIATION_EXECUTION_BACKEND=local|postgres   # default postgres
REMEDIATION_LOCAL_STATE_DIR=/path/to/state     # required when the backend is local
REMEDIATION_DATA_DIR=/var/lib/remediation      # accepted instead; the container's mounted data directory
SANDBOX_DRIVER=local|kubernetes                # default kubernetes
SANDBOX_LOCAL_WORKSPACE_ROOT=/path/to/scratch  # optional parent for local check workspaces
SANDBOX_BROKER_MODE=http|inprocess             # default http
REMEDIATION_WORKER_INPROCESS=true|false        # default false
```

`SANDBOX_BROKER_MODE=inprocess` replaces the HTTPS broker client with `InProcessSandboxBroker`
over `LocalSubprocessDriver`, so no separate broker service is deployed. There is then no
transport trust boundary and no attestation; the evidence still carries the driver's honest
`development_unverified` level, which a policy without `allow_development_verification` refuses.
The four `SANDBOX_BROKER_*` settings are not read in this mode.

`REMEDIATION_WORKER_INPROCESS=true` runs the durable worker loop as an asyncio task in the
FastAPI lifespan, sharing this process's execution backend with the HTTP handlers, so one
container accepts a request and drives it to a terminal state without `python -m src.worker`.
Shutdown cancels the task; the lease then expires and the usual recovery budget applies. Both
switches are development-only and each logs a warning when selected. The image carries a pinned
Node 20 LTS runtime so the local driver can run a repository's `node` checks as subprocesses.

The image creates `REMEDIATION_DATA_DIR` (default `/var/lib/remediation`) owned by uid 65532 before the volume is mounted, so a named-volume mount inherits that ownership and the service can write its SQLite database and artifacts without a manual `chown`.

`REMEDIATION_EXECUTION_BACKEND=local` stores executions in SQLite and content-addressed JSON artifacts on the local filesystem. It implements the same enqueue idempotency, lease claim, heartbeat, fenced completion, cancellation, and attempt-capped dead-lettering as the PostgreSQL backend, but it has no managed encryption, no cross-host coordination, and no retention controls.

`SANDBOX_DRIVER=local` runs each baseline and candidate check as a host subprocess in a fresh temporary directory, using the same trusted materializer and patch digest checks as the Kubernetes init container. It provides no network isolation, no kernel isolation, and no resource enforcement beyond a wall-clock timeout.

### Verification levels

Broker evidence carries an explicit `verification_level`:

- `independent_sandbox`: produced by the Kubernetes/gVisor driver. The verifier requires a matching digest-pinned runner image, `network: deny`, and a read-only root filesystem.
- `development_unverified`: produced by the local subprocess driver. The verifier accepts it only when the repair policy sets `allow_development_verification: true`, and the candidate's evidence and limitations record that the isolation guarantees were absent. The API control plane keeps this flag false in production, so development evidence can never be presented as a production verification.

Evidence with no `verification_level` is treated as `independent_sandbox` and must satisfy the full production isolation checks.

### End-to-end development run

```sh
python benchmarks/remediation/evaluate.py --suite seed --adapter engine-local
```

This runs the real engine in-process against the local backend and the local driver with a scripted provider double. It exercises intake, grouping, retrieval, patch policy, sandbox execution, evidence validation, and batch assembly, including the `multi-file-batch` fixture that produces two candidates and one combined verified batch. It measures pipeline integrity, not repair quality.

`--adapter engine` drives a deployed service over HTTP instead. It builds the same complete RepairRequest through `src/fixtures.py`, posts it to `/v1/repair`, polls `GET /v1/repair/{execution_id}` until the execution is terminal under a bounded timeout, and grades the result with the same verification-level-aware grading. It needs `REMEDIATION_SERVICE_URL` (or `--engine-url`), `REMEDIATION_SERVICE_INTERNAL_SECRET`, and `--allow-network`, and it errors with the missing variable's name otherwise. It never executes anything the service returns.

## Test

```sh
python -m pytest tests
```

The deterministic suite injects scripted provider and broker doubles; those tests prove bounds, contracts, Git identity, and fail-closed decisions, not model quality or real sandbox isolation.

## External prerequisites and accurate limitations

- The local execution backend and the local sandbox driver are development adapters. They satisfy no isolation, durability, or retention gate, and results from them are labelled `development_unverified`.
- Candidate syntax validation runs `node --check` for `.js`, `.cjs`, and `.mjs` files. TypeScript and JSX candidates and hosts without a Node toolchain record an explicit limitation instead of a silent pass.
- No real-model quality or real GKE isolation claim is made by local tests. Promotion requires the versioned repository evaluation suite and deployed attack fixtures.
- The included broker supports inline immutable-Secret payloads up to 700 KB. A production one-use encrypted object transport is still required for larger snapshots; it must not expose credentials or signed URLs to the untrusted process.
- Cluster NetworkPolicy, dedicated sandbox nodes, gVisor availability, pod/process quotas, orphan reconciliation, image build/signing, and workload identity are deployment responsibilities. `SANDBOX_NETWORK_POLICY_ATTESTED` is a gate, not proof.
- The API control plane owns durable leases, fencing, idempotency, artifact retention, spend reservations, and cancellation. This stateless service returns content-bound results but does not claim durable stage execution by itself.
- The control plane must supply a complete, non-truncated Git tree. Apply must use the returned exact `verified_tree_oid` with an expected-head write, then rerun verification/analysis on the resulting commit before merge.
- HMAC attestation needs managed secret rotation. Use asymmetric workload-identity signing if the broker crosses a trust-domain boundary.
