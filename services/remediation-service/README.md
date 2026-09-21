# Mitig8it remediation service

This service turns an authorized exact-commit JavaScript/TypeScript or Python snapshot and confirmed SQL-injection, command-injection, path-traversal, hardcoded-credential, or eval code-injection findings into a bounded candidate. The affected file's extension selects the toolchain per finding group (`.js`, `.cjs`, `.mjs`, `.ts`, `.tsx`, `.jsx` run under Node; `.py` under Python), a group that mixes both is split by language, and the hardcoded-credential and eval families are repaired for Python only. It is intentionally only a proposer: a candidate is `ready` only after a separate sandbox broker returns authenticated baseline/candidate evidence. The service has no GitHub, database, cloud, or shell tool available to the model and never executes repository code in its API process.

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

One job may carry several findings. They are grouped into connected components before any agent runs: two findings are connected when they name any file in common, counting each finding's affected file and every repository path its scanner trace names. One bounded agent loop runs per group, sequentially, and each group produces one candidate per finding it proves. Grouping shared files before execution is what keeps two agents from proposing conflicting edits to the same file.

The job's tool-call, token, and USD budgets are split evenly across the groups with a per-group floor. A group whose share would fall below the floor is not launched at all: its findings are reported `unsupported` with reason `budget_exhausted`, which is attributable, instead of a half-funded loop that burns budget and abstains. The first group always runs, so a single-finding job behaves exactly as it did before grouping existed. Durable spend reservations remain job-wide, so a resumed multi-group job can never exceed the job budget.

A group proposal is one set of hunks plus one regression test per finding, and every hunk names the finding it fixes (`finding_id`). After the group verification, `src/splitting.py` attributes each hunk to a finding: the tagged finding, or for an untagged hunk the nearest finding on its path; an import-only hunk is a prerequisite shared by every finding whose hunks use a name it binds. Every hunk owned by an unproven finding is dropped. The engine then rebuilds one candidate per proven finding from that finding's hunks and the prerequisites they use, verifies each candidate on its own unless its tree is the tree the group run already verified, and reports a finding whose test no longer passes without the dropped hunks as `dependent_hunk_unproven` instead of shipping it. A candidate therefore never carries a hunk its evidence does not cover, and a reviewer can apply one finding's fix without the others.

Candidates are then combined into one tree and that union is verified again, because per-candidate evidence never covers candidate interaction; a prerequisite hunk two candidates share is applied once, deduplicated by content and location. A later group whose patch changes a line range an already accepted candidate changes is reported `unsupported` with reason `overlapping_candidates` and is left out of the batch; the earlier candidates still ship. Every candidate's `finding_ids` names exactly the finding its evidence covers, and `evidence.groups` records each group's finding IDs, state, reason, and `candidate_ids`, so partial coverage is visible rather than silent.

Before a proposal is accepted, every changed file passes a syntax check, a runtime load check, and a static undefined-name check. The static check parses a Python file with `ast` and rejects a name the change introduces that nothing in the file binds (a builtin, parameter, import, definition, or assignment anywhere in the file) as `undefined_name:<name>`, since such a name raises `NameError` only when its function runs. A star import or a dynamic-scope call makes the check abstain. JavaScript and TypeScript get a lexical equivalent for identifiers the change introduces in call or member position, such as `execFile(...)` added without its `require`.

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

## Service-generated proofs and template-first patches

For every supported finding the engine first tries to write both halves of the repair itself,
before any model call, and records which path produced each candidate.

- `src/sites.py` derives the enclosing site over the exact snapshot: the Express route handler
  (`router.get('/orders/:id', (req, res) => ...)`, with its method, path, request and response
  names, and every `req.params/query/body` read) or the Python function or Flask view (its
  parameters, rule, methods, and `request.args/form/json` reads).
- `src/proofs.py` emits one harness regression test per finding from that site: it invokes the
  route or function with the family's injection payload and asserts the family's contract
  through the harness recorders (query text without the payload and values carrying it; an
  `execFile`/`spawn` argument array with the payload as its own element; no read outside the
  served directory and a 4xx for a traversal payload, then a legitimate name still read; the
  secret taken from the environment with the literal gone; nothing run for an `eval` payload
  while a literal still parses). The test is generated before the model is asked and handed to
  it as `proofs` in the task message: it is always the test that runs for that finding, and a
  test the model sends for it runs beside the proof (`.model.test.<ext>`), never instead.
- `src/templates.py` attempts a deterministic hunk per family: the concatenated or template
  literal query becomes `pg` placeholders with a values array (or the Python driver's
  placeholders with bound parameters, sqlite3 `?`, psycopg `%s`, SQLAlchemy `:p1`); `exec` of a
  command string becomes `execFile(command, args)` with the callback and options kept, widening
  the `child_process` require when needed; `path.join(base, input)` becomes `path.resolve` with a
  containment check that answers 400 before any read; a secret literal becomes
  `os.environ["NAME"]` plus `import os`; `eval(x)` becomes `ast.literal_eval(x)` plus
  `import ast`; a Python `subprocess.run("..." + x, shell=True)` becomes an argv list; a Flask
  `os.path.join(base, name)` gains a realpath check that aborts 400. A template declines a shape
  it does not recognize, and refuses to bind an interpolated name that is itself a SQL fragment.
- The template hunks of a group are combined (identical hunks once, import insertions on one
  anchor merged) into one bundle with the service proofs and verified exactly like a model
  proposal. Findings it proves ship as template candidates; the rest go to the model with their
  proofs and, for a template that failed its proof, the proof's failure tail (`prior_attempts`).
- A finding still unproven after the group pass gets one focused single-finding agent run
  (`max_attempts: 2`, no revisions, a slice of the remaining budget) with the same proof and the
  failure tail of the last attempt, unless the model had deliberately abstained.

`evidence.groups[].reason_evidence` records `proofs` (`service`, or `model:<reason>` when the
site could not be derived), `templates` (`proven`, `not_proven`, `rejected:<code>`, or
`not_attempted:<reason>`), `candidate_sources` (`template`, `model`, or `retry` per proven
finding), and `retries`; each candidate's `preview.evidence.candidate_source` says the same.
The agent trace carries one `template_patch` step per template pass. Findings whose
site or shape no generator recognizes fall back to the model-written test and hunk as before.

## Generated regression tests

Most repositories ship no verification fixture, so `policy.verification_checks` is often empty.
Every candidate must instead carry an agent-generated regression test, and the engine derives
the rest of the check set from the candidate itself.

- `propose_patch` requires `regression_tests`, a list of `{finding_id, path, content}` with one
  entry per finding the patch repairs. The path must be
  `.mitig8it/regression/<name>.test.{js,cjs,mjs}` for a JavaScript group or
  `.mitig8it/regression/<name>.test.py` for a Python group, must not already exist in the
  snapshot, and is rejected outright anywhere else, so a generated test can never overwrite
  repository code. The content must parse (`node --check` or `python -m py_compile`), may
  import only the language's standard library or built-ins, repository modules, and the service
  harness, and must exercise behavior: load the changed module through the harness and invoke
  it with an injection payload. A test that requires `supertest`, `express`, `pg`, `pytest`,
  `flask`, `requests`, or a test framework is rejected as `missing_dependency`, and one that
  only reads the file as text is rejected too.
- The sandbox has nothing installed, so the service materializes a dependency-free harness at
  `.mitig8it/harness.js` next to the tests in both workspaces. `require('../harness')` gives
  `load(path, options)`, which requires the target with fake `express`, `pg`, `child_process`,
  and `fs` injected, `invoke(app, method, route, {params, query, body})`, recorders such as
  `pg.queries`, `child_process.calls`, and `fs.reads`, and `assert` helpers. It is never a patch
  or a manifest entry, and a proposal that writes to it is rejected as `harness_path_protected`.
  See [contracts/test-harness-v1.md](contracts/test-harness-v1.md).
- Python groups get `.mitig8it/harness.py` instead, a standard-library-only file that is also
  the test runner (`python3 .mitig8it/harness.py <test>`). `import harness as h` gives
  `load(path, env=..., rows=..., stubs=...)`, which executes the module with fake `flask`,
  `sqlite3`, `psycopg`, `sqlalchemy`, `subprocess`, `os.system`, a recording `os.environ`, and
  a recording `open()`; `invoke(app, method, rule, params=..., query=..., json=...)` for Flask
  views; `call(fn, ...)` for plain functions; recorders `db.queries`, `subprocess.calls`,
  `fs.reads`, `env.reads`; and assertions per family (`assert_param`, `assert_argv`,
  `assert_inside`, `assert_env_read`, `assert_not_in_source`, `assert_no_commands`). See
  [contracts/test-harness-python-v1.md](contracts/test-harness-python-v1.md).
- Python families are gated before an agent runs. A CWE-89 finding whose query reaches no
  known driver `execute()` (sqlite3, psycopg, SQLAlchemy `text()`), such as a helper named
  `execute_query`, is skipped as `ambiguous_query_api`; a process call with a pipe is skipped as
  `shell_pipeline_unsupported`. A hardcoded-credential repair moves the literal to
  `os.environ["NAME"]` and records the limitation `<path> now reads NAME from the environment;
  the deployment must provide it`; an eval repair uses `ast.literal_eval` only where a literal
  is all the code needs, otherwise the agent abstains with `eval_semantics_unknown`.
- Each file is materialized into both the baseline and the candidate workspace and executed as
  its own `exploit` check with a 60-second timeout. A finding is proven when its test fails on
  the original tree and passes on the patched one; the candidate claims exactly the proven
  findings and the rest are reported in `skipped` as `not_repaired` or
  `regression_test_not_reproducing`. Test content is untrusted repository-adjacent code and
  runs only inside the sandbox driver, exactly like any other check.
- After the syntax check, patch policy also loads every changed JavaScript or Python file from
  a temporary copy of the candidate tree (`require` under Node, `runpy.run_path` under Python
  with a module name that is not `__main__`). A module that throws on load, such as a
  `ReferenceError` or `NameError` for an identifier used without its import, is rejected as
  `candidate_load_failed`; a dependency the snapshot does not carry, or an environment variable a
  Python module reads at import time, is recorded as a limitation instead.
- Every changed `.js`, `.cjs`, and `.mjs` file also gets a `node --check` `typecheck` check, and
  every changed `.py` file a `python3 -m py_compile` one. They need no fixture and no installed
  dependency, so they are the one behavior check every repository can always run.
- With `run_repository_tests: true` and a root `package.json` `scripts.test`, the repository's
  own suite runs as an `existing_test` check on both trees. The sandbox has no network, so a
  snapshot without installed dependencies records a limitation instead of running it.
- Policy-supplied `verification_checks` still run exactly as before; the generated checks are
  additive.

A candidate with no proven finding is never `ready`: `inconclusive` with
`regression_test_not_reproducing` when a test also passed on the baseline, `failed` when every
test still failed on the patched tree. The generated tests are recorded on the candidate as
`generated_tests` and in the batch manifest, separately from the application `file_manifest`,
which carries the full final content (`contents_base64`, `blob_oid`) of every changed file plus
the `verified_tree_oid` the apply path commits against.

Set `require_generated_regression_test: false` to restore the previous behavior, in which a
non-empty policy `verification_checks` with an `exploit` and a `behavior` check is mandatory.

## External prerequisites and accurate limitations

- The local execution backend and the local sandbox driver are development adapters. They satisfy no isolation, durability, or retention gate, and results from them are labelled `development_unverified`.
- Candidate syntax validation runs `node --check` for `.js`, `.cjs`, and `.mjs` files and `python -m py_compile` for `.py` files. TypeScript and JSX candidates and hosts without a Node toolchain record an explicit limitation instead of a silent pass. A TypeScript-only patch therefore derives no generic behavior check, and without a policy-supplied one the result is `unsupported`.
- A generated regression test is model-written code. It proves that the candidate changes the behavior the test names on this exact snapshot; it is not a reviewed test suite and does not prove the repair is complete.
- No real-model quality or real GKE isolation claim is made by local tests. Promotion requires the versioned repository evaluation suite and deployed attack fixtures.
- The included broker supports inline immutable-Secret payloads up to 700 KB. A production one-use encrypted object transport is still required for larger snapshots; it must not expose credentials or signed URLs to the untrusted process.
- Cluster NetworkPolicy, dedicated sandbox nodes, gVisor availability, pod/process quotas, orphan reconciliation, image build/signing, and workload identity are deployment responsibilities. `SANDBOX_NETWORK_POLICY_ATTESTED` is a gate, not proof.
- The API control plane owns durable leases, fencing, idempotency, artifact retention, spend reservations, and cancellation. This stateless service returns content-bound results but does not claim durable stage execution by itself.
- The control plane must supply a complete, non-truncated Git tree. Apply must use the returned exact `verified_tree_oid` with an expected-head write, then rerun verification/analysis on the resulting commit before merge.
- HMAC attestation needs managed secret rotation. Use asymmetric workload-identity signing if the broker crosses a trust-domain boundary.
