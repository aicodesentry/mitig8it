# Remediation operations runbook

## Preconditions before enabling any remediation flag

These preconditions govern a production configuration, meaning one that claims `independent_sandbox` verification. The single-instance development deployment described near the end of this runbook is the one documented exception: it runs with the flags on, the local execution backend, the local sandbox driver, both attestation gates false, and `REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION=true`, on repositories the operator owns. It produces `development_unverified` results only and is not release evidence.

For anything else, keep `REMEDIATION_ENABLED` false and do not set `SANDBOX_NETWORK_POLICY_ATTESTED=true` or `SANDBOX_NODE_LIMITS_ATTESTED=true` until all of the following have recorded staging evidence:

1. The Terraform variables point to an approved existing project/region, existing KMS key, and globally unique artifact bucket. Confirm the resulting API/worker Workload Identity emails are rendered into their Kubernetes ServiceAccounts.
2. Immutable images and narrow private CIDRs are supplied through `infrastructure/remediation/render_kubernetes.py`; the runner image digest is allowlisted by the broker.
3. The broker's `sandbox-broker` ServiceAccount can create/list/delete only its one-use Jobs and input Secrets, while a runner pod has no service-account token, no RBAC, and no network/metadata egress.
4. `SANDBOX_BROKER_URL` reaches the broker over TLS. Confirm `sandbox-broker-tls` contains `tls.crt`/`tls.key`, the certificate SAN matches the ClusterIP DNS name, and the repair image trusts its issuing CA.
5. The repair service's provider egress is reviewed and enforced by an egress gateway. The base manifests intentionally deny it.
6. An exploit and behavior check have passed through the actual GKE Sandbox runner with signed broker evidence. A local Docker result is not sufficient.

The repair API/worker persist durable request/result artifacts in CMEK-protected GCS. This does not widen runner authority: the current broker supports inline one-use Secret transfer only. A sandbox payload over 700 KB must return `unsupported`; do not work around the limit by mounting storage, passing cloud credentials, or enabling runner egress.

## Environment checklist

In the production shape, the repair service requires `REMEDIATION_SERVICE_INTERNAL_SECRET`, `REPAIR_LLM_BASE_URL`, `REPAIR_LLM_API_KEY`, `REPAIR_LLM_MODEL`, `SANDBOX_BROKER_URL`, `SANDBOX_BROKER_TOKEN`, `SANDBOX_BROKER_ATTESTATION_SECRET`, `SANDBOX_BROKER_ATTESTATION_KEY_ID`, `REMEDIATION_DATABASE_URL`, `REMEDIATION_ARTIFACT_BUCKET`, and `REMEDIATION_ARTIFACT_KMS_KEY`.

That shape is not what is deployed today. `deploy-remediation-cloudrun.yml` supplies exactly four values from Secret Manager, `codesentry-remediation-internal-secret`, `codesentry-repair-llm-base-url`, `codesentry-repair-llm-api-key`, and `codesentry-repair-llm-model`, and sets the rest as plain environment: `REMEDIATION_EXECUTION_BACKEND=local`, `REMEDIATION_LOCAL_STATE_DIR=/tmp/remediation`, `REMEDIATION_WORKER_INPROCESS=true`, `SANDBOX_BROKER_MODE=inprocess`, `SANDBOX_DRIVER=local`, and both attestation gates false. The four `SANDBOX_BROKER_*` settings are not read in that mode, and the service has no database, no artifact bucket, and no KMS key. The API service receives the same `codesentry-remediation-internal-secret`; the three `REPAIR_LLM_*` secrets are never placed on the API.

The broker requires `SANDBOX_BROKER_TOKEN`, `SANDBOX_BROKER_ATTESTATION_SECRET`, `SANDBOX_BROKER_ATTESTATION_KEY_ID`, `SANDBOX_BROKER_ID`, `SANDBOX_K8S_NAMESPACE`, `SANDBOX_K8S_SERVICE_ACCOUNT=sandbox-no-access`, `SANDBOX_K8S_RUNTIME_CLASS=gvisor`, `SANDBOX_ALLOWED_IMAGE_DIGESTS`, and initially `SANDBOX_NETWORK_POLICY_ATTESTED=false` plus `SANDBOX_NODE_LIMITS_ATTESTED=false`.

The dedicated worker is a separate `python -m src.worker` Deployment. It requires the same database/artifact settings and its own rendered Workload Identity. `REMEDIATION_WORKER_ENABLED=true` controls the control-plane polling worker only; it does not wire Cloud Tasks. API apply/merge operations additionally require the existing GitHub service URL and internal secret.

## Ambiguous GitHub write

1. Leave the action in `reconciling`; do not retry a commit or merge operation manually or by replaying the queue message.
2. Preserve the action ID, manifest digest, expected head/base, and adapter operation ID. Inspect the adapter reconciliation result and its commit marker/parent/tree evidence.
3. Record only `applied`, `not_applied`, or `unresolved` based on reconciliation. An `unresolved` result blocks the action and pages the owner; it is not permission to regenerate or reapply a patch.
4. Disable application (`REMEDIATION_ENABLED=false`) if any action appears to have bypassed exact-head/manifest checks. Preserve audit and GitHub response evidence before changing flags.

## Automatic generation and inline publication

With `REMEDIATION_GENERATE_ENABLED` and `REMEDIATION_PUBLISH_ENABLED` both on (the capabilities report shows `auto_generate.enabled: true`), the API queues one remediation job for the open, blocking findings of a pull request head right after that head's analysis is published. Rows carry `origin = 'automatic'` and a null `created_by`; a partial unique index allows one automatic job per head, whatever its state, and the queue step never fails or delays the analysis. When the job is ready, the `remediation.ready` outbox event publishes the verified fixes under the app's own inline finding comments: each section is wrapped in `<!-- mitig8it-fix:<candidate id> -->` markers and replaces earlier fix blocks in that comment, so a redelivery or a regeneration updates in place. A section is the GitHub suggestion block for the region on the finding's line, one `Verified: regression test failed on the original code and passed with this change (...)` line, and a collapsed `Details` block (the model's stated intent, the proof, the evidence, the limitations, and the human-in-the-loop sentence); nothing is written above the suggestion. A candidate's other regions of the same file (an added import, a change above the sink) each get a second inline comment on their lines when the diff shows them, marked `<!-- mitig8it-fix-extra:<fingerprint>:<n> -->` plus the same candidate marker, updated in place and removed when a regeneration no longer needs them; an import outside the diff is folded into a short note under the verified line. A fix that cannot be a suggestion at all is shown as a diff block with one line saying why. A finding the repair service skipped receives one `No automatic fix: <reason>` line.

1. To stop automatic generation only, set `REMEDIATION_PUBLISH_ENABLED=false`; manual generation from the panel keeps working. To stop both, set `REMEDIATION_GENERATE_ENABLED=false`.
2. A `remediation.ready` event that fails on the GitHub adapter backs off and dead-letters after `REMEDIATION_OUTBOX_MAX_ATTEMPTS`; a refusal (`publish_disabled`, `head_moved`, `job_not_ready`) is recorded as delivered with nothing written. `remediation_jobs.inline_fixes_head_sha` records the head the sections were written for.
3. The adapter reads the pull request head before writing and writes nothing when it moved; it edits only comments authored by the app. Applying a suggestion on GitHub is a normal human push that supersedes the job and starts a fresh analysis, exactly like any other push.
4. A re-analysis of the same head re-renders the finding comments while queuing no new job, so the API republishes the existing ready jobs' fix sections afterwards. Publication is keyed by candidate marker and therefore idempotent; a duplicated fix section means the marker changed, not that republication ran twice.
5. Generation is automatic whenever the `auto_generate` capability is on. The panel's "Generate fixes" button is the manual path and remains available while `generate` is on, whether or not `publish` is.

## Diagnosing a job

`GET /api/remediations/:id/evidence` is the first thing to read. It is authorized like the preview, it is read-only, and unlike the preview it answers in any job state, including a job that repaired nothing, which is exactly the case an operator needs to see. Nothing it returns can be applied.

It carries `job_id`, `job_state`, `stage`, `head_sha`, `base_sha`, `attempts`, `reason`, a `records[]` index of `{attempt, kind, recorded_at}`, and the persisted payloads by kind:

| Kind | What to look for |
| --- | --- |
| `groups` | Per group: the finding IDs, state, reason, and `reason_evidence`, which records whether each finding's proof came from the service or the model, whether its template was `proven`, `not_proven`, `rejected:<code>`, or `not_attempted:<reason>`, and whether each candidate's source was `template`, `model`, or `retry`. This is where a "why did nothing ship" question is answered |
| `verification` | The baseline and candidate check results, the verification level, and the evidence digest |
| `agent_trace` | The step sequence with argument digests only. A template pass appears as one `template_patch` step |
| `usage` | Input and output tokens and provider request IDs. A group the templates proved records zeros |
| `budget_reservation` | Reserved against settled spend, which is what to check after a provider outage |
| `candidates` | Per-candidate evidence, including `candidate_source` |

Payloads above 256 KB are dropped at persistence time rather than truncated, so a missing record of a kind that should exist means the payload was oversized, not that the stage did not run.

## Residual report

After an apply completes, meaning after the fresh analysis of the applied commit has finished, the API publishes one report comment per apply action and updates it in place on retry. The same text is used verbatim as the verification check summary. It states who requested the apply and in which commit, lists the applied fixes, then the remaining open findings grouped by file and ordered by severity, then the findings that were not repaired automatically with the reason for each, and ends with "Merging stays a human action on GitHub."

Informational findings in test code are listed separately and do not count toward the blocking total, and the check is green only when no blocking finding remains in the pull request's changed files.

If the report is missing, check that the action reached `completed`; `publishResidualComment` refuses with `action_not_completed` in every earlier state. The reconciler also sweeps for pending residual comments, so a transient GitHub failure resolves without intervention. If the report's remaining count disagrees with the inline finding comments on the same head, trust the inline comments and the database over the count, and record the discrepancy: one such case is on record in the ledger for test-only PR 127.

## Sandbox or verification failure

1. Treat broker transport, invalid MAC, timeout, missing dependencies, network-policy failure, or an incomplete check as `inconclusive`, never passed.
2. Set or keep both attestation gates false if a runner reaches DNS, metadata, the Kubernetes API, private networks, or the internet, or if process limits, ephemeral storage, or log rotation cannot be demonstrated. Disable generation while investigating.
3. Verify the runner uses `runtimeClassName: gvisor`, `sandbox-no-access`, no token mount, bounded `emptyDir`, and an allowlisted digest. Check the broker Job/Secret labels (`app=mitig8it-sandbox`, `execution=<digest-prefix>`) and delete only the exact orphan resources after evidence is retained.
4. Do not add a broad egress rule or Docker socket/host mount to make a fixture pass. Missing dependencies are unsupported until a reviewed, pinned runner image contains them.

## Expired worker lease

1. Stop duplicate workers first; an expired worker must not publish results or issue a GitHub mutation.
2. Inspect the job state version/fencing token, outbox status, and attempt record. Resume only through the control-plane compare-and-swap claim path.
3. Reconcile any in-flight external action before reclaiming it. A task delivery or HTTP timeout does not prove the external operation failed.
4. `mitig8it_remediation_lease_reclaims_total` is incremented by the reconciler's lease sweep. Cross-check it against the job's fencing token history in the audit log before trusting a count. A single reclaim is normal recovery, which is why `Mitig8itRemediationLeaseReclaim` now needs more than three reclaims inside thirty minutes before it fires.

## Alert rules

The rules in `infrastructure/remediation/grafana/alerts/remediation-rules.yaml` are files. Nothing in this repository provisions them, and no deploy workflow points a collector or a scrape target at a deployed service, so importing them is a manual step and the metrics they query are not being collected today.

Import them with "No data" handled as NoData or OK, never as Alerting. The `mitig8it-remediation-pending` group deliberately queries metric names that no service emits yet; the names are fixed in advance so instrumentation does not rename them later. A rule with no series must read as no data. A silent pending rule is not evidence of a healthy system, and while the counters do not exist, use the job and action tables and the audit log instead.

## Queue, scheduler, and telemetry incidents

Cloud Tasks and Scheduler definitions are staging-only until the control plane owns enqueue/dispatch/reconciliation endpoints and validates OIDC identity. If those endpoints are unavailable, keep the Terraform queue/scheduler unapplied rather than falling back to unauthenticated HTTP or an in-process timer.

For telemetry, inspect the collector's upstream endpoint and redaction processor. Missing telemetry must not crash a job, but audit persistence failure blocks mutation. Never put source, prompts, patches, tokens, or arbitrary tool output into metric labels or logs.

## Provider outage

1. Confirm the failure is upstream before changing flags: generation stage attempts fail or time out while snapshotting and retrieval succeed, and the repair service logs provider transport or HTTP status errors rather than schema or policy rejections.
2. Leave `REMEDIATION_APPLY_ENABLED` and `REMEDIATION_MERGE_ENABLED` unchanged. A provider outage does not invalidate candidates that are already verified, and disabling apply strands them.
3. Set `REMEDIATION_GENERATE_ENABLED=false` when the error rate is sustained. Queued jobs then drain into a terminal `unsupported` or `inconclusive` state instead of consuming the spend ceiling on retries.
4. Check reserved against settled spend. Every attempt charges a worst case reservation before the call, so an outage that loses responses leaves reservations that reconciliation must release. Unsettled reservations reduce the effective budget of the next job until they are cleared.
5. A provider error is never a verification result. Confirm no job moved to `ready` during the outage window, and that partially completed trajectories resumed from their last checkpoint rather than restarting with a fresh budget.
6. Restore generation only after the provider's error rate recovers and the reservation drift returns to zero.

## Database saturation

1. Identify the exhausted resource before restarting anything: connection slots, transaction age, lock waits, or disk. The connection budget is global, so service instance count multiplied by per instance pool maximum, plus migration, admin, and reconciler reserves, must stay under database capacity.
2. Reduce demand at the edge. Set `REMEDIATION_GENERATE_ENABLED=false` and lower worker replicas. Do not raise pool maximums to clear a backlog; that moves the failure from the API into the database.
3. Do not restart the worker fleet to clear stuck jobs. A worker holding an expiring lease must be allowed to expire or to release the lease through the compare and swap claim path, otherwise two workers may publish results for one job.
4. Audit persistence failure blocks mutation by design. If audit writes fail, application and merge must stay blocked even when the rest of the database recovers.
5. After recovery, confirm the outbox drains, no action is stuck in `reconciling`, and no lease is held by a worker that no longer exists.

## Queue backlog

1. Separate a backlog from a stall. A backlog has jobs progressing slowly with queue age rising; a stall has no stage transitions at all, which points to workers, leases, or the database rather than to load.
2. Check admission control inputs: queue age, provider token and rate limits, GitHub installation limits, database capacity, and sandbox capacity. Backpressure should return a queued or limited state to callers rather than allowing unbounded retries.
3. Scale the worker deployment before touching per installation concurrency. Concurrency caps of two generation jobs per installation, one active writer per pull request, and ten outstanding requests per repository exist to stop one tenant occupying the queue, and lowering fairness to clear a backlog transfers the delay to other tenants.
4. Cancel superseded work rather than letting it run. Jobs whose pull request head has moved cannot produce an appliable candidate and will be rejected at write time anyway.
5. `mitig8it_remediation_queue_age_seconds` is specified but not yet emitted. Until it exists, measure queue age from the job table rather than from dashboards.

## Revoked installation

1. Treat a revoked or suspended GitHub App installation as an immediate write stop for that installation. Queued application and merge actions must fail closed with a permission error, not retry.
2. Flags and permissions are checked at execution time, immediately before each external write. A candidate generated while the installation was authorized carries no authority once it is revoked.
3. Reconcile any in flight write before marking the action failed. A revoked token does not prove the earlier commit or merge did not land; check the remote history for the commit marker, parent, and tree.
4. Delete or expire cached snapshots, retrieval indexes, and artifacts scoped to that installation according to the retention policy. Do not retain repository content after access is withdrawn.
5. Re-enabling requires a fresh installation authorization. Do not reuse a stored token, and do not resume a job that was generated under the previous authorization; regenerate it from the current head.

## Model or prompt regression

1. Confirm the regression is the model or the prompt, not the fixture set or a policy change. Compare verified repair precision, abstention, and regression rate for the affected cohort against the previous versioned release on the same suite and manifest version.
2. Pin the last known good versions. Set `REPAIR_LLM_MODEL` to the previously evaluated model identifier, and pin the recipe, prompt, retrieval ranking, tool schema, and verification policy versions to the release that last passed the gate. The request's `versions.repair_model` must match `REPAIR_LLM_MODEL`, so a mismatch fails closed instead of silently falling back.
3. Disable the affected cohort rather than the whole feature where the regression is scoped to one rule family, model cohort, or tenant. Where scope is unclear, set `REMEDIATION_GENERATE_ENABLED=false` for the cohort and leave already verified candidates alone.
4. Do not lower an evaluation gate to restore throughput. A failing release suite blocks promotion by design.
5. Record the regression as a permanent minimized fixture where data policy permits, then require a full sealed release suite run before the new version is promoted again.
6. Candidates applied before the regression was detected are not reverted automatically. Prepare a reviewed revert patch if any applied commit is implicated, and remember that a flag cannot undo a completed merge.

## Restore reconciliation after a database restore

1. Keep every write flag off while the restore is in progress. A restored snapshot is older than the GitHub history it describes, so it cannot prove that a commit or merge did not happen.
2. Bring the database up with workers stopped. Starting workers against a restored snapshot risks replaying outbox rows whose external effect already landed.
3. Enumerate every action that was not terminal in the snapshot, plus every action created after the snapshot timestamp that the audit trail or GitHub history shows. For each one, compare the expected head, manifest digest, and adapter operation identifier against the remote branch history.
4. Record the outcome as `applied`, `not_applied`, or `unresolved`. `unresolved` blocks the action and pages the owner. It is not permission to regenerate or reapply a patch.
5. Only after every action reaches a recorded outcome, restart workers, then re-enable generation, then publication, then application, then merge, in that order.
6. Confirm fencing tokens and lease state are consistent before the first worker starts. A restored fencing token that is lower than one already observed by GitHub allows a stale writer to act.
7. `mitig8it_remediation_reconciliation_age_seconds` is specified but not yet emitted, so track reconciliation age from the action table during the drill.

## Single-instance development deployment

One Cloud Run instance per service, no separate worker and no separate broker. It exists so the
feature can be enabled on a repository the operator owns, in development-verification mode. It is
not a production configuration and produces no release evidence.

API service (`codesentry-api`):

```text
REMEDIATION_ENABLED=true
REMEDIATION_GENERATE_ENABLED=true
REMEDIATION_PUBLISH_ENABLED=true
REMEDIATION_APPLY_ENABLED=true                  # omit to leave apply off
REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION=true # required: the only level this stack produces
REMEDIATION_DISPATCH_MODE=inprocess
REMEDIATION_WORKER_INPROCESS=true               # runs the control-plane worker in the API process
REMEDIATION_SERVICE_URL=https://codesentry-remediation-....run.app
REMEDIATION_SERVICE_AUDIENCE=https://codesentry-remediation-....run.app
REMEDIATION_SERVICE_INTERNAL_SECRET=...
REMEDIATION_SANDBOX_IMAGE_DIGEST=...            # policy input; unused by the local driver
REMEDIATION_VERIFICATION_CHECKS_JSON=[...]
REMEDIATION_ALLOWED_RULE_FAMILIES_JSON=[...]
REMEDIATION_INPUT_USD_PER_MILLION_TOKENS=...
REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS=...
REMEDIATION_POLICY_VERSION=...                  # optional
REMEDIATION_WORKER_POLL_MS=5000                 # optional, minimum 1000
REMEDIATION_RECONCILE_INTERVAL_MS=60000         # optional, minimum 1000
```

`REMEDIATION_WORKER_INPROCESS` is the API's own switch and does not read
`REMEDIATION_WORKER_ENABLED`, which still guards the standalone `node src/workers/index.js`
process. The in-process loop stops on SIGTERM with the rest of the API shutdown.

Repair service (`codesentry-remediation`):

```text
REMEDIATION_SERVICE_INTERNAL_SECRET=...         # the same value the API sends
REMEDIATION_EXECUTION_BACKEND=local
REMEDIATION_LOCAL_STATE_DIR=/tmp/remediation
REMEDIATION_WORKER_INPROCESS=true               # runs the durable worker loop in the API process
REMEDIATION_WORKER_POLL_SECONDS=2               # optional
SANDBOX_BROKER_MODE=inprocess                   # no separate broker service
SANDBOX_DRIVER=local
SANDBOX_LOCAL_WORKSPACE_ROOT=/tmp/sandbox       # optional
SANDBOX_NETWORK_POLICY_ATTESTED=false           # must stay false
SANDBOX_NODE_LIMITS_ATTESTED=false              # must stay false
REPAIR_LLM_BASE_URL=...
REPAIR_LLM_API_KEY=...
REPAIR_LLM_MODEL=...                            # must equal the request's versions.repair_model
```

`SANDBOX_BROKER_URL`, `SANDBOX_BROKER_TOKEN`, `SANDBOX_BROKER_ATTESTATION_SECRET`, and
`SANDBOX_BROKER_ATTESTATION_KEY_ID` are not read while `SANDBOX_BROKER_MODE=inprocess`. The
repair image carries a pinned Node 20 LTS runtime because the local driver runs the repository's
own checks (`node tests/verify.js`, `node --check`) as subprocesses in the service container.

Authentication: the repair service is deployed `--no-allow-unauthenticated`. When
`REMEDIATION_SERVICE_AUDIENCE` is set, the API attaches a Cloud Run identity token for that
audience as `Authorization: Bearer <id token>` and moves the shared internal secret to the
`x-internal-secret` header, which the repair service accepts as an alternative to the bearer.
With the audience unset the header layout is unchanged and the secret stays in `Authorization`.
The API's service account needs `roles/run.invoker` on the repair service.

Deploy with [.github/workflows/deploy-remediation-cloudrun.yml](../../.github/workflows/deploy-remediation-cloudrun.yml).

What a developer sees on a pull request in this mode:

| Step | What appears |
| --- | --- |
| Finding view | An amber warning on each candidate: "Verification level: development unverified. This fix was not verified in an isolated sandbox.", with the driver's limitations listed beside it. |
| Generate | Generation is automatic: a job is queued as soon as the head's analysis is published, and the verified fixes appear under the findings on GitHub. The panel's "Generate fixes" button is the manual path for a head whose automatic job did not run or failed. |
| Apply | Fixes are grouped by file and, within a file, by finding. Each finding shows its recommended fix with an "Apply this fix" button; "Apply all fixes in this file" and "Apply all N verified fixes" remain. One fix is committed on its own verification; several fixes are committed together only as the batch the repair service verified (any other combination is refused with `subset_not_verified`). Every apply is one commit against the exact reviewed head with an expected-head check, made only by explicit request. Buttons are disabled when apply is off, when the head moved, or when the consent digest no longer matches. |
| After apply | The remaining fixes of that generation are marked stale (the head moved) and shown greyed; "Regenerate remaining fixes" starts a new generation on the new head once its analysis completes. A fresh analysis runs on the applied commit, the app's verification check is published, and one residual report comment per apply (updated in place) lists what was applied and what remains open by file and severity, including findings that were not repaired and why. The check is green only when no open finding of any severity remains in the pull request's changed files; informational test-code findings are listed but do not fail it. Merging stays a human action on GitHub. |

Limits of this mode:

- Every result is `development_unverified`. It is a pipeline integrity signal, not repair quality
  and not release evidence.
- No isolation. Repository checks run as ordinary subprocesses in the repair container: no gVisor,
  no NetworkPolicy, no read-only root, no resource limits beyond a wall-clock timeout.
- One instance and one concurrent request per service. The execution store is a per-instance SQLite
  file on ephemeral storage and does not survive a revision or an instance replacement.
- Owned test repositories only. Do not enable it on a repository whose contents the operator does
  not control, because the repository's own commands execute inside the service container.

## Local development stack

`docker-compose.yml` runs the remediation services locally: `remediation-service` on 8002, `remediation-worker` running `python -m src.worker`, `sandbox-broker` on 8003, `api-worker` running `node src/workers/index.js`, and `otel-collector` configured by `infrastructure/remediation/otel/collector-dev.yaml`.

```sh
docker compose build remediation-service remediation-worker sandbox-broker
docker compose up api-service api-worker remediation-service remediation-worker sandbox-broker otel-collector
```

The compose defaults set `REMEDIATION_GENERATE_ENABLED=true` and leave publish, apply, and merge false. `REMEDIATION_ENABLED`, the global kill switch, is false by default, so every capability stays off until a developer opts in explicitly. Provider settings `REPAIR_LLM_BASE_URL`, `REPAIR_LLM_API_KEY`, and `REPAIR_LLM_MODEL` are passed through from the host environment and are unset by default.

Limitations that make this stack unsuitable as evidence:

- `REMEDIATION_EXECUTION_BACKEND=local` and `SANDBOX_DRIVER=local` mean there is no Kubernetes Job, no gVisor runtime class, no NetworkPolicy, and no node level process, storage, or log limits. Every result is `development_unverified`.
- `SANDBOX_NETWORK_POLICY_ATTESTED` and `SANDBOX_NODE_LIMITS_ATTESTED` are false and must stay false. Nothing this stack reports can justify setting either to true.
- The broker speaks plain HTTP. The deployed broker terminates TLS itself and is never reachable without it, so the local setup does not exercise the transport the deployment depends on.
- There is no CMEK artifact bucket, no Cloud Tasks transport, and no upstream telemetry backend. The collector prints redacted telemetry to stdout and keeps nothing.
- The repair service image creates `/var/lib/remediation` owned by uid 65532 at build time, so a fresh `remediation_data` named volume inherits that ownership. A bind mount from the host must be writable by uid 65532.

Promotion out of development still requires the staging evidence listed under the preconditions at the top of this runbook.
