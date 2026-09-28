# Centralized Security Guardrails

Mitig8it enforces guardrails as a centralized control model, not per-service ad hoc behavior.

## 1) Network and Ingress
- **Enforced.** `api-service` is the only Cloud Run service reachable without a
  Google-signed identity token. It is the one deploy that passes
  `--allow-unauthenticated`, in the `COMMON` array of the `Deploy API` step of
  `.github/workflows/deploy-api-cloudrun.yml`. The Firebase Hosting site is the other
  public surface, and its rewrites in `firebase.json` send `/auth`, `/api` and `/health`
  to that same `codesentry-api` service, so it adds no second origin.
- **Enforced, and stronger than "may be private based on environment".**
  `analysis-service` is closed on every deploy, in two independent layers.
  `.github/workflows/deploy-analysis-cloudrun.yml` deploys it
  `--no-allow-unauthenticated` and its next step, `Grant API access to Analysis gRPC
  service`, binds `roles/run.invoker` to the API runtime service account and to nothing
  else. `deploy-github-cloudrun.yml` and `deploy-remediation-cloudrun.yml` close their
  services the same way, so three of the four Cloud Run services are IAM-closed and none
  of it is conditional. The limit worth knowing: nothing restricts ingress at the network
  layer. `deploy-analysis-cloudrun.yml` passes `--ingress all` explicitly and the other
  three pass no `--ingress` flag at all, which is the same thing by default. IAM is the
  whole edge, and for `analysis-service` and `github-service` it is also the only layer,
  for the reason given in section 3.
- **Enforced.** `POST /webhooks/github` is the only webhook route a deployed environment
  exposes. `services/api-service/src/routes/webhooks.js` declares exactly one handler,
  `router.post('/github', ...)`, and `services/api-service/src/app.js` mounts it at
  `/webhooks` behind `express.raw({ type: 'application/json', limit: '10mb' })`.
  `services/github-service/src/routes/webhooks.js` declares a second receiver plus
  `/register` and `/unregister`, but `services/github-service/src/index.js` returns
  immediately after `startGrpcServer()` when `SERVICE_MODE=grpc`, which is what
  `deploy-github-cloudrun.yml` sets, so that Express app never listens in a deployed
  environment. Its `/register` handler skips its own check when the shared secret is
  unset, which is fail-open; it is development-grade and reachable only on the HTTP
  transport.

## 2) Secret Authority
- **Provisioned, and false for three secrets.** `deploy-api-cloudrun.yml` passes
  `JWT_SECRET`, `ENCRYPTION_KEY`, `DATABASE_URL`, the GitHub App id and private key,
  `GITHUB_WEBHOOK_SECRET`, the OAuth client id and secret, and
  `REMEDIATION_SERVICE_INTERNAL_SECRET` through `--set-secrets`, which are Secret Manager
  references; `deploy-remediation-cloudrun.yml` does the same for its four. Three secrets
  do not come from Secret Manager at all. `GITHUB_SERVICE_INTERNAL_SECRET` (the API and
  GitHub deploys), `ANALYSIS_SERVICE_INTERNAL_SECRET` (the analysis deploy) and
  `WEBHOOK_SECRET` (the GitHub deploy) are passed with `--update-env-vars` from the
  `CODESENTRY_INTERNAL_SECRET` and `CODESENTRY_WEBHOOK_SECRET` Actions secrets, so they
  are stored as plain environment variables on the revision and are readable by anyone who
  can describe the service. `GITHUB_WEBHOOK_SECRET` and `WEBHOOK_SECRET` are the same
  GitHub App webhook secret held under two different authorities. No code refuses a secret
  that arrived as a plain environment variable, so "must" states an intention and not a
  check.
- **Enforced for this repository, and that is all it covers.** The `Secret scan
  (Gitleaks)` job in `.github/workflows/ci.yml` runs on every pull request and push, and
  `.gitignore` excludes every `.env` shape except `.env.example`. Both act on what is
  committed here; neither can say anything about a `.env` on an operator's machine or in a
  deployed environment. `docker-compose.yml` does carry literal secrets in source
  (`devpass123`, `dev-webhook-secret`, `dev-remediation-internal-secret`), all
  development-grade defaults behind `${VAR:-default}` and none of them a production value.
- **Not implemented.** There is no rotation. No workflow, job or script rotates
  `JWT_SECRET`, `GITHUB_WEBHOOK_SECRET` or `GITHUB_SERVICE_INTERNAL_SECRET`, and nothing
  measures their age or refuses a stale one. `docs/production-readiness.md` and
  `ROADMAP.md` both record rotation as a pending owner action. Two properties make the
  absence worse than a missing cron job: `--set-secrets` pins `:latest`, which resolves
  when a revision is created, so even a rotated Secret Manager version does not reach the
  service until the next deploy; and one value, `CODESENTRY_INTERNAL_SECRET`, is the
  secret for the GitHub boundary, the analysis boundary, the API's `/internal` router and
  both `/metrics` endpoints, so rotating it is a simultaneous change to five places.

## 3) Internal Service Authentication
- **Not implemented on the deployed transport.** A deployed API does not send
  `x-internal-secret` to the GitHub service, and the GitHub service does not check it.
  `deploy-api-cloudrun.yml` sets `INTERNAL_SERVICE_TRANSPORT=grpc`, which sends
  `githubServiceRequest` in
  `services/api-service/src/services/prAnalysisOrchestrator.js` down the gRPC branch (the
  `isGrpcTransport()` test at line 127); the `x-internal-secret` header is set only in the
  HTTP fallback below it. On the receiving side
  `services/github-service/src/index.js` returns after `startGrpcServer()` in that mode,
  so `ensureInternalAuth` in `services/github-service/src/middleware/internalAuth.js`
  never runs, and `services/github-service/src/github_grpc_server.js` installs only a
  correlation-id interceptor and no auth interceptor. The analysis boundary is the same
  and more so: `services/analysis-service/Dockerfile.prod` runs
  `analysis_grpc_server.py`, which imports the `*_payload` functions straight out of
  `main.py` and therefore bypasses the FastAPI `require_internal_auth` dependency
  entirely, and the server calls `add_insecure_port`. What protects both boundaries in a
  deployed environment is the Cloud Run IAM check from section 1, reached with the
  identity token that `createCloudRunCallCredentials` in
  `services/api-service/src/clients/grpcConnection.js` puts in
  `x-serverless-authorization`. One layer, not two.
- **Enforced on the HTTP transport, which is development-grade.** With
  `INTERNAL_SERVICE_TRANSPORT` unset or `http`, the header is sent and
  `ensureInternalAuth` checks it with `crypto.timingSafeEqual`, rejects a mismatch with
  401, and returns 500 when the secret is unconfigured rather than passing the request
  through. `require_internal_auth` in `services/analysis-service/src/main.py` does the
  same with `hmac.compare_digest` and a 503. Both are correct; neither is on the deployed
  path.
- **Enforced, and missing from this document until now.** Two `x-internal-secret`
  boundaries do run in a deployed environment. Inbound, the API's `/internal` router
  applies its own `ensureInternalAuth` to every route through `router.use(...)` in
  `services/api-service/src/routes/internal.js`, constant-time and failing closed, and it
  has to, because it sits on the one publicly reachable service. Outbound, the repair
  service is genuine defence in depth: `deploy-remediation-cloudrun.yml` deploys it
  `--no-allow-unauthenticated` and `require_internal_auth` in
  `services/remediation-service/src/main.py` additionally requires
  `REMEDIATION_SERVICE_INTERNAL_SECRET` via `secrets.compare_digest`, failing closed with
  503 when unset, with the secret coming from Secret Manager. Both `/metrics` endpoints
  are gated by the same header, and the API's only in `NODE_ENV=production`.
- **Enforced.** `GITHUB_SERVICE_INTERNAL_SECRET` is the shared secret name, and
  `services/api-service/src/index.js` refuses to start without it when
  `NODE_ENV=production`. It is not one secret for one boundary: the analysis path falls
  back to it when `ANALYSIS_SERVICE_INTERNAL_SECRET` is unset, and both `/metrics`
  handlers fall back to it when `METRICS_AUTH_TOKEN` is unset.

## 4) Input Guardrails
- **Enforced, and it fails closed.** `verifyWebhookSignature` in
  `services/api-service/src/services/githubApp.js` runs before the event is dispatched,
  requires an `sha256=` prefixed `x-hub-signature-256`, compares with
  `crypto.timingSafeEqual`, and throws rather than returning false when
  `GITHUB_WEBHOOK_SECRET` is unset, so an unconfigured service rejects every delivery
  instead of accepting them. It sits at the top of the single `POST /github` handler, so
  it covers every event type with no per-event opt-out.
- **Enforced in the database, not only in code.** The claim transaction in
  `services/api-service/src/routes/webhooks.js` inserts into `webhook_deliveries` with
  `ON CONFLICT (delivery_id) DO UPDATE ... WHERE processing_status IN ('failed',
  'received')` and treats `rowCount === 0` as a duplicate, and
  `services/api-service/migrations/0001_initial_schema.sql` declares `delivery_id
  VARCHAR(255) NOT NULL UNIQUE`. Because the claim and the work share one transaction, a
  failed delivery rolls its claim back and stays retryable.
- **Not implemented as written.** There is no payload constraint for oversized fields and
  none for batch event size. The only bounds on a webhook body are the `10mb`
  `express.raw` limit in `services/api-service/src/app.js` and the `VARCHAR` widths in
  `0001_initial_schema.sql` (`pull_requests.title` is `VARCHAR(1000)`), and the second is
  not a guardrail: an over-width field raises a Postgres error that rolls the delivery
  back rather than being rejected or truncated at the edge. For batch size, the
  `installation_repositories` handler loops over every entry of `repositories_added` and
  `repositories_removed` with no cap and one query per repository, so a large
  installation event is bounded only by the 10 MB body limit. The one explicit byte cap
  found anywhere nearby, `MAX_EVIDENCE_PAYLOAD_BYTES` in
  `services/api-service/src/db/remediation.js`, guards remediation evidence rows and has
  nothing to do with webhook input.
- **Enforced for status and reason; not implemented for UUID and severity.** The status
  allowlist is real: `PATCH /findings/:id/status` in
  `services/api-service/src/routes/findings.js` rejects anything outside `['open',
  'dismissed', 'accepted_risk', 'fixed']` with 400, and a dismissal's reason must survive
  `findingOutcomes.normalizeDismissalReason`, which refuses an unrecognised value and
  returns the allowed list. `POST /suppressions` in
  `services/api-service/src/routes/suppressions.js` requires `repository_id`, `reason`,
  and one of `finding_id` or `fingerprint`, and refuses a `fingerprint` that contradicts
  the named finding. What is not checked: no route validates UUID shape. The only
  `UUID_PATTERN` in the service is in `services/api-service/src/routes/reports.js`;
  `findings.js` and `suppressions.js` pass path and body identifiers straight into
  parameterised SQL, so a malformed id becomes a Postgres cast error and a 500 rather than
  a 400. `severity` is a query filter on `GET /findings` and is passed through to the
  query builder unvalidated. A suppression's `reason` is checked for presence only, not
  against a vocabulary; `normalizeDismissalReason` is applied to it afterwards, for the
  outcome log, and cannot refuse the suppression.

## 5) Authorization and Audit
- **Enforced, but not owner based. The scope is a grant row, and the previous sentence
  named a model this codebase removed.** Every authorization predicate in the API is the
  presence of a `(user_id, repository_id)` row in `repository_access`, not ownership.
  `repositories.owner_id` appears in exactly three places in the service, all of them
  INSERT column lists that write `NULL` (`services/api-service/src/routes/installations.js`
  line 229, `services/api-service/src/routes/webhooks.js` lines 92 and 160), and no SELECT
  or WHERE anywhere reads it. Migration
  `services/api-service/migrations/0010_repository_access_revocation.sql` deletes every
  pre-existing grant and says why: grants derived from installation-wide access are not
  proof of a user's repository permissions. The grants are written by
  `grantRepositoryAccess` in `installations.js` from the intersection of the app's access
  and the user's own GitHub visibility, and revoked by
  `revokeMissingAccessForInstallation` in `services/api-service/src/db/repositories.js`
  plus the triggers in that same migration. The same predicate covers findings,
  suppressions, pull requests, analysis runs, reports, webhook events and remediation, and
  the Postgres row-level security policies in `migrations/0013`, `0014` and `0022` key on
  it too.
- **Not implemented: there is no R in this RBAC.** `repository_access.role` exists and is
  enforced nowhere. `grantRepositoryAccess` writes the literal `'read'` for every user, and
  the only statement in the service that reads the column is an `ORDER BY CASE ra.role`
  in `services/api-service/src/db/remediation.js` that picks a display actor for
  automatic jobs, which is inert because every synced grant is `'read'`. Authorization is
  binary: the grant that permits reading a repository also permits connecting it,
  changing a finding's status, creating and deleting suppressions, and requesting a
  remediation. `services/api-service/src/middleware/auth.js` verifies the JWT and sets
  `req.user`; it makes no authorization decision, and there is no `requireRepoAccess`
  middleware, so the check is inlined in each query and has to be confirmed per query
  rather than centrally.
- **Enforced for suppressions.** Both suppression mutation routes in
  `services/api-service/src/routes/suppressions.js` write `audit_logs`:
  `'suppression.created'` on `POST /suppressions` and `'suppression.deleted'` on
  `DELETE /suppressions/:id`. These are the only two paths in the service that insert or
  delete a suppression row.
- **Not implemented for five of the six finding status paths, so "all" is false.** One
  path audits: `updateStatus` in `services/api-service/src/db/findings.js`, behind
  `PATCH /api/findings/:id/status`, writes `'finding.status.updated'` in the same
  transaction as the UPDATE. Five do not, and three of them touch `findings.status` on
  every analysis run:
  - `dismiss` (`db/findings.js`), called from `applySuppressions` in
    `prAnalysisOrchestrator.js`, moves a finding `open` to `dismissed` on a suppression
    match with no audit row and no outcome row.
  - `markFixed` (`db/findings.js`), called from `persistAndFilter`, bulk-updates every
    finding the fresh analysis no longer reports to `fixed` in one statement. It records
    `finding_outcomes` and no `audit_logs`.
  - `upsert` (`db/findings.js`) re-opens on re-detection with
    `status = CASE WHEN status = 'fixed' OR suppression_applied THEN 'open' ELSE status END`,
    with neither an audit row nor an outcome row.
  - `handleReviewComment` in `services/api-service/src/services/findingThreadEvents.js`
    dismisses a finding when a reviewer replies on the thread. This is a person
    dismissing a finding, the same intent the `PATCH` route audits, and it writes
    `finding_outcomes` only. Whether a dismissal is audited depends on which channel it
    arrived through.
  - `restoreExpiredSuppressions` (`db/findings.js`) moves findings back to `open` when a
    suppression expires or is deleted, unaudited, and it is called from the three read
    helpers `listByPullRequest`, `listAll` and `getById`, so a plain `GET /api/findings`
    changes finding statuses across every repository the caller can reach and records
    nothing.

  Nothing structurally prevents this. There is no shared audit helper in `src/db/`: the
  one `audit()` function is private to `db/remediation.js`, and `db/findings.js` and
  `routes/suppressions.js` each hand-write their own INSERT. An adjacent gap is already in
  `docs/architecture/known-debt.md`, which records that inline fix publication and
  feedback are not written to `audit_logs`.

## 6) Analysis Guardrails
- **Enforced, with two silent limits and one that fails the run closed.** The changed-file
  cap is real and honest in both products: `FILE_CAP = 200` in
  `services/github-service/src/services/githubInternalOperations.js` and
  `MAX_CHANGED_FILES = 200` in `action/orchestrator/pr_scope.py` both review the first 200
  files in path order and report a `file_cap` limitation rather than refusing the pull
  request, and `action/tests/test_node_parity.py` pins the two to each other. The tier 1
  time budgets in `services/analysis-service/src/main.py`
  (`TIER1_BUDGET_SECONDS`, 20 s; `TIER1_FILE_BUDGET_SECONDS`, 2 s) stop the work and
  append a `budget` limitation. `analyze_pull_request_payload` in the same file refuses a
  payload of more than 300 files outright, as a 413 or a gRPC `INVALID_ARGUMENT`, though
  both callers cap at 200 first, so it is defence in depth and not the operative limit.
  Three things the sentence hides:
  - A file over 500 kB does not degrade the review, it fails it. `fetchFileContents`
    skips the file (`Buffer.byteLength(content) > 500000`) and the orchestrator then
    throws `Required source content response is incomplete`
    (`prAnalysisOrchestrator.js`); `action/orchestrator/run.py` raises the equivalent
    `ActionError` and says why in a comment. That is the safe direction, and it means one
    large generated file that the vendor filters miss aborts the whole analysis.
  - The 200 kB per-patch cap in tier 1 (`if len(patch) > 200_000: continue` in `main.py`)
    drops the file with no limitation, no log and no counter, inside the same loop that
    records a limitation for both of its time budgets. The run reports coverage it did not
    earn.
  - Tier 2 passes `--max-target-bytes 500000` to the scanner in
    `services/analysis-service/src/opengrep_runner.py`, and nothing reads the scanner's
    `paths.skipped`, so those skips are equally invisible.

  `OPENGREP_BATCH_MAX_FILES` (25) and `OPENGREP_BATCH_MAX_BYTES` (1 MiB) in
  `opengrep_runner.py` are not limits and should not be read as any: `build_scan_batches`
  says in its own docstring that an over-budget file still gets its own batch, because
  dropping it would hide code. Nothing is excluded and every batch's findings are merged.
- **Enforced and much stronger than written for the App. Not implemented in the Action,
  so as an unqualified claim it is false.** In the App the gate is
  `explainInlineCommentDecision` in
  `services/api-service/src/services/prAnalysisOrchestrator.js`, and it is not one
  threshold. It requires status `open`, refuses a baseline finding, refuses an
  informational test-code finding, applies a 0.70 floor on the finding's numeric
  `confidence`, vetoes anything whose `sanitizer_status` is allowlisted, sanitized or
  validated, then raises the floor by analysis scope: 0.80 for taint (and additionally
  refuses a weak trace quality, weak evidence strength or a trace with no steps), 0.85
  for ast-pattern (and refuses low or weak evidence), 0.90 for pattern. An unrecognised
  scope is refused by default, and `buildSurfaceDecisions` additionally requires the
  finding's file and line to be reviewable in the diff. Upstream,
  `partition_by_posting_policy` in `main.py` removes every finding from a quarantined rule
  before the response is built, so a rule whose measured precision is below the threshold
  reaches nothing at all. Because tier 1 findings carry no `analysis_scope`, they default
  to `pattern` and face the 0.90 floor, so most tier 1 rules are never inline in the App.

  The Action enforces none of this. `plan_comments` in `action/orchestrator/run.py`
  filters on informational, a usable path and line, diff anchoring and the 40-comment cap,
  and reads no confidence, scope, sanitizer or evidence field; `confidence` appears
  nowhere in `action/` outside one test fixture. Every non-quarantined finding at any
  confidence is posted inline if it lands on a changed line, so a rule that is
  summary-only in the App is an inline comment in the Action on the same diff.
  `action/tests/test_node_parity.py` pins many behaviours between the two products but
  nothing about this gate, so the divergence is untested in either direction.

  Two App-side caveats: `services/analysis-service/src/llm_triage.py` lets tier 3 replace
  a finding's `confidence` with the model's `adjusted_confidence` with no bound relative
  to the rule's shipped value, so a low-confidence rule can be lifted over the floor by a
  model verdict; and `publishInlineFixes` in
  `services/api-service/src/services/remediationInlineFixes.js` can create the inline
  comment the gate refused, for a finding with a published verified fix. That path is
  gated on the remediation policy's `publish` capability, and the shipped default policy
  is `remediation-v1-disabled`, so it is latent rather than live.
- **Enforced.** No informational finding is posted inline. A finding in test code is
  downgraded to the
  informational severity upstream, cannot block the check, and carries no fix the author is
  asked to apply, so both the App and the Action report it as a count in the check run summary
  and the review body ("N informational findings in test code, not posted") and annotate
  nothing. The App retires the inline comments earlier runs left for one, by fingerprint, on
  every analysis; a comment carrying a published verified fix is kept.

## 7) CI Guardrails
- Secret scanning on every PR/push.
- API and analysis tests required.
- Branch protection should require `Guardrails` workflow success before merge.

## 8) Monitoring Guardrails
- Uptime checks for API and analysis health endpoints.
- Alerts for 5xx, latency spikes, and error bursts.
- Correlation IDs in logs for cross-service tracing.
