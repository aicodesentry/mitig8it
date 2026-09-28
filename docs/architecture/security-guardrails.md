# Centralized Security Guardrails

Mitig8it enforces guardrails as a centralized control model, not per-service ad hoc behavior.

Every item below carries its state, because a guardrails document that reads the same whether or
not a control is switched on is the document an auditor trusts and the code contradicts. The
states are:

- **Enforced.** The code refuses without it. Nothing to switch on.
- **Provisioned.** The configuration is in this repository and an operator applies it. Written is
  not applied, and this document cannot tell you which is true of your project.
- **Not implemented.** Named here because its absence is worth knowing, not because it is planned.

As of 2026-09-28.

## 1) Network and Ingress
- Public ingress allowed only for `api-service`.
- `analysis-service` may be private/internal based on environment.
- GitHub webhook endpoint: `POST /webhooks/github` only.

## 2) Secret Authority
- Secrets must come from Secret Manager in deployed environments.
- No production secrets in `.env` files or source code.
- Rotate `JWT_SECRET`, `GITHUB_WEBHOOK_SECRET`, and `GITHUB_SERVICE_INTERNAL_SECRET` regularly.

## 3) Internal Service Authentication
- API -> GitHub service calls require `x-internal-secret`.
- GitHub service rejects requests missing/mismatching the shared secret.
- Shared secret: `GITHUB_SERVICE_INTERNAL_SECRET`.

## 4) Input Guardrails
- Webhook signature verification for all GitHub events.
- Webhook idempotency via `webhook_deliveries.delivery_id`.
- Payload constraints for oversized fields and batch event size.
- Strict validation for finding/suppression APIs (UUID/status/severity/reason checks).

## 5) Authorization and Audit
- API RBAC scope is repository owner based.
- All finding status changes and suppression mutations write `audit_logs` entries.

## 6) Analysis Guardrails
- Large file/diff limits are enforced in analysis pipeline paths.
- High-confidence findings only for inline PR comments.
- No informational finding is posted inline. A finding in test code is downgraded to the
  informational severity upstream, cannot block the check, and carries no fix the author is
  asked to apply, so both the App and the Action report it as a count in the check run summary
  and the review body ("N informational findings in test code, not posted") and annotate
  nothing. The App retires the inline comments earlier runs left for one, by fingerprint, on
  every analysis; a comment carrying a published verified fix is kept.

## 7) CI Guardrails
- **Enforced.** Secret scanning on every pull request and push, as the `Secret scan (Gitleaks)`
  job in `.github/workflows/ci.yml`.
- **Enforced.** API, GitHub service, analysis, frontend, docker build and remediation integration
  jobs all run on every pull request, and all of them feed the aggregate `Required CI` job.
- **Not implemented.** `Required CI` is a job name, not a merge gate. There is no branch
  protection rule and no ruleset on `main`, so nothing refuses a merge whose checks failed and
  nothing refuses a direct push. `.github/workflows/dependabot-automerge.yml` polls for
  `Required CI` itself before merging, which is one workflow doing the work a branch rule should
  do, for one kind of pull request.
- **Enforced.** `.github/CODEOWNERS` requests a review on every pull request. A request is not a
  requirement: making it one needs the branch rule above. GitHub does not request a review from
  the author, so this does not fire on pull requests opened by the code owner.

## 8) Monitoring Guardrails
- **Provisioned.** Cloud Monitoring alert policies and an email notification channel in
  `infrastructure/monitoring/*.tf`, evaluating PromQL against the managed Prometheus sidecar.
  They are applied by an operator; `docs/runbooks/observability.md` has the steps. The sidecar is
  opt-in through `METRICS_SIDECAR_ENABLED`, so an unapplied project emits nothing and the
  policies stay silent rather than firing.
- **Provisioned.** Equivalent Grafana rules in
  `infrastructure/remediation/grafana/alerts/remediation-rules.yaml`. They are an alternative to
  the Cloud Monitoring policies, not an addition: running both pages twice for one incident.
- **Enforced.** Correlation IDs in logs for cross-service tracing.
- **Not implemented.** Uptime checks against the API and analysis health endpoints.

## 9) Verification Sandbox

The largest trust boundary in the system, and the one this document previously did not mention.
The remediation service proves a repair by running a repository's own checks. What isolates that
execution depends on `SANDBOX_DRIVER`:

- **Not implemented, and the production default.** `SANDBOX_DRIVER=local` runs the repository's
  own commands inside the remediation service container: no kernel, network or filesystem
  isolation, and no broker trust boundary. `local` is the default of the `sandbox_driver` input
  in `.github/workflows/deploy-remediation-cloudrun.yml`, so an ordinary deploy runs this one.
  Every result it produces is labelled `development_unverified`, which is the honest label and
  not a mitigation. Use it only for repositories the operator owns and has enrolled as test
  repositories.
- **Provisioned.** `SANDBOX_DRIVER=cloud_run_job` runs each check in a separate Cloud Run job
  container with its own unprivileged user and a denied network, and labels evidence
  `isolated_job`. It requires `infrastructure/remediation/terraform` with
  `enable_cloud_run_job_sandbox=true` and every step of `docs/runbooks/sandbox-cloud-run-job.md`,
  including the smoke test proving the job's own probes came back denied.
- Neither driver justifies `SANDBOX_NETWORK_POLICY_ATTESTED` or `SANDBOX_NODE_LIMITS_ATTESTED`.
  `cloud_run_job` still has no read-only root filesystem, no gVisor runtime class and no broker
  trust boundary, so it is a real sandbox and still not the production level.
