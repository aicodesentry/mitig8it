# Mitig8it hardening handoff

Local change set: branch `fix/security-analysis-hardening`, based on `6b02c87`. Changes are unstaged and uncommitted for human review. Nothing was deployed, pushed, merged or posted to GitHub. Existing user documents are preserved. The completed [issue tracker](HARDENING-TRACKER.md) maps defects to implementation, regression coverage and remaining risks.

## Changes

Repository grants now come from the intersection of the user's GitHub access and the app installation. Webhooks no longer manufacture grants; membership removal/suspension revokes direct access. OAuth callbacks require the initiating browser cookie. Credentialed origins use exact trusted entries, including the existing CodeSentry Firebase site.

Webhook claiming and durable job insertion share one database transaction. A per-PR PostgreSQL session lock spans analysis so concurrent or apparently stale workers cannot race the same PR. Worker concurrency reserves two pool connections for queries.

Analysis fails closed on incomplete required tiers, content failures, persistence failures and intended feedback publication failures. Benign command comments cannot bypass deterministic detection. Queued commit SHA travels through HTTP/gRPC and is checked against PR content. One final persistence/review operation reconciles empty scans and avoids tier-level duplicate feedback.

Current finding status is separate from immutable historical snapshots. Automatic suppression provenance enables expiry/removal recovery without undoing manual dismissals. Retries allocate a new analysis attempt. GitHub reviews, marked comments and checks reuse existing owned feedback.

The playground now has authenticated API health, analysis and history endpoints, using the existing internal scanner transports. Results are private to the user; five successful analyses per UTC day are allowed, with atomic reservations and failed-request quota recovery. Raw source is not persisted, though finding snippets are part of result JSON. Account-scoped report caching and logout invalidation prevent metadata crossing accounts. Numeric totals coerce database string counts. Default API discovery includes `src/__tests__`.

## Migration and rollout instructions — not executed outside disposable databases

1. Take the normal database backup and pause old API/webhook/worker writers before migration. Do not run mixed old/new revisions: old code can recreate unverified grants or mutate current evidence using obsolete lifecycle assumptions.
2. Run the repository migration command from `services/api-service`: `npm run db:migrate`, followed by `npm run db:verify`. The migration runner applies new files once.
3. Migration `0010_repository_access_revocation.sql` invalidates **all existing repository access grants** and adds membership/suspension revocation triggers. Repositories, activation settings and analysis history remain. Users must sync their installations again to restore verified access. Do not restore old grants as a rollback shortcut.
4. Migration `0011_analysis_evidence.sql` creates historical snapshots and suppression provenance. It backfills evidence still present in current findings. Evidence already overwritten/deleted before this migration cannot be reconstructed without backups. Old automatic dismissals whose suppressions were already deleted cannot safely be inferred; review those manually if affected. Matching legacy manual and automatic dismissal reasons can be ambiguous.
5. Migration `0012_playground_history.sql` adds per-user playground results and quota reservations. Existing database/environment identifiers remain unchanged.
6. Roll out API, GitHub adapter, analysis service and frontend as a coordinated revision. `FetchPullRequestFilesRequest.commit_sha` is an additive protobuf field, but the new adapter requires a SHA for correctness: old callers must not remain active. Regenerated JavaScript bindings are included. Python also preserves protobuf's default PR zero for playground calls.
7. Resume writers, have users resync, and verify login, repository visibility, a finding scan, a clean rescan, suppression deletion and a retry in the intended staging environment before production release.

A deployment or destructive rollback requires separate authorization. Schema deletion/downgrade is not supplied. Keep old writers stopped if reverting application code would restore the original vulnerabilities.

## Verification

| Final check | Exact result |
|---|---|
| Frontend tests | 47 passed, 14 files |
| Frontend lint / production build | Passed / passed |
| API default tests including src suites | 256 passed, 24 suites |
| API lint | Passed |
| GitHub adapter tests / lint | 28 passed / passed |
| Full Python tests, native Semgrep and rule validation | 274 passed, zero skipped |
| Real PostgreSQL access/webhook integration | 6 passed, zero skipped |
| Real PostgreSQL lifecycle/migration/quota integration | 8 passed, zero skipped |
| Local actual Python HTTP/gRPC and API smoke | 4 passed, zero skipped |
| Actual frontend with controlled API browser fixtures | 5 scenarios passed, zero browser runtime errors |
| Compose configuration / CI YAML parse / diff whitespace | Passed |
| Analysis Docker image build and corrected Compose command | Passed; actual tier 1 and native tier 2 each detected eval |

Total: **605 unit/component/native tests and 18 integration tests**, plus 5 browser scenarios. Native scanner tests were rerun with an available Semgrep executable and correct CA certificate path; initial environment skips/timeouts were not counted as passes. All final listed checks passed.

From the corresponding service directory:

```sh
# frontend
npm test
npm run lint
npm run build

# services/api-service
npm test -- --runInBand
npm run lint

# services/github-service
npm test -- --runInBand
npm run lint

# services/analysis-service; activate an environment with requirements-test.txt installed
python -m pytest src/tests -q --tb=short
```

On this workstation, native Python verification used `/private/tmp/mitig8it-review-venv/bin/python`, put that venv's bin directory on PATH, set `SSL_CERT_FILE` to its certifi `cacert.pem`, and disabled Semgrep version checks. No runtime dependency versions were changed in the repository.

The database integration commands **reset the public schema**. They guard against non-loopback databases and require a dedicated name ending `_test`; never point them at a database containing useful data. Access and lifecycle suites must use separate databases if run in parallel:

```sh
# services/api-service; set DATABASE_URL to the appropriate disposable database
npm run test:integration:access
npm run test:integration:lifecycle
```

Locally these used a newly initialized PostgreSQL cluster on loopback port 55439, user `review_admin`, databases `mitig8it_access_test` and `mitig8it_lifecycle_test`. Both tested old migrations 1–9 followed by 10–12, preserved legacy state, and idempotent reapplication. CI now runs both suites against its disposable Postgres service, followed by its existing fresh migration/verification/reapplication step.

`npm run test:integration:transport` additionally needs the migrated disposable database, local `ANALYSIS_SERVICE_URL` and `ANALYSIS_GRPC_URL`, matching existing internal-secret settings, and `LLM_TRIAGE_ENABLED=false`. Local smoke used HTTP 8019 and gRPC 50079. It exercises actual native tier1/tier2 findings, internal authentication, binary parity, playground persistence and synthetic PR zero. GitHub is not called.

Browser fixture runner: `frontend/tests/browser/security-smoke.cjs`, exporting an async function receiving a Playwright page. Run against Vite on127.0.0.1:5178 in an isolated browser. It intercepts API calls and verifies logout/account privacy, successful playground CSRF request, quota exhaustion and scanner failure. Screenshots were captured in `/private/tmp/mitig8it-browser-account-isolation.png` and `/private/tmp/mitig8it-browser-playground.png`. This is browser behavior verification with fixtures, not live OAuth or live cloud verification.

## Compatibility and limits

- All existing environment variable names, including `CODESENTRY_*`, were preserved. No `.env`, secret values, infrastructure identifiers, service IDs, deployment IDs or production database names were changed. The old playground analysis URL definition remains; the UI now uses the authenticated API transport.
- GitHub error/retry/deduplication tests use controlled doubles. No live GitHub reviews/checks/comments were created. GitHub's API has no atomic compare-head-and-write operation; a push during remote publication can race a head check, although checks remain attached to the analyzed SHA and per-PR local work is serialized.
- Legacy failed webhook deliveries that already committed work under old code lack a reliable delivery-to-job link. Retrying one can create another attempt; new transactional intake prevents that failure mode going forward.
- Reused inline threads retain their original GitHub position. Existing unmarked legacy comments are left intact. Snapshot history preserves evidence but cannot repair previously lost records.
- Revocation takes effect when authoritative synchronization or a relevant webhook updates local membership/access. This change does not add a live GitHub permission lookup to every API request.
- Queue leases use one database connection per active scan; concurrency is capped at pool capacity minus two. PostgreSQL releases the advisory lock when its connection dies; the live stale-worker exclusion was tested, but a process crash during remote publication was not injected.
- Live OAuth/Firebase proxy behavior, external LLM credentials, remote CI and the complete cloud deployment remain unverified. No approval claim is based on mocked external services.

Docker Desktop was started to resolve the initial daemon limitation. A fresh `mitig8it-hardening-analysis-test` image built successfully. A disposable container ran the exact corrected Compose uvicorn command with fixture credentials and LLM calls disabled; actual HTTP tier 1 and native tier 2 scans both detected the eval fixture. The full multi-service Compose stack was not started with the user’s `.env`. The disposable container and locally launched test servers were stopped after verification.
