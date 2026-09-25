# Mitig8it hardening tracker — completed local implementation

Branch: `fix/security-analysis-hardening`; base: `6b02c87`; verified September 6, 2026.
Scope: `BUG-REVIEW-2026-09-05.md` and directly connected defects.
Existing environment variable names, secret names, deployment identifiers and database contracts are preserved. Original untracked review/planning documents are untouched.

Three specialists worked with exclusive file ownership on this separate shared branch. A owned auth/access/webhook/suppression routes; B owned analysis/finding persistence, Python, GitHub and protobuf; C owned frontend/runtime/test discovery and assigned queue work. Root owned playground API, database/transport integration, retry isolation and integration review. Shared migrations were allocated in advance. Cross-review resolved retry snapshot mutation, stale-worker concurrency and database connection exhaustion.

Paths below are repository-relative: API = `services/api-service`, Python = `services/analysis-service/src`, GitHub = `services/github-service`.

| Issue / root cause | Severity / owner | Reproduction and regression coverage | Implemented source | Verification / remaining risk |
|---|---|---|---|---|
| 1. Installation-wide tokens granted repositories beyond user permissions | P1 / A | `API/tests/installations-sync.test.js`, `repo-access-control.test.js`, `integration/access.integration.js`: installation member lacks repository access; webhook must not grant it | `API/src/routes/installations.js`, `webhooks.js`, migration `0010` | Fixed; unit and real DB pass. Existing grants invalidated; users must resync. |
| 2. Removing installation membership left direct grants intact | P1 / A | `integration/access.integration.js`: remove membership/suspend installation, direct API becomes inaccessible | Migration `0010_repository_access_revocation.sql`, installation synchronization | Fixed; real DB pass. GitHub permission changes must reach sync or webhook intake before local grants reflect them. |
| 3. Signed OAuth state transferred between browsers | P1 / A | `API/tests/auth.test.js`: valid state without initiating cookie rejected before token exchange; red reproduced | `API/src/routes/auth.js` | Fixed; API pass. Uses Firebase-forwarded `__session`; live GitHub/Firebase OAuth not exercised. |
| 4. CORS accepted unrelated Firebase origins containing codesentry | P1 / A | `API/tests/cors.test.js`, `auth.test.js`: reject unrelated host, accept exact existing Firebase site; red reproduced | `API/src/app.js` | Fixed; API pass. Existing configured origins retained. |
| 5. Tier/content/persistence/publication failures could approve checks | P1 / B | `API/tests/orchestrator.test.js`, `analysisLifecycle.test.js`; `Python/tests/test_analysis_fail_closed.py`: required tier outage, malformed result, missing detector, persistence/publication failure | Orchestrator, `Python/main.py`, `opengrep_runner.py` | Fixed; regressions and native detector tests pass. Optional LLM fallback retains deterministic behavior. |
| 6. Benign command comments suppressed deterministic findings | P1 / B | `Python/tests/test_finding_quality.py`: vulnerable source with `# git add .` / `# pytest`; red reproduced | `Python/finding_quality.py` | Fixed; full Python suite and native rules pass. |
| 7. Failed webhook claims prevented safe retry | P2 / A | `API/tests/webhook.test.js`, `integration/access.integration.js`: six simultaneous signed duplicates; injected job insert failure then same-delivery retry | `API/src/routes/webhooks.js` | Fixed; real DB gives one job/five duplicates and rollback recovery. Legacy failed delivery with previously committed job cannot be identified reliably; see handoff. |
| 8. Empty clean scans retained open findings and blocking reviews | P2 / B | API lifecycle, DB lifecycle and GitHub lifecycle: empty rescan after finding/prior owned blocker | Orchestrator, `API/src/db/findings.js`, GitHub adapter | Fixed; DB and controlled GitHub tests pass. Remote writes simulated. |
| 9. Queued SHA differed from moving PR content | P2 / B | API/GitHub lifecycle: binary contract and head movement tests; local transport smoke | `proto/github.proto`, generated clients/servers, orchestrator, GitHub file adapter | Fixed; SHA forwarded, head checked before/after fetch; oversized scope fails closed. Coordinate API/adapter rollout. |
| 10. Deleted/expired suppressions permanently dismissed findings; mismatched finding bypassed validation | P2 / A+B | `API/tests/suppressions-security.test.js`, DB lifecycle: cross-repository ID, expiry, deletion, manual dismissal, clean suppressed finding | `API/src/routes/suppressions.js`, `db/findings.js`, migration `0011` | Fixed; real DB pass. Legacy deleted suppression provenance cannot be reconstructed automatically. |
| 11. Rescans overwrote historical finding evidence | P2 / B+root | DB lifecycle: recurring finding changes, running snapshot replacement, immutable terminal snapshots including new IDs | `API/src/db/findings.js`, migration `0011_analysis_evidence.sql` | Fixed; upgrade and DB pass. Previously destroyed evidence needs backups to recover. |
| 12. Tiers/retries created duplicate feedback | P2 / B | API/GitHub lifecycle: existing marked inline comment/review/check reused; superseded review rejected | Orchestrator and GitHub adapter | Fixed; controlled GitHub tests pass. Reused threads keep original position; legacy unmarked comments not rewritten. |
| 13. Documented/Compose analysis import path failed | P2 / C | Compose config validation; actual corrected uvicorn startup and transport smoke | `docker-compose.yml`, `README.md` | Fixed; native startup, Docker image build and exact Compose command with both scanner tiers pass. |
| 14. Playground used unavailable endpoint | P2 / root+C | `API/tests/playground.test.js`: seven red route tests before implementation; DB quota/history; browser success/429/502; real scanner HTTP/gRPC | `API/src/routes/playground.js`, migration `0012`, `frontend/src/pages/CodeAnalysisTest.jsx` | Fixed; authenticated backend, real scanner and browser fixtures pass. Five successful runs/day UTC; no live provider calls. |
| 15. Report cache survived account switching | P2 / C | ReportsPage/API client tests; browser logout and second-user failed-refresh scenario | `ReportsPage.jsx`, `frontend/src/services/privateCache.js`, `api.js` | Fixed; account-keyed state, invalidation and stale request guards verified. |
| 16. Critical/high strings concatenated | P3 / C | `frontend/src/pages/__tests__/RepositoryDetailsPage.test.jsx`: string counts | `frontend/src/pages/RepositoryDetailsPage.jsx` | Fixed; frontend tests pass. |
| 17. Default API discovery omitted src suites | P2 / C+root | Clean HEAD default 175 vs explicit 218; final default command discovers 24 suites | API Jest config/package scripts, CI database test step | Fixed; final 256 API tests pass. DB/transport commands require disposable services. |
| 18. Retry mutated failed run's historical identity | P2 / root | `API/tests/reportsRetry.test.js` red before fix; DB verifies new pending ID and untouched evidence | `API/src/routes/reports.js` | Fixed; retry creates new attempt and requires active repository. |
| 19. Concurrent/stale workers could publish against same PR | P2 / C+root | Queue tests and DB lifecycle: simultaneous claims, stale timestamp while live lease held | `API/src/db/analysisRuns.js`, orchestrator | Fixed; per-PR session advisory lease spans work, released in finally. Real process crash not injected. |
| 20. New queue leases could exhaust connection pool | P2 / C+root | `API/tests/analysisQueueConcurrency.test.js`: red 4 before fix; configured 100 starts 18 with pool 20 | Orchestrator concurrency cap | Fixed; six regressions pass. Each active scan holds one DB connection. |
| 21. Protobuf omitted synthetic PR zero, breaking playground gRPC | P2 / root | `Python/tests/test_grpc_contracts.py`: binary default roundtrip red before fix; transport initially3/4 then4/4 | `Python/analysis_grpc_server.py` | Fixed; explicit scalar default preserved for analysis and triage. |

## Baseline and final evidence

Clean HEAD archive independently passed **218 API tests**, including 43 excluded by old default discovery. Frontend 38, GitHub 20 and Python 252 passed at baseline;15 native tests initially skipped until native tooling/certificates were configured. The historical543 total matches the complete baseline including native tests. Newly introduced red tests were distinguished from baseline failures using the clean archive.

| Final combined check | Result |
|---|---|
| Frontend `npm test` | 47 passed / 14 files |
| Frontend lint and production build | Passed |
| API `npm test -- --runInBand` | 256 passed / 24 suites, including `src/__tests__` |
| API lint | Passed |
| GitHub tests and lint | 28 passed; lint passed |
| Python complete suite with native Semgrep / rule validation | 274 passed, zero skipped |
| Disposable PostgreSQL access integration | 6 passed, zero skipped |
| Disposable PostgreSQL lifecycle/migration integration | 8 passed, zero skipped |
| Actual local Python HTTP/gRPC and API transport integration | 4 passed, zero skipped |
| Browser fixtures against actual frontend | 5 scenarios passed; no runtime errors |
| Analysis container build/startup and tier 1/tier 2 HTTP smoke | Passed |
| Compose config / CI YAML / diff whitespace | Passed |

Totals: **605 unit/component/native tests plus 18 integration tests**, all passing, and 5 browser scenarios. Browser/GitHub fixtures are controlled doubles, not live GitHub verification. See [HARDENING-HANDOFF.md](HARDENING-HANDOFF.md) for commands, migration sequencing and verification limits. No deployment, push, merge, live GitHub write or production data change was performed.
