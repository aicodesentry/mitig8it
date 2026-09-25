# Project bug review — September 5, 2026

Review started September 5 and completed September 6, 2026. Reviewed checkout: `6b02c87`. Found 16 actionable bugs: six P1, nine P2, one P3. P1 means urgent security or core detection failure; P2 means a functional correctness issue; P3 means a lower-impact display bug.

This review covered the React frontend, Express API and GitHub adapter, Python detection pipeline, protobuf transport, database access/migrations, Docker setup, and deployment/CI configuration. Findings below distinguish executed reproductions from code-path analysis. This is not a claim that every possible defect has been found. No production credentials, live GitHub writes, or production database mutations were used. Application source was not changed.

1. **[P1] Organization installation access is mistaken for access to every repository.**

   Location: [installations.js:88](services/api-service/src/routes/installations.js#L88), [webhooks.js:16](services/api-service/src/routes/webhooks.js#L16).

   Sync prefers the app installation token's complete repository list, then grants the current user `admin` access to every returned repository. The user-scoped repository endpoint is only a fallback. Separately, PR webhooks grant every linked installation user access to that PR's repository. A user who can access one repository in an organization installation can therefore receive access to private repositories they cannot access on GitHub. Finding APIs trust these local access rows, exposing stored snippets and allowing status changes. Both grant paths need a verified per-user repository intersection; installation membership alone cannot authorize a repository. **Evidence: traced both grant paths and the finding authorization queries.**

2. **[P1] Revoked installation membership leaves direct API access intact.**

   Location: [installations.js:73](services/api-service/src/db/installations.js#L73), [findings.js:3](services/api-service/src/db/findings.js#L3).

   When an installation disappears from a user's sync response, reconciliation deletes `user_installations` but leaves `repository_access`. Revocation for missing repositories only runs inside installations that are still returned. Repository lists can hide the installation while direct repository/finding endpoints continue accepting the stale access row. A former member with a valid local session can still retrieve stored private findings using known IDs. Delete dependent access grants when reconciling removed memberships, and enforce a consistent current-access condition on all endpoints. **Evidence: code-path and SQL analysis; not a live organization test.**

3. **[P1] OAuth state is not bound to the browser that started sign-in.**

   Location: [auth.js:136](services/api-service/src/routes/auth.js#L136), [auth.js:159](services/api-service/src/routes/auth.js#L159).

   State is signed and expires, but the callback never compares it with a cookie or browser session. An attacker can initiate their own authorization and send the resulting unused callback URL to another browser, which then receives a session for the attacker's account. This is login CSRF, not a demonstrated theft of an existing victim session. Bind state to an initiating browser nonce and consume it on callback. **Executed reproduction:** state obtained by client A was accepted by a callback with no cookies, and the callback issued client B the mocked attacker's session.

4. **[P1] The CORS allowlist trusts arbitrary Firebase sites containing `codesentry`.**

   Location: [app.js:45](services/api-service/src/app.js#L45).

   `origin.endsWith('.web.app') && origin.includes('codesentry')` accepts unrelated origins such as `https://codesentry-attacker-owned.web.app`. CORS enables credentials, production session cookies use `SameSite=None`, and the same allowlist gates CSRF origins. When the browser sends the session cookie, such an origin can read authenticated responses and send the accepted CSRF header on mutations. Use exact configured origins. **Executed reproduction:** the actual CORS middleware returned that synthetic origin and `Access-Control-Allow-Credentials: true`.

5. **[P1] Analysis outages produce successful security checks.**

   Location: [prAnalysisOrchestrator.js:834](services/api-service/src/services/prAnalysisOrchestrator.js#L834), [prAnalysisOrchestrator.js:918](services/api-service/src/services/prAnalysisOrchestrator.js#L918).

   All three tier calls catch and log errors. Execution then posts `conclusion: success` and marks the run completed when no blocking counts were accumulated. An unreachable analysis service therefore looks like a clean scan. Persistence errors inside the same tier blocks can also be swallowed. Track required-tier execution and persistence success explicitly; failed/incomplete scans must not approve the commit. **Executed reproduction:** all tier requests threw, yet the check was successful and the run completed.

6. **[P1] Harmless comment text bypasses deterministic security detection.**

   Location: [finding_quality.py:20](services/analysis-service/src/finding_quality.py#L20), [finding_quality.py:114](services/analysis-service/src/finding_quality.py#L114).

   Any line containing strings such as `pytest` or `git add ` is discarded as a transcript artifact before regex matching. These strings can appear in ordinary source comments and literals. **Executed reproduction:** `eval(user_input)` produced a critical `code.injection.eval` finding; `eval(user_input) # git add .` and `eval(user_input) # pytest` each produced zero Tier 1 findings. This proves a Tier 1 bypass; it does not assert that every full-content Tier 2 rule is bypassed. Restrict transcript handling to known transcript inputs rather than filtering runtime code by substring.

7. **[P2] Failed webhook deliveries cannot be retried with the same delivery ID.**

   Location: [webhooks.js:50](services/api-service/src/routes/webhooks.js#L50).

   The duplicate check acknowledges every existing delivery, including `failed` and abandoned `received` rows. Once processing fails after insertion, redelivery returns success without creating the missing analysis run. The separate SELECT/INSERT also races concurrent deliveries. Use an atomic claim with explicit processed, retryable, and in-progress states. **Executed reproduction:** a stored `failed` delivery returned `deduplicated: true` after only a SELECT.

8. **[P2] Clean rescans leave old findings open and earlier blocking reviews in place.**

   Location: [prAnalysisOrchestrator.js:821](services/api-service/src/services/prAnalysisOrchestrator.js#L821), [prAnalysisOrchestrator.js:843](services/api-service/src/services/prAnalysisOrchestrator.js#L843).

   Reconciliation and review submission are conditional on nonempty findings or a Tier 3 change. If a later commit fixes everything, none of those branches runs. Existing database findings stay open, and the GitHub adapter's review-supersession logic is never invoked, despite a new successful check. Finalize every successful scan, including an empty result set, and supersede previous blocking feedback. **Executed reproduction:** an all-empty successful scan called neither `markFixed` nor review submission.

9. **[P2] Queued runs analyze a moving PR diff but attribute results to the queued SHA.**

   Location: [prAnalysisOrchestrator.js:803](services/api-service/src/services/prAnalysisOrchestrator.js#L803), [githubInternalOperations.js:73](services/github-service/src/services/githubInternalOperations.js#L73).

   A job keeps its original `commit_sha`, but file retrieval uses only PR number. If commit B arrives before the job for A runs, it receives B's current PR patches, enriches content using A's SHA, and publishes results/checks on A. Queue delays and retrying an older failed run trigger this mismatch. Use an immutable comparison for the queued base/head pair, or reject superseded runs after verifying the PR head. **Evidence: traced payloads through HTTP/gRPC and the GitHub adapter.**

10. **[P2] Removing or expiring a suppression does not restore affected findings.**

    Location: [prAnalysisOrchestrator.js:628](services/api-service/src/services/prAnalysisOrchestrator.js#L628), [findings.js:148](services/api-service/src/db/findings.js#L148), [suppressions.js:95](services/api-service/src/routes/suppressions.js#L95).

    Applying a suppression permanently changes the finding to `dismissed`. Deleting the suppression only removes its record; future upserts reopen `fixed` findings but preserve `dismissed`. When a suppression expires, the same behavior occurs. Even a later rescan leaves the vulnerability hidden from actionable results. Distinguish suppression-derived dismissal from a manual dismissal and recompute it when suppression applicability changes. **Evidence: complete suppression/create/delete/rescan state path.**

11. **[P2] Rescans remove findings from historical analysis reports.**

    Location: [findings.js:141](services/api-service/src/db/findings.js#L141), [reports.js:53](services/api-service/src/routes/reports.js#L53).

    Finding upsert overwrites the existing row's `analysis_run_id`. Report details retrieve findings using that mutable ID. If the same finding recurs in run B, it disappears from run A's details; run A's stored count can still say it found vulnerabilities while its modal shows none. Preserve per-run finding snapshots or a run/finding association table. **Evidence: update statement and historical-report query.**

12. **[P2] Each analysis tier reposts earlier inline findings.**

    Location: [prAnalysisOrchestrator.js:843](services/api-service/src/services/prAnalysisOrchestrator.js#L843), [prAnalysisOrchestrator.js:756](services/api-service/src/services/prAnalysisOrchestrator.js#L756).

    Tier 2 concatenates its results with Tier 1 and posts every actionable finding again. Tier 3 can do the same. Inline posting creates new comments without reconciling previously posted finding IDs. One unchanged Tier 1 finding can therefore appear repeatedly during a single run and again on later pushes. Reconcile comments by stable finding identity, or publish one final review. **Evidence: cumulative lists and unconditional per-comment POST path.**

13. **[P2] Docker Compose overrides the working analysis startup command with a broken import path.**

    Location: [docker-compose.yml:85](docker-compose.yml#L85), [main.py:13](services/analysis-service/src/main.py#L13).

    Compose starts `uvicorn src.main:app` from `/app`, but `main.py` imports `finding_quality` as a top-level module in `/app/src`. The Dockerfile's working `main:app --app-dir src` command is overridden. On a normal fresh environment without a custom `PYTHONPATH`, the analysis service cannot load. **Executed reproduction:** importing `src.main` from the service root failed with `ModuleNotFoundError: No module named 'finding_quality'` despite installed dependencies. Align Compose and documented standalone startup with the Dockerfile.

14. **[P2] The routed code playground calls an endpoint absent from both active backends.**

    Location: [api.js:213](frontend/src/services/api.js#L213), [App.jsx:87](frontend/src/App.jsx#L87).

    `/dashboard/analysis` submits to `/api/analysis/analyze`. The Express API has no such route, and the active FastAPI app never includes the legacy `analysis_routes` router. Default Firebase `/api` forwarding sends this request to the Express API. An API health response can make the playground appear healthy while every analysis request fails. Implement an authenticated adapter to the current analysis service or remove the unavailable flow. **Executed verification:** the active Python route table lacks the endpoint; Express and Firebase routing were inspected.

15. **[P2] Report cache data crosses account boundaries in a shared browser.**

    Location: [ReportsPage.jsx:10](frontend/src/pages/ReportsPage.jsx#L10), [AuthContext.jsx:43](frontend/src/contexts/AuthContext.jsx#L43).

    Report and repository metadata is cached in localStorage under keys that omit the user ID. Logout does not clear these keys. After account A logs out and B logs in within five minutes, B's Reports page immediately renders A's cached metadata before refreshing; a failed refresh leaves it in component state. Scope caches to the authenticated user and clear private caches on logout. **Evidence: cache write/read and logout paths; no browser session test performed.**

16. **[P3] Repository critical/high totals concatenate strings.**

    Location: [RepositoryDetailsPage.jsx:55](frontend/src/pages/RepositoryDetailsPage.jsx#L55), [pullRequests.js:37](services/api-service/src/db/pullRequests.js#L37).

    PostgreSQL `COUNT` columns are bigint values, returned as strings by the configured `pg` client. The UI adds them without numeric conversion: `"2" + "3"` displays `23`; `"0" + "0"` displays `00`. Cast counts in SQL or normalize them to numbers before adding. **Evidence: SQL result types, absence of a custom bigint parser, and the JSX expression.**

Validation performed:

- Frontend: 38 tests pass; lint and production build pass.
- API: 175 default tests pass; lint passes. An additional 43 tests under `src/__tests__` pass when explicitly selected. `jest.config.js` matches only `tests/`, so normal `npm test` and CI omit those authentication, encryption, and finding utility suites.
- GitHub adapter: 20 tests pass; lint passes.
- Analysis service: 267 tests pass across the initial suite and targeted integration runs. Initially 15 Semgrep integration tests skipped because the native executable could not load system trust anchors. Providing the installed CA bundle and disabling Semgrep's version check allowed the detection integration tests to pass. The remaining rule-validation test timed out in the sandbox and passed outside it with authorized network access. No assertion failures remain.
- Total: 543 distinct existing tests passed. Lint passed in all three JavaScript projects; the frontend production build passed. These results do not cover the missing scenarios documented above.
- Five isolated Node reproductions passed their assertions of existing buggy behavior: analysis failure, empty rescan, failed webhook retry, browser-unbound OAuth state, and permissive CORS. Harness: `/private/tmp/mitig8it-review-repro.cjs`. Database and external requests were stubbed; this is not an end-to-end production test.
- Executed Python checks confirmed the comment-based Tier 1 bypass, missing playground route, and startup import failure.

Limits: no live GitHub OAuth/organization permission test, production deployment, browser UI audit, fresh database migration run, dependency vulnerability audit, or full container end-to-end run. Existing untracked planning/review documents were left intact. Address findings 1–6 first, then fix scan/review lifecycle consistency before relying on successful checks as a merge gate.
