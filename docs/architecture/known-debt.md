# Known engineering debt

Items an engineering review raised that were deliberately not fixed. Eight items from the same review were fixed in [PR 421](https://github.com/aicodesentry/mitig8it/pull/421): the blocking analysis handlers moved off the event loop, the repair lease stays alive while candidates combine, GitHub writes are sent once and only reads retry, the policy timeout became the one verification deadline, the auth-bypass rule's exclusion was anchored, OpenGrep scan paths were contained, the analysis internal secret is compared in constant time, and webhook unregister requires it. Nothing on this page is fixed.

Each entry states what the issue is, where it is, and why it was left. None of these is a correctness defect under the loads this system has seen; they are cost, clarity, and drift risks that were not worth taking alongside the hot-path fixes.

## Pinned pool connection

**What.** `claimNextQueuedRun` checks a client out of the pg pool, takes a session-scoped `pg_try_advisory_lock`, commits the claim transaction, and hands the caller a `releaseLease()` closure. The connection stays checked out for the whole analysis, which is minutes, because a session advisory lock dies with its session. Maximum analysis concurrency is therefore bounded by pool size rather than by worker capacity.

**Where.** `services/api-service/src/db/analysisRuns.js`, `claimNextQueuedRun`.

**Why deferred.** It is the property that makes the lease correct: a crashed connection releases its lease and a slow live worker cannot be reclaimed. The concurrency cost is already bounded explicitly in the orchestrator and covered by `tests/analysisQueueConcurrency.test.js`, and it is recorded as accepted residual risk in `HARDENING-TRACKER.md` rows 19 and 20. Replacing it means moving to an advisory lock held in a separate connection or to a lease table with heartbeats, which changes the recovery semantics and needs its own test pass.

## N+1 persistence

**What.** Findings are persisted one at a time. `persistAndFilter` loops over findings calling `upsertFinding`, and each call issues a select then an update or insert, so a 200-finding pull request is more than 200 sequential round trips. The same shape appears when applying suppressions, one `UPDATE findings` per suppressed row, and when persisting remediation evidence, one insert per record.

**Where.** `services/api-service/src/services/prAnalysisOrchestrator.js` (`persistAndFilter`, `applySuppressions`), `services/api-service/src/db/findings.js` (`upsert`), `services/api-service/src/db/remediation.js` (`persistEvidence`).

**Why deferred.** Finding counts per pull request are small in practice and each round trip is on a pooled local connection. The batched form already exists in the same file, `snapshotRun` inserts a whole run with one `jsonb_array_elements` statement, so the pattern is understood and the change is mechanical when finding volume justifies it. It touches the dedup and fingerprint path, which is the part of the system with the most behavioural tests.

## Shared failure classifier

**What.** Four independent mappings from an error to "retryable" or "fail closed", with no shared module. Two of them are in the same file and disagree: `ECONNREFUSED`, `ETIMEDOUT`, `EAI_AGAIN`, `ENOTFOUND`, and any 5xx are transient to one and not to the other.

**Where.** `services/api-service/src/services/prAnalysisOrchestrator.js` (`isTransientServiceError`, `isTransientInfrastructureError`), `services/api-service/src/services/remediationWorkflow.js` (an inline chain deciding `queued` against `inconclusive`), `services/api-service/src/clients/grpcConnection.js` (`isRetryableMetadataError`). The GitHub adapter has its own split in `services/github-service/src/services/githubInternalOperations.js`.

**Why deferred.** The two that disagree are answering different questions. One decides whether to retry a call, the other whether a required tier may be treated as absent, and fail-closed analysis deliberately treats fewer things as transient than a retry loop does. Unifying them means first writing down which question each caller is asking, which is a design task rather than a refactor. The divergence is currently documented only here.

## Contracts package

**What.** The repair request and policy shape is declared twice: as Pydantic models in the repair service and again as `DEFAULT_POLICY` plus a hand-built wire payload in the control plane. The only thing keeping them aligned is a test that reaches across the service boundary with a relative path to the exported JSON Schema.

**Where.** `services/remediation-service/src/models.py` and `contracts/repair-request.schema.json` on the Python side; `services/api-service/src/services/remediationPolicy.js` and `src/services/remediationWorkflow.js` on the Node side; `services/api-service/tests/repairRequestContract.test.js` is the sync mechanism.

**Why deferred.** Drift is already real, and it is bounded drift rather than breakage. The two copies disagree on `max_snapshot_files` (120 in `DEFAULT_POLICY`, 500 in `RepairPolicy`), `max_file_bytes` (500000 against 512000), `max_snapshot_bytes` (500000 against 10000000), and `max_output_chars` (64000 against 2000000), and `max_context_tokens` sits on the Node policy but on the Python `RepairLimits` rather than on `RepairPolicy`. In every case the control plane's value is the tighter one, so the request it sends is always inside what the service accepts and the schema test passes. A shared package means a published artifact and a release process for two languages, which is not worth it while one repository holds both. The risk is that the next divergence goes the other way, and nothing would catch it except that test.

## Module splits

**What.** Several modules carry more than one responsibility and are large enough that a reader cannot hold them.

**Where.** By line count, excluding generated protobuf: `services/github-service/src/services/githubInternalOperations.js` (1,821), `services/remediation-service/src/patches.py` (1,418), `services/api-service/src/db/remediation.js` (1,405), `services/api-service/src/services/prAnalysisOrchestrator.js` (1,288), `services/remediation-service/src/agent/loop.py` (1,190), `services/remediation-service/src/engine.py` (977), `services/remediation-service/src/executions.py` (955), `services/remediation-service/src/templates.py` (946).

**Why deferred.** These are the files under the most active change. Splitting them during the remediation work would have made every concurrent branch conflict, and a split that only moves code makes history harder to read for no behavioural gain. `templates.py` and `engine.py` in particular are still growing per family.

## RLS cast

**What.** Every tenant-scope row-level security policy casts the column rather than the setting: `installation_id::text = current_setting('app.tenant_id', true)` and `ra.user_id::text = current_setting('app.user_id', true)`. Coercing the row's key to text means the b-tree indexes on `installation_id` and `repository_access(user_id)` cannot serve the policy predicate, and a malformed `app.tenant_id` silently matches nothing instead of raising.

**Where.** `services/api-service/migrations/0013_remediation_control_plane.sql` (the ten tenant-scoped tables), `0014_remediation_control_plane_hardening.sql` (writer leases), `0022_remediation_job_evidence.sql`, and `services/remediation-service/migrations/0001_remediation_executions.sql`.

**Why deferred.** Silently matching nothing is the safe direction for a security predicate, and the row counts are small enough that the lost index has not shown up. Changing it means rewriting policies across four migrations, which must be a new migration rather than an edit, and it changes the failure mode from "returns nothing" to "raises", which needs a deliberate decision about what a malformed tenant setting should do.

## Frontend memoization

**What.** `RemediationPanel` recomputes a full O(n times m) longest-common-subsequence diff for every changed file on every render, with no `useMemo`. The component re-renders on each poll tick and on each `setFeedback`, `setNotice`, or `setBusy` call. The same render body also rebuilds several filters, a `Map`, and the file grouping each time.

**Where.** `frontend/src/components/RemediationPanel.jsx`, the `.map` over changes and the filter and grouping block above it; the diff itself is `longestCommonRows` in `frontend/src/lib/lineDiff.js`.

**Why deferred.** Diffs are small, the panel is one route, and no slowness has been reported. It is worth noting that the rest of the frontend does this correctly, so this is an inconsistency rather than a house style: `DashboardPage`, `PullRequestFindingsPage`, `RepositoriesPage`, and `OnboardingContext` all memoize equivalent work, and `RemediationPanel` imports `useCallback` but never `useMemo`.

## Test honesty

**What.** Part of the unit layer asserts against mocks rather than behaviour. The clearest case mocks the database module entirely and dispatches on SQL substrings, so tests named for session leases and skip-locked claims assert only that a string containing `pg_try_advisory_lock` was passed to a fake client. They pass whether or not the lock is session-scoped, whether the lock key is right, and whether `SKIP LOCKED` does anything. The frontend remediation panel tests mock the whole API surface.

**Where.** `services/api-service/tests/analysisRunsQueue.test.js` is the clearest example. Mock-assertion density is also high in `tests/remediation.test.js`, `tests/mergeController.test.js`, `tests/analysisTransientRetry.test.js`, and `tests/remediationActionWorker.test.js`. `frontend/src/components/__tests__/RemediationPanel.test.jsx` mocks `services/api`.

**Why deferred.** Real-Postgres integration suites cover the same paths (`services/api-service/tests/integration/access.integration.js` and `remediation.integration.js`), so this is duplicated confidence rather than a coverage hole, and the mock layer is what keeps CI fast without a database for most jobs. The honest statement of what is not covered already exists in `HARDENING-TRACKER.md` ("Remote writes simulated", "Real process crash not injected", "live GitHub/Firebase OAuth not exercised") and `HARDENING-HANDOFF.md`. What is missing is the same honesty at the point of the test, so a reader of `analysisRunsQueue.test.js` knows its assertions are structural.

## Quadratic work

**What.** Six loops whose cost is quadratic in an input this system does not currently make large.

**Where.**

| Location | Symbol | Shape |
| --- | --- | --- |
| `services/analysis-service/src/finding_quality.py` | `cluster_findings` | Each deduped finding is compared against every member of every existing cluster. Runs on every analysis. |
| `services/remediation-service/src/patches.py` | `combine_patch_bundles` | Per path, per patch, per changed range, scanning all previously accepted ranges. |
| `services/remediation-service/src/patches.py` | `bundles_conflict`, `_bundle_ranges` | Recomputes a line-by-line diff for every already-accepted bundle on every call. |
| `services/remediation-service/src/engine.py` | the candidate acceptance loop | Calls `bundles_conflict` once per pass, so the accepted set's diffs are re-derived from scratch. |
| `services/remediation-service/src/patches.py` | `_occurrences` | Naive substring search over file lines, used by `locate_hunk`. |
| `services/remediation-service/src/splitting.py` | `is_import_only`, `attribute_hunks` | List scans inside list comprehensions, and findings by hunks by prerequisites. |

**Why deferred.** Every input is bounded by policy: `max_files` is 5, `max_changed_lines` is 200, and a job carries a handful of findings, so the largest of these runs over single-digit collections. `cluster_findings` is the one that scales with something a user controls, the number of findings in a pull request, and it is the one to fix first if analysis latency becomes a complaint. PR 421 moved the combine loop onto a worker thread so it stops starving the lease heartbeat; the quadratic work itself was left in place deliberately, because the heartbeat was the defect and the cost was not.

## Detection gaps the vulnerable corpus measured

The September 2026 vulnerable-corpus run (`docs/validation/vulnerable-corpus-2026-09.md`)
put 171 labelled vulnerabilities in 23 repositories through both tiers. These are the gaps
it found and did not close, with the reason each was left.

**Cross-site scripting: 1 of 32 labelled vulnerabilities found.** Two separate causes, and
neither is a pattern that can be narrowed or widened.

*Template files are not analysed at all.* `TIER2_SUPPORTED_EXTENSIONS` in
`scripts/replay/prodfilters.py` and its production counterpart
`shouldFetchFullFileContent` list no template language, so `.html`, `.ejs`, `.pug`, `.dust`
and `.jinja2` files are never fetched or scanned. Eleven of the missed XSS labels are in
those files, including every reflected and stored XSS in NodeGoat and dvna. Adding a
template language is a scanner decision with its own precision question, not a rule edit.

*HTML built by string interpolation has no rule.* The remaining misses are
`` return `<img src="${src}" alt="${alt}">` `` in TypeScript and `'<br/>%s' % comic.text` in
Python, which is what CVE-2026-61824, CVE-2026-68921 and GHSA-75mw-h36v-2jv7 all are. No
rule in either tier looks for it. This is a new rule, not a narrowing.

**Command injection through one variable.** `cwe-78.js-exec-interpolated` requires the
template literal to be inside the `exec` call. Four labelled vulnerabilities
(`sebhildebrandt/systeminformation` CVE-2026-50289 and all three `electerm/electerm`
CVE-2026-49255 sites) build the command on one line and run it on the next. Matching
`exec($VAR)` for any variable is how a rule reaches a precision of 0.02, so this needs one
hop of data flow, which the AST pattern engine does not provide.

**A tier 1 rule reports one finding per file.** `pattern_findings` in
`services/analysis-service/src/main.py` emits at most one finding per rule per file, at the
first match. `enrocrypt/hashing.py` offers eight digests including MD5; `crypto.weak.hash`
reports the first one and the CVE is at the eighth. Nine of the 18 labels that were found in
the file but not on the line are this. It keeps a file with fifty weak hashes from producing
fifty comments, which is why it is there, and it caps recall on any file with more than one
instance of the same defect.

**Repair templates need a function they can call.** The route requirement this entry used to
describe is gone: `sites.js_site_for_line` falls back from the enclosing route to the enclosing
function, method or `exports.name` binding, and the 123 `enclosing_route_not_found` refusals on
the corpus are now 0. The reach barely moved with it, from 25 templated findings to 30, because
the refusals moved down to the next obstacle rather than away. The largest is now
`enclosing_function_not_found`: 67 findings in code at module scope, where there is no function
for a generated test to drive at all. Next is `module_not_loadable_by_node`, 52 findings in
TypeScript, which plain `node` cannot `require` and for which the sandbox has no toolchain.
`docs/validation/vulnerable-corpus-2026-09.md` has the full before and after.

**Three rules the corpus could not decide.** `xss.unsafe_html_render` (16 findings, 2
adjudicated, 0.50), `auth.bypass.missing_check` (8 findings, 1 adjudicated, 0.00) and
`opengrep.cwe-798.hardcoded-secret-js` (5 findings, 2 adjudicated, 0.50) are all below the
three adjudicated findings the posting policy requires before it will act. A larger hand-read
sample than 40 of 1687 is the cheapest way to close this.

**`opengrep.cwe-489.py-debug-constant-true` is one reading short of re-enabling.** It has two
measured hits, both `DEBUG = True` in a real Django settings module, which is exactly the
shape its quarantine reason doubted. The quarantine reason is now known to be wrong and the
rule still cannot come back, because the policy asks for three.

**Pre-existing tier 2 rules pass their check id as `internal_type`.** The rules in
`javascript.yml` and `python.yml` declare no `internal_type`, so `opengrep_runner` sets it to
the check id and `taxonomy.canonicalize_internal_type` returns it unchanged: a finding
arrives as `internal_type: "cwe-502.pickle-loads"`, a category of one that nothing else can
group with. `tests/test_tier2_rule_metadata.py` forbids this for the coverage rules and the
older files are out of its scope. `scripts/replay/score.py` works around it by deriving the
class from the CWE.

## Provenance

There is no issue tracker entry or written review document behind this list. It was reconstructed from the code, from PR 421, and from the residual-risk notes in `HARDENING-TRACKER.md` and `HARDENING-HANDOFF.md`. Every location above was confirmed in the source at the time of writing.

## From the database audit of 2026-09-22

- Budget reservations are a flat 0.05 USD for the snapshotting stage only; settled jobs have cost up to 0.28 USD, so the budget gate cannot refuse an over-budget job. Reserve per stage from the policy estimate (`services/api-service/src/db/remediation.js`, `reserveUsage`; `remediationPolicy.js`, `stageEstimate`).
- Two old jobs carry numeric gRPC status codes in `failure_reason.code` (3 and 9) from before the error mapper normalised codes; consumers that compare strings miss them. Normalise at the boundary and backfill the two rows.
- One candidate row from 2026-09-20 has the legacy bare-array `file_manifest` shape; its job is still `ready`. Make the reader tolerant or supersede the job.
- Sandbox check output tails are persisted in `remediation_job_evidence` without redaction; on a customer repository a harness assertion could echo repository values. Redact or hash values in tails before persisting (`services/api-service/src/services/remediationWorkflow.js`, `buildEvidenceRecords`).
- Inline fix publication and feedback are not audited in `audit_logs`; apply and merge are. Emit audit rows on both.
- `evidence_details` is empty on findings persisted before migration 0007; expected, but reports that read it should treat empty as unknown.
- Autovacuum has not run on the small remediation tables; harmless at the current size, revisit when `remediation_jobs` grows.
- The application connects as a role with `BYPASSRLS`, so the forced row-level security policies are defined but never enforced in production. Provision a non-bypass runtime role before any second tenant is onboarded.
