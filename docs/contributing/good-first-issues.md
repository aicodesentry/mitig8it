# Good first issues

Eight bounded pieces of work, each drawn from [../architecture/known-debt.md](../architecture/known-debt.md),
where the problem is already understood and written down. None of them needs a decision from
anyone. Each says the file to start in, what "done" looks like, and how to check.

Set up first: [CONTRIBUTING.md](../../CONTRIBUTING.md), then `make deps`.

If you start one, say so on the issue so two people do not do it twice.

---

## 1. Memoize the diff in the remediation panel

**Start in** `frontend/src/components/RemediationPanel.jsx`.

`RemediationPanel` recomputes a full longest-common-subsequence diff for every changed file on
every render, with no `useMemo`. It re-renders on each poll tick and on each `setFeedback`,
`setNotice` and `setBusy` call, so the diff is recomputed for a state change that cannot have
altered it. The same render body also rebuilds several filters, a `Map` and the file grouping each
time. The component imports `useCallback` and never `useMemo`.

Wrap the `longestCommonRows` call (`frontend/src/lib/lineDiff.js`) and the grouping block in
`useMemo`, keyed on the candidate data rather than on the component's own UI state.

`DashboardPage`, `PullRequestFindingsPage`, `RepositoriesPage` and `OnboardingContext` all memoize
equivalent work. Follow whichever of those reads closest.

**Verify.** `make test-frontend`. The existing
`frontend/src/components/__tests__/RemediationPanel.test.jsx` must still pass unchanged: if you
have to edit it, the memo key is wrong.

---

## 2. Say in the test what the test actually asserts

**Start in** `services/api-service/tests/analysisRunsQueue.test.js`.

That file mocks the database module entirely and dispatches on SQL substrings. Tests named for
session leases and skip-locked claims assert only that a string containing
`pg_try_advisory_lock` was passed to a fake client. They pass whether or not the lock is
session-scoped, whether the lock key is right, and whether `SKIP LOCKED` does anything. The real
coverage is in `services/api-service/tests/integration/access.integration.js` and
`remediation.integration.js`, which run against Postgres.

This is a documentation fix at the point of the test, not a rewrite. Add a header comment to the
file, and a line to each affected test name or description, saying that the assertion is
structural and naming the integration test that covers the behaviour. Do the same for
`services/api-service/tests/remediation.test.js` and
`services/api-service/tests/analysisTransientRetry.test.js`, which have the same density, and for
`frontend/src/components/__tests__/RemediationPanel.test.jsx`, which mocks the whole API surface.

**Verify.** `make test-api` and `make test-frontend` still pass. Nothing should change but the
text. The point is that a reader of the file knows what it proves.

---

## 3. Give the contract test a direction

**Start in** `services/api-service/tests/repairRequestContract.test.js`.

The repair request and policy shape is declared twice: Pydantic models in
`services/remediation-service/src/models.py` and `DEFAULT_POLICY` in
`services/api-service/src/services/remediationPolicy.js`. Four limits have already drifted, and
every one of them drifted in the safe direction, so nothing catches it:

| Limit | Control plane | Repair service |
| --- | ---: | ---: |
| `max_snapshot_files` | 120 | 500 |
| `max_file_bytes` | 500000 | 512000 |
| `max_snapshot_bytes` | 500000 | 10000000 |
| `max_output_chars` | 64000 | 2000000 |

The control plane being tighter is why the request it sends is always inside what the service
accepts. Nothing asserts that it stays that way, and the next divergence may go the other way.

Add a test asserting the invariant directly: for each shared numeric limit, the control plane's
value is less than or equal to the repair service's. Read the Python side from
`services/remediation-service/contracts/repair-request.schema.json`, which the existing test already reaches for, rather than
parsing Python.

**Verify.** `make test-api`. Then flip one `DEFAULT_POLICY` value above its Python counterpart by
hand and confirm the new test fails; put it back.

---

## 4. Batch the suppression update

**Start in** `services/api-service/src/services/prAnalysisOrchestrator.js`, function
`applySuppressions`.

Applying suppressions issues one `UPDATE findings` per suppressed row. The batched form of this
pattern already exists in the same codebase: `snapshotRun` in `services/api-service/src/db/remediation.js`
inserts a whole run with a single `jsonb_array_elements` statement. Copy that shape: one statement
taking an array of ids.

This is the smallest of the three N+1 sites in the known-debt entry and the one furthest from the
dedup and fingerprint logic, which is why it is the one to start with rather than
`persistAndFilter`.

**Verify.** `make test-api`, then the integration suite, which needs a disposable database:
`cd services/api-service && npm run test:integration:remediation`. The number of suppressed
findings must be identical before and after.

---

## 5. Write down which question each failure classifier answers

**Start in** `services/api-service/src/services/prAnalysisOrchestrator.js`.

There are four independent mappings from an error to "retryable" or "fail closed", with no shared
module. Two of them live in this one file and disagree: `isTransientServiceError` and
`isTransientInfrastructureError` take opposite views of `ECONNREFUSED`, `ETIMEDOUT`, `EAI_AGAIN`,
`ENOTFOUND` and any 5xx. The other two are the inline chain in
`services/api-service/src/services/remediationWorkflow.js` that decides `queued` against
`inconclusive`, and `isRetryableMetadataError` in
`services/api-service/src/clients/grpcConnection.js`. The github service has its own split in
`services/github-service/src/services/githubInternalOperations.js`.

The disagreement is probably correct: one decides whether to retry a call, the other whether a
required tier may be treated as absent, and fail-closed analysis should treat fewer things as
transient than a retry loop does. Nobody has written that down, so it currently reads as a bug.

Do not unify them. Add a doc comment above each of the five, naming the question it answers, who
calls it, and what happens on a wrong answer in each direction. Then add a short section to
`docs/architecture/known-debt.md` replacing the current entry with what you found.

**Verify.** `make test-api` and `make test-github` still pass. The value here is that the next
person to look does not "fix" the disagreement.

---

## 6. Normalise the two numeric gRPC status codes

**Start in** `services/api-service/src/services/remediationWorkflow.js`.

Two old job rows carry a numeric gRPC status code in `failure_reason.code` (the values 3 and 9),
written before the error mapper normalised codes to strings. Consumers that compare strings miss
them silently.

Two parts. Normalise at the boundary so a numeric code can never be persisted again, and add a
migration that backfills the two existing rows to their string equivalents. The mapping is in the
error mapper; 3 is `INVALID_ARGUMENT` and 9 is `FAILED_PRECONDITION`.

**Verify.** `make test-api`, plus a test that a numeric code arriving at the boundary is stored as
a string. Migrations live in `services/api-service/migrations/`; add a new one rather than editing
an existing file.

---

## 7. Audit the two actions that are not audited

**Start in** `services/api-service/src/services/remediationWorkflow.js`.

`audit_logs` records an apply and a merge. It does not record inline fix publication or user
feedback, so the record of what the product did to a repository has two holes in it. The database
audit of 22 September 2026 found this.

Emit an audit row on both, with the same shape the existing apply and merge rows use. Find those
two call sites and follow them exactly: the same actor field, the same resource identifiers, the
same reason string convention.

**Verify.** `make test-api`, then
`cd services/api-service && npm run test:integration:lifecycle`, which exercises the lifecycle
against a real database and is where an assertion on the new rows belongs.

---

## 8. Redact the sandbox check output before it is persisted

**Start in** `services/api-service/src/services/remediationWorkflow.js`, function
`buildEvidenceRecords`.

Tails of sandbox check output are persisted into `remediation_job_evidence` without redaction. On
a customer repository, a harness assertion that prints a value it compared would put that value in
the evidence record, which the evidence endpoint then returns.

Redact or hash the values in those tails before they are persisted. The service already has a
redaction helper used on traces and logs; reuse it rather than writing a second one, so there is
one definition of what a secret looks like.

Note what this does and does not change: `GET /api/remediations/:id/evidence` must still return a
useful record, so a redacted tail should keep the structure and the check's own exit status. An
evidence record nobody can read is not an improvement.

**Verify.** `make test-api`, plus a test that a check tail containing a value matching the
redaction pattern is stored redacted. The adversarial fixtures under
`benchmarks/remediation/fixtures/` are the right shape to borrow a hostile output from.

---

## What is deliberately not on this list

These are in the known-debt document and are not first issues, for reasons the document gives:

- **The pinned pool connection.** Changing it changes lease recovery semantics and needs its own
  test pass.
- **The module splits.** Eight files over 900 lines each, all under active change. A split now
  conflicts with every concurrent branch.
- **The row-level security cast.** It spans four migrations and flips a failure mode from
  "returns nothing" to "raises", which is a decision rather than a refactor.
- **The six quarantined tier 1 rules.** Each needs a rule design, not a regex repair: a null check
  has to know what can be null, an authorization rule what a route handler is.
- **The cross-site scripting and command injection detection gaps.** New rules and one hop of data
  flow the AST pattern engine does not provide.
