# TASK 03: Fix webhook deduplication permanently dropping failed and orphaned deliveries

Repo: mitig8it. Service: `services/api-service` (Node.js/Express, CommonJS, PostgreSQL 15).
Primary file: `services/api-service/src/routes/webhooks.js`.

## Problem

`POST /webhooks/github` deduplicates on the presence of a `webhook_deliveries` row, ignoring that row's status.

Current code, `services/api-service/src/routes/webhooks.js:51-59`:

```js
const existing = await pool.query(
  'SELECT id, processing_status FROM webhook_deliveries WHERE delivery_id = $1',
  [deliveryId]
);

if (existing.rowCount > 0) {
  return res.status(200).json({ success: true, deduplicated: true });
}
```

`processing_status` is selected and then discarded. The row is inserted with status `received` (line 61) before any work happens, flipped to `processed` on success (line 240), and flipped to `failed` in the catch block (line 258) which then returns 500.

Two ways a delivery becomes permanently unprocessable:

1. **Processing threw.** The row is left at `failed` and the endpoint returns 500. GitHub shows the delivery as failed. When anyone redelivers it (GitHub App → Advanced → Redeliver, or `POST /app/hook/deliveries/{id}/attempts`), the redelivery carries the same `X-GitHub-Delivery` GUID, hits the check above, and returns 200 `deduplicated: true` without doing anything. The documented recovery path for a failed webhook is a silent no-op.
2. **The instance died mid-processing.** The row is stuck at `received` forever with no catch block ever running. This is not hypothetical here: the API runs on Cloud Run with no `--min-instances` and no `--no-cpu-throttling`, and the orchestrator does its work after the HTTP response, so instances are reaped mid-flight by design. Any redelivery is again a no-op.

In both cases the practical result is that the pull request is never analyzed and nothing surfaces the gap.

There is also a time-of-check-to-time-of-use race in the existing shape: two concurrent deliveries with the same `delivery_id` both see an empty SELECT, both attempt the INSERT, and the second violates the `delivery_id` unique constraint (`services/api-service/migrations/0001_initial_schema.sql:186`), landing in the catch block and marking a delivery `failed` that was actually a duplicate.

## Required changes

### 1. Replace the check-then-insert with a single atomic claim

Delete the `SELECT ... WHERE delivery_id` block and the separate `INSERT INTO webhook_deliveries` that follows it. Replace both with one statement that claims the delivery only when it is genuinely claimable:

```js
const claim = await pool.query(
  `INSERT INTO webhook_deliveries (delivery_id, event_type, action, processing_status, received_at)
   VALUES ($1, $2, $3, 'received', NOW())
   ON CONFLICT (delivery_id) DO UPDATE
      SET processing_status = 'received',
          received_at = NOW(),
          processed_at = NULL,
          error_message = NULL
    WHERE webhook_deliveries.processing_status = 'failed'
       OR (webhook_deliveries.processing_status = 'received'
           AND webhook_deliveries.received_at < NOW() - make_interval(mins => $4::int))
   RETURNING id, (xmax = 0) AS inserted`,
  [deliveryId, event, payload.action || null, staleMinutes]
);
```

Semantics this produces:

- **No existing row** — inserts, `inserted = true`, proceed with processing.
- **Existing row is `failed`** — reclaimed, `inserted = false`, proceed with processing. This is the fix for case 1.
- **Existing row is `received` and older than the staleness window** — treated as orphaned, reclaimed, proceed. This is the fix for case 2.
- **Existing row is `received` and recent** — the `DO UPDATE ... WHERE` does not match, so zero rows return. Another worker owns it; do not process.
- **Existing row is `processed`** — zero rows return. A genuine duplicate.

Note why this is race-safe: `ON CONFLICT DO UPDATE` takes a row lock and re-evaluates its `WHERE` against the committed row, so if two workers race for the same stale row, the loser sees the winner's refreshed `received_at` and correctly returns zero rows. Do not reintroduce a preliminary SELECT.

When `claim.rowCount === 0`, run one follow-up read to distinguish the two zero-row cases and respond without processing:

```js
const existing = await pool.query(
  'SELECT processing_status FROM webhook_deliveries WHERE delivery_id = $1',
  [deliveryId]
);
const status = existing.rows[0]?.processing_status || 'unknown';
return res.status(200).json({
  success: true,
  deduplicated: true,
  reason: status === 'processed' ? 'already_processed' : 'in_flight',
});
```

Return 200 in both cases. Returning 5xx for an in-flight duplicate would mark a delivery failed in GitHub's log when nothing is wrong.

**Intended behaviour, do not "fix" it:** a redelivery of an already-`processed` webhook is a deliberate no-op. Idempotency is the point. Forcing a fresh analysis is a separate concern that belongs behind an explicit re-run action, not behind webhook redelivery.

### 2. Make the staleness window configurable

Add a module-level helper mirroring the existing pattern at `services/api-service/src/services/prAnalysisOrchestrator.js:955`:

```js
function webhookStaleMinutes() {
  const parsed = Number(process.env.WEBHOOK_STALE_MINUTES || 15);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 15;
}
```

Default 15 minutes. It must be shorter than the analysis queue's 20-minute stale reclaim (`ANALYSIS_QUEUE_STALE_MINUTES`) so a webhook can be re-driven before its downstream run is independently reclaimed. Add `WEBHOOK_STALE_MINUTES` to `.env.example` and to the env var table in `docs/getting-started/environment.md`.

### 3. Prevent the fix from creating duplicate analysis runs

This is mandatory. Without it, fixing dedup introduces a worse bug.

`services/api-service/src/routes/webhooks.js:215-221` inserts into `analysis_runs` unconditionally, with no conflict handling. Once reprocessing is possible, a reclaimed delivery for a PR that already has a queued run will create a second run for the same commit, producing a duplicate analysis and a duplicate posted review.

Inside the existing `transaction(...)` block, before the `INSERT INTO analysis_runs`, check for an active run on the same pull request and commit:

```js
const activeRun = await client.query(
  `SELECT id FROM analysis_runs
    WHERE pull_request_id = $1
      AND commit_sha = $2
      AND status IN ('pending', 'running')
    LIMIT 1`,
  [prResult.rows[0].id, pr.head.sha]
);
```

If a row exists, do not insert. Leave `analysisPayload` null, and have the handler respond with `analysis_queued: false, already_queued: true`. The existing run is already claimable by the queue worker, so no notification is needed. If no row exists, insert as today.

Scoping on `commit_sha` matters: a `synchronize` event with a new head SHA is a legitimately new run and must still be created.

### 4. Log the claim outcome

Emit one structured log line per delivery recording which path was taken — `inserted`, `reclaimed_failed`, `reclaimed_stale`, `already_processed`, or `in_flight` — alongside `deliveryId`, `event`, and `correlationId`, using the existing `logger`. Derive `reclaimed_*` from the pre-claim status where available; it is acceptable to log `reclaimed` without distinguishing the two sub-cases if that keeps the claim to a single query. This is the only visibility into whether orphaned deliveries are actually occurring in production, so it must not be dropped.

### 5. Leave the failure path alone

The catch block keeps marking the row `failed` and returning 500. That is correct and is now genuinely recoverable, because a redelivery will reclaim it.

## Tests

Extend `services/api-service/tests/webhook.test.js`, which currently holds only 2 tests. Follow its existing conventions: `jest.mock('../src/config/database')`, mocked `pool.query`, and a valid HMAC signature helper (invalid-signature and inactive-repository cases are already covered there).

Cover at minimum:

1. A delivery whose existing row is `processed` returns 200 with `reason: 'already_processed'` and performs no processing queries.
2. A delivery whose existing row is `failed` is reclaimed and processed through to completion. Assert the claim query ran and processing continued.
3. A delivery whose existing row is `received` and recent returns 200 with `reason: 'in_flight'` and does not process.
4. A delivery whose existing row is `received` and stale is reclaimed and processed.
5. A `pull_request` event for a PR that already has a `pending` run at the same `commit_sha` does not insert a new `analysis_runs` row. Assert no `pool.query`/`client.query` call contains `INSERT INTO analysis_runs`.
6. A `synchronize` event with a different `commit_sha` does create a new run.
7. The claim query passes `staleMinutes` as a parameter, not string-interpolated into the SQL.

Simulate cases 1-4 by controlling what the mocked claim query returns (`rowCount: 0` or `rowCount: 1`) and what the follow-up status SELECT returns, rather than by trying to fake clock behaviour.

## Acceptance criteria

1. `npm run lint` and `npm test` pass in `services/api-service`; all existing tests still pass alongside the new ones.
2. No schema migration is added — this task is code-only. The `delivery_id` unique constraint the claim relies on already exists.
3. All SQL stays parameterized. `make_interval(mins => $4::int)` is the parameterized form; do not build an interval by string concatenation.
4. `WEBHOOK_STALE_MINUTES` is documented in `.env.example` and `docs/getting-started/environment.md`.
5. The PR description states explicitly what happens on redelivery of a `processed` webhook (no-op, intended) and confirms the duplicate-run guard from step 3 is present and tested.

## Conventions

- Commit message: single line, imperative, no Co-Authored-By trailer.
- CommonJS requires, existing `{ error: '...' }` response shape, existing `logger` usage.
- Do not touch `services/github-service/src/routes/webhooks.js` in this task — that file is a separate, unauthenticated second ingress slated for deletion in its own change.
- Do not add Cloud Run `--min-instances` / `--no-cpu-throttling` flags here; that is a related but separate deploy-configuration task.
