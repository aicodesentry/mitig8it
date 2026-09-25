# TASK 02: Fix cross-repository scope bug in suppression creation

Repo: mitig8it. Service: `services/api-service` (Node.js/Express, CommonJS, PostgreSQL 15).
File: `services/api-service/src/routes/suppressions.js`.

## Problem

`POST /api/suppressions` verifies that the caller has access to the supplied `repository_id`, but then resolves `finding_id` without checking that the finding actually belongs to that repository.

Current code, `services/api-service/src/routes/suppressions.js:52-55`:

```js
if (!resolvedFingerprint && resolvedFindingId) {
  const finding = await pool.query('SELECT fingerprint FROM findings WHERE id = $1', [resolvedFindingId]);
  resolvedFingerprint = finding.rows[0]?.fingerprint;
}
```

There is no `repository_id` predicate. The repository access check above it (lines 37-47) only proves the caller can access the repository named in the request body, not the repository that owns the finding.

Two consequences:

1. **Broken access control (OWASP A01).** A caller with access to repo A can pass `repository_id = A` together with a `finding_id` belonging to repo B, which they may have no access to. The suppression row is created under repo A but stores repo B's `fingerprint` and a `finding_id` pointing into repo B. `GET /api/suppressions` then `LEFT JOIN findings f ON f.id = s.finding_id` (line 22) and returns `f.title, f.category, f.severity` — leaking another repository's finding metadata to the caller. Exploitation requires knowing a finding UUID from the other repository, so this is not trivially enumerable, but it is still a real cross-tenant boundary violation in a security product.
2. **Data integrity.** Suppression matching is fingerprint-based. A suppression scoped to repo A carrying a fingerprint computed from repo B's code silently suppresses (or fails to suppress) the wrong findings.

The `findings` table has a `repository_id UUID` column (`services/api-service/migrations/0001_initial_schema.sql:127`) with an index at line 282, so scoping the lookup is a one-predicate change with no schema work.

## Required changes

### 1. Scope the finding lookup to the requested repository

In `services/api-service/src/routes/suppressions.js`, change the lookup to require the finding to belong to the repository the caller already proved access to:

```js
if (!resolvedFingerprint && resolvedFindingId) {
  const finding = await pool.query(
    'SELECT fingerprint FROM findings WHERE id = $1 AND repository_id = $2',
    [resolvedFindingId, repository_id]
  );
  resolvedFingerprint = finding.rows[0]?.fingerprint;
}
```

Then handle the mismatch case explicitly rather than falling through to the generic message. When `finding_id` was supplied but no row matched, return `404` with `{ error: 'Finding not found' }`. Return `404`, not `403`, so the response does not disclose whether the finding exists in another repository. Keep the existing `400 'Fingerprint could not be resolved'` for the case where neither a `fingerprint` nor a resolvable `finding_id` was given.

Note the ordering requirement: the repository access check at lines 37-47 must stay ahead of this lookup, so the `repository_id` used as the predicate is always one the caller can access.

### 2. Harden the read path (defense in depth)

Any suppression rows already written by the buggy path would still leak through `GET /api/suppressions`. Constrain the join so a row can only ever surface finding metadata from its own repository. In the `GET /suppressions` query (line 22), change:

```sql
LEFT JOIN findings f ON f.id = s.finding_id
```

to:

```sql
LEFT JOIN findings f ON f.id = s.finding_id AND f.repository_id = s.repository_id
```

This keeps the row visible (it is the caller's own suppression) but nulls out the foreign finding's title, category, and severity.

### 3. Check for existing bad rows

Run this against production (read-only) and report the count in the PR description:

```sql
SELECT COUNT(*)
FROM suppressions s
JOIN findings f ON f.id = s.finding_id
WHERE f.repository_id IS DISTINCT FROM s.repository_id;
```

If the count is zero, note that and change nothing else. If it is non-zero, do NOT delete the rows in this task — report them and open a follow-up, since deleting a suppression silently re-opens findings for the user who suppressed them.

### 4. Tests

There is currently no test file for the suppressions routes. Create `services/api-service/tests/suppressions.test.js` following the existing pattern in `services/api-service/tests/repo-access-control.test.js`: `jest.mock('../src/config/database')` with a mocked `pool.query`, a `jwt.sign` helper for the auth token, and `supertest` against `createApp()`.

Cover at minimum:

1. `POST /api/suppressions` with a `finding_id` belonging to a different repository returns 404 and performs no `INSERT` (assert no `pool.query` call contains `INSERT INTO suppressions`).
2. `POST /api/suppressions` with a `finding_id` in the correct repository returns 201 and stores the fingerprint read from that finding.
3. `POST /api/suppressions` with an explicit `fingerprint` and no `finding_id` still works (the lookup is skipped).
4. `POST /api/suppressions` for a repository the caller cannot access returns 404 (existing behaviour, guard against regression).
5. The finding-lookup query passes both `finding_id` and `repository_id` as parameters. Assert on the params array, not on SQL string formatting.

## Acceptance criteria

1. `npm run lint` and `npm test` pass in `services/api-service`; the existing 170 tests still pass and the new suppression tests pass.
2. No schema migration is added — this task is code-only.
3. The production count query from step 3 has been run and its result is stated in the PR description.
4. Manual reasoning check documented in the PR: with the fix, a caller holding access to repo A and a valid finding UUID from repo B receives 404 and no row is written.

## Conventions

- Commit message: single line, imperative, no Co-Authored-By trailer.
- CommonJS requires, existing error-response shape (`{ error: '...' }`), parameterized queries only — never interpolate values into SQL.
- Do not refactor the rest of the file, do not rename anything codesentry-related, and do not touch other routes in this task.
