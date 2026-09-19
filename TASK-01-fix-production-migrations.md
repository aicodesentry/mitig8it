# TASK 01: Fix silent no-op production database migrations

Repo: mitig8it (local path: this repository). Service affected: `services/api-service` (Node.js/Express, deployed to Google Cloud Run via `.github/workflows/deploy-api-cloudrun.yml`). Database: PostgreSQL 15.

## Problem

Production migrations have never run, and every layer reports success anyway.

Evidence (all verified in current code):

1. `services/api-service/Dockerfile.prod` copies only `package*.json` and `src/`:
   ```dockerfile
   COPY package*.json ./
   RUN npm ci --omit=dev
   COPY src ./src
   ```
   The `services/api-service/migrations/` directory (9 files, `0001_initial_schema.sql` through `0009_analysis_run_queue_indexes.sql`) is never copied into the image.
2. `services/api-service/src/services/migrationRunner.js:6` resolves `MIGRATIONS_DIR = path.resolve(__dirname, '../../migrations')`, which is `/app/migrations` inside the image. That path does not exist in the production image.
3. `listMigrationFiles()` (migrationRunner.js:8-11) returns `[]` when the directory is missing, instead of throwing. Therefore `planMigrations()` finds zero pending migrations.
4. The deploy workflow (`.github/workflows/deploy-api-cloudrun.yml`, step "Run API migrations from release image") runs `docker run --rm ... "$IMAGE" npm run db:migrate`, which exits 0 having applied nothing.
5. At startup, `ensureDatabaseSchema()` (`src/services/schemaBootstrap.js`) in production defaults to verify-only mode (`AUTO_MIGRATE` unset and `NODE_ENV=production`), calls `getPendingMigrations()`, gets `[]` for the same reason, and logs "API database schema is up to date".
6. Corroboration that this failed in practice: `scripts/p0-live-migration.sql`, `scripts/p1-verification.sql`, and `scripts/profile-hardening-live.sql` at repo root are hand-written re-implementations of migrations 0001/0002/0008, with headers saying to run them manually against the live database. They exist because the pipeline silently did nothing.

Consequence: the production schema is whatever the manual scripts happened to create. Migrations 0003 through 0007 and 0009 may be partially or fully absent in production (`src/db/analysisRuns.js` contains error-code-driven fallbacks catching Postgres errors `42P01`/`42703`, which is runtime evidence of missing schema).

## Required changes

Make each change exactly as specified. Do not switch to a migration framework in this task, and do not refactor unrelated code.

### 1. Ship migrations in the production image

In `services/api-service/Dockerfile.prod`, after `COPY src ./src`, add:

```dockerfile
COPY migrations ./migrations
```

Check `services/api-service/Dockerfile` (the dev image) for the same omission and fix it the same way if present.

### 2. Make a missing migrations directory a hard error

In `services/api-service/src/services/migrationRunner.js`, change `listMigrationFiles()` so a missing directory throws instead of returning `[]`:

```js
function listMigrationFiles(migrationsDir = MIGRATIONS_DIR) {
  if (!fs.existsSync(migrationsDir)) {
    throw new Error(
      `Migrations directory not found: ${migrationsDir}. ` +
      'The deployment artifact is missing the migrations/ folder; refusing to treat this as "no pending migrations".'
    );
  }
  // ... unchanged
}
```

Also throw if the directory exists but contains zero `.sql` files (same failure class: a bad COPY of an empty folder must not pass as success).

Update `tests/migrationRunner.test.js` accordingly: add a test asserting that `listMigrationFiles('/nonexistent')` throws, and one asserting an empty directory throws. Fix any existing tests that relied on the old `[]` behavior.

### 3. Prevent concurrent migration races

In `applyMigrations()` in the same file, take a Postgres advisory lock for the whole run so two concurrent deploys (or a deploy racing app startup with `AUTO_MIGRATE=true`) cannot interleave:

```js
await client.query('SELECT pg_advisory_lock($1)', [727274]); // arbitrary fixed app-wide key
try {
  // existing planMigrations + per-migration BEGIN/COMMIT loop, unchanged
} finally {
  await client.query('SELECT pg_advisory_unlock($1)', [727274]);
}
```

The lock must be taken on the same `client` connection used for the migration loop (advisory locks are per-session). Keep the existing per-migration transaction and checksum logic exactly as is.

### 4. Add a CI guard so this class of bug cannot recur

In `.github/workflows/deploy-api-cloudrun.yml`, after the "Build API image" step and before the migration step, add:

```yaml
      - name: Assert migrations are in the release image
        run: |
          docker run --rm "$IMAGE" sh -c 'ls migrations/*.sql'
```

This fails the deploy if the image ever ships without migration files again. If other deploy workflows (e.g., for other services) run `db:migrate` from an image, add the same guard there.

### 5. Make the first real production run safe (reconciliation)

When migrations finally run for real against production, `schema_migrations` will be empty (or missing) while much of the schema already exists from the manual scripts. Handle this as follows:

a. Audit each of the 9 files in `services/api-service/migrations/` for idempotency against a database that already has partial schema: every `CREATE TABLE`, `CREATE INDEX`, `ALTER TABLE ... ADD COLUMN` must use `IF NOT EXISTS`; every `ADD CONSTRAINT` must be guarded (Postgres has no `ADD CONSTRAINT IF NOT EXISTS` for most forms, so wrap in a `DO $$ ... EXCEPTION WHEN duplicate_object THEN NULL; $$` block or check `pg_constraint` first). `0001` is already written in this reconciliation style; verify the others and patch any non-idempotent statement. Do NOT change the semantics of any migration, only its guards. Note: `planMigrations()` compares checksums of applied migrations only; since none are recorded as applied in production, editing the files does not trigger checksum mismatch there. For any environment where `schema_migrations` already has rows (e.g., local dev databases), document that developers must reset with the existing local reset script.

b. Do not hand-edit `schema_migrations` in production and do not build a separate baseline script. With all 9 files idempotent, the correct reconciliation is simply to run `npm run db:migrate` once against production: it applies each file (no-op where the manual scripts already created objects, real changes where they did not) and records all 9 rows in the ledger. From then on the normal pipeline works.

c. Precondition for the production run, to be stated in the PR description as an operator step: take a Cloud SQL backup/snapshot immediately before the first real migration run.

d. After the production run succeeds, delete `scripts/p0-live-migration.sql`, `scripts/p1-verification.sql`, and `scripts/profile-hardening-live.sql` (superseded), and remove the `isSchemaMismatch` fallback branches in `src/db/analysisRuns.js` in a FOLLOW-UP task, not this one.

### 6. Integration test in CI

In the api-service CI job (`.github/workflows/ci.yml`), add a Postgres 15 service container and a step that proves the pipeline end to end:

```yaml
      - name: Migration pipeline check
        env:
          DATABASE_URL: postgres://postgres:postgres@localhost:5432/postgres
        working-directory: services/api-service
        run: |
          npm run db:migrate
          npm run db:verify
          npm run db:migrate   # second run must apply zero migrations and exit 0
```

This validates: all migrations apply cleanly to a fresh database, the verify script agrees, and re-running is a no-op via the checksum ledger. If the workflow already has a Postgres service for other tests, reuse it.

## Acceptance criteria (all must pass)

1. `docker build -f services/api-service/Dockerfile.prod services/api-service` then `docker run --rm <image> sh -c 'ls migrations/*.sql'` lists all 9 files.
2. `docker run --rm -e DATABASE_URL=<fresh postgres> <image> npm run db:migrate` applies all 9 migrations and logs their names; a second identical run applies zero.
3. With the migrations directory deleted from a test image, `npm run db:migrate` and `npm run db:verify` both exit non-zero with the explicit "Migrations directory not found" error. Startup via `ensureDatabaseSchema()` also fails loudly in that case.
4. All 9 migrations run cleanly against a database pre-seeded by executing `scripts/p0-live-migration.sql`, `scripts/p1-verification.sql`, and `scripts/profile-hardening-live.sql` first (this simulates production). Zero errors, all 9 recorded in `schema_migrations`.
5. `npm test` and `npm run lint` pass in `services/api-service`. New/updated tests cover the missing-directory and empty-directory throw paths.
6. CI workflow changes are syntactically valid (`act` dry run or careful YAML review) and the new assert step fails when the COPY line is removed (verify once locally by building without the COPY).

## Conventions

- Commit messages: single line, imperative, no Co-Authored-By trailer.
- Match existing code style (CommonJS requires, existing logger patterns, structured JSON logs in scripts).
- Do not upgrade the base image, rename anything codesentry-related, or touch unrelated files in this task.
