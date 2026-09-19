// Run explicitly with NODE_ENV=test DATABASE_URL=postgres://.../<name>_test node --test this-file.
// This suite resets the public schema of its guarded, isolated database.
const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHmac } = require('node:crypto');

const databaseUrl = new URL(process.env.DATABASE_URL || 'http://invalid');
if (process.env.NODE_ENV !== 'test' || !['127.0.0.1', 'localhost', '[::1]'].includes(databaseUrl.hostname)
    || !/^\/[a-z0-9_]+_test$/.test(databaseUrl.pathname)
    || !['postgres:', 'postgresql:'].includes(databaseUrl.protocol)) {
  throw new Error('Requires NODE_ENV=test and a loopback PostgreSQL DATABASE_URL ending in _test');
}
process.env.GITHUB_WEBHOOK_SECRET = 'local-access-integration-secret';
process.env.JWT_SECRET = 'local-access-jwt-secret';

const request = require('supertest');
const jwt = require('jsonwebtoken');
const { pool } = require('../../src/config/database');
const { applyMigrations, MIGRATIONS_DIR } = require('../../src/services/migrationRunner');
const installationsDb = require('../../src/db/installations');
const workerPath = require.resolve('../../src/services/prAnalysisOrchestrator');
// External worker execution is excluded; queue persistence and the HTTP route are real.
require.cache[workerPath] = { id: workerPath, filename: workerPath, loaded: true,
  exports: { notifyAnalysisQueued() {} } };
const { createApp } = require('../../src/app');
const app = createApp();
let legacyDir;
let userId;
let repoId;

async function seed() {
  await pool.query('TRUNCATE analysis_run_findings, analysis_runs, findings, pull_requests, repository_access, user_installations, repositories, installations, users, webhook_deliveries CASCADE');
  await pool.query("INSERT INTO installations (id, account_login, account_type) VALUES (42, 'fixture-org', 'Organization'), (43, 'other-org', 'Organization')");
  userId = (await pool.query("INSERT INTO users (github_id, github_username) VALUES (1001, 'fixture-user') RETURNING id")).rows[0].id;
  repoId = (await pool.query("INSERT INTO repositories (github_id, installation_id, name, full_name, private, is_active, settings) VALUES (999, 42, 'service', 'fixture-org/service', TRUE, TRUE, '{\"retained\":true}') RETURNING id")).rows[0].id;
  await pool.query('INSERT INTO user_installations (user_id, installation_id) VALUES ($1, 42), ($1, 43)', [userId]);
  await pool.query("INSERT INTO repository_access (user_id, repository_id, role) VALUES ($1, $2, 'read')", [userId, repoId]);
}
function payload() {
  return { action: 'opened', installation: { id: 42 },
    repository: { id: 999, name: 'service', full_name: 'fixture-org/service', private: true, default_branch: 'main' },
    pull_request: { id: 123, number: 7, title: 'Fixture', body: '', state: 'open', draft: false,
      head: { sha: 'a'.repeat(40), ref: 'branch' }, base: { sha: 'b'.repeat(40), ref: 'main' }, user: { login: 'fixture-user' } } };
}
function deliver(id, data = payload(), event = 'pull_request') {
  const body = JSON.stringify(data);
  const signature = `sha256=${createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET).update(body).digest('hex')}`;
  return request(app).post('/webhooks/github').set('Content-Type', 'application/json')
    .set('x-github-event', event).set('x-github-delivery', id).set('x-hub-signature-256', signature).send(body);
}
async function count(table) {
  assert(['analysis_runs', 'repository_access', 'webhook_deliveries'].includes(table));
  return Number((await pool.query(`SELECT COUNT(*) AS count FROM ${table}`)).rows[0].count);
}
before(async () => {
  await pool.query('DROP SCHEMA public CASCADE');
  await pool.query('CREATE SCHEMA public');
  legacyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mitig8it-access-migrations-'));
  for (const file of fs.readdirSync(MIGRATIONS_DIR).filter(name => /^000[1-9].*\.sql$/.test(name))) {
    fs.copyFileSync(path.join(MIGRATIONS_DIR, file), path.join(legacyDir, file));
  }
  await applyMigrations(legacyDir);
});
after(async () => { await pool.end(); if (legacyDir) fs.rmSync(legacyDir, { recursive: true, force: true }); });

test('upgrade invalidates unverified grants but retains repository activation/settings/history', async () => {
  userId = (await pool.query("INSERT INTO users (github_id, github_username) VALUES (1001, 'fixture-user') RETURNING id")).rows[0].id;
  await pool.query("INSERT INTO installations (id, account_login) VALUES (42, 'fixture-org')");
  repoId = (await pool.query("INSERT INTO repositories (github_id, installation_id, name, full_name, is_active, settings) VALUES (999, 42, 'service', 'fixture-org/service', TRUE, '{\"retained\":true}') RETURNING id")).rows[0].id;
  await pool.query('INSERT INTO repository_access (user_id, repository_id) VALUES ($1, $2)', [userId, repoId]);
  await pool.query("INSERT INTO analysis_runs (repository_id, status, commit_sha) VALUES ($1, 'completed', $2)", [repoId, 'a'.repeat(40)]);
  const applied = await applyMigrations();
  assert(applied.includes('0010_repository_access_revocation.sql'));
  assert.equal(await count('repository_access'), 0);
  const repo = (await pool.query('SELECT is_active, settings FROM repositories WHERE id=$1', [repoId])).rows[0];
  assert.equal(repo.is_active, true);
  assert.deepEqual(repo.settings, { retained: true });
  assert.equal(await count('analysis_runs'), 1);
  assert.deepEqual(await applyMigrations(), []);
});

test('membership reconciliation revokes direct repository API access', async () => {
  await seed();
  const token = jwt.sign({ user_id: userId }, process.env.JWT_SECRET);
  assert.equal((await request(app).get(`/api/repositories/${repoId}`).set('Authorization', `Bearer ${token}`)).status, 200);
  await installationsDb.reconcileUserInstallations(pool, userId, [43]);
  assert.equal(await count('repository_access'), 0);
  assert.equal((await request(app).get(`/api/repositories/${repoId}`).set('Authorization', `Bearer ${token}`)).status, 404);
});

test('installation suspension revokes membership and repository grants', async () => {
  await seed();
  assert.equal((await deliver('suspend', { action: 'suspend', installation: { id: 42, account: { login: 'fixture-org', type: 'Organization' } } }, 'installation')).status, 200);
  assert.equal(await count('repository_access'), 0);
  assert.equal((await pool.query('SELECT 1 FROM user_installations WHERE installation_id=42')).rowCount, 0);
});

test('parallel identical signed deliveries create one job and no repository grants', async () => {
  await seed();
  await pool.query('DELETE FROM repository_access');
  const responses = await Promise.all(Array.from({ length: 6 }, () => deliver('parallel')));
  assert(responses.every(res => res.status === 200));
  assert.equal(responses.filter(res => res.body.deduplicated).length, 5);
  assert.equal(await count('analysis_runs'), 1);
  assert.equal(await count('webhook_deliveries'), 1);
  assert.equal(await count('repository_access'), 0);
  assert.equal((await pool.query("SELECT processing_status FROM webhook_deliveries WHERE delivery_id='parallel'")).rows[0].processing_status, 'processed');
});

test('failed job insert rolls back claim and repository writes; same delivery retries', async () => {
  await seed();
  await pool.query(`CREATE FUNCTION reject_fixture_job() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$;
    CREATE TRIGGER reject_fixture_job BEFORE INSERT ON analysis_runs FOR EACH ROW EXECUTE FUNCTION reject_fixture_job()`);
  try {
    assert.equal((await deliver('rollback')).status, 500);
    assert.equal(await count('analysis_runs'), 0);
    assert.equal(await count('webhook_deliveries'), 0);
    assert.equal((await pool.query('SELECT 1 FROM pull_requests')).rowCount, 0);
  } finally {
    await pool.query('DROP TRIGGER reject_fixture_job ON analysis_runs; DROP FUNCTION reject_fixture_job()');
  }
  assert.equal((await deliver('rollback')).status, 200);
  assert.equal(await count('analysis_runs'), 1);
});

test('legacy failed delivery with no committed job is reclaimable', async () => {
  await seed();
  await pool.query("INSERT INTO webhook_deliveries (delivery_id, event_type, processing_status) VALUES ('legacy-failed', 'pull_request', 'failed')");
  const response = await deliver('legacy-failed');
  assert.equal(response.status, 200);
  assert.equal(response.body.analysis_queued, true);
  assert.equal(await count('analysis_runs'), 1);
  assert.equal((await deliver('legacy-failed')).body.deduplicated, true);
  assert.equal(await count('analysis_runs'), 1);
  // Old implementations could commit a job before marking a delivery failed.
  // Those pre-upgrade partial deliveries have no durable delivery-to-job link;
  // their jobs cannot be safely identified from a legacy failed row alone.
});
