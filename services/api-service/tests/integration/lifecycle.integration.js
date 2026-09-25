// Run against a disposable loopback database; never loads .env.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const url = new URL(process.env.DATABASE_URL || 'postgres://invalid');
assert.ok(['postgres:', 'postgresql:'].includes(url.protocol)
  && ['127.0.0.1', 'localhost'].includes(url.hostname)
  && /^\/[a-zA-Z0-9_]+_test$/.test(url.pathname),
  'DATABASE_URL must name a disposable loopback *_test database');
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'isolated-lifecycle-test';
const { pool } = require('../../src/config/database');
const { applyMigrations, MIGRATIONS_DIR } = require('../../src/services/migrationRunner');
const findings = require('../../src/db/findings');
const runs = require('../../src/db/analysisRuns');
const orchestrator = require('../../src/services/prAnalysisOrchestrator');
orchestrator.callAnalysisTier = async () => ({ findings: [] });
orchestrator.notifyAnalysisQueued = () => {};
const { createApp } = require('../../src/app');
const request = require('supertest');
const jwt = require('jsonwebtoken');
let nextId = 10000;
let legacy;

async function fixture() {
  const n = nextId++;
  const user = (await pool.query('INSERT INTO users (github_id,github_username) VALUES ($1,$2) RETURNING id', [n, `user${n}`])).rows[0].id;
  await pool.query("INSERT INTO installations (id,status) VALUES ($1,'active')", [n]);
  await pool.query('INSERT INTO user_installations (user_id,installation_id) VALUES ($1,$2)', [user, n]);
  const repo = (await pool.query(`INSERT INTO repositories (github_id,installation_id,name,full_name,is_active,settings)
    VALUES ($1,$1,'fixture',$2,true,'{"preserved":true}') RETURNING id`, [n, `fixture/repo${n}`])).rows[0].id;
  await pool.query('INSERT INTO repository_access (user_id,repository_id) VALUES ($1,$2)', [user, repo]);
  const pr = (await pool.query("INSERT INTO pull_requests (repository_id,pr_number,head_sha,state) VALUES ($1,1,$2,'open') RETURNING id", [repo, 'a'.repeat(40)])).rows[0].id;
  const run = await newRun(repo, pr);
  return { user, repo, pr, run, installation: n, token: jwt.sign({ user_id: user }, process.env.JWT_SECRET) };
}
async function newRun(repo, pr) {
  return (await pool.query("INSERT INTO analysis_runs (repository_id,pull_request_id,pr_number,commit_sha,status) VALUES ($1,$2,1,$3,'completed') RETURNING id", [repo, pr, 'a'.repeat(40)])).rows[0].id;
}
function findingParams(f, extra = {}) {
  return { repositoryId: f.repo, installationId: f.installation, pullRequestId: f.pr, runId: f.run,
    prNumber: 1, commitSha: 'a'.repeat(40), fingerprint: randomUUID(), ruleId: 'test.rule',
    title: 'Original evidence', description: 'Fixture finding', category: 'security', severity: 'high',
    confidence: 0.9, filePath: 'app.py', lineStart: 1, isBaseline: false, ...extra };
}

before(async () => {
  await pool.query('DROP SCHEMA public CASCADE');
  await pool.query('CREATE SCHEMA public');
  const baseline = fs.mkdtempSync(path.join(os.tmpdir(), 'mitig8it-migrations-'));
  for (const file of fs.readdirSync(MIGRATIONS_DIR).filter(f => /^000[1-9]_.*\.sql$/.test(f))) {
    fs.copyFileSync(path.join(MIGRATIONS_DIR, file), path.join(baseline, file));
  }
  await applyMigrations(baseline);
  legacy = await fixture();
  legacy.finding = await findings.upsert(findingParams(legacy));
  await applyMigrations();
});
after(async () => { await pool.end(); });

test('upgrade invalidates unverified access but preserves repository state and backfills historical evidence', async () => {
  assert.equal((await pool.query('SELECT * FROM repository_access WHERE user_id=$1', [legacy.user])).rowCount, 0);
  const repo = (await pool.query('SELECT is_active,settings FROM repositories WHERE id=$1', [legacy.repo])).rows[0];
  assert.equal(repo.is_active, true);
  assert.equal(repo.settings.preserved, true);
  assert.equal((await findings.listByAnalysisRun(legacy.run))[0].title, 'Original evidence');
  assert.deepEqual(await applyMigrations(), []);
});

test('historical evidence stays unchanged after a recurring finding is updated and resnapshotted', async () => {
  const f = await fixture();
  const params = findingParams(f);
  const first = await findings.upsert(params);
  await pool.query("UPDATE analysis_runs SET status='running' WHERE id=$1", [f.run]);
  await findings.snapshotRun(f.run, [first]);
  await pool.query("UPDATE analysis_runs SET status='completed' WHERE id=$1", [f.run]);
  const nextRun = await newRun(f.repo, f.pr);
  const second = await findings.upsert({ ...params, id: first.id, runId: nextRun, title: 'Changed evidence', severity: 'critical' });
  await pool.query("UPDATE analysis_runs SET status='running' WHERE id=$1", [nextRun]);
  await findings.snapshotRun(nextRun, [second]);
  await findings.snapshotRun(f.run, [second]);
  assert.equal((await findings.listByAnalysisRun(f.run))[0].title, 'Original evidence');
  assert.equal((await findings.listByAnalysisRun(nextRun))[0].severity, 'critical');
  await findings.snapshotRun(nextRun, []);
  assert.equal((await findings.listByAnalysisRun(nextRun)).length, 0);
  await pool.query("UPDATE analysis_runs SET status='failed' WHERE id=$1", [nextRun]);
  await findings.snapshotRun(nextRun, [second]);
  assert.equal((await findings.listByAnalysisRun(nextRun)).length, 0);
  const unseen = { ...second, id: randomUUID() };
  await findings.snapshotRun(f.run, [unseen]);
  assert.equal((await findings.listByAnalysisRun(f.run)).length, 1);
});

test('retry allocates a new queued attempt while leaving failed evidence intact', async () => {
  const f = await fixture();
  const row = await findings.upsert(findingParams(f));
  await pool.query("UPDATE analysis_runs SET status='running' WHERE id=$1", [f.run]);
  await findings.snapshotRun(f.run, [row]);
  await pool.query("UPDATE analysis_runs SET status='failed' WHERE id=$1", [f.run]);
  const res = await request(createApp()).post(`/api/reports/pr-analyses/${f.run}/retry`).auth(f.token, { type: 'bearer' });
  assert.equal(res.status, 200);
  assert.notEqual(res.body.analysis_run_id, f.run);
  assert.equal((await pool.query('SELECT status FROM analysis_runs WHERE id=$1', [f.run])).rows[0].status, 'failed');
  assert.equal((await findings.listByAnalysisRun(f.run))[0].id, row.id);
  assert.equal((await pool.query('SELECT status FROM analysis_runs WHERE id=$1', [res.body.analysis_run_id])).rows[0].status, 'pending');
  await pool.query("UPDATE analysis_runs SET status='completed' WHERE id=$1", [res.body.analysis_run_id]);
});

test('a transient failure re-queues a delayed attempt that the queue withholds until it is due', async () => {
  const f = await fixture();
  await pool.query("UPDATE analysis_runs SET status='running' WHERE id=$1", [f.run]);
  const retry = await runs.requeueAfterTransientFailure(f.run, {
    errorMessage: '2 UNKNOWN: Metadata token request timed out',
    delayMs: 60_000,
  });
  assert.ok(retry && retry.id !== f.run);
  assert.equal(retry.auto_retry_count, 1);

  const failed = (await pool.query('SELECT status,error_message FROM analysis_runs WHERE id=$1', [f.run])).rows[0];
  assert.equal(failed.status, 'failed');
  assert.match(failed.error_message, /Metadata token/);

  // The retry is pending but not yet due, so no worker may claim it.
  const queued = (await pool.query('SELECT status,triggered_by FROM analysis_runs WHERE id=$1', [retry.id])).rows[0];
  assert.equal(queued.status, 'pending');
  assert.equal(queued.triggered_by, 'auto_retry');
  assert.equal(await runs.claimNextQueuedRun(), null);

  await pool.query("UPDATE analysis_runs SET not_before = NOW()-INTERVAL '1 second' WHERE id=$1", [retry.id]);
  const claimed = await runs.claimNextQueuedRun();
  assert.equal(claimed.analysis_run_id, retry.id);
  assert.equal(claimed.auto_retry_count, 1);
  try { await runs.markCompleted(retry.id, { findingsCount: 0, counts: {}, filesAnalyzed: 0 }); }
  finally { await claimed.releaseLease(); }
});

test('expired automatic suppression reopens; manual dismissal survives expiration', async () => {
  const f = await fixture();
  const auto = await findings.upsert(findingParams(f));
  const manual = await findings.upsert(findingParams(f));
  await findings.dismiss(auto.id, 'false_positive');
  await findings.updateStatus(manual.id, f.user, { status: 'dismissed', dismissalReason: 'reviewed manually' });
  await pool.query(`INSERT INTO suppressions (repository_id,fingerprint,reason,expires_at) VALUES ($1,$2,'false_positive',NOW()-INTERVAL '1 second')`, [f.repo, auto.fingerprint]);
  const rows = await findings.listByPullRequest(f.pr, f.user, { status: 'all' });
  assert.equal(rows.find(r => r.id === auto.id).status, 'open');
  assert.equal(rows.find(r => r.id === manual.id).status, 'dismissed');
});

test('deleting a suppression restores visibility immediately through the actual API route', async () => {
  const f = await fixture();
  const row = await findings.upsert(findingParams(f));
  const suppression = (await pool.query("INSERT INTO suppressions (repository_id,fingerprint,reason) VALUES ($1,$2,'false_positive') RETURNING id", [f.repo, row.fingerprint])).rows[0].id;
  await findings.dismiss(row.id, 'false_positive');
  const res = await request(createApp()).delete(`/api/suppressions/${suppression}`).auth(f.token, { type: 'bearer' });
  assert.equal(res.status, 200);
  assert.equal((await findings.getById(row.id, f.user)).status, 'open');
});

test('clean scan fixes automatically suppressed findings without later resurrection', async () => {
  const f = await fixture();
  const row = await findings.upsert(findingParams(f));
  await findings.dismiss(row.id, 'false_positive');
  await findings.markFixed({ repositoryId: f.repo, pullRequestId: f.pr, activeFingerprints: [] });
  await findings.restoreExpiredSuppressions(f.repo);
  assert.equal((await findings.getById(row.id, f.user)).status, 'fixed');
});

// Two analysis tiers reported the same flaw under two fingerprints until the taxonomy
// made both tiers name one internal type. The re-analysis carries only the surviving
// fingerprint, so the merged-away one leaves no open finding and no orphaned comment.
test('a fingerprint that a later run merged away is fixed while the surviving one stays open', async () => {
  const f = await fixture();
  const survivor = await findings.upsert(findingParams(f, { ruleId: 'opengrep.cwe-89.sql-template-literal' }));
  const mergedAway = await findings.upsert(findingParams(f, { ruleId: 'sql.injection.raw_query' }));

  await findings.markFixed({ repositoryId: f.repo, pullRequestId: f.pr, activeFingerprints: [survivor.fingerprint] });

  assert.equal((await findings.getById(survivor.id, f.user)).status, 'open');
  assert.equal((await findings.getById(mergedAway.id, f.user)).status, 'fixed');
});

test('concurrent queue claim serializes a PR even when its live run appears stale', async () => {
  const f = await fixture();
  const second = await newRun(f.repo, f.pr);
  await pool.query("UPDATE analysis_runs SET status='pending' WHERE id = ANY($1::uuid[])", [[f.run, second]]);
  const claims = await Promise.all([runs.claimNextQueuedRun(), runs.claimNextQueuedRun()]);
  const active = claims.filter(Boolean);
  assert.equal(active.length, 1);
  try {
    await pool.query("UPDATE analysis_runs SET started_at = NOW()-INTERVAL '1 hour' WHERE id=$1", [active[0].analysis_run_id]);
    assert.equal(await runs.claimNextQueuedRun(), null);
    await runs.markCompleted(active[0].analysis_run_id, { findingsCount: 0, counts: {}, filesAnalyzed: 0 });
  } finally { await active[0].releaseLease(); }
  const next = await runs.claimNextQueuedRun();
  assert.ok(next);
  try { await runs.markCompleted(next.analysis_run_id, { findingsCount: 0, counts: {}, filesAnalyzed: 0 }); }
  finally { await next.releaseLease(); }
});

test('server quota admits exactly five concurrent analyses and scopes history by user', async () => {
  const f = await fixture();
  const outsider = await fixture();
  const app = createApp();
  const responses = await Promise.all(Array.from({ length: 6 }, () => request(app).post('/api/analysis/analyze')
    .auth(f.token, { type: 'bearer' }).send({ code: 'x = 1', language: 'python' })));
  assert.equal(responses.filter(r => r.status === 200).length, 5);
  assert.equal(responses.filter(r => r.status === 429).length, 1);
  const history = await request(app).get('/api/analysis/history').auth(f.token, { type: 'bearer' });
  assert.equal(history.body.total, 5);
  const other = await request(app).get(`/api/analysis/history?user_id=${f.user}`).auth(outsider.token, { type: 'bearer' });
  assert.equal(other.body.total, 0);
});
