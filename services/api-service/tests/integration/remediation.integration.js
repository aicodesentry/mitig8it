// Run against a disposable loopback database; never loads .env.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { randomUUID } = require('node:crypto');
const url = new URL(process.env.DATABASE_URL || 'postgres://invalid');
assert.ok(['postgres:', 'postgresql:'].includes(url.protocol)
  && ['127.0.0.1', 'localhost'].includes(url.hostname)
  && /^\/[a-zA-Z0-9_]+_test$/.test(url.pathname),
  'DATABASE_URL must name a disposable loopback *_test database');
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'isolated-remediation-test';
process.env.GITHUB_WEBHOOK_SECRET = 'isolated-remediation-webhook-secret';
process.env.REMEDIATION_ENABLED = 'true';
process.env.REMEDIATION_GENERATE_ENABLED = 'true';
process.env.REMEDIATION_PUBLISH_ENABLED = 'true';
process.env.REMEDIATION_SERVICE_URL = 'http://repair.invalid';
process.env.REMEDIATION_SERVICE_INTERNAL_SECRET = 'repair-secret';
process.env.GITHUB_SERVICE_URL = 'http://github.invalid';
process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'github-secret';
process.env.REMEDIATION_SANDBOX_IMAGE_DIGEST = 'sha256:integration';
process.env.REMEDIATION_VERIFICATION_CHECKS_JSON = '["unit"]';
process.env.REMEDIATION_ALLOWED_RULE_FAMILIES_JSON = '["injection"]';
process.env.REMEDIATION_INPUT_USD_PER_MILLION_TOKENS = '3';
process.env.REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS = '15';
process.env.REMEDIATION_OUTBOX_MAX_ATTEMPTS = '2';

const { pool } = require('../../src/config/database');
const { applyMigrations } = require('../../src/services/migrationRunner');
const orchestrator = require('../../src/services/prAnalysisOrchestrator');
orchestrator.callAnalysisTier = async () => ({ findings: [] });
orchestrator.notifyAnalysisQueued = () => {};

// The apply route calls the GitHub adapter for live authorization. The class is
// replaced before the routes destructure it; no network call is ever made here.
const githubRemediationClient = require('../../src/services/githubRemediationClient');
let authorizeResponse = null;
// Every adapter response the merge controller consumes is scripted here. No network
// call is ever made, and each call is counted so "exactly once" can be asserted.
const githubCalls = { authorize: 0, head: 0, eligibility: 0, merge: 0, check_run: 0, cancel: 0, comment: 0, finding_fixes: 0 };
let lastCheckRun = null;
const publishedComments = new Map();
const publishedFixSections = [];
let headResponse = null;
let eligibilityResponse = null;
let mergeResponse = null;
function resolve(scripted, payload, fallback) {
  if (typeof scripted === 'function') return scripted(payload);
  return scripted || fallback;
}
githubRemediationClient.GitHubRemediationClient = class {
  async authorize(payload) {
    githubCalls.authorize += 1;
    if (typeof authorizeResponse === 'function') return authorizeResponse(payload);
    return { state: 'authorized', installation_active: true, repository_granted: true, actor_write_permission: true,
      head_sha: payload.head_sha, base_sha: payload.base_sha, head_branch: 'feature', base_branch: 'main' };
  }
  async readPullRequestHead(payload) {
    githubCalls.head += 1;
    return resolve(headResponse, payload, { head_sha: payload.head_sha, base_sha: payload.base_sha,
      state: 'open', draft: false, merged: false, fork: false, mergeable_state: 'clean' });
  }
  async readMergeEligibility(payload) {
    githubCalls.eligibility += 1;
    return resolve(eligibilityResponse, payload, { eligible: true, blockers: [], protection_source: 'branch_protection',
      head_sha: payload.head_sha, base_sha: payload.base_sha });
  }
  async merge(payload) {
    githubCalls.merge += 1;
    return resolve(mergeResponse, payload, { state: 'merged', operation_id: payload.action_id, commit_sha: 'd'.repeat(40) });
  }
  async createCheckRun(payload) {
    githubCalls.check_run += 1;
    lastCheckRun = payload;
    return { state: 'published', operation_id: payload.action_id, check_run_id: 4242, external_id: payload.external_id, updated: false };
  }
  // The residual report comment is keyed by external id: a second publication for the
  // same id updates the recorded comment instead of adding one.
  async publishComment(payload) {
    githubCalls.comment += 1;
    const existing = publishedComments.get(payload.external_id);
    const comment = { id: existing?.id || 700 + publishedComments.size, body: payload.body, head_sha: payload.head_sha, publications: (existing?.publications || 0) + 1 };
    publishedComments.set(payload.external_id, comment);
    return { state: 'published', operation_id: payload.action_id, comment_id: comment.id, external_id: payload.external_id, updated: Boolean(existing) };
  }
  // Verified fix sections under finding comments: recorded per job for assertions.
  async publishFindingFixSections(payload) {
    githubCalls.finding_fixes += 1;
    publishedFixSections.push(payload);
    return { state: 'published', operation_id: payload.action_id, reason: '',
      results: payload.sections.map((section) => ({ finding_fingerprint: section.finding_fingerprint, candidate_id: section.candidate_id, comment_id: 900, mode: section.hunk ? 'suggestion' : 'diff', updated: true, reason: '' })) };
  }
  async cancelScheduledMerge(payload) {
    githubCalls.cancel += 1;
    return { state: 'not_scheduled', operation_id: payload.action_id, merged: false, reason: 'auto_merge_not_enabled' };
  }
};

function resetCounts() { for (const key of Object.keys(githubCalls)) githubCalls[key] = 0; }

function resetGitHubStub() {
  resetCounts();
  authorizeResponse = null; headResponse = null; eligibilityResponse = null; mergeResponse = null;
}

// The stored user connection is a consent prerequisite, not authorization. It is
// stubbed so the test exercises the live permission path rather than OAuth storage.
const githubUserAuth = require('../../src/services/githubUserAuth');
githubUserAuth.getGithubAccessTokenForUser = async () => ({ githubUsername: 'integration-actor' });

const remediationDb = require('../../src/db/remediation');
const workflow = require('../../src/services/remediationWorkflow');
const outbox = require('../../src/services/remediationOutbox');
const reconciler = require('../../src/services/remediationReconciler');
const verificationCheck = require('../../src/services/remediationVerificationCheck');
const residualReport = require('../../src/services/remediationResidualReport');
const { createApp } = require('../../src/app');
const request = require('supertest');
const jwt = require('jsonwebtoken');

let nextId = 90000;

// Every remediation table forces row level security, so direct assertions run with an
// explicit worker context rather than bypassing the policy.
async function workerQuery(text, params) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.remediation_worker', '1', true)");
    const result = await client.query(text, params);
    await client.query('COMMIT');
    return result;
  } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
}

async function fixture({ headSha = crypto.randomBytes(20).toString('hex') } = {}) {
  const n = nextId++;
  const head = headSha.slice(0, 40);
  const base = 'b'.repeat(40);
  const user = (await pool.query('INSERT INTO users (github_id,github_username) VALUES ($1,$2) RETURNING id', [n, `user${n}`])).rows[0].id;
  await pool.query("INSERT INTO installations (id,status) VALUES ($1,'active')", [n]);
  await pool.query('INSERT INTO user_installations (user_id,installation_id) VALUES ($1,$2)', [user, n]);
  const repo = (await pool.query(`INSERT INTO repositories (github_id,installation_id,name,full_name,is_active)
    VALUES ($1,$1,'fixture',$2,true) RETURNING id`, [n, `fixture/repo${n}`])).rows[0].id;
  await pool.query('INSERT INTO repository_access (user_id,repository_id) VALUES ($1,$2)', [user, repo]);
  const pr = (await pool.query(`INSERT INTO pull_requests (repository_id,github_pr_id,pr_number,head_sha,base_sha,head_branch,base_branch,state)
    VALUES ($1,$2,1,$3,$4,'feature','main','open') RETURNING id`, [repo, n, head, base])).rows[0].id;
  const run = (await pool.query(`INSERT INTO analysis_runs (repository_id,pull_request_id,pr_number,commit_sha,status,completed_at)
    VALUES ($1,$2,1,$3,'completed',NOW()) RETURNING id`, [repo, pr, head])).rows[0].id;
  const finding = randomUUID();
  await pool.query(`INSERT INTO analysis_run_findings (analysis_run_id,finding_id,snapshot) VALUES ($1,$2,$3)`,
    [run, finding, JSON.stringify({ id: finding, file_path: 'src/app.js', rule_id: 'injection.sql', severity: 'high' })]);
  return { n, user, repo, pr, run, finding, head, base, installation: n,
    fullName: `fixture/repo${n}`, token: jwt.sign({ user_id: user, github_username: `user${n}` }, process.env.JWT_SECRET) };
}

// Moves a job to ready with one verified candidate, as the repair service would.
async function makeReady(f, jobId) {
  const candidate = (await workerQuery(
    `INSERT INTO remediation_candidates (job_id,installation_id,repository_id,candidate_version,finding_snapshot_ids,artifact_digest,context_manifest_digest,file_manifest,preview,verification_level)
     VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,'independent_sandbox') RETURNING id`,
    [jobId, f.installation, f.repo, [f.finding], 'a'.repeat(64), 'c'.repeat(64),
      JSON.stringify({ verified_tree_oid: 'f'.repeat(40), files: [{ path: 'src/app.js', contents_base64: Buffer.from('fixed\n').toString('base64') }] }),
      JSON.stringify({ verified_tree_oid: 'f'.repeat(40), changes: [] })]
  )).rows[0].id;
  await workerQuery(`UPDATE remediation_jobs SET state='ready', stage='ready' WHERE id=$1`, [jobId]);
  const job = (await workerQuery('SELECT * FROM remediation_jobs WHERE id=$1', [jobId])).rows[0];
  const digest = remediationDb.hash({ job: job.id, head: job.head_sha, base: job.base_sha, candidates: [{ id: candidate, artifact_digest: 'a'.repeat(64) }] });
  return { candidate, digest, job };
}

function signedWebhook(app, event, payload) {
  const raw = Buffer.from(JSON.stringify(payload));
  const signature = `sha256=${crypto.createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET).update(raw).digest('hex')}`;
  return request(app).post('/webhooks/github')
    .set('x-github-event', event).set('x-github-delivery', randomUUID())
    .set('x-hub-signature-256', signature).set('Content-Type', 'application/json').send(raw.toString('utf8'));
}

before(async () => {
  await pool.query('DROP SCHEMA public CASCADE');
  await pool.query('CREATE SCHEMA public');
  await applyMigrations();
});
after(async () => { await pool.end(); });

test('intake commits the job and its outbox event atomically and replays a duplicate request', async () => {
  const f = await fixture();
  const app = createApp();
  const first = await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({});
  assert.equal(first.status, 202);
  assert.equal(first.body.replay, false);
  const jobId = first.body.job.id;

  const events = await workerQuery('SELECT event_type, status, attempts FROM workflow_outbox WHERE aggregate_id=$1', [jobId]);
  assert.equal(events.rowCount, 1);
  assert.equal(events.rows[0].event_type, 'remediation.queued');
  assert.equal(events.rows[0].status, 'pending');
  assert.equal((await workerQuery('SELECT id FROM workflow_events WHERE aggregate_id=$1', [jobId])).rowCount, 1);

  const second = await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({});
  assert.equal(second.status, 202);
  assert.equal(second.body.job.id, jobId);
  assert.equal(second.body.replay, true);
  assert.equal((await workerQuery('SELECT id FROM remediation_jobs WHERE pull_request_id=$1', [f.pr])).rowCount, 1);
});

test('a job that ended in a terminal failure does not shadow a fresh identical request, while a ready job still replays', async () => {
  const f = await fixture();
  const app = createApp();
  const first = await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({});
  assert.equal(first.status, 202);
  await workerQuery("UPDATE remediation_jobs SET state='inconclusive', stage='inconclusive', failure_reason='{\"code\":\"ERR_BAD_REQUEST\"}' WHERE id=$1", [first.body.job.id]);

  const retry = await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({});
  assert.equal(retry.status, 202);
  assert.equal(retry.body.replay, false);
  assert.notEqual(retry.body.job.id, first.body.job.id);
  assert.equal(retry.body.job.state, 'queued');
  assert.equal((await workerQuery('SELECT id FROM remediation_jobs WHERE pull_request_id=$1', [f.pr])).rowCount, 2);

  await workerQuery("UPDATE remediation_jobs SET state='ready', stage='ready' WHERE id=$1", [retry.body.job.id]);
  const replay = await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({});
  assert.equal(replay.status, 202);
  assert.equal(replay.body.replay, true);
  assert.equal(replay.body.job.id, retry.body.job.id);
});

test('an expired lease is reclaimed with a new fencing token and the expired worker cannot complete the stage', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;

  const first = await remediationDb.claimJobById(jobId, 'worker-a', 60);
  assert.ok(first);
  assert.equal(Number(first.attempt_count), 0, 'claiming must not consume an attempt');
  await workerQuery(`UPDATE remediation_jobs SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1`, [jobId]);

  const reclaimed = await remediationDb.reclaimExpiredLeases(10);
  assert.ok(reclaimed.includes(jobId));
  const afterReclaim = (await workerQuery('SELECT attempt_count, fencing_token FROM remediation_jobs WHERE id=$1', [jobId])).rows[0];
  assert.equal(Number(afterReclaim.attempt_count), 0, 'a pure lease expiry must not consume an attempt');
  assert.ok(Number(afterReclaim.fencing_token) > Number(first.fencing_token));

  const second = await remediationDb.claimJobById(jobId, 'worker-b', 60);
  assert.ok(second);
  assert.ok(Number(second.fencing_token) > Number(first.fencing_token));

  assert.equal(await remediationDb.completeStage(first, { state: 'ready', stage: 'ready', outcome: 'ready' }), false);
  assert.equal((await workerQuery('SELECT state FROM remediation_jobs WHERE id=$1', [jobId])).rows[0].state, 'queued',
    'the fenced worker must not change state');
  assert.equal(await remediationDb.completeStage(second, { state: 'inconclusive', stage: 'inconclusive', outcome: 'repair_failure', reason: { code: 'repair_failure' } }), true);
  const failed = (await workerQuery('SELECT state, attempt_count FROM remediation_jobs WHERE id=$1', [jobId])).rows[0];
  assert.equal(failed.state, 'inconclusive');
  assert.equal(Number(failed.attempt_count), 1, 'a real failure consumes exactly one attempt');
});

test('an outbox event is delivered only after its handler succeeds and is dead-lettered after the attempt limit', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const outboxId = (await workerQuery('SELECT id FROM workflow_outbox WHERE aggregate_id=$1', [jobId])).rows[0].id;

  const failing = async () => { throw new Error('handler exploded'); };
  const onlyThisEvent = async (dispatcher) => {
    const claimed = await outbox.claimPendingOutbox(50);
    for (const event of claimed) {
      if (event.id !== outboxId) { await outbox.markFailed(event.id, 0, 'not this test'); continue; }
      try { await dispatcher(event); await outbox.markDelivered(event.id); }
      catch (error) { await outbox.markFailed(event.id, event.attempts, error.message); }
    }
  };

  await onlyThisEvent(failing);
  let row = (await workerQuery('SELECT * FROM workflow_outbox WHERE id=$1', [outboxId])).rows[0];
  assert.equal(row.status, 'pending');
  assert.equal(Number(row.attempts), 1);
  assert.equal(row.delivered_at, null, 'a failed handler must never record delivery');
  assert.match(row.last_error, /handler exploded/);

  await workerQuery('UPDATE workflow_outbox SET next_attempt_at=NOW() WHERE id=$1', [outboxId]);
  await onlyThisEvent(failing);
  row = (await workerQuery('SELECT * FROM workflow_outbox WHERE id=$1', [outboxId])).rows[0];
  assert.equal(row.status, 'dead_letter');
  assert.equal(row.dead_letter_reason, 'max_dispatch_attempts_exceeded');
  assert.equal(row.delivered_at, null);

  // A fresh event delivered by a successful handler records delivery exactly once.
  await workerQuery("UPDATE workflow_outbox SET status='pending', attempts=0, next_attempt_at=NOW(), dead_letter_reason=NULL WHERE id=$1", [outboxId]);
  let handled = 0;
  await onlyThisEvent(async () => { handled += 1; return { status: 'executed' }; });
  row = (await workerQuery('SELECT * FROM workflow_outbox WHERE id=$1', [outboxId])).rows[0];
  assert.equal(handled, 1);
  assert.equal(row.status, 'delivered');
  assert.ok(row.delivered_at);
});

test('an unroutable event type is never reported as delivered', async () => {
  const f = await fixture();
  const dispatcher = outbox.createDispatcher('inprocess');
  await assert.rejects(() => dispatcher({ id: randomUUID(), aggregate_id: f.pr, event_type: 'remediation.invented' }),
    /No remediation outbox handler is registered/);
});

test('cloud_tasks dispatch refuses to pretend an event was enqueued', () => {
  assert.throws(() => outbox.createDispatcher('cloud_tasks'), /not implemented/);
});

test('a synchronize webhook supersedes the job and invalidates its candidates', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const ready = await makeReady(f, jobId);

  const newHead = 'e'.repeat(40);
  const response = await signedWebhook(app, 'pull_request', {
    action: 'synchronize',
    installation: { id: f.installation },
    repository: { id: f.n, name: 'fixture', full_name: f.fullName, private: false, default_branch: 'main' },
    pull_request: { id: f.n, number: 1, title: 't', body: '', state: 'open', draft: false,
      head: { sha: newHead, ref: 'feature' }, base: { sha: f.base, ref: 'main' }, user: { login: 'dev' }, html_url: 'https://example.invalid' },
  });
  assert.equal(response.status, 200);

  const job = (await workerQuery('SELECT state, cancellation_reason FROM remediation_jobs WHERE id=$1', [jobId])).rows[0];
  assert.equal(job.state, 'superseded');
  assert.equal(job.cancellation_reason, 'head_changed');
  const candidate = (await workerQuery('SELECT rejection_reason FROM remediation_candidates WHERE id=$1', [ready.candidate])).rows[0];
  assert.equal(candidate.rejection_reason.code, 'head_changed');
});

test('the reconciler quarantines a job that exhausted its attempts', async () => {
  const app = createApp();
  const exhausted = await fixture();
  const exhaustedJob = (await request(app).post(`/api/pull-requests/${exhausted.pr}/remediations`).auth(exhausted.token, { type: 'bearer' }).send({})).body.job.id;
  await workerQuery('UPDATE remediation_jobs SET attempt_count=9 WHERE id=$1', [exhaustedJob]);

  await reconciler.runReconciliation();
  const quarantined = (await workerQuery('SELECT state, failure_reason FROM remediation_jobs WHERE id=$1', [exhaustedJob])).rows[0];
  assert.equal(quarantined.state, 'dead_letter');
  assert.equal(quarantined.failure_reason.code, 'max_attempts_exceeded');
});

test('a legitimate retry of the same stage reuses its reservation instead of reporting quota exhaustion', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const job = await remediationDb.claimJobById(jobId, 'worker-usage', 60);
  const first = await remediationDb.reserveUsage(job, 'snapshotting', 0.05);
  assert.ok(first);
  const retry = await remediationDb.reserveUsage(job, 'snapshotting', 0.05);
  assert.ok(retry, 'a retry of the same stage must not be reported as quota exhaustion');
  assert.equal(retry.id, first.id);
  // A later stage reserves its own estimate rather than the whole ceiling.
  const next = await remediationDb.reserveUsage(job, 'generating', 0.8);
  assert.ok(next);
  assert.notEqual(next.id, first.id);
  const budget = await remediationDb.budgetSnapshot(f.installation, 2);
  assert.ok(budget.available > 0);
});


test('a retry under a new fencing token does not mint a second reservation', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const job = await remediationDb.claimJobById(jobId, 'worker-a', 60);
  const first = await remediationDb.reserveUsage(job, 'snapshotting', 0.05);
  assert.ok(first);

  // Losing the lease and being reclaimed bumps the fencing token. That used to change the
  // reservation key, so every reclaimed attempt charged the installation again.
  await pool.query('UPDATE remediation_jobs SET lease_expires_at = NOW() - INTERVAL \'1 minute\' WHERE id=$1', [jobId]);
  const reclaimed = await remediationDb.claimJobById(jobId, 'worker-b', 60);
  assert.ok(Number(reclaimed.fencing_token) > Number(job.fencing_token), 'the reclaim must bump the fencing token');
  const retry = await remediationDb.reserveUsage(reclaimed, 'snapshotting', 0.05);

  assert.equal(retry.id, first.id, 'a reclaimed attempt must reuse the stage reservation');
  const rows = await pool.query("SELECT COUNT(*)::int AS n FROM usage_reservations WHERE job_id=$1 AND stage='snapshotting'", [jobId]);
  assert.equal(rows.rows[0].n, 1);
});

test('a job that ends releases what it never spent, and the ceiling stops counting it', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const job = await remediationDb.claimJobById(jobId, 'worker-a', 60);
  await remediationDb.reserveUsage(job, 'snapshotting', 0.05);
  const before = await remediationDb.budgetSnapshot(f.installation, 2);
  assert.ok(before.reserved > 0);

  await remediationDb.completeStage(job, { state: 'inconclusive', stage: 'inconclusive', outcome: 'quota_exhausted' });

  const row = await pool.query("SELECT state, actual_amount FROM usage_reservations WHERE job_id=$1", [jobId]);
  assert.equal(row.rows[0].state, 'released');
  assert.equal(Number(row.rows[0].actual_amount), 0);
  const after = await remediationDb.budgetSnapshot(f.installation, 2);
  assert.equal(after.reserved, 0);
  const audited = await pool.query("SELECT COUNT(*)::int AS n FROM audit_logs WHERE action='remediation.usage_released' AND resource_id=$1", [jobId]);
  assert.equal(audited.rows[0].n, 1);
});

test('the reconciler releases reservations stranded by a job that already ended', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const job = await remediationDb.claimJobById(jobId, 'worker-a', 60);
  await remediationDb.reserveUsage(job, 'snapshotting', 0.05);
  // The job ends without releasing, exactly as it did before this fix.
  await pool.query("UPDATE remediation_jobs SET state='inconclusive', stage='inconclusive' WHERE id=$1", [jobId]);
  const stranded = await pool.query("SELECT COUNT(*)::int AS n FROM usage_reservations WHERE job_id=$1 AND state='reserved'", [jobId]);
  assert.equal(stranded.rows[0].n, 1);

  const summary = await reconciler.runReconciliation();

  assert.equal(summary.usage.released, 1);
  const cleared = await pool.query("SELECT state FROM usage_reservations WHERE job_id=$1", [jobId]);
  assert.equal(cleared.rows[0].state, 'released');
  const budget = await remediationDb.budgetSnapshot(f.installation, 2);
  assert.equal(budget.reserved, 0);
});

// The App cannot apply a fix, so an action is only ever created by the push webhook
// observing a commit GitHub co-authored to the app. This is that row.
async function observeApply(f, jobId, candidateIds, digest, appliedSha) {
  const inserted = await workerQuery(
    `INSERT INTO remediation_actions (job_id,installation_id,repository_id,pull_request_id,actor_id,actor_login,
       action_type,head_sha,base_sha,batch_manifest_digest,candidate_ids,idempotency_key,payload_hash,state,observed_commit_sha)
     VALUES ($1,$2,$3,$4,$5,$6,'observed_apply',$7,$8,$9,$10,$11,$12,'applied',$13) RETURNING id`,
    [jobId, f.installation, f.repo, f.pr, f.user, `user${f.n}`, f.head, f.base, digest, candidateIds,
      `observed:${appliedSha}`, remediationDb.hash({ commit_sha: appliedSha }), appliedSha]
  );
  return inserted.rows[0].id;
}

async function completeApplication(actionId, appliedSha) {
  await workerQuery(
    `UPDATE remediation_actions SET state='applied', observed_commit_sha=$2, observed_tree_oid=$3 WHERE id=$1`,
    [actionId, appliedSha, 'f'.repeat(40)]
  );
  const action = (await workerQuery('SELECT * FROM remediation_actions WHERE id=$1', [actionId])).rows[0];
  const checking = await remediationDb.enterChecking(action, { commitSha: appliedSha, treeOid: 'f'.repeat(40) });
  assert.ok(checking, 'the action must enter checking with a verification analysis');
  // The analysis is left pending on purpose: completion is what each test decides.
  return checking.analysisRunId;
}

// --- Per-finding apply: subset consent, stale marking, residual report -------------

// Moves a job to ready with several verified candidates, one per file, plus the
// combined verification run the repair service would have recorded for the batch.
async function makeReadyWith(f, jobId, paths) {
  const rows = [];
  for (let index = 0; index < paths.length; index += 1) {
    const artifact = String(index + 1).repeat(64).slice(0, 64);
    const tree = String(index + 1).repeat(40).slice(0, 40);
    const finding = index === 0 ? f.finding : randomUUID();
    const id = (await workerQuery(
      `INSERT INTO remediation_candidates (job_id,installation_id,repository_id,candidate_version,finding_snapshot_ids,artifact_digest,context_manifest_digest,file_manifest,preview,verification_level)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'independent_sandbox') RETURNING id`,
      [jobId, f.installation, f.repo, index + 1, [finding], artifact, 'c'.repeat(64),
        JSON.stringify({ verified_tree_oid: tree, files: [{ path: paths[index], contents_base64: Buffer.from(`fixed ${index}\n`).toString('base64') }] }),
        JSON.stringify({ verified_tree_oid: tree, changes: [{ path: paths[index], unified_diff: '@@ -1 +1 @@' }] })]
    )).rows[0].id;
    rows.push({ id, artifact_digest: artifact, finding });
  }
  await workerQuery(
    `INSERT INTO verification_runs (job_id,installation_id,repository_id,candidate_digest,original_tree_sha,candidate_tree_sha,base_sha,verifier_identity,policy_version,outcome,evidence_digest,coverage_gaps,limitations)
     VALUES ($1,$2,$3,$4,$5,$6,$7,'remediation-service','v1','passed',$8,'[]','[]')`,
    [jobId, f.installation, f.repo, rows[0].artifact_digest, f.head, 'e'.repeat(40), f.base, 'd'.repeat(64)]
  );
  await workerQuery(`UPDATE remediation_jobs SET state='ready', stage='ready' WHERE id=$1`, [jobId]);
  const job = (await workerQuery('SELECT * FROM remediation_jobs WHERE id=$1', [jobId])).rows[0];
  const digestFor = (ids) => remediationDb.manifestDigestFor(job, rows.filter((row) => ids.includes(row.id)));
  return { rows, job, digestFor };
}

// An open finding that belongs to the verification run's immutable snapshot. Its mutable
// analysis_run_id points at a later webhook run for the same commit, as it does in
// production when the webhook's analysis upserts the same fingerprint last: membership
// must come from the snapshot, never from that pointer.
async function insertOpenFinding(f, runId, { severity, path, title, testCode = false }) {
  const commit = (await pool.query('SELECT commit_sha FROM analysis_runs WHERE id=$1', [runId])).rows[0].commit_sha;
  const laterRun = (await pool.query(
    `INSERT INTO analysis_runs (repository_id,pull_request_id,pr_number,commit_sha,status,triggered_by,completed_at)
     VALUES ($1,$2,1,$3,'completed','webhook',NOW()) RETURNING id`, [f.repo, f.pr, commit])).rows[0].id;
  const id = (await pool.query(
    `INSERT INTO findings (repository_id,installation_id,pull_request_number,pull_request_id,analysis_run_id,commit_sha,fingerprint,rule_id,title,description,category,severity,file_path,line_start,status,evidence_details)
     VALUES ($1,$2,1,$3,$4,$5,$6,'rule',$7,'d','injection',$8,$9,10,'open',$10) RETURNING id`,
    [f.repo, f.installation, f.pr, laterRun, commit, randomUUID().replace(/-/g, ''), title, severity, path,
      JSON.stringify(testCode ? { extra: { in_test_code: true, original_severity: severity } } : {})]
  )).rows[0].id;
  await pool.query(`INSERT INTO analysis_run_findings (analysis_run_id,finding_id,snapshot) VALUES ($1,$2,$3)`,
    [runId, id, JSON.stringify({ id, file_path: path, severity, title, status: 'open' })]);
  return id;
}

test('the verification check blocks on any open finding severity and the residual report is published once per action', async () => {
  resetGitHubStub();
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const ready = await makeReadyWith(f, jobId, ['services/customers.js']);
  const appliedSha = '6'.repeat(40);
  const actionId = await observeApply(f, jobId, [ready.rows[0].id], ready.digestFor([ready.rows[0].id]), appliedSha);
  const runId = await completeApplication(actionId, appliedSha);
  const medium = await insertOpenFinding(f, runId, { severity: 'medium', path: 'services/orders.js', title: 'Command injection' });
  await insertOpenFinding(f, runId, { severity: 'info', path: 'tests/orders.test.js', title: 'Hardcoded secret', testCode: true });
  await pool.query(`UPDATE analysis_runs SET status='completed', completed_at=NOW() WHERE id=$1`, [runId]);

  // Nothing is posted before the action completes.
  const early = await residualReport.publishResidualComment(actionId);
  assert.equal(early.published, false);
  assert.equal(githubCalls.comment, 0);

  const completed = await reconciler.completeVerifiedActions(10);
  assert.equal(completed.completed, 1);
  const action = (await workerQuery('SELECT * FROM remediation_actions WHERE id=$1', [actionId])).rows[0];
  assert.equal(action.state, 'completed');

  // A medium finding blocks; the informational test-code finding is listed but does not.
  const analysis = await remediationDb.blockingFindingsForAction(action);
  assert.equal(analysis.blocking, 1);
  assert.deepEqual(analysis.open.map((finding) => [finding.severity, finding.informational]), [['medium', false], ['info', true]]);
  assert.ok(lastCheckRun, 'the verification check was published on completion');
  assert.equal(lastCheckRun.conclusion, 'failure');
  assert.match(lastCheckRun.summary, /Open findings on the applied head \(any severity, excluding informational test-code findings\): 1/);
  assert.match(lastCheckRun.summary, /- services\/orders\.js\n  - medium: Command injection \(line 10\)/);
  assert.match(lastCheckRun.summary, /Hardcoded secret in tests\/orders\.test\.js:10/);

  // The residual comment was published once on completion and is updated in place on retry.
  const comment = publishedComments.get(actionId);
  assert.equal(comment.publications, 1);
  assert.match(comment.body, /### Mitig8it remediation report/);
  assert.match(comment.body, /Applied \(1 fix\):\n- .* in src\/app\.js/);
  assert.match(comment.body, /Remaining open findings in the pull request's changed files: 1 \(plus 1 informational finding in test code\)\./);
  assert.match(comment.body, /Merging stays a human action on GitHub\./);
  assert.equal(action.residual_comment_id, String(comment.id));
  assert.equal(action.residual_comment_head_sha, appliedSha);
  assert.deepEqual(await remediationDb.listActionsNeedingResidualComment(10), []);
  const again = await residualReport.publishResidualComment(actionId);
  assert.equal(again.published, true); assert.equal(again.updated, true);
  assert.equal(publishedComments.get(actionId).publications, 2);
  assert.equal(publishedComments.get(actionId).id, comment.id);

  // Once the medium finding is closed the check turns green, and the report follows.
  await pool.query(`UPDATE findings SET status='fixed' WHERE id=$1`, [medium]);
  const republished = await verificationCheck.publishVerificationCheck(actionId);
  assert.equal(republished.conclusion, 'success');
  assert.match(lastCheckRun.title, /no open findings remain/);
});

test('a failed automatic job does not block the next analysis from queuing a fresh automatic job for the same head', async () => {
  const autoGenerate = require('../../src/services/remediationAutoGenerate');
  const f = await fixture();
  const open = await insertOpenFinding(f, f.run, { severity: 'high', path: 'src/app.js', title: 'SQL injection' });
  await pool.query(`UPDATE analysis_run_findings SET snapshot = snapshot || $2::jsonb WHERE finding_id=$1`, [open, JSON.stringify({ fingerprint: `fp-${open}`, line_start: 10, line_end: 10 })]);
  const first = await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: f.pr, analysisRunId: f.run });
  assert.equal(first.enqueued, true);
  await workerQuery(`UPDATE remediation_jobs SET state='inconclusive', stage='inconclusive', failure_reason='{"code":"SNAPSHOT_UNAVAILABLE"}' WHERE id=$1`, [first.job_id]);
  const retry = await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: f.pr, analysisRunId: f.run });
  assert.equal(retry.enqueued, true);
  assert.notEqual(retry.job_id, first.job_id);
  const jobs = await workerQuery(`SELECT state FROM remediation_jobs WHERE pull_request_id=$1 AND head_sha=$2 AND origin='automatic' ORDER BY created_at`, [f.pr, f.head]);
  assert.deepEqual(jobs.rows.map((row) => row.state), ['inconclusive', 'queued']);
  const again = await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: f.pr, analysisRunId: f.run });
  assert.deepEqual(again, { enqueued: false, reason: 'exists', job_id: retry.job_id });
});

test('one automatic job is queued per head after analysis, it is claimable without a creator, and its verified fixes are published once under the findings', async () => {
  const autoGenerate = require('../../src/services/remediationAutoGenerate');
  const f = await fixture();
  const open = await insertOpenFinding(f, f.run, { severity: 'high', path: 'src/app.js', title: 'SQL injection' });
  await pool.query(`UPDATE analysis_run_findings SET snapshot = snapshot || $2::jsonb WHERE finding_id=$1`, [open, JSON.stringify({ fingerprint: `fp-${open}`, line_start: 10, line_end: 10 })]);

  const first = await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: f.pr, analysisRunId: f.run });
  assert.equal(first.enqueued, true);
  assert.equal(first.findings, 1);
  const second = await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: f.pr, analysisRunId: f.run });
  assert.deepEqual(second, { enqueued: false, reason: 'exists', job_id: first.job_id });
  const jobs = await workerQuery(`SELECT id, origin, created_by, finding_snapshot_ids, state FROM remediation_jobs WHERE pull_request_id=$1 AND head_sha=$2`, [f.pr, f.head]);
  assert.equal(jobs.rowCount, 1);
  assert.equal(jobs.rows[0].origin, 'automatic');
  assert.equal(jobs.rows[0].created_by, null);
  assert.deepEqual(jobs.rows[0].finding_snapshot_ids, [open]);
  const queued = await workerQuery(`SELECT COUNT(*)::int AS n FROM workflow_outbox WHERE aggregate_id=$1 AND event_type='remediation.queued'`, [first.job_id]);
  assert.equal(queued.rows[0].n, 1);

  // The worker can claim a job that has no creator; the snapshot actor is a user who
  // connected the repository, whose live write permission the adapter still checks.
  const claimed = await remediationDb.claimJobById(first.job_id, 'integration-auto');
  assert.ok(claimed);
  assert.equal(claimed.creator_login, `user${f.n}`);
  await workerQuery(`UPDATE remediation_jobs SET lease_owner=NULL, lease_expires_at=NULL WHERE id=$1`, [first.job_id]);

  // Ready: one verified candidate for the open finding, then the outbox publishes its
  // section once and a redelivered event produces the identical request.
  const original = 'const db = require("./db");\nasync function order(id) {\n  return db.query(`SELECT * FROM orders WHERE id = ${id}`);\n}\n';
  const fixed = original.replace('db.query(`SELECT * FROM orders WHERE id = ${id}`)', "db.query('SELECT * FROM orders WHERE id = $1', [id])");
  await workerQuery(
    `INSERT INTO remediation_candidates (job_id,installation_id,repository_id,candidate_version,finding_snapshot_ids,artifact_digest,context_manifest_digest,file_manifest,preview,verification_level)
     VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,'independent_sandbox')`,
    [first.job_id, f.installation, f.repo, [open], 'a'.repeat(64), 'c'.repeat(64),
      JSON.stringify({ verified_tree_oid: 'f'.repeat(40), files: [{ path: 'src/app.js', contents_base64: Buffer.from(fixed).toString('base64') }] }),
      JSON.stringify({ changes: [{ path: 'src/app.js', original, replacement: fixed, unified_diff: '@@ -3 +3 @@\n-old\n+new' }], rationale: 'Parameterize the query.',
        reasoning: { intended_behavior: 'Same row for the same id.' }, evidence: { status: 'passed', evidence_digest: 'e'.repeat(64), generated_tests: [{ path: 'tests/orders.regression.test.js' }], limitations: [] } })]
  );
  await workerQuery(`UPDATE remediation_jobs SET state='ready', stage='ready', state_version=state_version+1 WHERE id=$1`, [first.job_id]);
  const readyJob = (await workerQuery('SELECT * FROM remediation_jobs WHERE id=$1', [first.job_id])).rows[0];
  const client = await pool.connect();
  try {
    await client.query('BEGIN'); await client.query("SELECT set_config('app.remediation_worker', '1', true)");
    await remediationDb.appendEvent(client, readyJob, 'remediation.ready', { stage: 'ready', outcome: 'ready' });
    await client.query('COMMIT');
  } finally { client.release(); }
  outbox.registerDefaultHandlers({ executeClaimedJob: async () => {}, executeClaimedAction: async () => {}, workerId: 'integration-auto' });
  const before = publishedFixSections.length;
  await outbox.processPending({ limit: 50, dispatcher: outbox.createDispatcher('inprocess') });
  assert.equal(publishedFixSections.length, before + 1);
  const payload = publishedFixSections[before];
  assert.equal(payload.actor_login, 'system');
  assert.equal(payload.head_sha, f.head);
  assert.equal(payload.sections.length, 1);
  assert.equal(payload.sections[0].finding_fingerprint, `fp-${open}`);
  assert.deepEqual(payload.sections[0].hunk.replacement_lines, ["  return db.query('SELECT * FROM orders WHERE id = $1', [id]);"]);
  assert.equal(payload.sections[0].hunk.start_line, 3);
  const recorded = await workerQuery('SELECT inline_fixes_head_sha FROM remediation_jobs WHERE id=$1', [first.job_id]);
  assert.equal(recorded.rows[0].inline_fixes_head_sha, f.head);

  // A redelivery of the ready event is the same request again, which the adapter
  // applies in place by candidate marker.
  await workerQuery(`UPDATE workflow_outbox SET status='pending', next_attempt_at=NOW() WHERE aggregate_id=$1 AND event_type='remediation.ready'`, [first.job_id]);
  await outbox.processPending({ limit: 50, dispatcher: outbox.createDispatcher('inprocess') });
  assert.equal(publishedFixSections.length, before + 2);
  assert.deepEqual(publishedFixSections[before + 1], payload);
});

// Reopening a pull request re-runs the analysis on the same head. That run re-renders
// the inline finding comments, and the ready job for that head is reused rather than
// regenerated, so nothing would write the verified fix sections back under them. The
// two hooks the orchestrator runs after a completed analysis are exercised here in
// the order it runs them.
test('a second completed analysis on the same head reuses the ready job and republishes its verified fixes exactly once', async () => {
  const autoGenerate = require('../../src/services/remediationAutoGenerate');
  const f = await fixture();
  const open = await insertOpenFinding(f, f.run, { severity: 'high', path: 'src/app.js', title: 'SQL injection' });
  await pool.query(`UPDATE analysis_run_findings SET snapshot = snapshot || $2::jsonb WHERE finding_id=$1`, [open, JSON.stringify({ fingerprint: `fp-${open}`, line_start: 10, line_end: 10 })]);
  const queued = await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: f.pr, analysisRunId: f.run });
  assert.equal(queued.enqueued, true);

  const original = 'const db = require("./db");\nasync function order(id) {\n  return db.query(`SELECT * FROM orders WHERE id = ${id}`);\n}\n';
  const fixed = original.replace('${id}`)', "$1', [id])");
  await workerQuery(
    `INSERT INTO remediation_candidates (job_id,installation_id,repository_id,candidate_version,finding_snapshot_ids,artifact_digest,context_manifest_digest,file_manifest,preview,verification_level)
     VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,'independent_sandbox')`,
    [queued.job_id, f.installation, f.repo, [open], 'a'.repeat(64), 'c'.repeat(64),
      JSON.stringify({ verified_tree_oid: 'f'.repeat(40), files: [{ path: 'src/app.js', contents_base64: Buffer.from(fixed).toString('base64') }] }),
      JSON.stringify({ changes: [{ path: 'src/app.js', original, replacement: fixed, unified_diff: '@@ -3 +3 @@\n-old\n+new' }],
        reasoning: { intended_behavior: 'Same row for the same id.' }, evidence: { status: 'passed', limitations: [] } })]
  );
  await workerQuery(`UPDATE remediation_jobs SET state='ready', stage='ready' WHERE id=$1`, [queued.job_id]);

  // The job's fixes are published for this head, as the ready event does.
  const inlineFixes = require('../../src/services/remediationInlineFixes');
  const before = publishedFixSections.length;
  assert.equal((await inlineFixes.publishInlineFixes(queued.job_id)).published, true);
  assert.equal(publishedFixSections.length, before + 1);
  const published = await workerQuery('SELECT inline_fixes_published_at, inline_fixes_head_sha FROM remediation_jobs WHERE id=$1', [queued.job_id]);
  assert.ok(published.rows[0].inline_fixes_published_at);
  assert.equal(published.rows[0].inline_fixes_head_sha, f.head);

  // The reopened pull request's analysis: a second completed run for the same head.
  const second = (await pool.query(`INSERT INTO analysis_runs (repository_id,pull_request_id,pr_number,commit_sha,status,triggered_by,completed_at)
    VALUES ($1,$2,1,$3,'completed','webhook',NOW()) RETURNING id`, [f.repo, f.pr, f.head])).rows[0].id;
  await pool.query(`INSERT INTO analysis_run_findings (analysis_run_id,finding_id,snapshot)
    SELECT $1, finding_id, snapshot FROM analysis_run_findings WHERE analysis_run_id=$2`, [second, f.run]);

  // The ready job for this head and selection is reused, not regenerated.
  const reused = await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: f.pr, analysisRunId: second });
  assert.deepEqual(reused, { enqueued: false, reason: 'exists', job_id: queued.job_id });
  const jobs = await workerQuery(`SELECT COUNT(*)::int AS n FROM remediation_jobs WHERE pull_request_id=$1 AND head_sha=$2`, [f.pr, f.head]);
  assert.equal(jobs.rows[0].n, 1);

  // The republication hook writes the sections back exactly once.
  const result = await autoGenerate.republishInlineFixesForCompletedAnalysis({ pullRequestId: f.pr, headSha: f.head });
  assert.deepEqual(result, { republished: 1, jobs: 1 });
  assert.equal(publishedFixSections.length, before + 2);
  const republished = publishedFixSections[before + 1];
  assert.equal(republished.head_sha, f.head);
  assert.deepEqual(republished.sections.map((section) => section.finding_fingerprint), [`fp-${open}`]);
  assert.deepEqual(republished.sections, publishedFixSections[before].sections);

  // A head that has no ready job with published fixes writes nothing.
  assert.deepEqual(await autoGenerate.republishInlineFixesForCompletedAnalysis({ pullRequestId: f.pr, headSha: 'c'.repeat(40) }),
    { republished: 0, reason: 'no_published_ready_job' });
  assert.equal(publishedFixSections.length, before + 2);
});

test('repair evidence outlives the execution record: it is persisted with the completion and readable once the job is ready', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const claimed = await remediationDb.claimJobById(jobId, 'worker-evidence', 60);
  assert.ok(claimed);

  // The response the repair service returns, carrying the evidence that until now lived
  // only on the execution backend's own disk. The output tail is deliberately over bound.
  const failureOutput = `${'x'.repeat(6000)}AssertionError: query was still concatenated`;
  const repairResponse = {
    state: 'ready', head_sha: f.head, base_sha: f.base, manifest_digest: 'm'.repeat(64),
    candidates: [{ artifact_digest: 'a'.repeat(64), finding_ids: [f.finding],
      preview: { changes: [{ path: 'src/app.js', contents_base64: Buffer.from('never persisted').toString('base64') }],
        evidence: { status: 'passed', verification_level: 'independent_sandbox', evidence_digest: 'e'.repeat(64),
          summary: ['Regression test tests/app.test.js failed on the original code and passed on the fix.'],
          limitations: ['Not run: repository test suite.'] } },
      verification: { status: 'passed' } }],
    skipped: [{ finding_id: 'other-finding', code: 'not_repaired', message: 'No candidate proved this finding.' }],
    usage: { provider_request_id: 'req_integration' },
    evidence: {
      context_manifest_digest: 'c'.repeat(64), verification_level: 'independent_sandbox', verified_tree_oid: 'f'.repeat(40),
      agent_trace: Array.from({ length: 260 }, (_, index) => ({ sequence: index + 1, tool: 'read_file',
        arguments_digest_only: { path_digest: 'must-not-be-persisted' }, outcome: 'ok', reason: null, result_bytes: 100 + index })),
      usage: { input_tokens: 9000, output_tokens: 1500, provider_request_ids: ['req_integration'] },
      budget_reservation: { settled_calls: 3, overage_calls: 1, overage_tokens: 120, overage_usd: 0.004,
        settlements: [{ call_index: 3, reserved_tokens: 800, reserved_usd: 0.01, actual_tokens: 920, actual_usd: 0.014, overage_tokens: 120, overage_usd: 0.004 }] },
      groups: [{ group_index: 0, finding_ids: [f.finding, 'other-finding'], state: 'ready', reason: null,
        candidate_ids: ['candidate-0'], repaired_finding_ids: [f.finding],
        coverage: { revisions_used: 1, max_revisions: 2, proven_finding_ids: [f.finding], stopped: 'revision_budget_spent' },
        unproven_findings: [{ finding_id: 'other-finding', code: 'not_repaired', message: 'no reproducing test' }] }],
      limitations: ['Not run: repository test suite.'],
      verification_run: { outcome: 'passed', reason_code: null, coverage_gaps: [],
        checks: [{ check_id: 'generated_regression', kind: 'generated_test', finding_id: f.finding,
          baseline: { completed: true, status: 'failed', exit_code: 1, duration_ms: 120, output_tail: failureOutput },
          candidate: { completed: true, status: 'passed', exit_code: 0, duration_ms: 118, output_tail: null } }] },
    },
  };

  assert.equal(await remediationDb.completeStage(claimed, {
    state: 'ready', stage: 'ready', outcome: 'ready', stagePath: [],
    candidates: repairResponse.candidates,
    verification: { status: 'passed', evidence_digest: 'e'.repeat(64), candidate_tree_sha: 'f'.repeat(40), limitations: [] },
    outputDigest: remediationDb.hash(repairResponse),
    evidence: workflow.buildEvidenceRecords(repairResponse, { cost: 0.0271 }),
  }), true);

  // One row per kind, bound to the attempt that produced it.
  const stored = await workerQuery('SELECT attempt, kind FROM remediation_job_evidence WHERE job_id=$1 ORDER BY kind', [jobId]);
  assert.deepEqual(stored.rows.map((row) => row.kind),
    ['agent_trace', 'budget_reservation', 'candidate_evidence', 'groups', 'usage', 'verification']);
  assert.ok(stored.rows.every((row) => Number(row.attempt) === 1));

  const evidence = await request(app).get(`/api/remediations/${jobId}/evidence`).auth(f.token, { type: 'bearer' });
  assert.equal(evidence.status, 200);
  assert.equal(evidence.body.job_state, 'ready');
  assert.equal(evidence.body.agent_trace.total, 260);
  assert.equal(evidence.body.agent_trace.truncated, true);
  assert.equal(evidence.body.agent_trace.items.length, 200);
  assert.deepEqual(Object.keys(evidence.body.agent_trace.items[0]).sort(), ['outcome', 'reason', 'result_bytes', 'sequence', 'tool']);
  assert.deepEqual(evidence.body.usage, { input_tokens: 9000, output_tokens: 1500, cost_usd: 0.0271, provider_request_ids: ['req_integration'] });
  assert.equal(evidence.body.budget_reservation.overage_calls, 1);
  assert.equal(evidence.body.budget_reservation.settlements.items[0].actual_tokens, 920);
  assert.equal(evidence.body.groups.groups.items[0].coverage.stopped, 'revision_budget_spent');
  assert.equal(evidence.body.groups.skipped.items[0].finding_id, 'other-finding');
  assert.equal(evidence.body.candidates.items[0].evidence.verification_level, 'independent_sandbox');

  const check = evidence.body.verification.checks.items[0];
  assert.equal(check.candidate.status, 'passed');
  assert.equal(Buffer.byteLength(check.baseline.output_tail, 'utf8'), 2048, 'an output tail is bounded at 2 KB');
  assert.ok(check.baseline.output_tail.endsWith('AssertionError: query was still concatenated'), 'the tail keeps the end, where the failure is');
  assert.equal(check.baseline.output_truncated, true);

  // No file contents, no patch text and no tool arguments are ever persisted.
  const serialized = JSON.stringify(evidence.body);
  assert.ok(!serialized.includes('contents_base64'));
  assert.ok(!serialized.includes('must-not-be-persisted'));
  assert.ok(!serialized.includes(Buffer.from('never persisted').toString('base64')));

  // The preview keeps working. Authorization is the row level security scope the preview
  // already uses, which this superuser-owned test database does not enforce; the route
  // requires a token and refuses an id it cannot read.
  assert.equal((await request(app).get(`/api/remediations/${jobId}/preview`).auth(f.token, { type: 'bearer' })).status, 200);
  assert.equal((await request(app).get(`/api/remediations/${jobId}/evidence`)).status, 401);
  assert.equal((await request(app).get(`/api/remediations/${randomUUID()}/evidence`).auth(f.token, { type: 'bearer' })).status, 404);
});
