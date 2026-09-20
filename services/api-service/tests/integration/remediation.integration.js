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
process.env.REMEDIATION_APPLY_ENABLED = 'true';
process.env.REMEDIATION_MERGE_ENABLED = 'true';
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
const githubCalls = { authorize: 0, head: 0, eligibility: 0, merge: 0, check_run: 0, cancel: 0, comment: 0 };
let lastCheckRun = null;
const publishedComments = new Map();
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
const outbox = require('../../src/services/remediationOutbox');
const reconciler = require('../../src/services/remediationReconciler');
const mergeController = require('../../src/services/mergeController');
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

test('an apply idempotency key replays the same action and rejects a different payload', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const ready = await makeReady(f, jobId);
  const body = { head_sha: f.head, base_sha: f.base, manifest_digest: ready.digest, candidate_ids: [ready.candidate],
    merge_when_ready: false, idempotency_key: 'integration-apply-key' };

  const first = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' }).send(body);
  assert.equal(first.status, 202, JSON.stringify(first.body));
  const second = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' }).send(body);
  assert.equal(second.status, 202);
  assert.equal(second.body.action.id, first.body.action.id);
  assert.equal(second.body.replay, true);
  assert.equal((await workerQuery('SELECT id FROM remediation_actions WHERE job_id=$1', [jobId])).rowCount, 1);

  const changed = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' })
    .send({ ...body, merge_when_ready: true });
  assert.equal(changed.status, 409);
  assert.equal(changed.body.error, 'Idempotency key was already used with a different request');

  // The pull request writer lease is held by the in-flight action.
  assert.equal((await workerQuery('SELECT action_id FROM remediation_writer_leases WHERE pull_request_id=$1', [f.pr])).rows[0].action_id,
    first.body.action.id);
});

test('a second concurrent apply for the same pull request is refused while a writer holds the lease', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const ready = await makeReady(f, jobId);
  const body = { head_sha: f.head, base_sha: f.base, manifest_digest: ready.digest, candidate_ids: [ready.candidate],
    merge_when_ready: false, idempotency_key: 'integration-writer-key-1' };
  assert.equal((await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' }).send(body)).status, 202);
  const second = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' })
    .send({ ...body, idempotency_key: 'integration-writer-key-2' });
  assert.equal(second.status, 409);
  assert.equal(second.body.code, 'writer_lease_held');
});

test('a synchronize webhook supersedes the job, invalidates candidates and cancels the merge intent', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const ready = await makeReady(f, jobId);
  const applied = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' }).send({
    head_sha: f.head, base_sha: f.base, manifest_digest: ready.digest, candidate_ids: [ready.candidate],
    merge_when_ready: true, idempotency_key: 'integration-supersede-key',
  });
  assert.equal(applied.status, 202, JSON.stringify(applied.body));

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
  const intent = (await workerQuery('SELECT state, cancellation_reason FROM merge_intents WHERE action_id=$1', [applied.body.action.id])).rows[0];
  assert.equal(intent.state, 'cancelled');
  assert.equal(intent.cancellation_reason, 'head_changed');
});

test('a synchronize webhook whose new head is the recorded application commit keeps the merge intent', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const ready = await makeReady(f, jobId);
  const applied = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' }).send({
    head_sha: f.head, base_sha: f.base, manifest_digest: ready.digest, candidate_ids: [ready.candidate],
    merge_when_ready: true, idempotency_key: 'integration-application-commit',
  });
  const applicationCommit = '9'.repeat(40);
  await workerQuery(`UPDATE remediation_actions SET state='applied', observed_commit_sha=$2 WHERE id=$1`, [applied.body.action.id, applicationCommit]);
  await workerQuery(`UPDATE merge_intents SET state='waiting_for_checks', applied_sha=$2 WHERE action_id=$1`, [applied.body.action.id, applicationCommit]);

  const response = await signedWebhook(app, 'pull_request', {
    action: 'synchronize',
    installation: { id: f.installation },
    repository: { id: f.n, name: 'fixture', full_name: f.fullName, private: false, default_branch: 'main' },
    pull_request: { id: f.n, number: 1, title: 't', body: '', state: 'open', draft: false,
      head: { sha: applicationCommit, ref: 'feature' }, base: { sha: f.base, ref: 'main' }, user: { login: 'dev' }, html_url: 'https://example.invalid' },
  });
  assert.equal(response.status, 200);
  const intent = (await workerQuery('SELECT state FROM merge_intents WHERE action_id=$1', [applied.body.action.id])).rows[0];
  assert.equal(intent.state, 'waiting_for_checks', 'the system must not cancel the intent over its own application commit');
});

test('a check_run webhook records a merge re-evaluation hint without deciding anything', async () => {
  const f = await fixture();
  const app = createApp();
  const response = await signedWebhook(app, 'check_run', {
    action: 'completed',
    installation: { id: f.installation },
    repository: { id: f.n, full_name: f.fullName },
    check_run: { head_sha: f.head, pull_requests: [{ number: 1 }], conclusion: 'success' },
  });
  assert.equal(response.status, 200);
  const hints = await workerQuery(
    `SELECT payload FROM workflow_events WHERE aggregate_id=$1 AND event_type='remediation.merge.reevaluate'`, [f.pr]);
  assert.equal(hints.rowCount, 1);
  assert.equal(hints.rows[0].payload.reason, 'check_run.completed');
});

test('the reconciler expires merge intents past their expiry and quarantines exhausted jobs', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const ready = await makeReady(f, jobId);
  const applied = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' }).send({
    head_sha: f.head, base_sha: f.base, manifest_digest: ready.digest, candidate_ids: [ready.candidate],
    merge_when_ready: true, idempotency_key: 'integration-reconcile-key',
  });
  assert.equal(applied.status, 202, JSON.stringify(applied.body));
  await workerQuery(`UPDATE merge_intents SET expires_at=NOW()-INTERVAL '1 hour' WHERE action_id=$1`, [applied.body.action.id]);

  const exhausted = await fixture();
  const exhaustedJob = (await request(app).post(`/api/pull-requests/${exhausted.pr}/remediations`).auth(exhausted.token, { type: 'bearer' }).send({})).body.job.id;
  await workerQuery('UPDATE remediation_jobs SET attempt_count=9 WHERE id=$1', [exhaustedJob]);

  const summary = await reconciler.runReconciliation();
  assert.ok(summary.merge_intents.expired >= 1);
  assert.equal((await workerQuery('SELECT state FROM merge_intents WHERE action_id=$1', [applied.body.action.id])).rows[0].state, 'expired');
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

// Drives one apply-and-merge action to the point where its merge intent is evaluable
// against the real database: applied commit recorded, fresh analysis completed.
async function applyAndMerge(f, key) {
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const ready = await makeReady(f, jobId);
  const applied = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' }).send({
    head_sha: f.head, base_sha: f.base, manifest_digest: ready.digest, candidate_ids: [ready.candidate],
    merge_when_ready: true, idempotency_key: key,
  });
  assert.equal(applied.status, 202, JSON.stringify(applied.body));
  return { app, jobId, ready, actionId: applied.body.action.id };
}

async function intentState(actionId) {
  return (await workerQuery('SELECT * FROM merge_intents WHERE action_id=$1', [actionId])).rows[0];
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

test('a merge intent advances waiting_for_application to waiting_for_checks to eligible to merged', async () => {
  resetGitHubStub();
  const f = await fixture();
  const appliedSha = '1'.repeat(40);
  const { actionId } = await applyAndMerge(f, 'integration-merge-advance');
  // The apply route performed its own live authorization; the merge controller's own
  // calls are what this test counts.
  resetCounts();
  assert.equal((await intentState(actionId)).state, 'waiting_for_application');

  // Nothing is applied yet: the controller must not reach GitHub at all.
  let result = await mergeController.evaluateForAction(actionId);
  assert.equal(result.state, 'waiting_for_application');
  assert.deepEqual(result.blockers, ['waiting_for_application']);
  assert.equal(githubCalls.authorize, 0);
  assert.equal(githubCalls.merge, 0);

  const analysisRunId = await completeApplication(actionId, appliedSha);
  result = await mergeController.evaluateForAction(actionId);
  assert.equal(result.state, 'waiting_for_checks');
  assert.deepEqual(result.blockers, ['application_verification_pending']);
  assert.equal((await intentState(actionId)).applied_sha, appliedSha);

  // The verification check is published for the applied head before it can gate a merge.
  await mergeController.publishVerificationCheck(actionId);
  assert.equal(githubCalls.check_run, 1);

  // A completed application whose check has not settled is still not eligible.
  assert.equal(await remediationDb.completeAction(actionId, { headSha: appliedSha }), null,
    'completion requires the verification analysis to be completed');
  await workerQuery(`UPDATE analysis_runs SET status='completed', completed_at=NOW() WHERE id=$1`, [analysisRunId]);
  assert.ok(await remediationDb.completeAction(actionId, { headSha: appliedSha }));
  await mergeController.publishVerificationCheck(actionId);
  const publishedAction = (await workerQuery('SELECT * FROM remediation_actions WHERE id=$1', [actionId])).rows[0];
  assert.equal(publishedAction.verification_check_status, 'completed');
  assert.equal(publishedAction.verification_check_conclusion, 'success');
  assert.equal(publishedAction.verification_check_head_sha, appliedSha);

  headResponse = (payload) => ({ head_sha: payload.head_sha, base_sha: f.base, state: 'open', draft: false, merged: false, fork: false });
  result = await mergeController.evaluateForAction(actionId);
  assert.equal(result.state, 'merged', JSON.stringify(result));
  const intent = await intentState(actionId);
  assert.equal(intent.state, 'merged');
  assert.equal(intent.observed_merge_sha, 'd'.repeat(40));
  assert.equal(Number(intent.merge_attempts), 1);
  assert.equal(intent.external_operation_id, actionId);
  assert.ok(intent.last_evaluated_at);
  assert.equal(githubCalls.merge, 1, 'exactly one guarded merge call per eligibility evaluation');
  assert.equal(githubCalls.eligibility, 1);

  // A merged intent is terminal; a later evaluation must not call GitHub again.
  const again = await mergeController.evaluateForAction(actionId);
  assert.equal(again.state, 'merged');
  assert.equal(githubCalls.merge, 1);
});

test('a revoked actor permission blocks the merge and the blocker list is persisted', async () => {
  resetGitHubStub();
  const f = await fixture();
  const appliedSha = '2'.repeat(40);
  const { actionId } = await applyAndMerge(f, 'integration-merge-permission');
  const analysisRunId = await completeApplication(actionId, appliedSha);
  await workerQuery(`UPDATE analysis_runs SET status='completed', completed_at=NOW() WHERE id=$1`, [analysisRunId]);
  await remediationDb.completeAction(actionId, { headSha: appliedSha });
  await mergeController.publishVerificationCheck(actionId);

  authorizeResponse = async () => ({ state: 'authorized', installation_active: true, repository_granted: true, actor_write_permission: false });
  const result = await mergeController.evaluateForAction(actionId);
  assert.equal(result.state, 'blocked');
  const intent = await intentState(actionId);
  assert.deepEqual(intent.blockers, ['actor_write_permission_missing']);
  assert.equal(githubCalls.merge, 0);
});

test('the merge controller sweep expires an intent past its expiry without calling GitHub', async () => {
  resetGitHubStub();
  const f = await fixture();
  const { actionId } = await applyAndMerge(f, 'integration-merge-expiry');
  await workerQuery(`UPDATE merge_intents SET expires_at=NOW()-INTERVAL '1 hour' WHERE action_id=$1`, [actionId]);
  resetCounts();

  const summary = await mergeController.sweep({ staleSeconds: 0, limit: 50 });
  assert.ok(summary.evaluated >= 1);
  const intent = await intentState(actionId);
  assert.equal(intent.state, 'expired');
  assert.equal(intent.cancellation_reason, 'expired');
  assert.ok(intent.last_evaluated_at);
  assert.equal(githubCalls.merge, 0);
  assert.equal(githubCalls.authorize, 0);
});

test('a merge re-evaluation hint dispatched through the outbox evaluates the intent exactly once', async () => {
  resetGitHubStub();
  outbox.registerDefaultHandlers({
    executeClaimedJob: async () => {}, executeClaimedAction: async () => {}, workerId: 'integration-merge',
  });
  const f = await fixture();
  const appliedSha = '3'.repeat(40);
  const { app, actionId } = await applyAndMerge(f, 'integration-merge-hint');
  const analysisRunId = await completeApplication(actionId, appliedSha);
  await workerQuery(`UPDATE analysis_runs SET status='completed', completed_at=NOW() WHERE id=$1`, [analysisRunId]);
  await remediationDb.completeAction(actionId, { headSha: appliedSha });
  await mergeController.publishVerificationCheck(actionId);
  // A GitHub blocker keeps the intent non-terminal so a duplicate dispatch would show.
  eligibilityResponse = { eligible: false, blockers: ['required_approvals_missing'], protection_source: 'branch_protection' };
  headResponse = (payload) => ({ head_sha: payload.head_sha, base_sha: f.base, state: 'open', draft: false, merged: false, fork: false });
  // The completion event queued its own evaluation; deliver it first so the hint below
  // is measured on its own.
  await outbox.processPending({ limit: 50, dispatcher: outbox.createDispatcher('inprocess') });
  resetGitHubStub();
  eligibilityResponse = { eligible: false, blockers: ['required_approvals_missing'], protection_source: 'branch_protection' };
  headResponse = (payload) => ({ head_sha: payload.head_sha, base_sha: f.base, state: 'open', draft: false, merged: false, fork: false });

  const hint = await signedWebhook(app, 'check_run', {
    action: 'completed',
    installation: { id: f.installation },
    repository: { id: f.n, full_name: f.fullName },
    check_run: { head_sha: appliedSha, pull_requests: [{ number: 1 }], conclusion: 'success' },
  });
  assert.equal(hint.status, 200);
  const pending = await workerQuery(
    `SELECT id, status FROM workflow_outbox WHERE aggregate_id=$1 AND event_type='remediation.merge.reevaluate'`, [f.pr]);
  assert.equal(pending.rowCount, 1, 'the hint must be recorded as exactly one dispatchable outbox row');

  const dispatcher = outbox.createDispatcher('inprocess');
  await outbox.processPending({ limit: 50, dispatcher });
  assert.equal(githubCalls.eligibility, 1, 'the hint must trigger exactly one evaluation');
  assert.equal(githubCalls.merge, 0);
  const intent = await intentState(actionId);
  assert.equal(intent.state, 'blocked');
  assert.deepEqual(intent.blockers, ['required_approvals_missing']);

  // A second pass finds nothing pending: the delivered hint is never replayed.
  await outbox.processPending({ limit: 50, dispatcher });
  assert.equal(githubCalls.eligibility, 1);
  assert.equal((await workerQuery(`SELECT status FROM workflow_outbox WHERE id=$1`, [pending.rows[0].id])).rows[0].status, 'delivered');
});

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

async function insertOpenFinding(f, runId, { severity, path, title, testCode = false }) {
  return (await pool.query(
    `INSERT INTO findings (repository_id,installation_id,pull_request_number,pull_request_id,analysis_run_id,commit_sha,fingerprint,rule_id,title,description,category,severity,file_path,line_start,status,evidence_details)
     VALUES ($1,$2,1,$3,$4,$5,$6,'rule',$7,'d','injection',$8,$9,10,'open',$10) RETURNING id`,
    [f.repo, f.installation, f.pr, runId, f.head.slice(0, 40), randomUUID().replace(/-/g, ''), title, severity, path,
      JSON.stringify(testCode ? { extra: { in_test_code: true, original_severity: severity } } : {})]
  )).rows[0].id;
}

test('consent binds the exact subset: one candidate applies on its own digest, other digests are refused', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const ready = await makeReadyWith(f, jobId, ['services/customers.js', 'services/orders.js', 'services/users.js']);
  const [one, two, three] = ready.rows;

  const preview = await request(app).get(`/api/remediations/${jobId}/preview`).auth(f.token, { type: 'bearer' });
  assert.equal(preview.status, 200);
  assert.equal(preview.body.candidates[0].manifest_digest, ready.digestFor([one.id]));
  assert.equal(preview.body.manifest_digest, ready.digestFor([one.id, two.id, three.id]));
  assert.equal(preview.body.files.length, 3);

  const body = (candidateIds, digest, key) => ({ head_sha: f.head, base_sha: f.base, manifest_digest: digest, candidate_ids: candidateIds,
    merge_when_ready: false, idempotency_key: key });

  // A digest over a different subset never matches the consent for this one.
  const wrong = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' })
    .send(body([one.id], ready.digestFor([one.id, two.id, three.id]), 'integration-subset-wrong'));
  assert.equal(wrong.status, 409); assert.equal(wrong.body.code, 'manifest_mismatch');

  // Two of three were never verified together.
  const pair = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' })
    .send(body([one.id, two.id], ready.digestFor([one.id, two.id]), 'integration-subset-pair'));
  assert.equal(pair.status, 422); assert.equal(pair.body.code, 'subset_not_verified');

  // Merging is never requested by the product.
  const merge = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' })
    .send({ ...body([one.id], ready.digestFor([one.id]), 'integration-subset-merge'), merge_when_ready: true });
  assert.equal(merge.status, 202, 'the integration environment opts into the operator merge flag');

  assert.equal((await workerQuery('SELECT COUNT(*)::int AS n FROM remediation_actions WHERE job_id=$1', [jobId])).rows[0].n, 1);
  const stored = (await workerQuery('SELECT candidate_ids, batch_manifest_digest FROM remediation_actions WHERE job_id=$1', [jobId])).rows[0];
  assert.deepEqual(stored.candidate_ids, [one.id]);
  assert.equal(stored.batch_manifest_digest, ready.digestFor([one.id]));
  const material = await remediationDb.actionMaterial((await workerQuery('SELECT * FROM remediation_actions WHERE job_id=$1', [jobId])).rows[0]);
  assert.equal(material.manifestDigest, ready.digestFor([one.id]));
  assert.equal(material.fullBatch, false);
  assert.equal(material.combinedTreeOid, 'e'.repeat(40));
});

test('after one candidate is applied the remaining candidates are stale, the job is superseded and nothing else applies', async () => {
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const ready = await makeReadyWith(f, jobId, ['services/customers.js', 'services/orders.js']);
  const [one, two] = ready.rows;
  const applied = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' }).send({
    head_sha: f.head, base_sha: f.base, manifest_digest: ready.digestFor([one.id]), candidate_ids: [one.id],
    merge_when_ready: false, idempotency_key: 'integration-stale-one',
  });
  assert.equal(applied.status, 202, JSON.stringify(applied.body));
  const action = (await workerQuery('SELECT * FROM remediation_actions WHERE id=$1', [applied.body.action.id])).rows[0];
  const commitSha = '5'.repeat(40);

  const marked = await remediationDb.markCandidatesAfterApply(action, commitSha);
  assert.deepEqual(marked.jobs, [jobId]);
  assert.deepEqual(marked.candidates, [two.id]);
  const candidates = (await workerQuery('SELECT id, rejection_reason FROM remediation_candidates WHERE job_id=$1 ORDER BY candidate_version', [jobId])).rows;
  assert.equal(candidates[0].rejection_reason.code, 'applied');
  assert.equal(candidates[0].rejection_reason.commit_sha, commitSha);
  assert.equal(candidates[1].rejection_reason.code, 'head_changed');
  assert.equal((await workerQuery('SELECT state FROM remediation_jobs WHERE id=$1', [jobId])).rows[0].state, 'superseded');

  // The preview stays readable and reports the stale state; nothing more can be applied.
  const preview = await request(app).get(`/api/remediations/${jobId}/preview`).auth(f.token, { type: 'bearer' });
  assert.equal(preview.status, 200);
  assert.equal(preview.body.applicable, false);
  assert.equal(preview.body.manifest_digest, null);
  assert.deepEqual(preview.body.candidates.map((c) => c.status), ['applied', 'stale']);
  assert.equal(preview.body.candidates[1].stale_reason, 'head_changed');
  // The writer lease from the in-flight action is released so the refusal is about the job, not the lease.
  await workerQuery('DELETE FROM remediation_writer_leases WHERE pull_request_id=$1', [f.pr]);
  const again = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' }).send({
    head_sha: f.head, base_sha: f.base, manifest_digest: ready.digestFor([two.id]), candidate_ids: [two.id],
    merge_when_ready: false, idempotency_key: 'integration-stale-two',
  });
  assert.equal(again.status, 409); assert.equal(again.body.code, 'job_not_ready');
});

test('the verification check blocks on any open finding severity and the residual report is published once per action', async () => {
  resetGitHubStub();
  const f = await fixture();
  const app = createApp();
  const jobId = (await request(app).post(`/api/pull-requests/${f.pr}/remediations`).auth(f.token, { type: 'bearer' }).send({})).body.job.id;
  const ready = await makeReadyWith(f, jobId, ['services/customers.js']);
  const applied = await request(app).post(`/api/remediations/${jobId}/apply`).auth(f.token, { type: 'bearer' }).send({
    head_sha: f.head, base_sha: f.base, manifest_digest: ready.digestFor([ready.rows[0].id]), candidate_ids: [ready.rows[0].id],
    merge_when_ready: false, idempotency_key: 'integration-residual',
  });
  assert.equal(applied.status, 202, JSON.stringify(applied.body));
  const actionId = applied.body.action.id;
  const appliedSha = '6'.repeat(40);
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
  const republished = await mergeController.publishVerificationCheck(actionId);
  assert.equal(republished.conclusion, 'success');
  assert.match(lastCheckRun.title, /no open findings remain/);
});
