// Run explicitly with:
//   NODE_ENV=test DATABASE_URL=postgres://.../mitig8it_purge_test \
//     node --test tests/integration/installation-purge.integration.js
// This suite resets the public schema of its guarded, isolated database.
//
// It seeds one installation across every table the purge touches, plus a second
// installation with the same shape, purges the first, and asserts that not one row of
// the first survives and not one row of the second was touched. Anything less than that
// would not prove the claim the Security page makes.
const assert = require('node:assert/strict');
const { test, before, after, beforeEach } = require('node:test');

const databaseUrl = new URL(process.env.DATABASE_URL || 'http://invalid');
if (process.env.NODE_ENV !== 'test' || !['127.0.0.1', 'localhost', '[::1]'].includes(databaseUrl.hostname)
    || !/^\/[a-z0-9_]+_test$/.test(databaseUrl.pathname)
    || !['postgres:', 'postgresql:'].includes(databaseUrl.protocol)) {
  throw new Error('Requires NODE_ENV=test and a loopback PostgreSQL DATABASE_URL ending in _test');
}
process.env.GITHUB_WEBHOOK_SECRET = 'local-purge-integration-secret';
process.env.JWT_SECRET = 'local-purge-jwt-secret';

const { pool } = require('../../src/config/database');
const { applyMigrations } = require('../../src/services/migrationRunner');
const purge = require('../../src/services/installationPurge');

const KEEP = 43;
const DOOMED = 42;

// Every table the purge deletes from, plus the installation row itself. Asserting
// against this list is what makes a newly added tenant table fail the test loudly
// instead of quietly surviving an uninstall.
const SCOPED_TABLES = [...purge.purgeTables(), 'installations'];

// How to count the rows of one installation in each table. Tables without an
// installation_id are counted through repositories, exactly as the purge scopes them.
const COUNT_SQL = {
  installations: 'SELECT COUNT(*) c FROM installations WHERE id = $1',
  user_installations: 'SELECT COUNT(*) c FROM user_installations WHERE installation_id = $1',
  repositories: 'SELECT COUNT(*) c FROM repositories WHERE installation_id = $1',
  repository_access: `SELECT COUNT(*) c FROM repository_access WHERE repository_id IN
    (SELECT id FROM repositories WHERE installation_id = $1)`,
  pull_requests: `SELECT COUNT(*) c FROM pull_requests WHERE repository_id IN
    (SELECT id FROM repositories WHERE installation_id = $1)`,
  analysis_runs: `SELECT COUNT(*) c FROM analysis_runs WHERE repository_id IN
    (SELECT id FROM repositories WHERE installation_id = $1)`,
  analysis: `SELECT COUNT(*) c FROM analysis WHERE repository_id IN
    (SELECT id FROM repositories WHERE installation_id = $1)`,
  analysis_run_findings: `SELECT COUNT(*) c FROM analysis_run_findings WHERE analysis_run_id IN
    (SELECT ar.id FROM analysis_runs ar JOIN repositories r ON r.id = ar.repository_id
      WHERE r.installation_id = $1)`,
  findings: `SELECT COUNT(*) c FROM findings WHERE installation_id = $1 OR repository_id IN
    (SELECT id FROM repositories WHERE installation_id = $1)`,
  suppressions: `SELECT COUNT(*) c FROM suppressions WHERE repository_id IN
    (SELECT id FROM repositories WHERE installation_id = $1)`,
  audit_logs: `SELECT COUNT(*) c FROM audit_logs WHERE repository_id IN
    (SELECT id FROM repositories WHERE installation_id = $1)`,
  webhook_events: `SELECT COUNT(*) c FROM webhook_events WHERE repository_id IN
    (SELECT id FROM repositories WHERE installation_id = $1)`,
};

function countSql(table) {
  return COUNT_SQL[table] || `SELECT COUNT(*) c FROM ${table} WHERE installation_id = $1`;
}

// The purge's own DELETEs run with the worker tenant scope set. Counting must too, or
// row level security hides rows that are still there and the test passes on a lie.
async function countRows(table, installationId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [String(installationId)]);
    await client.query("SELECT set_config('app.remediation_worker', '1', true)");
    const result = await client.query(countSql(table), [installationId]);
    await client.query('COMMIT');
    return Number(result.rows[0].c);
  } finally {
    client.release();
  }
}

async function countAll(installationId) {
  const counts = {};
  for (const table of SCOPED_TABLES) counts[table] = await countRows(table, installationId);
  return counts;
}

// One installation, fully populated: a repository, a pull request, an analysis run with
// findings and a suppression, the whole remediation control plane, an audit row and a
// webhook event.
async function seedInstallation(installationId, { login }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [String(installationId)]);
    await client.query("SELECT set_config('app.remediation_worker', '1', true)");

    await client.query(
      `INSERT INTO installations (id, account_login, account_type, target_type, status)
       VALUES ($1, $2, 'Organization', 'Organization', 'active')`, [installationId, login]);

    const userId = (await client.query(
      `INSERT INTO users (github_id, github_username, installation_id)
       VALUES ($1, $2, $3) RETURNING id`,
      [installationId * 10, `${login}-user`, installationId])).rows[0].id;

    await client.query('INSERT INTO user_installations (user_id, installation_id) VALUES ($1, $2)',
      [userId, installationId]);

    const repositoryId = (await client.query(
      `INSERT INTO repositories (github_id, installation_id, name, full_name, private, default_branch, is_active)
       VALUES ($1, $2, 'service', $3, TRUE, 'main', TRUE) RETURNING id`,
      [installationId * 100, installationId, `${login}/service`])).rows[0].id;

    await client.query("INSERT INTO repository_access (user_id, repository_id, role) VALUES ($1, $2, 'admin')",
      [userId, repositoryId]);

    const pullRequestId = (await client.query(
      `INSERT INTO pull_requests (repository_id, github_pr_id, pr_number, title, state, head_sha, base_sha, head_branch, base_branch, author)
       VALUES ($1, $2, 7, 'Fixture', 'open', $3, $4, 'feature', 'main', $5) RETURNING id`,
      [repositoryId, installationId * 1000, 'a'.repeat(40), 'b'.repeat(40), `${login}-user`])).rows[0].id;

    const analysisRunId = (await client.query(
      `INSERT INTO analysis_runs (repository_id, pull_request_id, pr_number, commit_sha, status, triggered_by)
       VALUES ($1, $2, 7, $3, 'completed', 'webhook') RETURNING id`,
      [repositoryId, pullRequestId, 'a'.repeat(40)])).rows[0].id;

    await client.query(
      `INSERT INTO analysis (repository_id, status) VALUES ($1, 'completed')`, [repositoryId]);

    const findingId = (await client.query(
      `INSERT INTO findings (installation_id, repository_id, pull_request_id, analysis_run_id, rule_id, title,
         description, category, severity, file_path, line_start, fingerprint)
       VALUES ($1, $2, $3, $4, 'sql_injection', 'SQL injection', 'Concatenated query', 'injection', 'high', 'src/app.js', 4, $5) RETURNING id`,
      [installationId, repositoryId, pullRequestId, analysisRunId, `${installationId}-fingerprint`])).rows[0].id;

    await client.query(
      `INSERT INTO analysis_run_findings (analysis_run_id, finding_id, snapshot)
       VALUES ($1, $2, '{}'::jsonb)`, [analysisRunId, findingId]);

    await client.query(
      `INSERT INTO suppressions (finding_id, repository_id, fingerprint, reason, suppressed_by)
       VALUES ($1, $2, $3, 'accepted risk', $4)`,
      [findingId, repositoryId, `${installationId}-fingerprint`, userId]);

    await client.query(
      `INSERT INTO audit_logs (user_id, repository_id, action, resource_type, resource_id, details)
       VALUES ($1, $2, 'finding.status.updated', 'finding', $3, '{}'::jsonb)`,
      [userId, repositoryId, findingId]);

    await client.query(
      `INSERT INTO webhook_events (repository_id, event_type, payload)
       VALUES ($1, 'pull_request', '{}'::jsonb)`, [repositoryId]);

    // The remediation control plane.
    const jobId = (await client.query(
      `INSERT INTO remediation_jobs (installation_id, repository_id, pull_request_id, analysis_run_id, created_by,
         state, stage, head_sha, base_sha, selection_hash, finding_snapshot_ids, deadline_at, policy_version, policy_manifest)
       VALUES ($1,$2,$3,$4,$5,'ready','ready',$6,$7,$8,ARRAY[$9::uuid],NOW() + INTERVAL '1 day','v1','{}'::jsonb) RETURNING id`,
      [installationId, repositoryId, pullRequestId, analysisRunId, userId,
        'a'.repeat(40), 'b'.repeat(40), 'a'.repeat(64), findingId])).rows[0].id;

    const candidateId = (await client.query(
      `INSERT INTO remediation_candidates (job_id, installation_id, repository_id, candidate_version,
         finding_snapshot_ids, artifact_digest, context_manifest_digest, file_manifest, preview, verification_level)
       VALUES ($1,$2,$3,1,ARRAY[$4::uuid],$5,'ctx','{}'::jsonb,'{}'::jsonb,'independent_sandbox') RETURNING id`,
      [jobId, installationId, repositoryId, findingId, 'c'.repeat(64)])).rows[0].id;

    await client.query(
      `INSERT INTO remediation_attempts (job_id, installation_id, repository_id, stage, attempt_number, fencing_token)
       VALUES ($1,$2,$3,'verifying',1,1)`, [jobId, installationId, repositoryId]);

    await client.query(
      `INSERT INTO verification_runs (job_id, installation_id, repository_id, candidate_id, original_tree_sha,
         base_sha, policy_version, outcome)
       VALUES ($1,$2,$3,$4,$5,$6,'v1','passed')`,
      [jobId, installationId, repositoryId, candidateId, 'd'.repeat(40), 'b'.repeat(40)]);

    const actionId = (await client.query(
      `INSERT INTO remediation_actions (job_id, installation_id, repository_id, pull_request_id, actor_id, actor_login,
         action_type, head_sha, base_sha, batch_manifest_digest, candidate_ids, idempotency_key, payload_hash, state, observed_commit_sha)
       VALUES ($1,$2,$3,$4,$5,$6,'observed_apply',$7,$8,$9,ARRAY[$10::uuid],$11,$12,'completed',$13) RETURNING id`,
      [jobId, installationId, repositoryId, pullRequestId, userId, `${login}-user`, 'a'.repeat(40), 'b'.repeat(40),
        'e'.repeat(64), candidateId, `observed:${'f'.repeat(40)}`, 'f'.repeat(64), 'f'.repeat(40)])).rows[0].id;

    // A historical merge intent from before the App dropped its write access. The purge
    // must delete these too; nothing retains them past an uninstall.
    await client.query(
      `INSERT INTO merge_intents (action_id, installation_id, repository_id, actor_id, approved_manifest_digest,
         approved_head_sha, approved_base_sha, expires_at, state)
       VALUES ($1,$2,$3,$4,$5,$6,$7,NOW() + INTERVAL '1 day','waiting_for_checks')`,
      [actionId, installationId, repositoryId, userId, 'e'.repeat(64), 'a'.repeat(40), 'b'.repeat(40)]);

    await client.query(
      `INSERT INTO remediation_writer_leases (pull_request_id, installation_id, repository_id, owner_id, action_id, expires_at)
       VALUES ($1,$2,$3,$4,$5,NOW() + INTERVAL '1 hour')`,
      [pullRequestId, installationId, repositoryId, userId, actionId]);

    await client.query(
      `INSERT INTO remediation_job_evidence (job_id, installation_id, repository_id, attempt, kind, payload)
       VALUES ($1,$2,$3,1,'agent_trace','{}'::jsonb)`, [jobId, installationId, repositoryId]);

    await client.query(
      `INSERT INTO usage_reservations (job_id, installation_id, repository_id, reservation_key, stage, reserved_amount, state)
       VALUES ($1,$2,$3,$4,'verifying',0.5,'reserved')`, [jobId, installationId, repositoryId, `${jobId}:verifying`]);

    await client.query(
      `INSERT INTO repair_memory (installation_id, repository_id, job_id, candidate_id, weakness_signature,
         source_digest, patch_digest, verification_outcome, status, expires_at)
       VALUES ($1,$2,$3,$4,'sql_parameterization',$5,$6,'passed','observed',NOW() + INTERVAL '90 days')`,
      [installationId, repositoryId, jobId, candidateId, 'a'.repeat(64), 'b'.repeat(64)]);

    await client.query(
      `INSERT INTO workflow_events (aggregate_id, aggregate_type, installation_id, repository_id, sequence, event_type, payload)
       VALUES ($1,'remediation_job',$2,$3,1,'remediation.ready','{}'::jsonb)`, [jobId, installationId, repositoryId]);

    await client.query(
      `INSERT INTO workflow_outbox (aggregate_id, installation_id, repository_id, event_sequence, event_type, payload)
       VALUES ($1,$2,$3,1,'remediation.ready','{}'::jsonb)`, [jobId, installationId, repositoryId]);

    await client.query('COMMIT');
    return { userId, repositoryId, pullRequestId, jobId, actionId, findingId };
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch (_) { /* released below */ }
    throw error;
  } finally {
    client.release();
  }
}

before(async () => {
  await pool.query('DROP SCHEMA public CASCADE');
  await pool.query('CREATE SCHEMA public');
  await applyMigrations();
});

after(async () => { await pool.end(); });

beforeEach(async () => {
  await pool.query(`TRUNCATE
    remediation_job_evidence, usage_reservations, remediation_attempts, verification_runs, merge_intents,
    remediation_writer_leases, remediation_actions, repair_memory, remediation_candidates, remediation_jobs,
    workflow_outbox, workflow_events, analysis_run_findings, suppressions, findings, analysis_runs, analysis,
    pull_requests, audit_logs, webhook_events, repository_access, repositories, user_installations,
    installations, users, webhook_deliveries CASCADE`);
});

test('every table the purge covers is actually seeded, so a zero afterwards means something', async () => {
  await seedInstallation(DOOMED, { login: 'doomed-org' });
  const counts = await countAll(DOOMED);
  for (const table of SCOPED_TABLES) {
    assert.ok(counts[table] > 0, `${table} was not seeded, so purging it proves nothing`);
  }
});

test('purging one installation removes every row for it and touches no other installation', async () => {
  await seedInstallation(DOOMED, { login: 'doomed-org' });
  await seedInstallation(KEEP, { login: 'kept-org' });
  const before = await countAll(KEEP);

  await pool.query(
    "UPDATE installations SET status='deleted', deleted_at=NOW() - INTERVAL '25 hours', purge_after=NOW() - INTERVAL '1 hour' WHERE id=$1",
    [DOOMED]);

  const result = await purge.purgeInstallation(DOOMED);
  assert.equal(result.purged, true);

  const after = await countAll(DOOMED);
  for (const table of SCOPED_TABLES) {
    assert.equal(after[table], 0, `${table} still has rows for the purged installation`);
  }

  const kept = await countAll(KEEP);
  assert.deepEqual(kept, before, 'the other installation was modified by the purge');

  // The user account survives; only its link to the purged installation goes.
  const users = await pool.query('SELECT installation_id FROM users WHERE installation_id = $1', [DOOMED]);
  assert.equal(users.rowCount, 0);
  assert.equal(Number((await pool.query('SELECT COUNT(*) c FROM users')).rows[0].c), 2);
});

test('one audit row records the counts per table and survives the purge', async () => {
  await seedInstallation(DOOMED, { login: 'doomed-org' });
  await pool.query(
    "UPDATE installations SET deleted_at=NOW(), purge_after=NOW() - INTERVAL '1 hour' WHERE id=$1", [DOOMED]);
  const result = await purge.purgeInstallation(DOOMED);

  const audits = await pool.query(
    "SELECT details FROM audit_logs WHERE action = 'installation.purged'");
  assert.equal(audits.rowCount, 1);
  const details = audits.rows[0].details;
  assert.equal(details.installation_id, String(DOOMED));
  for (const table of purge.purgeTables()) {
    assert.ok(Number.isInteger(details.counts[table]), `no count recorded for ${table}`);
  }
  assert.equal(details.counts.repositories, 1);
  assert.equal(details.counts.findings, 1);
  assert.equal(details.counts.merge_intents, 1);
  assert.equal(result.counts.installations, 1);
});

test('a reinstall inside the grace period cancels the purge and no row is deleted', async () => {
  await seedInstallation(DOOMED, { login: 'doomed-org' });
  const before = await countAll(DOOMED);

  // Marking an installation deleted also fires the long-standing
  // revoke_inactive_installation_access trigger, which revokes the derived access rows.
  // Those are re-derived from GitHub on the next installation sync, so a reinstall gets
  // them back; nothing that holds review data is touched. Everything else must survive.
  const derivedAccess = new Set(['repository_access', 'user_installations']);

  const client = await pool.connect();
  try {
    await purge.markInstallationDeleted(client, DOOMED);
  } finally { client.release(); }

  // Nothing is due yet: the grace period has 24 hours to run.
  assert.deepEqual(await purge.purgeDeletedInstallations(10), { due: 0, purged: 0, skipped: 0, failed: 0 });

  const reinstall = await pool.connect();
  try {
    assert.equal(await purge.cancelScheduledPurge(reinstall, DOOMED), true);
  } finally { reinstall.release(); }

  // Even once the original deadline passes, a cancelled purge never runs.
  await pool.query("UPDATE installations SET updated_at = NOW() WHERE id = $1", [DOOMED]);
  assert.deepEqual(await purge.purgeDeletedInstallations(10), { due: 0, purged: 0, skipped: 0, failed: 0 });

  const after = await countAll(DOOMED);
  for (const table of SCOPED_TABLES) {
    if (derivedAccess.has(table)) continue;
    assert.equal(after[table], before[table], `${table} lost rows although the purge was cancelled`);
  }

  const row = (await pool.query('SELECT deleted_at, purge_after FROM installations WHERE id=$1', [DOOMED])).rows[0];
  assert.equal(row.deleted_at, null);
  assert.equal(row.purge_after, null);
});

test('the sweep purges only what is due, and the grace period holds everything else', async () => {
  await seedInstallation(DOOMED, { login: 'doomed-org' });
  await seedInstallation(KEEP, { login: 'kept-org' });

  await pool.query(
    "UPDATE installations SET deleted_at=NOW(), purge_after=NOW() - INTERVAL '1 minute' WHERE id=$1", [DOOMED]);
  await pool.query(
    "UPDATE installations SET deleted_at=NOW(), purge_after=NOW() + INTERVAL '23 hours' WHERE id=$1", [KEEP]);

  const summary = await purge.purgeDeletedInstallations(10);
  assert.deepEqual(summary, { due: 1, purged: 1, skipped: 0, failed: 0 });

  for (const table of SCOPED_TABLES) {
    assert.equal(await countRows(table, DOOMED), 0, `${table} survived for the due installation`);
  }
  assert.equal(await countRows('installations', KEEP), 1);
  assert.ok(await countRows('remediation_jobs', KEEP) > 0);
});

test('a marked installation is skipped by the claim queries while it waits to be purged', async () => {
  await seedInstallation(DOOMED, { login: 'doomed-org' });
  const remediationDb = require('../../src/db/remediation');
  const analysisRunsDb = require('../../src/db/analysisRuns');
  const repositoriesDb = require('../../src/db/repositories');

  await pool.query("UPDATE remediation_jobs SET state='queued', next_attempt_at=NOW() WHERE installation_id=$1", [DOOMED]);
  await pool.query("UPDATE analysis_runs SET status='pending' WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id=$1)", [DOOMED]);
  await pool.query("UPDATE repositories SET profile_status='queued' WHERE installation_id=$1", [DOOMED]);

  // While it is live, all three claim it. A claimed analysis run owns its session until
  // its lease is released, so release it or the pool never drains.
  assert.ok(await remediationDb.claimNextJob('worker-live'));
  const claimed = await analysisRunsDb.claimNextQueuedRun();
  assert.ok(claimed);
  await claimed.releaseLease();
  assert.ok(await repositoriesDb.claimNextProfileJob());

  // Reset and mark it deleted.
  await pool.query("UPDATE remediation_jobs SET state='queued', lease_owner=NULL, lease_expires_at=NULL WHERE installation_id=$1", [DOOMED]);
  await pool.query("UPDATE analysis_runs SET status='pending', started_at=NULL WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id=$1)", [DOOMED]);
  await pool.query("UPDATE repositories SET profile_status='queued' WHERE installation_id=$1", [DOOMED]);
  const client = await pool.connect();
  try { await purge.markInstallationDeleted(client, DOOMED); } finally { client.release(); }

  assert.equal(await remediationDb.claimNextJob('worker-deleted'), null);
  assert.equal(await analysisRunsDb.claimNextQueuedRun(), null);
  assert.equal(await repositoriesDb.claimNextProfileJob(), null);
});
