const crypto = require('crypto');
const { pool } = require('../config/database');

const ACTIVE_STATES = new Set(['queued', 'snapshotting', 'retrieving', 'planning', 'generating', 'verifying']);
const TERMINAL_STATES = new Set(['ready', 'cancelled', 'superseded', 'unsupported', 'inconclusive', 'failed', 'dead_letter']);

function hash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

async function scopedTransaction({ tenantId, userId, worker = false }, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // set_config rather than SET prevents pool-context leakage after COMMIT/ROLLBACK.
    if (tenantId != null) await client.query("SELECT set_config('app.tenant_id', $1, true)", [String(tenantId)]);
    if (userId) await client.query("SELECT set_config('app.user_id', $1, true)", [String(userId)]);
    if (worker) await client.query("SELECT set_config('app.remediation_worker', '1', true)");
    const value = await fn(client);
    await client.query('COMMIT');
    return value;
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch (_) { /* connection will be released */ }
    throw error;
  } finally {
    client.release();
  }
}

async function requestScope(userId, fn) {
  return scopedTransaction({ userId }, fn);
}

async function getAuthorizedPullRequest(client, pullRequestId, userId, { forUpdate = false } = {}) {
  const result = await client.query(
    `SELECT pr.id, pr.repository_id, pr.pr_number, pr.head_sha, pr.base_sha, pr.state AS pr_state,
            r.installation_id, r.full_name AS repository_full_name, r.is_active
       FROM pull_requests pr
       JOIN repositories r ON r.id = pr.repository_id
       JOIN repository_access ra ON ra.repository_id = r.id AND ra.user_id = $2
      WHERE pr.id = $1 ${forUpdate ? 'FOR UPDATE OF pr' : ''}`,
    [pullRequestId, userId]
  );
  return result.rows[0] || null;
}

async function createJob({ pullRequestId, userId, findingIds, policy }) {
  return requestScope(userId, async (client) => {
    const pr = await getAuthorizedPullRequest(client, pullRequestId, userId, { forUpdate: true });
    if (!pr || !pr.is_active) return { kind: 'not_found' };
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [String(pr.installation_id)]);
    if (!pr.head_sha || !pr.base_sha) return { kind: 'unsupported', reason: 'missing_immutable_revision' };
    const run = await client.query(
      `SELECT id, commit_sha FROM analysis_runs
        WHERE pull_request_id = $1 AND status = 'completed' AND commit_sha = $2
        ORDER BY completed_at DESC NULLS LAST, created_at DESC LIMIT 1`, [pullRequestId, pr.head_sha]
    );
    if (!run.rowCount) return { kind: 'unsupported', reason: 'no_completed_analysis_for_head' };
    const snapshots = await client.query(
      `SELECT finding_id, snapshot FROM analysis_run_findings WHERE analysis_run_id = $1`, [run.rows[0].id]
    );
    const selected = snapshots.rows.filter((row) => !findingIds?.length || findingIds.includes(row.finding_id));
    if (!selected.length || (findingIds?.length && selected.length !== new Set(findingIds).size)) {
      return { kind: 'unsupported', reason: 'findings_not_in_immutable_analysis_snapshot' };
    }
    if (new Set(selected.map((row) => row.snapshot?.file_path).filter(Boolean)).size > Number(policy.max_files || 5)) {
      return { kind: 'unsupported', reason: 'selected_findings_exceed_file_limit' };
    }
    const selectionHash = hash(selected.map((row) => row.finding_id).sort());
    const insert = await client.query(
      `INSERT INTO remediation_jobs
       (installation_id, repository_id, pull_request_id, analysis_run_id, head_sha, base_sha,
        selection_hash, finding_snapshot_ids, state, stage, deadline_at, policy_version, policy_manifest, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'queued','snapshotting',NOW() + ($9::int * INTERVAL '1 minute'),$10,$11,$12)
       ON CONFLICT (repository_id, pull_request_id, analysis_run_id, head_sha, selection_hash, policy_version)
       WHERE state NOT IN ('cancelled','superseded','unsupported','inconclusive','failed','dead_letter')
       DO UPDATE SET updated_at = remediation_jobs.updated_at
       RETURNING *, (xmax = 0) AS created`,
      [pr.installation_id, pr.repository_id, pr.id, run.rows[0].id, pr.head_sha, pr.base_sha, selectionHash, selected.map((row) => row.finding_id),
        policy.max_runtime_minutes, policy.version, JSON.stringify(policy), userId]
    );
    const job = insert.rows[0];
    if (job.created) {
      await appendEvent(client, job, 'remediation.queued', { stage: 'snapshotting' });
      await audit(client, userId, job.repository_id, 'remediation.requested', 'remediation_job', job.id,
        { pull_request_id: pr.id, head_sha: job.head_sha, selected_findings: selected.map((r) => r.finding_id) });
    }
    return { kind: 'ok', job, created: job.created, snapshots: selected, pr };
  });
}

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

// Automatic generation after a completed analysis. There is no requesting user, so
// the transaction runs in the worker role with the pull request's installation as the
// tenant and the audit row carries no user. The selection is every open, blocking
// finding of the immutable snapshot, bounded to the policy's file limit by severity.
// At most one automatic job exists per pull request head: an earlier one, whatever
// its state, means this call does nothing.
async function createAutomaticJob({ pullRequestId, analysisRunId, policy }) {
  return scopedTransaction({ worker: true }, async (client) => {
    const prResult = await client.query(
      `SELECT pr.id, pr.repository_id, pr.head_sha, pr.base_sha, r.installation_id, r.is_active, i.status AS installation_status
         FROM pull_requests pr
         JOIN repositories r ON r.id = pr.repository_id
         JOIN installations i ON i.id = r.installation_id
        WHERE pr.id = $1 FOR UPDATE OF pr`, [pullRequestId]
    );
    const pr = prResult.rows[0];
    if (!pr || !pr.is_active || pr.installation_status !== 'active') return { kind: 'not_found' };
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [String(pr.installation_id)]);
    if (!pr.head_sha || !pr.base_sha) return { kind: 'unsupported', reason: 'missing_immutable_revision' };
    const run = await client.query(
      `SELECT id FROM analysis_runs WHERE id = $1 AND pull_request_id = $2 AND status = 'completed' AND commit_sha = $3`,
      [analysisRunId, pullRequestId, pr.head_sha]
    );
    if (!run.rowCount) return { kind: 'unsupported', reason: 'no_completed_analysis_for_head' };
    const existing = await client.query(
      `SELECT id, state FROM remediation_jobs WHERE pull_request_id = $1 AND head_sha = $2 AND origin = 'automatic'
        ORDER BY created_at DESC LIMIT 1`, [pullRequestId, pr.head_sha]
    );
    if (existing.rowCount) return { kind: 'exists', job: existing.rows[0] };
    const snapshots = await client.query(
      `SELECT arf.finding_id, arf.snapshot
         FROM analysis_run_findings arf JOIN findings f ON f.id = arf.finding_id
        WHERE arf.analysis_run_id = $1 AND f.status = 'open' AND NOT COALESCE(f.suppression_applied, false)
          AND NOT (LOWER(COALESCE(f.severity, '')) = 'info' OR COALESCE((f.evidence_details->'extra'->>'in_test_code')::boolean, false))`,
      [run.rows[0].id]
    );
    const rows = snapshots.rows.filter((row) => row.snapshot?.file_path);
    if (!rows.length) return { kind: 'unsupported', reason: 'no_open_findings' };
    const rank = (row) => SEVERITY_RANK[String(row.snapshot?.severity || '').toLowerCase()] ?? 4;
    rows.sort((a, b) => rank(a) - rank(b) || String(a.snapshot.file_path).localeCompare(String(b.snapshot.file_path)));
    const maxFiles = Number(policy.max_files || 5);
    const files = [];
    for (const row of rows) if (!files.includes(row.snapshot.file_path) && files.length < maxFiles) files.push(row.snapshot.file_path);
    const selected = rows.filter((row) => files.includes(row.snapshot.file_path));
    const ceiling = Number(policy.max_spend_usd || 0);
    const used = await client.query(OUTSTANDING_RESERVED_SQL, [pr.installation_id, [...TERMINAL_STATES]]);
    if (ceiling - Number(used.rows[0].amount) <= 0) return { kind: 'budget_exhausted', reserved: Number(used.rows[0].amount), ceiling };
    const selectionHash = hash(selected.map((row) => row.finding_id).sort());
    const insert = await client.query(
      `INSERT INTO remediation_jobs
       (installation_id, repository_id, pull_request_id, analysis_run_id, head_sha, base_sha,
        selection_hash, finding_snapshot_ids, state, stage, deadline_at, policy_version, policy_manifest, created_by, origin)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'queued','snapshotting',NOW() + ($9::int * INTERVAL '1 minute'),$10,$11,NULL,'automatic')
       ON CONFLICT (repository_id, pull_request_id, analysis_run_id, head_sha, selection_hash, policy_version)
       WHERE state NOT IN ('cancelled','superseded','unsupported','inconclusive','failed','dead_letter')
       DO UPDATE SET updated_at = remediation_jobs.updated_at
       RETURNING *, (xmax = 0) AS created`,
      [pr.installation_id, pr.repository_id, pr.id, run.rows[0].id, pr.head_sha, pr.base_sha, selectionHash, selected.map((row) => row.finding_id),
        policy.max_runtime_minutes, policy.version, JSON.stringify(policy)]
    );
    const job = insert.rows[0];
    // The same selection already queued by a user is that user's job, not a new one.
    if (!job.created) return { kind: 'exists', job };
    await appendEvent(client, job, 'remediation.queued', { stage: 'snapshotting', origin: 'automatic' });
    await audit(client, null, job.repository_id, 'remediation.requested', 'remediation_job', job.id,
      { pull_request_id: pr.id, head_sha: job.head_sha, origin: 'automatic', selected_findings: selected.map((r) => r.finding_id) });
    return { kind: 'ok', job, created: true, selected: selected.map((row) => row.finding_id) };
  });
}

// Everything the inline fix publication needs, in worker scope: a ready job is
// system-owned work with no requesting user.
async function jobPublishContext(jobId) {
  return scopedTransaction({ worker: true }, async (client) => {
    const result = await client.query(
      `SELECT j.*, r.full_name AS repository_full_name, r.is_active AS repository_active,
              pr.pr_number, pr.head_sha AS current_head_sha, i.status AS installation_status,
              u.github_username AS creator_login
         FROM remediation_jobs j
         JOIN repositories r ON r.id=j.repository_id
         JOIN pull_requests pr ON pr.id=j.pull_request_id
         JOIN installations i ON i.id=j.installation_id
         LEFT JOIN users u ON u.id=j.created_by
        WHERE j.id=$1`, [jobId]
    );
    const job = result.rows[0];
    if (!job) return null;
    const candidates = await client.query(
      `SELECT id, finding_snapshot_ids, artifact_digest, context_manifest_digest, file_manifest, preview, verification_level, rejection_reason
       FROM remediation_candidates WHERE job_id=$1 ORDER BY candidate_version`, [jobId]
    );
    const verification = await client.query(`SELECT outcome, evidence_digest, coverage_gaps, limitations, candidate_tree_sha FROM verification_runs WHERE job_id=$1 ORDER BY created_at DESC LIMIT 1`, [jobId]);
    const findings = await findingSnapshots(client, job);
    return { job, candidates: candidates.rows, verification: verification.rows[0] || null,
      manifestDigest: manifestDigestFor(job, candidates.rows), findings };
  });
}

async function recordInlineFixesPublished(job, { headSha }) {
  await scopedTransaction({ tenantId: job.installation_id, worker: true }, (client) => client.query(
    `UPDATE remediation_jobs SET inline_fixes_published_at=NOW(), inline_fixes_head_sha=$2, updated_at=NOW() WHERE id=$1`,
    [job.id, headSha]
  ));
}

async function appendEvent(client, job, eventType, payload, sequenceOverride) {
  const sequence = Number(sequenceOverride || job.state_version || 1);
  await client.query(
    `INSERT INTO workflow_events (aggregate_id, aggregate_type, installation_id, repository_id, sequence, event_type, payload)
     VALUES ($1,'remediation_job',$2,$3,$4,$5,$6) ON CONFLICT (aggregate_id, sequence) DO NOTHING`,
    [job.id, job.installation_id, job.repository_id, sequence, eventType, JSON.stringify(payload)]
  );
  await client.query(
    `INSERT INTO workflow_outbox (aggregate_id, installation_id, repository_id, event_sequence, event_type, payload)
     VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (aggregate_id, event_sequence) DO NOTHING`,
    [job.id, job.installation_id, job.repository_id, sequence, eventType, JSON.stringify(payload)]
  );
}

async function audit(client, userId, repositoryId, action, resourceType, resourceId, details) {
  await client.query(
    `INSERT INTO audit_logs (user_id, repository_id, action, resource_type, resource_id, details)
     VALUES ($1,$2,$3,$4,$5,$6)`, [userId || null, repositoryId, action, resourceType, resourceId, JSON.stringify(details || {})]
  );
}

async function getJobForUser(jobId, userId) {
  return requestScope(userId, async (client) => {
    const result = await client.query(
      `SELECT j.*, r.full_name AS repository_full_name, r.is_active AS repository_active,
              pr.pr_number, pr.head_branch, pr.base_branch, pr.state AS pull_request_state,
              i.status AS installation_status
       FROM remediation_jobs j
       JOIN repositories r ON r.id=j.repository_id
       JOIN pull_requests pr ON pr.id=j.pull_request_id
       JOIN installations i ON i.id=j.installation_id
       WHERE j.id=$1`, [jobId]
    );
    return result.rows[0] || null;
  });
}

async function getLatestForPullRequest(pullRequestId, userId) {
  return requestScope(userId, async (client) => {
    const pr = await getAuthorizedPullRequest(client, pullRequestId, userId);
    if (!pr) return null;
    const jobs = await client.query(`SELECT * FROM remediation_jobs WHERE pull_request_id=$1 ORDER BY created_at DESC LIMIT 1`, [pullRequestId]);
    const job = jobs.rows[0] || null;
    const action = job ? await client.query(`SELECT a.*, (SELECT state FROM merge_intents mi WHERE mi.action_id=a.id) AS merge_state FROM remediation_actions a WHERE a.job_id=$1 ORDER BY a.created_at DESC LIMIT 1`, [job.id]) : { rows: [] };
    const latestAction = action.rows[0] || null;
    const intent = latestAction
      ? await client.query(`SELECT * FROM merge_intents WHERE action_id=$1`, [latestAction.id])
      : { rows: [] };
    return { pr, job, action: latestAction, mergeIntent: intent.rows[0] || null };
  });
}

// Consent binds the exact ordered subset a human chose. The digest is computed over
// exactly those candidates, in their persisted order, so a digest for a different
// subset of the same job never matches.
function manifestDigestFor(job, candidates) {
  if (!job || !candidates?.length) return null;
  return hash({ job: job.id, head: job.head_sha, base: job.base_sha,
    candidates: candidates.map((c) => ({ id: c.id, artifact_digest: c.artifact_digest })) });
}

// Findings the job was generated for, from the immutable analysis snapshot, so the
// preview can name each finding beside its recommended fix.
async function findingSnapshots(client, job) {
  if (!job?.analysis_run_id) return [];
  const rows = await client.query(
    `SELECT finding_id, snapshot FROM analysis_run_findings WHERE analysis_run_id=$1 AND finding_id = ANY($2::uuid[])`,
    [job.analysis_run_id, job.finding_snapshot_ids || []]
  );
  return rows.rows.map((row) => ({
    id: row.finding_id, title: row.snapshot?.title || null, file_path: row.snapshot?.file_path || null,
    line_start: row.snapshot?.line_start ?? null, line_end: row.snapshot?.line_end ?? null,
    severity: row.snapshot?.severity || null, rule_id: row.snapshot?.rule_id || null,
    fingerprint: row.snapshot?.fingerprint || null,
  }));
}

async function getPreview(jobId, userId) {
  return requestScope(userId, async (client) => {
    const jobResult = await client.query(`SELECT * FROM remediation_jobs WHERE id=$1`, [jobId]);
    const job = jobResult.rows[0];
    if (!job) return null;
    const candidates = await client.query(
      `SELECT id, finding_snapshot_ids, artifact_digest, context_manifest_digest, file_manifest, preview, verification_level, rejection_reason
       FROM remediation_candidates WHERE job_id=$1 ORDER BY candidate_version`, [jobId]
    );
    const verification = await client.query(`SELECT outcome, evidence_digest, coverage_gaps, limitations, candidate_tree_sha FROM verification_runs WHERE job_id=$1 ORDER BY created_at DESC LIMIT 1`, [jobId]);
    const findings = await findingSnapshots(client, job);
    return { job, candidates: candidates.rows, verification: verification.rows[0] || null,
      manifestDigest: manifestDigestFor(job, candidates.rows), findings };
  });
}

// Claiming takes a lease and a fresh fencing token. It deliberately does not
// consume an attempt: an attempt is consumed when a stage really fails, so an
// expired lease reclaimed by the reconciler costs no retry budget.
// An automatic job has no creator; the left join keeps it claimable with a null login.
const CLAIM_SQL = `WITH candidate AS (
         SELECT id, created_by FROM remediation_jobs
          WHERE state = ANY($1::text[]) AND next_attempt_at <= NOW()
            AND (lease_expires_at IS NULL OR lease_expires_at < NOW())
            AND ($4::uuid IS NULL OR id = $4::uuid)
          ORDER BY next_attempt_at, created_at FOR UPDATE SKIP LOCKED LIMIT 1
       ) UPDATE remediation_jobs j SET lease_owner=$2, lease_expires_at=NOW()+($3::int * INTERVAL '1 second'),
          fencing_token=j.fencing_token+1, updated_at=NOW()
        FROM candidate LEFT JOIN users u ON u.id = candidate.created_by, repositories r, pull_requests pr
        WHERE j.id=candidate.id AND r.id=j.repository_id AND pr.id=j.pull_request_id
        RETURNING j.*, r.full_name AS repository_full_name, pr.pr_number, u.github_username AS creator_login`;

async function claimJob(workerId, leaseSeconds, jobId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.remediation_worker', '1', true)");
    const result = await client.query(CLAIM_SQL, [[...ACTIVE_STATES], workerId, leaseSeconds, jobId || null]);
    await client.query('COMMIT');
    return result.rows[0] || null;
  } catch (error) { try { await client.query('ROLLBACK'); } catch (_) { /* ignored */ } throw error; } finally { client.release(); }
}

async function claimNextJob(workerId, leaseSeconds = 60) {
  return claimJob(workerId, leaseSeconds, null);
}

// A dispatched event claims exactly the same row with the same compare-and-swap,
// so an event and the polling backup can never both execute one job.
async function claimJobById(jobId, workerId, leaseSeconds = 60) {
  return claimJob(workerId, leaseSeconds, jobId);
}

// A stage has exactly one reservation for the life of a job. The key used to carry the
// fencing token, so every retry minted a fresh charge against the installation ceiling and
// left the previous one outstanding forever. Keying it by job and stage is what
// `ON CONFLICT (job_id,stage,reservation_key) DO NOTHING` always meant.
function reservationKeyFor(job, stage) {
  return `${job.id}:${stage}`;
}

// Only work that can still spend counts against the ceiling. A reservation belonging to a
// job that has already ended is released, not outstanding.
const OUTSTANDING_RESERVED_SQL = `
  SELECT COALESCE(SUM(r.reserved_amount),0)::numeric AS amount
  FROM usage_reservations r JOIN remediation_jobs j ON j.id = r.job_id
  WHERE r.installation_id=$1 AND r.state='reserved' AND NOT (j.state = ANY($2))`;

async function reserveUsage(job, stage, amount) {
  return scopedTransaction({ tenantId: job.installation_id, worker: true }, async (client) => {
    const reservationKey = reservationKeyFor(job, stage);
    // A retry of the same stage is the same reservation, not a new charge and not an
    // exhausted quota. Any row for this job and stage counts, including one written under
    // the old fencing-token key.
    const existing = await client.query(
      `SELECT * FROM usage_reservations WHERE job_id=$1 AND stage=$2 AND state <> 'released'
       ORDER BY created_at DESC LIMIT 1`,
      [job.id, stage]
    );
    if (existing.rowCount) return existing.rows[0];
    const ceiling = Number(job.policy_manifest.max_spend_usd || 2);
    const used = await client.query(OUTSTANDING_RESERVED_SQL, [job.installation_id, [...TERMINAL_STATES]]);
    if (Number(used.rows[0].amount) + Number(amount) > ceiling) return null;
    const result = await client.query(
      `INSERT INTO usage_reservations (installation_id,repository_id,job_id,stage,reservation_key,reserved_amount,state)
       VALUES ($1,$2,$3,$4,$5,$6,'reserved') ON CONFLICT (job_id,stage,reservation_key) DO NOTHING RETURNING *`,
      [job.installation_id, job.repository_id, job.id, stage, reservationKey, amount]
    );
    if (result.rowCount) return result.rows[0];
    const raced = await client.query(
      `SELECT * FROM usage_reservations WHERE job_id=$1 AND stage=$2 AND reservation_key=$3`,
      [job.id, stage, reservationKey]
    );
    return raced.rows[0] || null;
  });
}

// Frees every reservation this job will never spend. Called inside the transaction that
// makes the job terminal, so a job cannot end while still holding budget.
async function releaseReservationsForJob(client, job, reason) {
  const released = await client.query(
    `UPDATE usage_reservations SET state='released', actual_amount=0, settled_at=NOW()
     WHERE job_id=$1 AND state='reserved' RETURNING id, stage, reserved_amount`,
    [job.id]
  );
  if (released.rowCount) {
    await audit(client, null, job.repository_id, 'remediation.usage_released', 'remediation_job', job.id, {
      reason,
      released: released.rowCount,
      amount: released.rows.reduce((total, row) => total + Number(row.reserved_amount), 0),
      stages: released.rows.map((row) => row.stage),
    });
  }
  return released.rowCount;
}

// Remaining installation budget, used by the apply route to answer 429 honestly.
async function budgetSnapshot(installationId, ceiling) {
  return scopedTransaction({ tenantId: installationId, worker: true }, async (client) => {
    const used = await client.query(OUTSTANDING_RESERVED_SQL, [installationId, [...TERMINAL_STATES]]);
    const reserved = Number(used.rows[0].amount);
    return { reserved, ceiling: Number(ceiling), available: Number(ceiling) - reserved };
  });
}

async function settleUsage(job, reservation, actualAmount, providerRequestId) {
  if (!reservation) return;
  await scopedTransaction({ tenantId: job.installation_id, worker: true }, (client) => client.query(
    `UPDATE usage_reservations SET actual_amount=$1, provider_request_id=$2, state='settled', settled_at=NOW()
     WHERE id=$3 AND state='reserved'`, [Math.max(0, Number(actualAmount) || 0), providerRequestId || null, reservation.id]
  ));
}

// What a stage actually cost, from the tokens the repair service reports priced at the
// job's own rates. A response without usage settles at zero rather than at the estimate:
// an unspent reservation is not a charge.
function usageCost(job, result) {
  const usage = result?.evidence?.usage || result?.usage || {};
  const input = Number(usage.input_tokens || 0);
  const output = Number(usage.output_tokens || 0);
  if (!input && !output) return Number(result?.usage?.actual_usd || 0);
  const policy = job.policy_manifest || {};
  const inputRate = Number(policy.input_usd_per_million_tokens || 0);
  const outputRate = Number(policy.output_usd_per_million_tokens || 0);
  return (input * inputRate + output * outputRate) / 1_000_000;
}

// The sweep that clears reservations stranded by an earlier defect or by a crash between
// the job ending and its release. A reservation whose job is terminal, or whose job is gone,
// can never be spent. Bounded per tick so one sweep cannot hold a long transaction.
async function releaseStrandedReservations(limit = 200) {
  return scopedTransaction({ worker: true }, async (client) => {
    const released = await client.query(
      `WITH stranded AS (
         SELECT r.id FROM usage_reservations r
         LEFT JOIN remediation_jobs j ON j.id = r.job_id
         WHERE r.state='reserved' AND (j.id IS NULL OR j.state = ANY($1::text[]))
         ORDER BY r.created_at FOR UPDATE OF r SKIP LOCKED LIMIT $2
       )
       UPDATE usage_reservations u SET state='released', actual_amount=0, settled_at=NOW()
       FROM stranded WHERE u.id = stranded.id
       RETURNING u.id, u.installation_id, u.repository_id, u.job_id, u.stage, u.reserved_amount`,
      [[...TERMINAL_STATES], limit]
    );
    for (const row of released.rows) {
      await audit(client, null, row.repository_id, 'remediation.usage_released', 'remediation_job', row.job_id, {
        reason: 'reconciler_stranded', stage: row.stage, amount: Number(row.reserved_amount),
      });
    }
    return released.rows;
  });
}

// The apply path commits whole files, never hunks, so `file_manifest` has to be the repair
// service's full-file manifest: `{ files: [{ path, contents_base64, new_sha256, blob_oid }],
// verified_tree_oid }`. A service that sent only the hunk patch list is stored in the same
// shape so `persistedChanges` finds the contents rather than blocking the apply.
function fileManifest(candidate) {
  const manifest = candidate.file_manifest;
  if (manifest && Array.isArray(manifest.files)) return manifest;
  const files = Array.isArray(manifest) ? manifest : Array.isArray(candidate.patch) ? candidate.patch : [];
  const verified = candidate.verified_tree_oid || candidate.preview?.verified_tree_oid || null;
  return { files, ...(verified ? { verified_tree_oid: verified } : {}) };
}

// A failed or exhausted stage consumes one attempt. A successful stage does not.
const ATTEMPT_CONSUMING_STATES = new Set(['queued', 'inconclusive', 'failed', 'dead_letter']);

async function completeStage(job, { state, stage, outcome, candidates = [], verification, reason, outputDigest, stagePath = [] }) {
  return scopedTransaction({ tenantId: job.installation_id, worker: true }, async (client) => {
    const current = await client.query(`SELECT * FROM remediation_jobs WHERE id=$1 FOR UPDATE`, [job.id]);
    const row = current.rows[0];
    if (!row || row.fencing_token !== job.fencing_token || row.lease_owner !== job.lease_owner) return false;
    // The remote service reports the stage it reached; the control plane persists the
    // walk through the declared sequence so the audit trail is not a single jump.
    const walk = stagePath.filter((name) => name && name !== stage);
    const nextVersion = Number(row.state_version) + walk.length + 1;
    for (let index = 0; index < candidates.length; index += 1) {
      const candidate = candidates[index];
      await client.query(
        `INSERT INTO remediation_candidates (job_id,installation_id,repository_id,candidate_version,finding_snapshot_ids,artifact_digest,context_manifest_digest,file_manifest,preview,verification_level)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (job_id,artifact_digest) DO NOTHING`,
        [row.id,row.installation_id,row.repository_id,index + 1,candidate.finding_ids || [],candidate.artifact_digest,
          candidate.context_manifest_digest || verification?.context_manifest_digest || '',JSON.stringify(fileManifest(candidate)),
          JSON.stringify(candidate.preview || candidate),candidate.preview?.evidence?.verification_level || candidate.verification_level || verification?.verification_level || 'none']
      );
    }
    if (verification) {
      await client.query(
        `INSERT INTO verification_runs (job_id,installation_id,repository_id,candidate_digest,original_tree_sha,candidate_tree_sha,base_sha,verifier_identity,policy_version,outcome,evidence_digest,coverage_gaps,limitations)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [row.id,row.installation_id,row.repository_id,candidates[0]?.artifact_digest || null,row.head_sha,verification.candidate_tree_sha || null,row.base_sha,
          'remediation-service',row.policy_version,verification.status === 'failed' ? 'failed' : verification.status === 'unsupported' ? 'unsupported' : verification.status === 'passed' || outcome === 'ready' ? 'passed' : 'inconclusive',verification.evidence_digest || null,JSON.stringify(verification.coverage_gaps || []),JSON.stringify(Array.isArray(verification.limitations) ? verification.limitations : [])]
      );
    }
    const consumesAttempt = ATTEMPT_CONSUMING_STATES.has(state);
    const changed = await client.query(
      `UPDATE remediation_jobs SET state=$1, stage=$2, state_version=$3, lease_owner=NULL, lease_expires_at=NULL,
       attempt_count=attempt_count + ($7::int), failure_reason=$4, updated_at=NOW(),
       next_attempt_at=CASE WHEN $1='queued' THEN NOW() + (LEAST(attempt_count + 1, 6) * INTERVAL '10 seconds') ELSE NOW() END
       WHERE id=$5 AND fencing_token=$6`,
      [state, stage, nextVersion, reason ? JSON.stringify(reason) : null, row.id, job.fencing_token, consumesAttempt ? 1 : 0]
    );
    if (!changed.rowCount) return false;
    const eventJob = { ...row, state_version: nextVersion };
    await client.query(`UPDATE remediation_attempts SET outcome=$1, output_digest=$2, completed_at=NOW() WHERE job_id=$3 AND fencing_token=$4 AND completed_at IS NULL`, [outcome, outputDigest || null, row.id, job.fencing_token]);
    for (let index = 0; index < walk.length; index += 1) {
      await appendEvent(client, row, `remediation.${walk[index]}`, { stage: walk[index], outcome: 'stage_entered' }, Number(row.state_version) + index + 1);
    }
    await appendEvent(client, eventJob, `remediation.${state}`, { stage, outcome, reason: reason || null });
    await audit(client, null, row.repository_id, `remediation.${state}`, 'remediation_job', row.id, { stage, outcome, fencing_token: job.fencing_token });
    // A terminal job spends nothing further, so anything it still holds is freed here, in
    // the transaction that ended it. A stage that did run settles before this point.
    if (TERMINAL_STATES.has(state)) await releaseReservationsForJob(client, row, `job_${state}`);
    return true;
  });
}

async function recordAttempt(job, stage, inputDigest) {
  await scopedTransaction({ tenantId: job.installation_id, worker: true }, (client) => client.query(
    `INSERT INTO remediation_attempts (job_id,installation_id,repository_id,stage,attempt_number,fencing_token,input_digest)
     VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (job_id,stage,attempt_number) DO NOTHING`,
    [job.id,job.installation_id,job.repository_id,stage,Number(job.attempt_count) + 1,job.fencing_token,inputDigest]
  ));
}

async function heartbeat(job, leaseSeconds = 60) {
  return scopedTransaction({ tenantId: job.installation_id, worker: true }, async (client) => {
    const result = await client.query(
      `UPDATE remediation_jobs SET lease_expires_at=NOW()+($1::int * INTERVAL '1 second'), updated_at=NOW()
       WHERE id=$2 AND lease_owner=$3 AND fencing_token=$4 AND state = ANY($5::text[])`,
      [leaseSeconds, job.id, job.lease_owner, job.fencing_token, [...ACTIVE_STATES]]
    );
    return result.rowCount === 1;
  });
}

// A running remote execution still advances the persisted stage. state and stage stay
// equal so `(state, next_attempt_at)` remains the runnable index and an observer never
// sees an invented stage such as "awaiting_repair".
async function deferForExternalExecution(job, executionId, { stage = 'verifying', stagePath = [], revision = false } = {}) {
  return scopedTransaction({ tenantId: job.installation_id, worker: true }, async (client) => {
    const current = await client.query(`SELECT * FROM remediation_jobs WHERE id=$1 FOR UPDATE`, [job.id]);
    const row = current.rows[0];
    if (!row || row.fencing_token !== job.fencing_token || row.lease_owner !== job.lease_owner) return false;
    const walk = stagePath.filter((name) => name && name !== stage);
    const nextVersion = Number(row.state_version) + walk.length + 1;
    const result = await client.query(
      `UPDATE remediation_jobs SET state=$1, stage=$1, state_version=$2, external_execution_id=$3,
       revision_count=revision_count + ($6::int),
       lease_owner=NULL, lease_expires_at=NULL, next_attempt_at=NOW()+INTERVAL '5 seconds', updated_at=NOW()
       WHERE id=$4 AND fencing_token=$5`,
      [stage, nextVersion, executionId, job.id, job.fencing_token, revision ? 1 : 0]
    );
    if (!result.rowCount) return false;
    for (let index = 0; index < walk.length; index += 1) {
      await appendEvent(client, row, `remediation.${walk[index]}`, { stage: walk[index], outcome: 'stage_entered' }, Number(row.state_version) + index + 1);
    }
    await appendEvent(client, { ...row, state_version: nextVersion }, `remediation.${stage}`, { stage, outcome: 'running', revision });
    return true;
  });
}

async function cancelJob(jobId, userId, reason = 'cancelled_by_user') {
  return requestScope(userId, async (client) => {
    const result = await client.query(
      `UPDATE remediation_jobs SET state='cancelled', cancellation_reason=$2, state_version=state_version+1,
       lease_expires_at=NULL, lease_owner=NULL, updated_at=NOW() WHERE id=$1 AND state = ANY($3::text[]) RETURNING *`,
      [jobId, reason, [...ACTIVE_STATES]]
    );
    if (result.rowCount) await audit(client, userId, result.rows[0].repository_id, 'remediation.cancelled', 'remediation_job', jobId, { reason });
    return result.rows[0] || null;
  });
}

const WRITER_LEASE_SECONDS = 600;

// One logical writer per pull request. The row is claimed in the same transaction as
// the action insert, so a second concurrent apply cannot start a parallel write.
async function acquireWriterLease(client, row, userId) {
  const result = await client.query(
    `INSERT INTO remediation_writer_leases (pull_request_id, installation_id, repository_id, owner_id, expires_at)
     VALUES ($1,$2,$3,$4,NOW() + ($5::int * INTERVAL '1 second'))
     ON CONFLICT (pull_request_id) DO UPDATE
       SET owner_id=EXCLUDED.owner_id, acquired_at=NOW(), action_id=NULL, expires_at=EXCLUDED.expires_at
     WHERE remediation_writer_leases.expires_at < NOW()
     RETURNING *`,
    [row.pull_request_id, row.installation_id, row.repository_id, userId, WRITER_LEASE_SECONDS]
  );
  return result.rows[0] || null;
}

async function releaseWriterLease(client, pullRequestId, actionId) {
  await client.query(
    `DELETE FROM remediation_writer_leases WHERE pull_request_id=$1 AND ($2::uuid IS NULL OR action_id=$2::uuid)`,
    [pullRequestId, actionId || null]
  );
}

async function createAction(job, userId, payload, actorLogin) {
  return requestScope(userId, async (client) => {
    const current = await client.query(`SELECT * FROM remediation_jobs WHERE id=$1 FOR UPDATE`, [job.id]);
    const row = current.rows[0];
    if (!row || row.state !== 'ready') return { kind: 'not_ready' };
    // RLS WITH CHECK on the new tables requires an explicit tenant context.
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [String(row.installation_id)]);
    const payloadHash = hash(payload);
    const existing = await client.query(`SELECT * FROM remediation_actions WHERE actor_id=$1 AND repository_id=$2 AND idempotency_key=$3`, [userId,row.repository_id,payload.idempotency_key]);
    if (existing.rowCount) return existing.rows[0].payload_hash === payloadHash ? { kind: 'ok', action: existing.rows[0], replay: true } : { kind: 'conflict' };
    const preview = await getPreviewWithinTransaction(client, row);
    if (payload.head_sha !== row.head_sha || payload.base_sha !== row.base_sha) return { kind: 'stale' };
    const selection = selectCandidates(row, preview.candidates, payload.candidate_ids);
    if (selection.kind !== 'ok') return selection;
    if (payload.manifest_digest !== selection.manifestDigest) return { kind: 'manifest_mismatch' };
    const wanted = selection.candidates.map((c) => c.id);
    const lease = await acquireWriterLease(client, row, userId);
    if (!lease) return { kind: 'writer_busy' };
    const insert = await client.query(
      `INSERT INTO remediation_actions (job_id,installation_id,repository_id,pull_request_id,actor_id,actor_login,action_type,head_sha,base_sha,batch_manifest_digest,candidate_ids,idempotency_key,payload_hash,state)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'requested') RETURNING *`,
      [row.id,row.installation_id,row.repository_id,row.pull_request_id,userId,actorLogin,payload.merge_when_ready ? 'apply_and_merge':'apply',row.head_sha,row.base_sha,selection.manifestDigest,wanted,payload.idempotency_key,payloadHash]
    );
    const action=insert.rows[0];
    await client.query(`UPDATE remediation_writer_leases SET action_id=$1 WHERE pull_request_id=$2`, [action.id, row.pull_request_id]);
    // The action row and its dispatch event commit together; the worker never
    // discovers an action that was not durably recorded.
    const actionEvent = JSON.stringify({ job_id: row.id, head_sha: row.head_sha, manifest_digest: selection.manifestDigest });
    await client.query(
      `INSERT INTO workflow_events (aggregate_id,aggregate_type,installation_id,repository_id,sequence,event_type,payload)
       VALUES ($1,'remediation_action',$2,$3,1,'remediation.action.requested',$4) ON CONFLICT (aggregate_id, sequence) DO NOTHING`,
      [action.id, row.installation_id, row.repository_id, actionEvent]
    );
    await client.query(
      `INSERT INTO workflow_outbox (aggregate_id,installation_id,repository_id,event_sequence,event_type,payload)
       VALUES ($1,$2,$3,1,'remediation.action.requested',$4) ON CONFLICT (aggregate_id, event_sequence) DO NOTHING`,
      [action.id, row.installation_id, row.repository_id, actionEvent]
    );
    if (payload.merge_when_ready) await client.query(`INSERT INTO merge_intents (action_id,installation_id,repository_id,actor_id,approved_manifest_digest,approved_head_sha,approved_base_sha,expires_at,state) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW()+INTERVAL '24 hours','waiting_for_application')`, [action.id,row.installation_id,row.repository_id,userId,selection.manifestDigest,row.head_sha,row.base_sha]);
    await audit(client,userId,row.repository_id,'remediation.apply.requested','remediation_action',action.id,{job_id:row.id,head_sha:row.head_sha,manifest_digest:selection.manifestDigest,candidate_ids:wanted,merge_when_ready:Boolean(payload.merge_when_ready)});
    return { kind:'ok',action };
  });
}

async function getPreviewWithinTransaction(client, job) {
  const candidates = await client.query(`SELECT * FROM remediation_candidates WHERE job_id=$1 ORDER BY candidate_version`, [job.id]);
  return { candidates: candidates.rows, manifestDigest: manifestDigestFor(job, candidates.rows) };
}

// Resolves a requested subset against the job's stored candidates. One candidate is
// applied on its own verification; more than one is allowed only when the repair
// service verified that exact combination, which today is the full batch. A stale or
// already applied candidate is never selectable.
function selectCandidates(job, stored, requestedIds) {
  const wanted = [...new Set(requestedIds || [])];
  if (!wanted.length) return { kind: 'invalid_candidates' };
  const byId = new Map(stored.map((c) => [c.id, c]));
  if (wanted.some((id) => !byId.has(id))) return { kind: 'invalid_candidates' };
  if (wanted.some((id) => byId.get(id).rejection_reason)) return { kind: 'candidate_stale' };
  const applicable = stored.filter((c) => !c.rejection_reason);
  const selected = stored.filter((c) => wanted.includes(c.id));
  const fullBatch = selected.length === applicable.length && selected.length === stored.length;
  if (selected.length > 1 && !fullBatch) return { kind: 'subset_not_verified' };
  return { kind: 'ok', candidates: selected, fullBatch, manifestDigest: manifestDigestFor(job, selected) };
}

async function getActionForUser(actionId, userId) {
  return requestScope(userId, async (client) => {
    const action = await client.query(`SELECT * FROM remediation_actions WHERE id=$1`, [actionId]);
    if (!action.rowCount) return null;
    const intent = await client.query(`SELECT * FROM merge_intents WHERE action_id=$1`, [actionId]);
    return { action: action.rows[0], mergeIntent: intent.rows[0] || null };
  });
}

async function cancelMerge(actionId, userId) {
  return requestScope(userId, async (client) => {
    const result = await client.query(
      `UPDATE merge_intents SET state='cancelled', cancellation_reason='cancelled_by_user', updated_at=NOW()
        WHERE action_id=$1 AND state = ANY($2::text[]) RETURNING *`,
      [actionId, ['waiting_for_application','waiting_for_checks','eligible','reconciling']]
    );
    if (result.rowCount) await audit(client, userId, result.rows[0].repository_id, 'remediation.merge.cancelled', 'merge_intent', result.rows[0].id, {});
    return result.rows[0] || null;
  });
}

async function claimAction(actionId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN'); await client.query("SELECT set_config('app.remediation_worker', '1', true)");
    const result = await client.query(
      `WITH candidate AS (SELECT id FROM remediation_actions WHERE state IN ('requested','reconciling')
         AND ($1::uuid IS NULL OR id = $1::uuid) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1)
       UPDATE remediation_actions a SET state=CASE WHEN a.state='reconciling' THEN 'reconciling' ELSE 'revalidating' END, updated_at=NOW()
       FROM candidate WHERE a.id=candidate.id RETURNING a.*`, [actionId || null]
    );
    await client.query('COMMIT'); return result.rows[0] || null;
  } catch (error) { try { await client.query('ROLLBACK'); } catch (_) { /* ignored */ } throw error; } finally { client.release(); }
}

async function claimNextAction(_workerId) { return claimAction(null); }
async function claimActionById(actionId) { return claimAction(actionId); }

async function actionMaterial(action) {
  return scopedTransaction({ tenantId: action.installation_id, worker: true }, async (client) => {
    const job = await client.query(`SELECT j.*,r.full_name AS repository_full_name,pr.pr_number FROM remediation_jobs j JOIN repositories r ON r.id=j.repository_id JOIN pull_requests pr ON pr.id=j.pull_request_id WHERE j.id=$1`, [action.job_id]);
    const candidates = await client.query(`SELECT * FROM remediation_candidates WHERE id = ANY($1::uuid[]) AND job_id=$2 ORDER BY candidate_version`, [action.candidate_ids, action.job_id]);
    // The manifest is recomputed over the consented subset in persisted order, from the
    // stored rows, so a replaced candidate or a different subset changes the digest.
    const all = await client.query(`SELECT id, artifact_digest, rejection_reason FROM remediation_candidates WHERE job_id=$1 ORDER BY candidate_version`, [action.job_id]);
    const jobRow = job.rows[0] || null;
    const manifestDigest = manifestDigestFor(jobRow, candidates.rows);
    // The combined tree is what the repair service verified for the whole batch; a single
    // candidate carries its own verified tree in its file manifest.
    const combined = await client.query(`SELECT candidate_tree_sha FROM verification_runs WHERE job_id=$1 ORDER BY created_at DESC LIMIT 1`, [action.job_id]);
    return { job: jobRow, candidates: candidates.rows, manifestDigest, orderedCandidateIds: candidates.rows.map((c) => c.id),
      fullBatch: candidates.rowCount === all.rowCount, combinedTreeOid: combined.rows[0]?.candidate_tree_sha || null };
  });
}

const TERMINAL_ACTION_STATES = new Set(['applied', 'completed', 'cancelled', 'superseded', 'blocked', 'failed', 'rejected']);

async function updateAction(action, state, fields = {}) {
  return scopedTransaction({ tenantId: action.installation_id, worker: true }, async (client) => {
    const result = await client.query(
      `UPDATE remediation_actions SET state=$1, external_operation_id=COALESCE($2,external_operation_id),
       observed_commit_sha=COALESCE($3,observed_commit_sha), observed_tree_oid=COALESCE($6,observed_tree_oid),
       failure_reason=$4, updated_at=NOW() WHERE id=$5 RETURNING *`,
      [state, fields.operationId || null, fields.commitSha || null, fields.reason ? JSON.stringify(fields.reason) : null, action.id, fields.treeOid || null]
    );
    if (result.rowCount) await audit(client, null, action.repository_id, `remediation.action.${state}`, 'remediation_action', action.id, fields.reason || {});
    // A write that can no longer progress must not hold the pull request writer lease.
    if (result.rowCount && TERMINAL_ACTION_STATES.has(state) && state !== 'applied') {
      await releaseWriterLease(client, result.rows[0].pull_request_id, action.id);
    }
    if (result.rowCount && state === 'applied' && fields.commitSha) {
      await client.query(
        `UPDATE merge_intents SET applied_sha=$2, state=CASE WHEN state='waiting_for_application' THEN 'waiting_for_checks' ELSE state END, updated_at=NOW()
          WHERE action_id=$1 AND state='waiting_for_application'`,
        [action.id, fields.commitSha]
      );
    }
    return result.rows[0] || null;
  });
}

// The applied commit is durable; the fresh analysis for the new head is enqueued once
// per action and head. A failed notification never reverts an applied action.
async function enterChecking(action, { commitSha, treeOid }) {
  return scopedTransaction({ tenantId: action.installation_id, worker: true }, async (client) => {
    const current = await client.query(`SELECT * FROM remediation_actions WHERE id=$1 FOR UPDATE`, [action.id]);
    const row = current.rows[0];
    if (!row || !['applied', 'checking'].includes(row.state)) return null;
    if (row.verification_analysis_run_id && row.verification_head_sha === commitSha) {
      return { action: row, analysisRunId: row.verification_analysis_run_id, created: false };
    }
    const existing = await client.query(
      `SELECT id FROM analysis_runs WHERE repository_id=$1 AND pull_request_id=$2 AND commit_sha=$3
        ORDER BY created_at DESC LIMIT 1`,
      [row.repository_id, row.pull_request_id, commitSha]
    );
    let analysisRunId = existing.rows[0]?.id;
    let created = false;
    if (!analysisRunId) {
      const inserted = await client.query(
        `INSERT INTO analysis_runs (repository_id, pull_request_id, pr_number, commit_sha, status, triggered_by)
         SELECT $1,$2,pr.pr_number,$3,'pending','remediation' FROM pull_requests pr WHERE pr.id=$2 RETURNING id`,
        [row.repository_id, row.pull_request_id, commitSha]
      );
      analysisRunId = inserted.rows[0]?.id;
      created = true;
    }
    if (!analysisRunId) return null;
    const updated = await client.query(
      `UPDATE remediation_actions SET state='checking', verification_analysis_run_id=$2, verification_head_sha=$3,
       observed_commit_sha=COALESCE($4,observed_commit_sha), observed_tree_oid=COALESCE($5,observed_tree_oid), updated_at=NOW()
       WHERE id=$1 RETURNING *`,
      [row.id, analysisRunId, commitSha, commitSha, treeOid || null]
    );
    await audit(client, null, row.repository_id, 'remediation.action.checking', 'remediation_action', row.id,
      { commit_sha: commitSha, tree_oid: treeOid || null, analysis_run_id: analysisRunId });
    return { action: updated.rows[0], analysisRunId, created };
  });
}

// Called by the reconciler or a webhook once the analysis for the applied head finishes.
async function completeAction(actionId, { headSha } = {}) {
  return scopedTransaction({ worker: true }, async (client) => {
    const current = await client.query(`SELECT * FROM remediation_actions WHERE id=$1 FOR UPDATE`, [actionId]);
    const row = current.rows[0];
    if (!row || row.state !== 'checking') return null;
    if (headSha && row.verification_head_sha && row.verification_head_sha !== headSha) return null;
    const analysis = await client.query(`SELECT status FROM analysis_runs WHERE id=$1`, [row.verification_analysis_run_id]);
    if (analysis.rows[0]?.status !== 'completed') return null;
    const updated = await client.query(
      `UPDATE remediation_actions SET state='completed', updated_at=NOW() WHERE id=$1 RETURNING *`, [row.id]
    );
    await releaseWriterLease(client, row.pull_request_id, row.id);
    // The merge controller learns about completion through the same durable outbox the
    // rest of the workflow uses; the periodic sweep remains the backup.
    await appendActionEvent(client, row, 'remediation.action.completed',
      { head_sha: row.verification_head_sha || row.observed_commit_sha, analysis_run_id: row.verification_analysis_run_id });
    await audit(client, null, row.repository_id, 'remediation.action.completed', 'remediation_action', row.id,
      { commit_sha: row.observed_commit_sha, analysis_run_id: row.verification_analysis_run_id });
    return updated.rows[0];
  });
}

// Audit-only denial record for a refused write. It never changes workflow state.
async function recordApplyDenial(userId, job, reason, details = {}) {
  return requestScope(userId, async (client) => {
    await audit(client, userId, job.repository_id, 'remediation.apply.denied', 'remediation_job', job.id,
      { reason, head_sha: job.head_sha, ...details });
  });
}

// --- Reconciliation helpers. Each one is bounded and independent of the others. ---

async function reclaimExpiredLeases(limit = 50) {
  return scopedTransaction({ worker: true }, async (client) => {
    // A pure lease expiry bumps the fencing token so the old worker is fenced out,
    // but it never consumes attempt_count: nothing has actually failed yet.
    const result = await client.query(
      `WITH expired AS (
         SELECT id FROM remediation_jobs
          WHERE state = ANY($1::text[]) AND lease_expires_at IS NOT NULL AND lease_expires_at < NOW()
          ORDER BY lease_expires_at FOR UPDATE SKIP LOCKED LIMIT $2
       ) UPDATE remediation_jobs j SET lease_owner=NULL, lease_expires_at=NULL,
          fencing_token=j.fencing_token+1, next_attempt_at=NOW(), updated_at=NOW()
        FROM expired WHERE j.id=expired.id RETURNING j.id`,
      [[...ACTIVE_STATES], limit]
    );
    return result.rows.map((row) => row.id);
  });
}

async function redispatchStuckOutbox(stuckSeconds = 300, limit = 100) {
  return scopedTransaction({ worker: true }, async (client) => {
    const result = await client.query(
      `WITH stuck AS (
         SELECT id FROM workflow_outbox
          WHERE status='dispatching' AND updated_at < NOW() - ($1::int * INTERVAL '1 second')
          ORDER BY updated_at FOR UPDATE SKIP LOCKED LIMIT $2
       ) UPDATE workflow_outbox o SET status='pending', next_attempt_at=NOW(), updated_at=NOW()
        FROM stuck WHERE o.id=stuck.id RETURNING o.id`,
      [stuckSeconds, limit]
    );
    return result.rows.map((row) => row.id);
  });
}

async function listStaleReconcilingActions(staleSeconds = 300, limit = 20) {
  return scopedTransaction({ worker: true }, async (client) => {
    const result = await client.query(
      `SELECT a.*, j.head_sha AS job_head_sha, r.full_name AS repository_full_name, pr.pr_number
         FROM remediation_actions a
         JOIN remediation_jobs j ON j.id=a.job_id
         JOIN repositories r ON r.id=a.repository_id
         JOIN pull_requests pr ON pr.id=a.pull_request_id
        WHERE a.state='reconciling' AND a.updated_at < NOW() - ($1::int * INTERVAL '1 second')
        ORDER BY a.updated_at LIMIT $2`, [staleSeconds, limit]
    );
    return result.rows;
  });
}

async function quarantineExhaustedJobs(limit = 50) {
  return scopedTransaction({ worker: true }, async (client) => {
    const result = await client.query(
      `WITH exhausted AS (
         SELECT id FROM remediation_jobs
          WHERE state = ANY($1::text[])
            AND attempt_count >= COALESCE((policy_manifest->>'max_attempts')::int, 3)
          ORDER BY updated_at FOR UPDATE SKIP LOCKED LIMIT $2
       ) UPDATE remediation_jobs j SET state='dead_letter', stage='dead_letter', state_version=j.state_version+1,
          lease_owner=NULL, lease_expires_at=NULL,
          failure_reason=jsonb_build_object('code','max_attempts_exceeded','attempts',j.attempt_count), updated_at=NOW()
        FROM exhausted WHERE j.id=exhausted.id RETURNING j.id, j.installation_id, j.repository_id, j.attempt_count`,
      [[...ACTIVE_STATES], limit]
    );
    for (const row of result.rows) {
      await audit(client, null, row.repository_id, 'remediation.dead_letter', 'remediation_job', row.id,
        { reason: 'max_attempts_exceeded', attempts: row.attempt_count });
    }
    return result.rows.map((row) => row.id);
  });
}

async function expireMergeIntents(limit = 100) {
  return scopedTransaction({ worker: true }, async (client) => {
    const result = await client.query(
      `UPDATE merge_intents SET state='expired', cancellation_reason='expired', updated_at=NOW()
        WHERE id IN (
          SELECT id FROM merge_intents
           WHERE expires_at < NOW() AND state = ANY($1::text[])
           ORDER BY expires_at LIMIT $2
        ) RETURNING id`,
      // A merging intent is never expired: an in-flight merge is settled by reading
      // authoritative GitHub state, not by declaring a timeout.
      [['waiting_for_application', 'waiting_for_checks', 'eligible', 'blocked', 'reconciling'], limit]
    );
    return result.rows.map((row) => row.id);
  });
}

async function listActionsAwaitingVerification(limit = 50) {
  return scopedTransaction({ worker: true }, async (client) => {
    const result = await client.query(
      `SELECT a.id, a.verification_head_sha FROM remediation_actions a
         JOIN analysis_runs ar ON ar.id = a.verification_analysis_run_id
        WHERE a.state='checking' AND ar.status='completed' ORDER BY a.updated_at LIMIT $1`, [limit]
    );
    return result.rows;
  });
}

// --- Webhook-driven invalidation. Runs on the caller's transaction when given one. ---

async function withClient(client, fn) {
  if (client) {
    await client.query("SELECT set_config('app.remediation_worker', '1', true)");
    return fn(client);
  }
  return scopedTransaction({ worker: true }, fn);
}

// A new head invalidates every proposal bound to the old one. The application commit
// created by this system is the one exception: it does not cancel its own merge intent.
async function supersedeForHeadChange({ client, pullRequestId, newHeadSha, reason = 'head_changed' }) {
  return withClient(client, async (db) => {
    const jobs = await db.query(
      `UPDATE remediation_jobs SET state='superseded', stage='superseded', cancellation_reason=$3,
       state_version=state_version+1, lease_owner=NULL, lease_expires_at=NULL, updated_at=NOW()
        WHERE pull_request_id=$1 AND head_sha <> $2 AND state <> ALL($4::text[]) RETURNING id`,
      [pullRequestId, newHeadSha, reason, [...TERMINAL_STATES].filter((state) => state !== 'ready')]
    );
    const candidates = await db.query(
      `UPDATE remediation_candidates c SET rejection_reason=jsonb_build_object('code',$3::text)
         FROM remediation_jobs j
        WHERE c.job_id=j.id AND j.pull_request_id=$1 AND j.head_sha <> $2 AND c.rejection_reason IS NULL
        RETURNING c.id`,
      [pullRequestId, newHeadSha, reason]
    );
    const intents = await db.query(
      `UPDATE merge_intents mi SET state='cancelled', cancellation_reason=$3, updated_at=NOW()
         FROM remediation_actions a
        WHERE mi.action_id=a.id AND a.pull_request_id=$1
          AND mi.state = ANY($4::text[])
          AND mi.approved_head_sha <> $2
          AND COALESCE(mi.applied_sha, a.observed_commit_sha, '') <> $2
        RETURNING mi.id`,
      [pullRequestId, newHeadSha, reason, ['waiting_for_application', 'waiting_for_checks', 'eligible', 'reconciling']]
    );
    return { jobs: jobs.rows.map((r) => r.id), candidates: candidates.rows.map((r) => r.id), mergeIntents: intents.rows.map((r) => r.id) };
  });
}

// After an apply commits, the applied candidates are recorded as applied and every
// other candidate of the pull request is stale: it was verified against a head that no
// longer exists. Nothing is rebased; a new generation on the new head replaces them.
async function markCandidatesAfterApply(action, commitSha) {
  return scopedTransaction({ tenantId: action.installation_id, worker: true }, async (client) => {
    await client.query(
      `UPDATE remediation_candidates SET rejection_reason=jsonb_build_object('code','applied','action_id',$2::text,'commit_sha',$3::text)
        WHERE id = ANY($1::uuid[]) AND rejection_reason IS NULL`,
      [action.candidate_ids, action.id, commitSha]
    );
    return supersedeForHeadChange({ client, pullRequestId: action.pull_request_id, newHeadSha: commitSha, reason: 'head_changed' });
  });
}

async function supersedeForBranchPush({ client, repositoryGithubId, branch, newHeadSha, reason = 'head_changed' }) {
  return withClient(client, async (db) => {
    const prs = await db.query(
      `SELECT pr.id FROM pull_requests pr JOIN repositories r ON r.id=pr.repository_id
        WHERE r.github_id=$1 AND pr.head_branch=$2 AND pr.state='open'`, [repositoryGithubId, branch]
    );
    const results = [];
    for (const row of prs.rows) {
      results.push(await supersedeForHeadChange({ client: db, pullRequestId: row.id, newHeadSha, reason }));
    }
    return results;
  });
}

// A hint is an append-only observation. A merge controller consumes it later; nothing
// here decides anything about a merge.
async function recordMergeReevaluationHint(pullRequestRef, reason) {
  const { client, pullRequestId, repositoryGithubId, prNumber, headSha } = pullRequestRef || {};
  return withClient(client, async (db) => {
    const located = await db.query(
      `SELECT pr.id, pr.repository_id, r.installation_id FROM pull_requests pr
         JOIN repositories r ON r.id=pr.repository_id
        WHERE ($1::uuid IS NOT NULL AND pr.id=$1::uuid)
           OR ($2::bigint IS NOT NULL AND r.github_id=$2::bigint AND (
                 ($3::int IS NOT NULL AND pr.pr_number=$3::int)
                 OR ($4::text IS NOT NULL AND pr.head_sha=$4::text)))
        LIMIT 20`,
      [pullRequestId || null, repositoryGithubId || null, prNumber ?? null, headSha || null]
    );
    const recorded = [];
    for (const row of located.rows) {
      if (row.installation_id == null) continue;
      const sequence = await db.query(
        `SELECT COALESCE(MAX(sequence),0)+1 AS next FROM workflow_events WHERE aggregate_id=$1`, [row.id]
      );
      const inserted = await db.query(
        `INSERT INTO workflow_events (aggregate_id, aggregate_type, installation_id, repository_id, sequence, event_type, payload)
         VALUES ($1,'pull_request',$2,$3,$4,'remediation.merge.reevaluate',$5)
         ON CONFLICT (aggregate_id, sequence) DO NOTHING RETURNING id`,
        [row.id, row.installation_id, row.repository_id, Number(sequence.rows[0].next), JSON.stringify({ reason, head_sha: headSha || null })]
      );
      if (!inserted.rowCount) continue;
      // The event is the record; the outbox row is its delivery. Both share the
      // aggregate sequence, so a duplicate webhook cannot dispatch twice.
      await db.query(
        `INSERT INTO workflow_outbox (aggregate_id, installation_id, repository_id, event_sequence, event_type, payload)
         VALUES ($1,$2,$3,$4,'remediation.merge.reevaluate',$5)
         ON CONFLICT (aggregate_id, event_sequence) DO NOTHING`,
        [row.id, row.installation_id, row.repository_id, Number(sequence.rows[0].next), JSON.stringify({ reason, head_sha: headSha || null })]
      );
      recorded.push(row.id);
    }
    return recorded;
  });
}


// --- Merge controller persistence ------------------------------------------------
// A merge intent is never advanced by a blind UPDATE. Every transition compares and
// swaps state_version, so a stale evaluator can never publish a decision.

const NON_TERMINAL_MERGE_STATES = Object.freeze([
  'waiting_for_application', 'waiting_for_checks', 'eligible', 'merging', 'blocked', 'reconciling',
]);

// One append-only event plus its outbox delivery for a remediation action aggregate.
async function appendActionEvent(client, action, eventType, payload) {
  const sequence = await client.query(
    `SELECT COALESCE(MAX(sequence),0)+1 AS next FROM workflow_events WHERE aggregate_id=$1`, [action.id]
  );
  const next = Number(sequence.rows[0].next);
  const body = JSON.stringify(payload || {});
  const inserted = await client.query(
    `INSERT INTO workflow_events (aggregate_id, aggregate_type, installation_id, repository_id, sequence, event_type, payload)
     VALUES ($1,'remediation_action',$2,$3,$4,$5,$6) ON CONFLICT (aggregate_id, sequence) DO NOTHING RETURNING id`,
    [action.id, action.installation_id, action.repository_id, next, eventType, body]
  );
  if (!inserted.rowCount) return false;
  await client.query(
    `INSERT INTO workflow_outbox (aggregate_id, installation_id, repository_id, event_sequence, event_type, payload)
     VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (aggregate_id, event_sequence) DO NOTHING`,
    [action.id, action.installation_id, action.repository_id, next, eventType, body]
  );
  return true;
}

const MERGE_INTENT_CONTEXT_SQL = `
  SELECT mi.*,
         a.state AS action_state, a.actor_login, a.job_id, a.pull_request_id, a.candidate_ids,
         a.head_sha AS action_head_sha, a.base_sha AS action_base_sha,
         a.observed_commit_sha, a.observed_tree_oid, a.batch_manifest_digest, a.idempotency_key,
         a.verification_analysis_run_id, a.verification_head_sha,
         a.verification_check_status, a.verification_check_conclusion, a.verification_check_head_sha,
         r.full_name AS repository_full_name, r.is_active AS repository_active,
         pr.pr_number, pr.state AS pull_request_state,
         i.status AS installation_status
    FROM merge_intents mi
    JOIN remediation_actions a ON a.id = mi.action_id
    JOIN repositories r ON r.id = mi.repository_id
    JOIN pull_requests pr ON pr.id = a.pull_request_id
    JOIN installations i ON i.id = mi.installation_id`;

async function mergeIntentContext(intentId) {
  return scopedTransaction({ worker: true }, async (client) => {
    const result = await client.query(`${MERGE_INTENT_CONTEXT_SQL} WHERE mi.id=$1`, [intentId]);
    return result.rows[0] || null;
  });
}

// The polling backup. It returns the least recently evaluated non-terminal intents so
// a lost webhook can never strand a merge decision.
async function listEvaluableMergeIntents({ staleSeconds = 300, limit = 25 } = {}) {
  return scopedTransaction({ worker: true }, async (client) => {
    const result = await client.query(
      `SELECT id FROM merge_intents
        WHERE state = ANY($1::text[])
          AND (last_evaluated_at IS NULL OR last_evaluated_at < NOW() - ($2::int * INTERVAL '1 second'))
        ORDER BY last_evaluated_at NULLS FIRST LIMIT $3`,
      [[...NON_TERMINAL_MERGE_STATES], staleSeconds, limit]
    );
    return result.rows.map((row) => row.id);
  });
}

async function listMergeIntentIdsForPullRequest(pullRequestId) {
  return scopedTransaction({ worker: true }, async (client) => {
    const result = await client.query(
      `SELECT mi.id FROM merge_intents mi JOIN remediation_actions a ON a.id=mi.action_id
        WHERE a.pull_request_id=$1 AND mi.state = ANY($2::text[]) ORDER BY mi.created_at`,
      [pullRequestId, [...NON_TERMINAL_MERGE_STATES]]
    );
    return result.rows.map((row) => row.id);
  });
}

async function mergeIntentIdForAction(actionId) {
  return scopedTransaction({ worker: true }, async (client) => {
    const result = await client.query(`SELECT id FROM merge_intents WHERE action_id=$1`, [actionId]);
    return result.rows[0]?.id || null;
  });
}

// Compare-and-swap on state_version. A null return means another evaluator already
// moved this intent; the caller must re-read rather than retry its own decision.
async function transitionMergeIntent(intent, state, fields = {}) {
  return scopedTransaction({ tenantId: intent.installation_id, worker: true }, async (client) => {
    const result = await client.query(
      `UPDATE merge_intents SET state=$2, state_version=state_version+1,
         blockers=COALESCE($3::jsonb, blockers),
         merge_attempts=merge_attempts + $4::int,
         external_operation_id=COALESCE($5, external_operation_id),
         observed_merge_sha=COALESCE($6, observed_merge_sha),
         applied_sha=COALESCE($7, applied_sha),
         cancellation_reason=COALESCE($8, cancellation_reason),
         latest_policy_checks=COALESCE($9::jsonb, latest_policy_checks),
         last_evaluated_at=NOW(), updated_at=NOW()
       WHERE id=$1 AND state_version=$10::bigint RETURNING *`,
      [intent.id, state, fields.blockers ? JSON.stringify(fields.blockers) : null,
        fields.attempt ? 1 : 0, fields.operationId || null, fields.observedMergeSha || null,
        fields.appliedSha || null, fields.reason || null,
        fields.checks ? JSON.stringify(fields.checks) : null, String(intent.state_version)]
    );
    if (!result.rowCount) return null;
    await audit(client, null, intent.repository_id, `remediation.merge.${state}`, 'merge_intent', intent.id,
      { blockers: fields.blockers || null, reason: fields.reason || null, observed_merge_sha: fields.observedMergeSha || null });
    return result.rows[0];
  });
}

// Records the outcome of an evaluation that did not change state. It still fences on
// state_version so two evaluators cannot interleave their blocker lists.
async function recordMergeEvaluation(intent, { blockers = [], checks = null } = {}) {
  return scopedTransaction({ tenantId: intent.installation_id, worker: true }, async (client) => {
    const result = await client.query(
      `UPDATE merge_intents SET state_version=state_version+1, blockers=$2::jsonb,
         latest_policy_checks=COALESCE($3::jsonb, latest_policy_checks), last_evaluated_at=NOW(), updated_at=NOW()
       WHERE id=$1 AND state_version=$4::bigint RETURNING *`,
      [intent.id, JSON.stringify(blockers), checks ? JSON.stringify(checks) : null, String(intent.state_version)]
    );
    return result.rows[0] || null;
  });
}

// The fresh analysis for the applied head. An analysis that has not completed is
// inconclusive, never a pass.
async function blockingFindingsForAction(action) {
  return scopedTransaction({ tenantId: action.installation_id, worker: true }, async (client) => {
    if (!action.verification_analysis_run_id) return { analysisState: 'missing', blocking: null };
    const run = await client.query(`SELECT status, commit_sha FROM analysis_runs WHERE id=$1`,
      [action.verification_analysis_run_id]);
    const row = run.rows[0];
    if (!row) return { analysisState: 'missing', blocking: null };
    if (row.status !== 'completed') return { analysisState: row.status || 'unknown', blocking: null, commitSha: row.commit_sha };
    // Every open finding in the pull request's changed files counts, whatever its
    // severity. Informational findings in test code are listed but never block.
    // Membership comes from the run's immutable snapshot: findings.analysis_run_id is
    // re-pointed by whichever run upserted a finding last (the webhook's run for the
    // same commit races this one), so filtering on it would report an empty head.
    const findings = await client.query(
      `SELECT f.id, f.title, f.file_path, f.line_start, f.line_end, f.severity, f.rule_id,
              (LOWER(f.severity)='info' OR COALESCE((f.evidence_details->'extra'->>'in_test_code')::boolean, false)) AS informational
         FROM analysis_run_findings arf
         JOIN findings f ON f.id = arf.finding_id
        WHERE arf.analysis_run_id=$1 AND f.status='open'
        ORDER BY f.file_path, CASE LOWER(f.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.line_start`,
      [action.verification_analysis_run_id]
    );
    const open = findings.rows.map((f) => ({ id: f.id, title: f.title, file_path: f.file_path, line_start: f.line_start, line_end: f.line_end,
      severity: String(f.severity || '').toLowerCase(), rule_id: f.rule_id, informational: Boolean(f.informational) }));
    return { analysisState: 'completed', blocking: open.filter((f) => !f.informational).length, open, commitSha: row.commit_sha };
  });
}

// What one action applied and what the job could not repair, from the immutable job
// snapshot. Combined with blockingFindingsForAction this is the residual report.
async function appliedReportForAction(action) {
  return scopedTransaction({ tenantId: action.installation_id, worker: true }, async (client) => {
    const job = await client.query(`SELECT * FROM remediation_jobs WHERE id=$1`, [action.job_id]);
    const jobRow = job.rows[0] || null;
    if (!jobRow) return { applied: [], unsupported: [] };
    const candidates = await client.query(
      `SELECT id, finding_snapshot_ids, file_manifest, preview FROM remediation_candidates WHERE id = ANY($1::uuid[]) AND job_id=$2 ORDER BY candidate_version`,
      [action.candidate_ids, action.job_id]);
    const findings = await findingSnapshots(client, jobRow);
    const byId = new Map(findings.map((f) => [f.id, f]));
    const applied = [];
    for (const candidate of candidates.rows) {
      const paths = (candidate.file_manifest?.files || candidate.preview?.changes || []).map((f) => f?.path).filter(Boolean);
      for (const findingId of candidate.finding_snapshot_ids || []) {
        const finding = byId.get(findingId) || { id: findingId };
        applied.push({ finding_id: findingId, title: finding.title || null, file_path: finding.file_path || paths[0] || null,
          line_start: finding.line_start ?? null, severity: finding.severity || null, candidate_id: candidate.id, paths });
      }
    }
    const unsupported = (jobRow.failure_reason?.skipped || []).map((item) => {
      const finding = byId.get(item.finding_id) || {};
      return { finding_id: item.finding_id || null, title: finding.title || null, file_path: finding.file_path || null,
        line_start: finding.line_start ?? null, severity: finding.severity || null, code: item.code || null, reason: item.reason || item.message || item.code || 'not repaired' };
    });
    return { applied, unsupported };
  });
}

async function recordResidualComment(action, { commentId, headSha }) {
  return scopedTransaction({ tenantId: action.installation_id, worker: true }, async (client) => {
    const result = await client.query(
      `UPDATE remediation_actions SET residual_comment_id=COALESCE($2::bigint, residual_comment_id), residual_comment_head_sha=$3,
         residual_comment_published_at=NOW(), updated_at=NOW() WHERE id=$1 RETURNING *`,
      [action.id, commentId == null ? null : String(commentId), headSha]
    );
    return result.rows[0] || null;
  });
}

// A completed action whose report was not yet published for its verification head.
async function listActionsNeedingResidualComment(limit = 25) {
  return scopedTransaction({ worker: true }, async (client) => {
    const result = await client.query(
      `SELECT a.id FROM remediation_actions a
        WHERE a.state='completed' AND a.verification_head_sha IS NOT NULL
          AND a.residual_comment_head_sha IS DISTINCT FROM a.verification_head_sha
        ORDER BY a.updated_at LIMIT $1`, [limit]
    );
    return result.rows.map((row) => row.id);
  });
}

// What this app actually published. The merge gate reads this row; it never assumes a
// check it did not publish.
async function recordVerificationCheck(action, { status, conclusion, checkRunId, headSha }) {
  return scopedTransaction({ tenantId: action.installation_id, worker: true }, async (client) => {
    const result = await client.query(
      `UPDATE remediation_actions SET verification_check_status=$2, verification_check_conclusion=$3,
         verification_check_run_id=COALESCE($4::bigint, verification_check_run_id),
         verification_check_head_sha=$5, verification_check_published_at=NOW(), updated_at=NOW()
       WHERE id=$1 RETURNING *`,
      [action.id, status, conclusion || null, checkRunId == null ? null : String(checkRunId), headSha]
    );
    return result.rows[0] || null;
  });
}

// Publication is retried until the published record matches the current verification
// head and phase. A failed publication never changes the action state.
async function listActionsNeedingVerificationCheck(limit = 25) {
  return scopedTransaction({ worker: true }, async (client) => {
    const result = await client.query(
      `SELECT a.id FROM remediation_actions a
        WHERE a.state IN ('checking','completed') AND a.verification_head_sha IS NOT NULL
          AND (a.verification_check_head_sha IS DISTINCT FROM a.verification_head_sha
               OR (a.state='completed' AND a.verification_check_status IS DISTINCT FROM 'completed'))
        ORDER BY a.updated_at LIMIT $1`, [limit]
    );
    return result.rows.map((row) => row.id);
  });
}

const ACTION_CHECK_CONTEXT_SQL = `
  SELECT a.*, r.full_name AS repository_full_name, pr.pr_number
    FROM remediation_actions a
    JOIN repositories r ON r.id = a.repository_id
    JOIN pull_requests pr ON pr.id = a.pull_request_id`;

async function actionCheckContext(actionId) {
  return scopedTransaction({ worker: true }, async (client) => {
    const action = await client.query(`${ACTION_CHECK_CONTEXT_SQL} WHERE a.id=$1`, [actionId]);
    const row = action.rows[0] || null;
    if (!row) return null;
    const candidates = await client.query(
      `SELECT id, artifact_digest, file_manifest, preview FROM remediation_candidates
        WHERE id = ANY($1::uuid[]) AND job_id=$2 ORDER BY candidate_version`, [row.candidate_ids, row.job_id]);
    return { action: row, candidates: candidates.rows };
  });
}

// --- Feedback and reviewed repair memory -----------------------------------------

async function getCandidateForFeedback(jobId, candidateId, userId) {
  return requestScope(userId, async (client) => {
    const job = await client.query(
      `SELECT j.id, j.installation_id, j.repository_id, j.pull_request_id, j.head_sha
         FROM remediation_jobs j WHERE j.id=$1`, [jobId]);
    if (!job.rowCount) return null;
    const candidate = await client.query(
      `SELECT id, artifact_digest, context_manifest_digest, verification_level, finding_snapshot_ids
         FROM remediation_candidates WHERE id=$1 AND job_id=$2`, [candidateId, jobId]);
    if (!candidate.rowCount) return { job: job.rows[0], candidate: null };
    return { job: job.rows[0], candidate: candidate.rows[0] };
  });
}

// An observation, never an approval. Section 11 requires human review before an
// example can influence generation, so status is fixed at 'observed' here.
async function recordRepairMemoryObservation({ job, candidate, userId, outcome, reason, expiryDays }) {
  return requestScope(userId, async (client) => {
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [String(job.installation_id)]);
    const weaknessSignature = hash({ repository: job.repository_id, findings: [...(candidate.finding_snapshot_ids || [])].sort() });
    const provenance = {
      actor_id: userId, job_id: job.id, candidate_id: candidate.id, head_sha: job.head_sha,
      pull_request_id: job.pull_request_id, recorded_by: 'remediation_feedback',
    };
    const result = await client.query(
      `INSERT INTO repair_memory (installation_id, repository_id, weakness_signature, source_digest, patch_digest,
         verification_outcome, status, expires_at, job_id, candidate_id, actor_id, head_sha, outcome, reason, provenance)
       VALUES ($1,$2,$3,$4,$5,$6,'observed', NOW() + ($7::int * INTERVAL '1 day'), $8,$9,$10,$11,$12,$13,$14)
       ON CONFLICT (candidate_id, actor_id) WHERE candidate_id IS NOT NULL AND actor_id IS NOT NULL
       DO UPDATE SET outcome=EXCLUDED.outcome, reason=EXCLUDED.reason, provenance=EXCLUDED.provenance,
         expires_at=EXCLUDED.expires_at, status='observed', updated_at=NOW()
       RETURNING id`,
      [job.installation_id, job.repository_id, weaknessSignature, candidate.context_manifest_digest,
        candidate.artifact_digest, candidate.verification_level || 'unknown', expiryDays,
        job.id, candidate.id, userId, job.head_sha, outcome, reason || null, JSON.stringify(provenance)]
    );
    await audit(client, userId, job.repository_id, 'remediation.feedback.recorded', 'remediation_candidate', candidate.id,
      { job_id: job.id, outcome, status: 'observed' });
    return result.rows[0] || null;
  });
}

module.exports = {
  ACTIVE_STATES, TERMINAL_STATES, hash, scopedTransaction, createJob, getJobForUser, getLatestForPullRequest, getPreview,
  claimNextJob, claimJobById, recordAttempt, heartbeat, deferForExternalExecution, reserveUsage, settleUsage, budgetSnapshot,
  usageCost, releaseStrandedReservations,
  completeStage, cancelJob, createAction, getActionForUser, cancelMerge, claimNextAction, claimActionById, actionMaterial,
  updateAction, enterChecking, completeAction, appendEvent, audit, recordApplyDenial,
  reclaimExpiredLeases, redispatchStuckOutbox, listStaleReconcilingActions, quarantineExhaustedJobs, expireMergeIntents,
  listActionsAwaitingVerification, supersedeForHeadChange, supersedeForBranchPush, recordMergeReevaluationHint,
  releaseWriterLease,
  NON_TERMINAL_MERGE_STATES, mergeIntentContext, listEvaluableMergeIntents, listMergeIntentIdsForPullRequest,
  mergeIntentIdForAction, transitionMergeIntent, recordMergeEvaluation, blockingFindingsForAction,
  recordVerificationCheck, listActionsNeedingVerificationCheck, actionCheckContext, recordRepairMemoryObservation,
  getCandidateForFeedback,
  manifestDigestFor, selectCandidates, markCandidatesAfterApply, appliedReportForAction,
  recordResidualComment, listActionsNeedingResidualComment,
  createAutomaticJob, jobPublishContext, recordInlineFixesPublished,
};
