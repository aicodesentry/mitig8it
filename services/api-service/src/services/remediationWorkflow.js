const crypto = require('crypto');
const remediationDb = require('../db/remediation');
const { RemediationServiceClient } = require('./remediationServiceClient');
const { GitHubRemediationClient } = require('./githubRemediationClient');
const policy = require('./remediationPolicy');
const metrics = require('./remediationMetrics');
const logger = require('../utils/logger');
const { withSpan, injectTrace } = require('../utils/telemetry');

const REPAIR_OUTCOMES = new Set(['ready', 'unsupported', 'inconclusive', 'failed']);
const STAGE_SEQUENCE = policy.STAGE_SEQUENCE;
// The remote service names its own phases; the control plane owns the persisted
// vocabulary and refuses to persist a stage it does not recognise.
const STAGE_ALIASES = Object.freeze({
  snapshot: 'snapshotting', snapshotting: 'snapshotting', queued: 'snapshotting',
  retrieve: 'retrieving', retrieval: 'retrieving', retrieving: 'retrieving',
  plan: 'planning', planning: 'planning',
  generate: 'generating', generation: 'generating', generating: 'generating',
  verify: 'verifying', verification: 'verifying', verifying: 'verifying',
});

function canonicalStage(reported) {
  if (typeof reported !== 'string') return null;
  return STAGE_ALIASES[reported.toLowerCase()] || null;
}

// Stages only move forward, except verifying -> generating which is a bounded revision.
function planStageTransition(currentStage, reportedStage) {
  const current = STAGE_SEQUENCE.indexOf(currentStage) >= 0 ? currentStage : STAGE_SEQUENCE[0];
  const target = canonicalStage(reportedStage) || current;
  const from = STAGE_SEQUENCE.indexOf(current);
  const to = STAGE_SEQUENCE.indexOf(target);
  if (to < from) {
    if (current === 'verifying' && target === 'generating') {
      return { stage: 'generating', stagePath: [], revision: true };
    }
    return { stage: current, stagePath: [], revision: false };
  }
  return { stage: target, stagePath: STAGE_SEQUENCE.slice(from, to), revision: false };
}

function stagePathToEnd(currentStage) {
  const from = Math.max(STAGE_SEQUENCE.indexOf(currentStage), 0);
  return STAGE_SEQUENCE.slice(from);
}
function sha256(value) { return crypto.createHash('sha256').update(value || '').digest('hex'); }
function repairPolicy(policy) {
  const names = ['policy_version', 'max_files', 'max_changed_lines', 'max_snapshot_files', 'max_file_bytes', 'max_snapshot_bytes',
    'max_tool_calls', 'max_attempts', 'max_revisions', 'max_context_chars', 'max_output_chars', 'max_total_tokens', 'max_output_tokens_per_call',
    'max_spend_usd', 'input_usd_per_million_tokens', 'output_usd_per_million_tokens', 'request_timeout_seconds', 'supported_platform',
    'allowed_rule_families', 'sandbox_image_digest', 'verification_checks', 'forbidden_path_prefixes', 'forbidden_filenames',
    'require_generated_regression_test', 'run_repository_tests'];
  const selected = Object.fromEntries(names.filter((name) => policy[name] !== undefined).map((name) => [name, policy[name]]));
  selected.allow_development_verification = require('./remediationPolicy').allowDevelopmentVerification();
  return selected;
}

async function loadSnapshot(job, findingPaths = []) {
  // The adapter verifies the actor's live write permission before reading the tree. An
  // automatic job borrows a connecting user's login for that; with none available the
  // job cannot proceed and says so instead of sending an invalid envelope.
  if (!job.creator_login) {
    const error = new Error('No repository user is available to authorize the snapshot'); error.code = 'ACTOR_UNAVAILABLE'; throw error;
  }
  const snapshot = await new GitHubRemediationClient().snapshot({ installation_id: job.installation_id, repository_full_name: job.repository_full_name,
    actor_login: job.creator_login, pr_number: job.pr_number, head_sha: job.head_sha, base_sha: job.base_sha,
    manifest_digest: remediationDb.hash({ job_id: job.id, head_sha: job.head_sha }), action_id: job.id, idempotency_key: `snapshot:${job.id}`,
    // The adapter selects these first and refuses the snapshot if any is missing, so the
    // finding files are never crowded out of a large repository's bounded snapshot.
    finding_paths: [...new Set(findingPaths.filter(Boolean))] });
  if (snapshot.head_sha !== job.head_sha || snapshot.base_sha !== job.base_sha || !Array.isArray(snapshot.files) || !Array.isArray(snapshot.tree_entries) || !snapshot.head_tree_oid) {
    const error = new Error('Immutable snapshot response is incomplete or stale'); error.code = 'SNAPSHOT_UNAVAILABLE'; throw error;
  }
  // The repair service's tree entry contract is exactly path, mode, type, sha; the adapter may
  // carry extra fields such as size that the strict model rejects.
  const treeEntries = snapshot.tree_entries.map((entry) => ({ path: entry.path, mode: entry.mode, type: entry.type, sha: entry.sha }));
  return { files: snapshot.files.map((file) => ({ path: file.path, content: file.content, sha: file.sha || sha256(file.content) })), treeEntries, headTreeOid: snapshot.head_tree_oid };
}

async function selectedFindings(job) {
  // Worker role is required because historical snapshots are not user-addressable.
  return remediationDb.scopedTransaction({ tenantId: job.installation_id, worker: true }, async (client) => {
    const rows = await client.query(`SELECT finding_id, snapshot FROM analysis_run_findings WHERE analysis_run_id=$1 AND finding_id = ANY($2::uuid[])`, [job.analysis_run_id, job.finding_snapshot_ids]);
    return rows.rows.map((row) => ({ id: row.finding_id, ...row.snapshot }));
  });
}

function buildPayload(job, snapshot, findings) {
  return { schema_version: 'v1', job_id: job.id, tenant_id: String(job.installation_id), installation_id: String(job.installation_id), repository_id: job.repository_id,
    repository_full_name: job.repository_full_name, pull_request_id: job.pull_request_id, pull_request_number: job.pr_number,
    head_sha: job.head_sha, base_sha: job.base_sha, analysis_run_id: job.analysis_run_id, stage: job.stage,
    fencing_token: job.fencing_token, attempt: Number(job.attempt_count || 0) + 1, findings, files: snapshot.files,
    tree_entries: snapshot.treeEntries, head_tree_oid: snapshot.headTreeOid,
    profile: { snapshot_coverage: { provided_paths: snapshot.files.map((file) => file.path) } }, policy: repairPolicy(job.policy_manifest), versions: { policy_version: job.policy_version },
    limits: { max_files: job.policy_manifest.max_files, max_changed_lines: job.policy_manifest.max_changed_lines, max_attempts: job.policy_manifest.max_attempts, max_tool_calls: job.policy_manifest.max_tool_calls, max_context_tokens: job.policy_manifest.max_context_tokens, max_spend_usd: job.policy_manifest.max_spend_usd } };
}

async function executeClaimedJob(job) {
  const started = process.hrtime.bigint();
  const stage = job.stage;
  // The flag is enforced here, inside the worker, before any external call.
  try {
    policy.assertGenerateEnabled();
  } catch (error) {
    await remediationDb.completeStage(job, { state: 'unsupported', stage: 'unsupported', outcome: 'flag_disabled',
      reason: { code: 'flag_disabled', capability: 'generate' } });
    metrics.stageAttempts.labels(stage, 'flag_disabled').inc();
    logger.warn('Remediation generation is disabled; job stopped before any external call', { job_id: job.id, error: error.code });
    return;
  }
  if (Number(job.revision_count) > Number(job.policy_manifest.max_revisions ?? policy.DEFAULT_POLICY.max_revisions)) {
    await remediationDb.completeStage(job, { state: 'inconclusive', stage: 'inconclusive', outcome: 'revision_budget_exhausted',
      reason: { code: 'revision_budget_exhausted', revisions: job.revision_count } });
    metrics.stageAttempts.labels(stage, 'revision_budget_exhausted').inc();
    return;
  }
  // Reserve this stage's own estimate, not the whole job ceiling.
  const reservation = await remediationDb.reserveUsage(job, stage, policy.stageEstimate(job.policy_manifest, stage));
  if (!reservation) {
    await remediationDb.completeStage(job, { state: 'inconclusive', stage, outcome: 'quota_exhausted', reason: { code: 'quota_exhausted' } });
    metrics.stageAttempts.labels(stage, 'quota_exhausted').inc(); return;
  }
  try {
    const findings = await selectedFindings(job);
    const requiredPaths = new Set(findings.map((finding) => finding.file_path).filter(Boolean));
    const snapshot = await loadSnapshot(job, [...requiredPaths]);
    if (!requiredPaths.size || ![...requiredPaths].every((path) => snapshot.files.some((file) => file.path === path))) {
      throw Object.assign(new Error('Exact source snapshot does not cover the selected findings within policy'), { code: 'SNAPSHOT_UNAVAILABLE' });
    }
    const payload = buildPayload(job, snapshot, findings);
    await remediationDb.recordAttempt(job, stage, remediationDb.hash({ head_sha: job.head_sha, files: snapshot.files.map((f) => [f.path, f.sha]), head_tree_oid: snapshot.headTreeOid }));
    const heartbeatTimer = setInterval(() => {
      remediationDb.heartbeat(job).catch(() => {}); // fencing is checked again on completion
    }, 15000);
    let result;
    try { result = await withSpan('remediation.stage', {
      stage, attempt: job.attempt_count, job_id: job.id, policy_version: job.policy_version,
    }, () => {
      const client = new RemediationServiceClient();
      return job.external_execution_id ? client.getExecution(job.external_execution_id, injectTrace()) : client.repair(payload, injectTrace());
    }); } finally { clearInterval(heartbeatTimer); }
    if (result.state === 'queued' || result.state === 'running') {
      const executionId = result.execution_id || job.external_execution_id;
      if (!executionId) throw Object.assign(new Error('Repair service running response lacks an execution ID'), { code: 'INVALID_REPAIR_RESPONSE' });
      const transition = planStageTransition(stage, result.stage);
      const maxRevisions = Number(job.policy_manifest.max_revisions ?? policy.DEFAULT_POLICY.max_revisions);
      if (transition.revision && Number(job.revision_count) + 1 > maxRevisions) {
        await remediationDb.completeStage(job, { state: 'inconclusive', stage: 'inconclusive', outcome: 'revision_budget_exhausted',
          reason: { code: 'revision_budget_exhausted', revisions: Number(job.revision_count) + 1 } });
        metrics.stageAttempts.labels(stage, 'revision_budget_exhausted').inc(); return;
      }
      await remediationDb.deferForExternalExecution(job, executionId, transition);
      metrics.stageAttempts.labels(transition.stage, 'running').inc(); return;
    }
    if (result.result) result = result.result;
    if (!REPAIR_OUTCOMES.has(result.state) || result.head_sha !== job.head_sha || result.base_sha !== job.base_sha) throw Object.assign(new Error('Repair service returned an invalid or stale response'), { code: 'INVALID_REPAIR_RESPONSE' });
    const candidates = result.candidates || [];
    if (result.state === 'ready' && (!result.manifest_digest || !candidates.length || candidates.some((candidate) => !candidate.artifact_digest || candidate.verification?.status !== 'passed'))) throw Object.assign(new Error('Repair service claimed ready without verified immutable candidates'), { code: 'INVALID_REPAIR_RESPONSE' });
    const verification = { ...(result.evidence?.verification_run || {}), status: result.state === 'ready' ? 'passed' : result.state, evidence_digest: result.evidence?.evidence_digest, context_manifest_digest: result.evidence?.context_manifest_digest,
      candidate_tree_sha: result.evidence?.verified_tree_oid || null, verification_level: result.evidence?.verification_level || null,
      limitations: Array.isArray(result.evidence?.limitations) ? result.evidence.limitations : [] };
    // Persist the walk through the declared sequence so the record shows the stages
    // the repair actually passed through, not one jump to a terminal state.
    const stagePath = result.state === 'ready' ? stagePathToEnd(stage) : [];
    // Settle before the job goes terminal: `completeStage` releases whatever is still
    // reserved, and a stage that really ran must be charged what it really cost.
    await remediationDb.settleUsage(job, reservation, remediationDb.usageCost(job, result), result.usage?.provider_request_id);
    await remediationDb.completeStage(job, { state: result.state, stage: result.state, outcome: result.state, candidates, verification, stagePath, reason: result.skipped?.length ? { code: result.reason?.code || null, skipped: result.skipped } : result.reason || null, outputDigest: remediationDb.hash(result) });
    metrics.stageAttempts.labels(stage, result.state).inc();
    metrics.stageDuration.labels(stage, result.state).observe(Number(process.hrtime.bigint() - started) / 1e9);
  } catch (error) {
    const retryable = error.response?.status >= 500 || error.code === 'ECONNABORTED' || error.code === 'ECONNREFUSED';
    // attempt_count is consumed by this completion, so compare the resulting count.
    const state = retryable && Number(job.attempt_count) + 1 < Number(job.policy_manifest.max_attempts || 3) ? 'queued' : 'inconclusive';
    await remediationDb.completeStage(job, { state, stage: state === 'queued' ? stage : 'inconclusive', outcome: error.code || 'repair_failure', reason: { code: error.code || 'repair_failure', message: 'Repair stage could not be completed safely' } });
    metrics.stageAttempts.labels(stage, state).inc();
    metrics.stageDuration.labels(stage, state).observe(Number(process.hrtime.bigint() - started) / 1e9);
  }
}

module.exports = { executeClaimedJob, buildPayload, loadSnapshot, repairPolicy, planStageTransition, canonicalStage, stagePathToEnd };
