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

// --- Durable repair evidence -------------------------------------------------------
// The repair service executes on a backend whose own record does not outlive the
// instance that ran it, so minutes after a job finished the agent trace, the check
// outcomes, the token usage, the cost and the budget settlements were unrecoverable and
// the control plane held nothing but the candidate preview. Everything below is copied
// out of the repair response at completion time and persisted with the job.
//
// What is copied is deliberately narrow. A trace entry keeps the tool, its place in the
// sequence, its outcome, its reason code and the size of its result; file contents,
// patch text, tool arguments and model prose are never persisted. A check keeps only the
// end of its output, bounded, because that is what explains a failure.
const MAX_TRACE_ENTRIES = 200;
const MAX_OUTPUT_TAIL_BYTES = 2048;
const MAX_CHECKS = 50;
const MAX_SETTLEMENTS = 50;
const MAX_GROUPS = 100;
const MAX_SKIPPED = 200;
const MAX_CODE_CHARS = 200;
const MAX_MESSAGE_CHARS = 500;
const MAX_IDS = 100;

function text(value, limit) {
  return typeof value === 'string' ? value.slice(0, limit) : null;
}

// A tail keeps the END of the output: the failure is at the bottom, not the top.
function tail(value, limit = MAX_OUTPUT_TAIL_BYTES) {
  if (typeof value !== 'string') return null;
  const bytes = Buffer.from(value, 'utf8');
  return bytes.length <= limit ? value : bytes.subarray(bytes.length - limit).toString('utf8');
}

function number(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function ids(value, limit = MAX_IDS) {
  return (Array.isArray(value) ? value : []).slice(0, limit).map((id) => text(String(id), MAX_CODE_CHARS)).filter(Boolean);
}

function bounded(value, limit, map) {
  const items = Array.isArray(value) ? value : [];
  return { total: items.length, truncated: items.length > limit, items: items.slice(0, limit).map(map) };
}

function reasonShape(reason) {
  if (!reason || typeof reason !== 'object') return null;
  return { code: text(reason.code, MAX_CODE_CHARS), message: text(reason.message, MAX_MESSAGE_CHARS) };
}

function traceEntry(entry) {
  const source = entry && typeof entry === 'object' ? entry : {};
  return { sequence: number(source.sequence), tool: text(source.tool, MAX_CODE_CHARS),
    outcome: text(source.outcome, MAX_CODE_CHARS), reason: text(source.reason, MAX_CODE_CHARS),
    result_bytes: number(source.result_bytes) };
}

function checkSide(side) {
  const source = side && typeof side === 'object' ? side : {};
  return { completed: source.completed === true, status: text(source.status, MAX_CODE_CHARS),
    exit_code: number(source.exit_code), duration_ms: number(source.duration_ms),
    output_truncated: source.output_truncated === true || (typeof source.output_tail === 'string' && Buffer.byteLength(source.output_tail) > MAX_OUTPUT_TAIL_BYTES),
    output_tail: tail(source.output_tail) };
}

function checkRecord(check) {
  const source = check && typeof check === 'object' ? check : {};
  return { check_id: text(source.check_id, MAX_CODE_CHARS), kind: text(source.kind, MAX_CODE_CHARS),
    finding_id: text(source.finding_id, MAX_CODE_CHARS),
    baseline: checkSide(source.baseline), candidate: checkSide(source.candidate) };
}

function groupRecord(group) {
  const source = group && typeof group === 'object' ? group : {};
  return { group_index: number(source.group_index), state: text(source.state, MAX_CODE_CHARS),
    reason: reasonShape(source.reason), language: text(source.language, MAX_CODE_CHARS),
    finding_ids: ids(source.finding_ids), repaired_finding_ids: ids(source.repaired_finding_ids),
    candidate_ids: ids(source.candidate_ids),
    coverage: source.coverage && typeof source.coverage === 'object' ? {
      revisions_used: number(source.coverage.revisions_used), max_revisions: number(source.coverage.max_revisions),
      proven_finding_ids: ids(source.coverage.proven_finding_ids), stopped: text(source.coverage.stopped, MAX_CODE_CHARS),
    } : null,
    unproven_findings: bounded(source.unproven_findings, MAX_SKIPPED,
      (item) => ({ finding_id: text(item?.finding_id, MAX_CODE_CHARS), ...reasonShape(item) })).items };
}

function settlementRecord(settlement) {
  const source = settlement && typeof settlement === 'object' ? settlement : {};
  return { call_index: number(source.call_index), reserved_tokens: number(source.reserved_tokens),
    reserved_usd: number(source.reserved_usd), actual_tokens: number(source.actual_tokens),
    actual_usd: number(source.actual_usd), overage_tokens: number(source.overage_tokens),
    overage_usd: number(source.overage_usd) };
}

// The response carries the combined verification run under `verification_run` when it is
// ready and under `verification` when it is not; both are the same evidence shape.
function verificationEvidence(evidence) {
  return evidence?.verification_run || evidence?.verification || null;
}

function buildEvidenceRecords(result, { cost = null } = {}) {
  const evidence = result?.evidence && typeof result.evidence === 'object' ? result.evidence : {};
  const records = [];

  const trace = bounded(evidence.agent_trace, MAX_TRACE_ENTRIES, traceEntry);
  if (trace.total) records.push({ kind: 'agent_trace', payload: trace });

  const usage = evidence.usage && typeof evidence.usage === 'object' ? evidence.usage : null;
  if (usage || cost !== null) {
    records.push({ kind: 'usage', payload: { input_tokens: number(usage?.input_tokens) ?? 0,
      output_tokens: number(usage?.output_tokens) ?? 0, cost_usd: cost === null ? null : number(cost),
      provider_request_ids: ids(usage?.provider_request_ids, MAX_SETTLEMENTS) } });
  }

  const reservation = evidence.budget_reservation;
  if (reservation && typeof reservation === 'object') {
    records.push({ kind: 'budget_reservation', payload: { settled_calls: number(reservation.settled_calls),
      overage_calls: number(reservation.overage_calls), overage_tokens: number(reservation.overage_tokens),
      overage_usd: number(reservation.overage_usd),
      settlements: bounded(reservation.settlements, MAX_SETTLEMENTS, settlementRecord) } });
  }

  const skipped = bounded(result?.skipped, MAX_SKIPPED,
    (item) => ({ finding_id: text(item?.finding_id, MAX_CODE_CHARS), ...reasonShape(item) }));
  const groups = bounded(evidence.groups, MAX_GROUPS, groupRecord);
  if (groups.total || skipped.total) records.push({ kind: 'groups', payload: { groups, skipped } });

  const run = verificationEvidence(evidence);
  if (run && typeof run === 'object') {
    records.push({ kind: 'verification', payload: { outcome: text(run.outcome, MAX_CODE_CHARS),
      reason_code: text(run.reason_code, MAX_CODE_CHARS),
      verification_level: text(run.verification_level || evidence.verification_level, MAX_CODE_CHARS),
      verified_tree_oid: text(run.verified_tree_oid || evidence.verified_tree_oid, MAX_CODE_CHARS),
      evidence_digest: text(evidence.evidence_digest, MAX_CODE_CHARS),
      checks: bounded(run.checks, MAX_CHECKS, checkRecord),
      coverage_gaps: bounded(run.coverage_gaps, MAX_CHECKS, (gap) => (typeof gap === 'string' ? text(gap, MAX_MESSAGE_CHARS) : reasonShape(gap))),
      limitations: bounded(evidence.limitations, MAX_CHECKS, (item) => text(String(item), MAX_MESSAGE_CHARS)) } });
  }

  // Each candidate's own `preview.evidence`: the per-candidate verification level, its
  // limitations and the one-sentence summary of each piece of evidence it rests on.
  const candidates = bounded(result?.candidates, MAX_GROUPS, (candidate) => ({
    artifact_digest: text(candidate?.artifact_digest, MAX_CODE_CHARS),
    finding_ids: ids(candidate?.finding_ids),
    evidence: candidate?.preview?.evidence && typeof candidate.preview.evidence === 'object' ? {
      status: text(candidate.preview.evidence.status, MAX_CODE_CHARS),
      verification_level: text(candidate.preview.evidence.verification_level, MAX_CODE_CHARS),
      evidence_digest: text(candidate.preview.evidence.evidence_digest, MAX_CODE_CHARS),
      verified_tree_oid: text(candidate.preview.evidence.verified_tree_oid, MAX_CODE_CHARS),
      summary: bounded(candidate.preview.evidence.summary, MAX_CHECKS, (line) => text(String(line), MAX_MESSAGE_CHARS)),
      limitations: bounded(candidate.preview.evidence.limitations, MAX_CHECKS, (line) => text(String(line), MAX_MESSAGE_CHARS)),
    } : null,
  }));
  if (candidates.total) records.push({ kind: 'candidate_evidence', payload: candidates });

  return records;
}

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

// A transient failure is one the next attempt can reasonably survive: the repair
// service or the GitHub adapter answering 5xx, Cloud Run aborting a request while an
// instance is still starting (429 "no available instance" or 503), or a dropped
// connection. A definite rejection (400, 401, 403, 404, 409, 422) is never retried.
const TRANSIENT_STATUSES = new Set([429, 502, 503, 504]);
const TRANSIENT_CODES = new Set(['ECONNABORTED', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN']);
function isTransientRepairFailure(error) {
  const status = Number(error?.response?.status || error?.status || 0);
  if (status >= 500 || TRANSIENT_STATUSES.has(status)) return true;
  return TRANSIENT_CODES.has(String(error?.code || ''));
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
    const cost = remediationDb.usageCost(job, result);
    await remediationDb.settleUsage(job, reservation, cost, result.usage?.provider_request_id);
    await remediationDb.completeStage(job, { state: result.state, stage: result.state, outcome: result.state, candidates, verification, stagePath, reason: result.skipped?.length ? { code: result.reason?.code || null, skipped: result.skipped } : result.reason || null, outputDigest: remediationDb.hash(result),
      // The execution backend's own record is gone within minutes; this is the only
      // durable account of what the repair did and why it ended as it did.
      evidence: buildEvidenceRecords(result, { cost }) });
    metrics.stageAttempts.labels(stage, result.state).inc();
    metrics.stageDuration.labels(stage, result.state).observe(Number(process.hrtime.bigint() - started) / 1e9);
  } catch (error) {
    const retryable = isTransientRepairFailure(error);
    // attempt_count is consumed by this completion, so compare the resulting count.
    const state = retryable && Number(job.attempt_count) + 1 < Number(job.policy_manifest.max_attempts || 3) ? 'queued' : 'inconclusive';
    await remediationDb.completeStage(job, { state, stage: state === 'queued' ? stage : 'inconclusive', outcome: error.code || 'repair_failure', reason: { code: error.code || 'repair_failure', message: 'Repair stage could not be completed safely' } });
    metrics.stageAttempts.labels(stage, state).inc();
    metrics.stageDuration.labels(stage, state).observe(Number(process.hrtime.bigint() - started) / 1e9);
  }
}

module.exports = { executeClaimedJob, isTransientRepairFailure, buildPayload, loadSnapshot, repairPolicy, planStageTransition, canonicalStage, stagePathToEnd,
  buildEvidenceRecords, MAX_TRACE_ENTRIES, MAX_OUTPUT_TAIL_BYTES };
