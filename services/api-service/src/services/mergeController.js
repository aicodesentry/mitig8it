const remediationDb = require('../db/remediation');
const policy = require('./remediationPolicy');
const metrics = require('./remediationMetrics');
const logger = require('../utils/logger');
const { GitHubRemediationClient } = require('./githubRemediationClient');

// Outcomes nothing re-evaluates. A merge that happened cannot be undone by a flag.
const TERMINAL_MERGE_STATES = new Set(['merged', 'cancelled', 'expired', 'superseded']);

// Blockers that mean "not yet", not "refused". They keep the intent in its waiting
// state so the user is not told GitHub is blocking a merge that nobody asked for yet.
const PENDING_BLOCKERS = new Set([
  'waiting_for_application', 'application_verification_pending', 'verification_analysis_incomplete',
  'applied_commit_unknown',
]);

const DEFAULT_MAX_MERGE_ATTEMPTS = 3;
const DEFAULT_SWEEP_MINUTES = 5;

function maxMergeAttempts() {
  const configured = Number(process.env.REMEDIATION_MAX_MERGE_ATTEMPTS);
  return Number.isInteger(configured) && configured > 0 ? configured : DEFAULT_MAX_MERGE_ATTEMPTS;
}

function sweepStaleSeconds() {
  const configured = Number(process.env.REMEDIATION_MERGE_SWEEP_MINUTES);
  const minutes = Number.isFinite(configured) && configured > 0 ? configured : DEFAULT_SWEEP_MINUTES;
  return Math.round(minutes * 60);
}

function client(options = {}) {
  return options.githubClient || new GitHubRemediationClient();
}

function appliedCommit(intent) {
  return intent.applied_sha || intent.observed_commit_sha || null;
}

// Every adapter call carries the consented identity. head_sha is the applied commit,
// which is what the consent was rebound to when the batch was committed.
function envelope(intent, headSha) {
  return {
    installation_id: Number(intent.installation_id),
    repository_full_name: intent.repository_full_name,
    actor_login: intent.actor_login,
    pr_number: Number(intent.pr_number),
    head_sha: headSha,
    base_sha: intent.approved_base_sha,
    manifest_digest: intent.approved_manifest_digest,
    action_id: intent.action_id,
    idempotency_key: intent.idempotency_key,
  };
}

function outcome(intent, state, blockers = []) {
  return { intent_id: intent.id, state, blockers };
}

function transitionMetric(state) {
  try { metrics.actionTransitions.labels(`merge_${state}`).inc(); } catch (_) { /* metrics are never load bearing */ }
}

async function transition(intent, state, fields = {}) {
  const updated = await remediationDb.transitionMergeIntent(intent, state, fields);
  if (!updated) {
    logger.info('Merge intent transition lost the compare-and-swap', { intent_id: intent.id, state });
    return null;
  }
  transitionMetric(state);
  return updated;
}

// A refusal is recorded with its machine-readable blocker list so a later hint can
// re-evaluate exactly what was blocking.
async function refuse(intent, blockers, checks) {
  const pending = blockers.length > 0 && blockers.every((code) => PENDING_BLOCKERS.has(code));
  if (pending) {
    // "Not yet" is not "GitHub refused". A previously blocked intent whose only
    // remaining blocker is pending work returns to its waiting state.
    if (intent.state === 'blocked') {
      const moved = await transition(intent, 'waiting_for_checks', { blockers, checks });
      return outcome(intent, moved ? 'waiting_for_checks' : intent.state, blockers);
    }
    await remediationDb.recordMergeEvaluation(intent, { blockers, checks });
    return outcome(intent, intent.state, blockers);
  }
  if (intent.state === 'blocked') {
    await remediationDb.recordMergeEvaluation(intent, { blockers, checks });
    return outcome(intent, 'blocked', blockers);
  }
  const moved = await transition(intent, 'blocked', { blockers, checks });
  return outcome(intent, moved ? 'blocked' : intent.state, blockers);
}

// --- Application stage ------------------------------------------------------------

async function advanceFromApplication(intent, options) {
  const state = intent.action_state;
  if (state === 'superseded') {
    const moved = await transition(intent, 'superseded', { reason: 'application_superseded', blockers: ['application_superseded'] });
    return outcome(intent, moved ? 'superseded' : intent.state, ['application_superseded']);
  }
  if (state === 'cancelled') {
    const moved = await transition(intent, 'cancelled', { reason: 'application_cancelled', blockers: ['application_cancelled'] });
    return outcome(intent, moved ? 'cancelled' : intent.state, ['application_cancelled']);
  }
  if (['blocked', 'failed', 'rejected'].includes(state)) {
    return refuse(intent, [`application_${state}`]);
  }
  if (!['applied', 'checking', 'completed'].includes(state)) {
    return refuse(intent, ['waiting_for_application']);
  }
  const applied = appliedCommit(intent);
  if (!applied) return refuse(intent, ['applied_commit_unknown']);
  const moved = await transition(intent, 'waiting_for_checks', { appliedSha: applied, blockers: [] });
  if (!moved) return outcome(intent, intent.state, []);
  return evaluateEligibility({ ...intent, ...moved, state: 'waiting_for_checks' }, options);
}

// --- Eligibility ------------------------------------------------------------------

function capabilityBlocker() {
  if (policy.capabilities().merge) return null;
  const reason = policy.capabilityReasons().merge;
  if (reason === 'global_kill_switch_off') return 'global_kill_switch_off';
  if (reason === 'feature_flag_off') return 'merge_flag_off';
  return 'merge_dependency_not_configured';
}

async function liveActorPermission(intent, applied, options) {
  try {
    const authorization = await client(options).authorize(envelope(intent, applied));
    if (authorization?.state !== 'authorized' || authorization.actor_write_permission !== true
      || authorization.installation_active !== true || authorization.repository_granted !== true) {
      return 'actor_write_permission_missing';
    }
    return null;
  } catch (error) {
    const status = error.response?.status;
    if (status === 403 || status === 404) return 'actor_write_permission_missing';
    if (status === 409) return 'revision_changed';
    logger.error('Merge controller could not verify live actor permission', { intent_id: intent.id, error: error.message });
    return 'authorization_unavailable';
  }
}

async function evaluateEligibility(intent, options = {}) {
  const checks = {};
  const capability = capabilityBlocker();
  if (capability) return refuse(intent, [capability], { capability });
  if (intent.installation_status !== 'active' || intent.repository_active === false) {
    return refuse(intent, ['installation_or_repository_inactive']);
  }
  if (['applied', 'checking'].includes(intent.action_state)) {
    return refuse(intent, ['application_verification_pending']);
  }
  if (intent.action_state !== 'completed') return advanceFromApplication(intent, options);

  const applied = appliedCommit(intent);
  if (!applied) return refuse(intent, ['applied_commit_unknown']);

  const permission = await liveActorPermission(intent, applied, options);
  if (permission) return refuse(intent, [permission], { actor_permission: permission });
  checks.actor_permission = 'verified';

  let head;
  try {
    head = await client(options).readPullRequestHead(envelope(intent, applied));
  } catch (error) {
    logger.error('Merge controller could not read the pull request head', { intent_id: intent.id, error: error.message });
    return refuse(intent, ['pull_request_state_unavailable']);
  }
  if (head.merged) {
    const moved = await transition(intent, 'merged', {
      observedMergeSha: intent.observed_merge_sha || head.head_sha || null,
      reason: Number(intent.merge_attempts) > 0 ? null : 'merged_outside_remediation', blockers: [],
    });
    return outcome(intent, moved ? 'merged' : intent.state, []);
  }
  if (head.head_sha !== applied) {
    const moved = await transition(intent, 'superseded', { reason: 'head_changed', blockers: ['pull_request_head_changed'] });
    return outcome(intent, moved ? 'superseded' : intent.state, ['pull_request_head_changed']);
  }
  if (head.base_sha !== intent.approved_base_sha) {
    const moved = await transition(intent, 'superseded', { reason: 'base_changed', blockers: ['pull_request_base_changed'] });
    return outcome(intent, moved ? 'superseded' : intent.state, ['pull_request_base_changed']);
  }
  if (head.state !== 'open') return refuse(intent, ['pull_request_not_open'], checks);
  if (head.fork) return refuse(intent, ['fork_pull_request_unsupported'], checks);
  checks.revisions = 'matched';

  const analysis = await remediationDb.blockingFindingsForAction(intent);
  if (analysis.analysisState !== 'completed') return refuse(intent, ['verification_analysis_incomplete'], checks);
  if (Number(analysis.blocking) > 0) {
    return refuse(intent, ['blocking_findings_present'], { ...checks, blocking_findings: Number(analysis.blocking) });
  }
  checks.blocking_findings = 0;

  // An absent check is a blocker. This app publishes its own verification check and
  // reads back what it published; it never assumes a check it did not publish.
  if (intent.verification_check_head_sha !== applied || !intent.verification_check_status) {
    return refuse(intent, ['verification_check_not_published'], checks);
  }
  if (intent.verification_check_status !== 'completed' || intent.verification_check_conclusion !== 'success') {
    return refuse(intent, ['verification_check_not_successful'], checks);
  }
  checks.verification_check = 'success';

  let eligibility;
  try {
    eligibility = await client(options).readMergeEligibility({ ...envelope(intent, applied), expected_head_sha: applied });
  } catch (error) {
    logger.error('Merge controller could not read merge eligibility', { intent_id: intent.id, error: error.message });
    return refuse(intent, ['merge_eligibility_unavailable'], checks);
  }
  const eligibilityBlockers = Array.isArray(eligibility.blockers) ? eligibility.blockers : ['merge_eligibility_unknown'];
  if (eligibility.eligible !== true || eligibilityBlockers.length > 0) {
    return refuse(intent, eligibilityBlockers.length ? eligibilityBlockers : ['merge_eligibility_unknown'],
      { ...checks, protection_source: eligibility.protection_source || 'unknown' });
  }
  checks.merge_eligibility = 'eligible';
  checks.protection_source = eligibility.protection_source || 'unknown';

  let eligible = intent;
  if (intent.state !== 'eligible') {
    const moved = await transition(intent, 'eligible', { blockers: [], checks });
    if (!moved) return outcome(intent, intent.state, []);
    eligible = { ...intent, ...moved };
  } else {
    const recorded = await remediationDb.recordMergeEvaluation(intent, { blockers: [], checks });
    if (!recorded) return outcome(intent, intent.state, []);
    eligible = { ...intent, ...recorded };
  }
  return attemptMerge(eligible, applied, options);
}

// --- Guarded merge ----------------------------------------------------------------

async function attemptMerge(intent, applied, options) {
  if (Number(intent.merge_attempts) >= maxMergeAttempts()) {
    const moved = await transition(intent, 'blocked', {
      blockers: ['merge_attempts_exhausted'], reason: 'merge_attempts_exhausted',
    });
    return outcome(intent, moved ? 'blocked' : intent.state, ['merge_attempts_exhausted']);
  }
  // Intent and external operation identity are durable before the write, so an
  // ambiguous response is always reconcilable rather than blindly repeated.
  const merging = await transition(intent, 'merging', { attempt: true, operationId: intent.action_id, blockers: [] });
  if (!merging) return outcome(intent, intent.state, []);
  const current = { ...intent, ...merging };

  let result;
  try {
    result = await client(options).merge({
      ...envelope(intent, applied),
      expected_head_sha: applied,
      expected_base_sha: intent.approved_base_sha,
      merge_method: intent.merge_method || 'squash',
    });
  } catch (error) {
    const code = error.response?.data?.code || error.response?.data?.error || error.message || 'merge_rejected';
    logger.warn('Guarded remediation merge was refused', { intent_id: intent.id, error: code });
    const moved = await transition(current, 'blocked', { blockers: ['merge_rejected'], reason: String(code).slice(0, 255) });
    return outcome(intent, moved ? 'blocked' : current.state, ['merge_rejected']);
  }
  if (result?.state === 'merged' && result.commit_sha) {
    const moved = await transition(current, 'merged', { observedMergeSha: result.commit_sha, operationId: result.operation_id, blockers: [] });
    return outcome(intent, moved ? 'merged' : current.state, []);
  }
  if (result?.state === 'reconciling') {
    const moved = await transition(current, 'reconciling', { operationId: result.operation_id, reason: 'ambiguous_merge_response' });
    return outcome(intent, moved ? 'reconciling' : current.state, []);
  }
  const moved = await transition(current, 'blocked', { blockers: ['merge_not_confirmed'], reason: result?.reason || 'merge_not_confirmed' });
  return outcome(intent, moved ? 'blocked' : current.state, ['merge_not_confirmed']);
}

// An ambiguous write is settled by reading authoritative state, never by writing again.
async function settleAmbiguousMerge(intent, options = {}) {
  const applied = appliedCommit(intent);
  if (!applied) return refuse(intent, ['applied_commit_unknown']);
  let head;
  try {
    head = await client(options).readPullRequestHead(envelope(intent, applied));
  } catch (error) {
    logger.error('Merge reconciliation could not read the pull request', { intent_id: intent.id, error: error.message });
    return outcome(intent, intent.state, ['pull_request_state_unavailable']);
  }
  if (head.merged) {
    const moved = await transition(intent, 'merged', { observedMergeSha: intent.observed_merge_sha || head.head_sha || null, blockers: [] });
    return outcome(intent, moved ? 'merged' : intent.state, []);
  }
  if (head.head_sha === applied) {
    // Not merged and the consented revision is intact: the attempt is spent, the
    // intent returns to eligible and the bounded attempt counter still applies.
    const moved = await transition(intent, 'eligible', { blockers: [], reason: 'merge_not_completed' });
    return outcome(intent, moved ? 'eligible' : intent.state, []);
  }
  logger.error('Remediation merge outcome remains unresolved after reconciliation', {
    intent_id: intent.id, observed_head: head.head_sha || null, applied_sha: applied,
  });
  const moved = await transition(intent, 'blocked', { blockers: ['merge_outcome_unresolved'], reason: 'merge_outcome_unresolved' });
  return outcome(intent, moved ? 'blocked' : intent.state, ['merge_outcome_unresolved']);
}

// --- Entry points -----------------------------------------------------------------

async function evaluateIntent(intent, options = {}) {
  if (!intent) return null;
  if (TERMINAL_MERGE_STATES.has(intent.state)) return outcome(intent, intent.state, []);
  const expiresAt = intent.expires_at ? new Date(intent.expires_at).getTime() : null;
  if (intent.state !== 'merging' && expiresAt && expiresAt <= Date.now()) {
    const moved = await transition(intent, 'expired', { reason: 'expired', blockers: ['expired'] });
    return outcome(intent, moved ? 'expired' : intent.state, ['expired']);
  }
  if (intent.state === 'merging' || intent.state === 'reconciling') return settleAmbiguousMerge(intent, options);
  if (intent.state === 'waiting_for_application') return advanceFromApplication(intent, options);
  return evaluateEligibility(intent, options);
}

async function evaluateIntentById(intentId, options = {}) {
  const intent = await remediationDb.mergeIntentContext(intentId);
  if (!intent) return null;
  try {
    return await evaluateIntent(intent, options);
  } catch (error) {
    logger.error('Merge intent evaluation failed', { intent_id: intentId, error: error.message });
    return { intent_id: intentId, state: intent.state, error: error.message };
  }
}

async function evaluateForAction(actionId, options = {}) {
  const intentId = await remediationDb.mergeIntentIdForAction(actionId);
  if (!intentId) return null;
  return evaluateIntentById(intentId, options);
}

async function evaluateForPullRequest(pullRequestId, options = {}) {
  const ids = await remediationDb.listMergeIntentIdsForPullRequest(pullRequestId);
  const results = [];
  for (const id of ids) results.push(await evaluateIntentById(id, options));
  return results.filter(Boolean);
}

// The polling backup required by the merge protocol. Webhook hints are hints.
async function sweep(options = {}) {
  const ids = await remediationDb.listEvaluableMergeIntents({
    staleSeconds: options.staleSeconds || sweepStaleSeconds(), limit: options.limit || 25,
  });
  const summary = { evaluated: 0, merged: 0, blocked: 0, expired: 0 };
  for (const id of ids) {
    const result = await evaluateIntentById(id, options);
    if (!result) continue;
    summary.evaluated += 1;
    if (result.state === 'merged') summary.merged += 1;
    if (result.state === 'blocked') summary.blocked += 1;
    if (result.state === 'expired') summary.expired += 1;
  }
  return summary;
}

// --- Verification check publication -----------------------------------------------

function verifiedTreeOid(action, candidates) {
  const fromAction = action.observed_tree_oid;
  const fromCandidate = candidates[0]?.preview?.verified_tree_oid || candidates[0]?.file_manifest?.verified_tree_oid;
  const tree = fromAction || fromCandidate;
  return typeof tree === 'string' && /^[0-9a-f]{40}$/i.test(tree) ? tree : null;
}

function checkOutput(action, candidates, analysis, conclusion) {
  const tree = verifiedTreeOid(action, candidates);
  const summary = [
    `Verified tree OID: ${tree || 'unavailable'}`,
    `Batch manifest digest: ${action.batch_manifest_digest}`,
    `Candidates in batch: ${candidates.length}`,
    `Applied commit: ${action.verification_head_sha || action.observed_commit_sha || 'unknown'}`,
    `Verification analysis: ${analysis.analysisState}`,
    analysis.analysisState === 'completed'
      ? `Blocking findings on the applied head: ${Number(analysis.blocking)}`
      : 'Blocking findings on the applied head: not established',
  ].join('\n');
  const title = conclusion === 'success'
    ? `${candidates.length} verified ${candidates.length === 1 ? 'fix' : 'fixes'} applied and re-analysed`
    : (conclusion ? 'Remediation verification did not pass' : 'Remediation verification in progress');
  return { title, summary };
}

// Published when the action enters checking and again when it settles. Publication is
// idempotent by external_id and never changes the action state.
async function publishVerificationCheck(actionId, options = {}) {
  const context = await remediationDb.actionCheckContext(actionId);
  if (!context) return null;
  const { action, candidates } = context;
  const headSha = action.verification_head_sha || action.observed_commit_sha;
  if (!headSha) return { published: false, reason: 'applied_commit_unknown' };
  if (!['checking', 'completed'].includes(action.state)) return { published: false, reason: 'action_not_verifiable' };

  const analysis = await remediationDb.blockingFindingsForAction(action);
  let status = 'in_progress';
  let conclusion = null;
  if (action.state === 'completed') {
    status = 'completed';
    conclusion = analysis.analysisState === 'completed' && Number(analysis.blocking) === 0 ? 'success' : 'failure';
  } else if (['failed', 'cancelled', 'missing'].includes(analysis.analysisState)) {
    // The verification analysis cannot complete; reporting anything but failure would
    // let an unverified commit satisfy the protected check.
    status = 'completed';
    conclusion = 'failure';
  }
  const { title, summary } = checkOutput(action, candidates, analysis, conclusion);

  try {
    const result = await client(options).createCheckRun({
      installation_id: Number(action.installation_id),
      repository_full_name: action.repository_full_name,
      actor_login: action.actor_login,
      pr_number: Number(action.pr_number),
      head_sha: headSha,
      base_sha: action.base_sha,
      manifest_digest: action.batch_manifest_digest,
      action_id: action.id,
      idempotency_key: action.idempotency_key,
      external_id: action.id,
      status, conclusion, title, summary,
    });
    if (result?.state !== 'published') {
      logger.warn('Remediation verification check publication was not confirmed', {
        action_id: action.id, state: result?.state || 'unknown',
      });
      return { published: false, reason: result?.reason || 'not_published' };
    }
    await remediationDb.recordVerificationCheck(action, { status, conclusion, checkRunId: result.check_run_id, headSha });
    return { published: true, status, conclusion, check_run_id: result.check_run_id };
  } catch (error) {
    // A failed publication never reverts the applied state. The reconciler retries it.
    logger.error('Remediation verification check could not be published', { action_id: action.id, error: error.message });
    return { published: false, reason: 'publication_failed', error: error.message };
  }
}

async function publishPendingVerificationChecks(options = {}) {
  const ids = await remediationDb.listActionsNeedingVerificationCheck(options.limit || 25);
  let published = 0;
  for (const id of ids) {
    const result = await publishVerificationCheck(id, options);
    if (result?.published) published += 1;
  }
  return { attempted: ids.length, published };
}

// --- Cancellation ------------------------------------------------------------------

// The database transition already happened. GitHub must also stop any scheduled merge,
// and an ambiguous answer is reconciled rather than reported as cancelled.
async function cancelScheduledMerge(intent, options = {}) {
  const applied = appliedCommit(intent) || intent.approved_head_sha;
  let result;
  try {
    result = await client(options).cancelScheduledMerge({ ...envelope(intent, applied), expected_head_sha: applied });
  } catch (error) {
    logger.error('Scheduled merge cancellation failed on GitHub', { intent_id: intent.id, error: error.message });
    await remediationDb.recordMergeEvaluation(intent, {
      blockers: Array.isArray(intent.blockers) ? intent.blockers : [],
      checks: { cancellation: 'github_cancellation_failed' },
    });
    return { state: intent.state, github: { state: 'failed', reason: error.message } };
  }
  if (result?.state === 'reconciling') {
    const moved = await transition(intent, 'reconciling', { operationId: result.operation_id, reason: 'ambiguous_cancellation_response' });
    return { state: moved ? 'reconciling' : intent.state, github: result };
  }
  await remediationDb.recordMergeEvaluation(intent, {
    blockers: Array.isArray(intent.blockers) ? intent.blockers : [],
    checks: { cancellation: result?.state || 'unknown' },
  });
  return { state: intent.state, github: result || null };
}

module.exports = {
  TERMINAL_MERGE_STATES, PENDING_BLOCKERS, maxMergeAttempts, sweepStaleSeconds,
  evaluateIntent, evaluateIntentById, evaluateForAction, evaluateForPullRequest, sweep,
  settleAmbiguousMerge, attemptMerge, evaluateEligibility,
  publishVerificationCheck, publishPendingVerificationChecks, cancelScheduledMerge,
};
