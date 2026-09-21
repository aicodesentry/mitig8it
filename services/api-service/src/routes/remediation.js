const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const remediationDb = require('../db/remediation');
const policy = require('../services/remediationPolicy');
const { GitHubRemediationClient } = require('../services/githubRemediationClient');
const { getGithubAccessTokenForUser } = require('../services/githubUserAuth');
const mergeController = require('../services/mergeController');
const logger = require('../utils/logger');

const router = express.Router();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{40,64}$/i;
const DIGEST = /^[0-9a-f]{64}$/i;

// Live authorization: the installation must still be active, the repository still
// granted, and the actor must hold write permission on GitHub right now. A stored
// grant or a mere token presence is never accepted as authorization to write code.
async function assertLiveWriteAuthorization(job, body, actorLogin) {
  if (job.installation_status !== 'active' || job.repository_active === false) {
    return { ok: false, status: 403, code: 'installation_or_repository_inactive',
      error: 'The installation or repository is no longer active for automated remediation' };
  }
  let authorization;
  try {
    authorization = await new GitHubRemediationClient().authorize({
      installation_id: job.installation_id, repository_full_name: job.repository_full_name, actor_login: actorLogin,
      pr_number: job.pr_number, head_sha: body.head_sha, base_sha: body.base_sha,
      manifest_digest: body.manifest_digest, action_id: `authorize-${job.id}`, idempotency_key: body.idempotency_key,
    });
  } catch (error) {
    const status = error.response?.status;
    if (status === 409) return { ok: false, status: 409, code: 'revision_changed', error: 'Preview revision or manifest has changed' };
    if (status === 403 || status === 404) {
      return { ok: false, status: 403, code: 'actor_write_permission_missing',
        error: 'The actor does not currently have write permission for this repository' };
    }
    if (status === 422) return { ok: false, status: 422, code: 'unsupported_pull_request', error: 'This pull request is unsupported for automated remediation' };
    return { ok: false, status: 502, code: 'authorization_unavailable', error: 'Live authorization could not be verified' };
  }
  if (authorization?.state !== 'authorized' || authorization.actor_write_permission !== true
    || authorization.installation_active !== true || authorization.repository_granted !== true) {
    return { ok: false, status: 403, code: 'actor_write_permission_missing',
      error: 'The actor does not currently have write permission for this repository' };
  }
  if (authorization.head_sha !== body.head_sha || authorization.base_sha !== body.base_sha) {
    return { ok: false, status: 409, code: 'revision_changed', error: 'Preview revision or manifest has changed' };
  }
  // Branch policy is default-allow: an empty pattern list never blocks a branch.
  for (const [kind, branch] of [['head', authorization.head_branch], ['base', authorization.base_branch]]) {
    if (!policy.branchAllowed(branch)) {
      return { ok: false, status: 422, code: 'branch_not_allowed', error: `Automated remediation is not allowed for this ${kind} branch` };
    }
  }
  return { ok: true, authorization };
}

// The merge intent the panel polls. Blockers and the evaluation timestamp are part of
// the contract: the user must be able to see why a merge has not happened.
function mergeIntentShape(intent) {
  if (!intent) return null;
  return {
    id: intent.id, action_id: intent.action_id, state: intent.state,
    blockers: Array.isArray(intent.blockers) ? intent.blockers : [],
    expires_at: intent.expires_at, merge_attempts: Number(intent.merge_attempts || 0),
    observed_merge_sha: intent.observed_merge_sha || null, applied_sha: intent.applied_sha || null,
    last_evaluated_at: intent.last_evaluated_at || null, merge_method: intent.merge_method,
    cancellation_reason: intent.cancellation_reason || null,
    latest_policy_checks: intent.latest_policy_checks || {},
  };
}

function failureReason(job) { return job?.failure_reason?.code || job?.cancellation_reason || null; }
function statusShape(job) {
  return { id: job.id, state: job.state, stage: job.stage, head_sha: job.head_sha, base_sha: job.base_sha,
    reason: failureReason(job), attempts: job.attempt_count, revision_count: job.revision_count, created_at: job.created_at, updated_at: job.updated_at };
}

router.get('/pull-requests/:pullRequestId/remediations', authenticateToken, async (req, res, next) => {
  try {
    if (!UUID.test(req.params.pullRequestId)) return res.status(400).json({ error: 'Invalid pull request ID' });
    const latest = await remediationDb.getLatestForPullRequest(req.params.pullRequestId, req.user.user_id);
    if (!latest) return res.status(404).json({ error: 'Pull request not found' });
    return res.json({ job: latest.job ? statusShape(latest.job) : null, action: latest.action ? { id: latest.action.id, state: latest.action.state, reason: latest.action.failure_reason?.code || null, rejection_reason: latest.action.failure_reason?.code || null, commit_sha: latest.action.observed_commit_sha, merge_state: latest.action.merge_state || null } : null, merge_intent: mergeIntentShape(latest.mergeIntent), capabilities: policy.capabilityReport() });
  } catch (error) { return next(error); }
});

router.post('/pull-requests/:pullRequestId/remediations', authenticateToken, async (req, res, next) => {
  try {
    if (!UUID.test(req.params.pullRequestId)) return res.status(400).json({ error: 'Invalid pull request ID' });
    if (req.body?.finding_ids && (!Array.isArray(req.body.finding_ids) || req.body.finding_ids.some((id) => !UUID.test(id)))) return res.status(400).json({ error: 'finding_ids must be UUIDs' });
    policy.assertGenerationEnabled();
    const created = await remediationDb.createJob({ pullRequestId: req.params.pullRequestId, userId: req.user.user_id, findingIds: req.body?.finding_ids, policy: policy.getPolicy() });
    if (created.kind === 'not_found') return res.status(404).json({ error: 'Pull request not found or repository is inactive' });
    if (created.kind === 'unsupported') return res.status(422).json({ error: 'Remediation request is unsupported', code: created.reason });
    return res.status(202).json({ job: statusShape(created.job), accepted: true, replay: !created.created });
  } catch (error) { return next(error); }
});

router.get('/remediations/:id', authenticateToken, async (req, res, next) => {
  try {
    if (!UUID.test(req.params.id)) return res.status(400).json({ error: 'Invalid remediation ID' });
    const job = await remediationDb.getJobForUser(req.params.id, req.user.user_id);
    if (!job) return res.status(404).json({ error: 'Remediation not found' });
    return res.json({ job: statusShape(job), capabilities: policy.capabilityReport() });
  } catch (error) { return next(error); }
});

// A candidate is applicable, applied by an earlier action, or stale because the head
// moved. The preview never hides a stale candidate: it is shown greyed with its reason.
function candidateStatus(candidate) {
  const code = candidate.rejection_reason?.code;
  if (!code) return { status: 'applicable', stale_reason: null, applied_commit_sha: null };
  if (code === 'applied') return { status: 'applied', stale_reason: null, applied_commit_sha: candidate.rejection_reason.commit_sha || null };
  return { status: 'stale', stale_reason: code, applied_commit_sha: null };
}

function candidatePaths(candidate) {
  const files = Array.isArray(candidate.file_manifest?.files) ? candidate.file_manifest.files
    : Array.isArray(candidate.preview?.changes) ? candidate.preview.changes : [];
  return [...new Set(files.map((f) => f?.path).filter(Boolean))];
}

// The preview is readable while the job is ready and after it was superseded by an
// application commit, so remaining candidates can be shown as stale rather than vanish.
const PREVIEWABLE_STATES = new Set(['ready', 'superseded']);

router.get('/remediations/:id/preview', authenticateToken, async (req, res, next) => {
  try {
    if (!UUID.test(req.params.id)) return res.status(400).json({ error: 'Invalid remediation ID' });
    const preview = await remediationDb.getPreview(req.params.id, req.user.user_id);
    if (!preview) return res.status(404).json({ error: 'Remediation not found' });
    if (!PREVIEWABLE_STATES.has(preview.job.state)) return res.status(409).json({ error: 'Immutable preview is not ready', state: preview.job.state });
    const applicable = preview.job.state === 'ready';
    const candidates = preview.candidates.map((candidate) => ({
      id: candidate.id, finding_ids: candidate.finding_snapshot_ids, changes: candidate.preview?.changes || [candidate.file_manifest],
      paths: candidatePaths(candidate), rationale: candidate.preview?.rationale || null,
      evidence: candidate.preview?.evidence || { artifact_digest: candidate.artifact_digest, context_manifest_digest: candidate.context_manifest_digest },
      verification_level: candidate.verification_level,
      // Consent for this one candidate alone: the digest the apply request must carry.
      manifest_digest: remediationDb.manifestDigestFor(preview.job, [candidate]),
      ...candidateStatus(candidate),
    }));
    const selectable = preview.candidates.filter((candidate) => !candidate.rejection_reason);
    // Per-file groups. A group of more than one candidate is only applicable as a unit
    // when it is the whole verified batch; otherwise the fixes are applied one at a time.
    const files = [...new Set(candidates.flatMap((c) => c.paths))].map((path) => {
      const ids = candidates.filter((c) => c.paths.includes(path) && c.status === 'applicable').map((c) => c.id);
      const rows = selectable.filter((c) => ids.includes(c.id));
      const batch = ids.length === selectable.length && selectable.length > 0;
      return { path, candidate_ids: ids, verified_together: ids.length <= 1 || batch,
        manifest_digest: (ids.length <= 1 || batch) ? remediationDb.manifestDigestFor(preview.job, rows) : null };
    });
    return res.json({ job_id: preview.job.id, job_state: preview.job.state, applicable, head_sha: preview.job.head_sha, base_sha: preview.job.base_sha,
      manifest_digest: applicable ? remediationDb.manifestDigestFor(preview.job, selectable) : null,
      verified_tree_oid: preview.verification?.candidate_tree_sha || null,
      candidates, files, findings: preview.findings || [],
      skipped: preview.job.failure_reason?.skipped || [], verification: preview.verification, capabilities: policy.capabilityReport() });
  } catch (error) { return next(error); }
});

// Read-only repair evidence: the agent trace, the token usage and cost, the budget
// settlements, the per-group coverage and the verification check outcomes the job
// produced. Same authorization as the preview. Unlike the preview it is readable in any
// state, because the evidence of a job that repaired nothing is exactly what an operator
// needs to see, and nothing here can be applied.
router.get('/remediations/:id/evidence', authenticateToken, async (req, res, next) => {
  try {
    if (!UUID.test(req.params.id)) return res.status(400).json({ error: 'Invalid remediation ID' });
    const evidence = await remediationDb.getEvidenceForUser(req.params.id, req.user.user_id);
    if (!evidence) return res.status(404).json({ error: 'Remediation not found' });
    const byKind = Object.fromEntries(evidence.records.map((row) => [row.kind, row.payload]));
    return res.json({
      job_id: evidence.job.id, job_state: evidence.job.state, stage: evidence.job.stage,
      head_sha: evidence.job.head_sha, base_sha: evidence.job.base_sha,
      attempts: Number(evidence.job.attempt_count || 0), reason: failureReason(evidence.job),
      agent_trace: byKind.agent_trace || null, usage: byKind.usage || null,
      budget_reservation: byKind.budget_reservation || null, groups: byKind.groups || null,
      verification: byKind.verification || null, candidates: byKind.candidate_evidence || null,
      records: evidence.records.map((row) => ({ attempt: Number(row.attempt), kind: row.kind, recorded_at: row.created_at })),
    });
  } catch (error) { return next(error); }
});

router.post('/remediations/:id/apply', authenticateToken, async (req, res, next) => {
  try {
    const body = req.body || {};
    if (!UUID.test(req.params.id) || !SHA.test(body.head_sha || '') || !SHA.test(body.base_sha || '') || !DIGEST.test(body.manifest_digest || '') || !Array.isArray(body.candidate_ids) || body.candidate_ids.some((id) => !UUID.test(id)) || typeof body.idempotency_key !== 'string' || body.idempotency_key.length < 8 || body.idempotency_key.length > 255 || typeof body.merge_when_ready !== 'boolean') return res.status(400).json({ error: 'Invalid immutable apply request' });
    policy.assertApplyEnabled();
    // Merging is a human action on GitHub. The product never asks for a merge; the
    // operator-only experimental flag is the only thing that lets this field through.
    if (body.merge_when_ready) {
      if (!policy.getPolicy().merge_enabled) {
        return res.status(400).json({ error: 'Automatic merge is not part of applying fixes. Merging stays a human action on GitHub.', code: 'merge_not_available' });
      }
      policy.assertMergeEnabled();
    }
    const job = await remediationDb.getJobForUser(req.params.id, req.user.user_id);
    if (!job) return res.status(404).json({ error: 'Remediation not found' });
    // The consented subset and its digest are checked before any GitHub call, so a
    // digest computed over a different subset never reaches live authorization.
    const consented = await remediationDb.getPreview(job.id, req.user.user_id);
    if (!consented || consented.job.state !== 'ready') return res.status(409).json({ error: 'Remediation is not ready', code: 'job_not_ready' });
    const selection = remediationDb.selectCandidates(consented.job, consented.candidates, body.candidate_ids);
    if (selection.kind === 'invalid_candidates') return res.status(422).json({ error: 'Candidate selection does not match the immutable verified batch', code: 'invalid_candidates' });
    if (selection.kind === 'candidate_stale') return res.status(409).json({ error: 'A selected fix is stale: the pull request head moved since it was verified. Regenerate remaining fixes.', code: 'candidate_stale' });
    if (selection.kind === 'subset_not_verified') {
      await remediationDb.recordApplyDenial(req.user.user_id, job, 'subset_not_verified', { candidate_ids: body.candidate_ids });
      return res.status(422).json({ error: 'This combination of fixes was not verified together. Apply one fix at a time, or apply all verified fixes as the batch that was verified.', code: 'subset_not_verified' });
    }
    if (body.manifest_digest !== selection.manifestDigest) {
      await remediationDb.recordApplyDenial(req.user.user_id, job, 'manifest_mismatch', { candidate_ids: body.candidate_ids });
      return res.status(409).json({ error: 'The manifest digest does not match the selected fixes', code: 'manifest_mismatch' });
    }
    // Token presence is a live user-consent prerequisite; the token is never passed onward.
    const githubIdentity = await getGithubAccessTokenForUser(req.user.user_id);
    const actorLogin = githubIdentity.githubUsername || req.user.github_username || 'unknown';

    const budget = await remediationDb.budgetSnapshot(job.installation_id, job.policy_manifest?.max_spend_usd ?? policy.DEFAULT_POLICY.max_spend_usd);
    if (budget.available <= 0) {
      await remediationDb.recordApplyDenial(req.user.user_id, job, 'budget_exhausted', { reserved: budget.reserved, ceiling: budget.ceiling });
      return res.status(429).json({ error: 'The remediation budget for this installation is exhausted', code: 'budget_exhausted' });
    }

    const authorized = await assertLiveWriteAuthorization(job, body, actorLogin);
    if (!authorized.ok) {
      await remediationDb.recordApplyDenial(req.user.user_id, job, authorized.code, { actor_login: actorLogin });
      logger.warn('Remediation apply denied', { job_id: job.id, actor_login: actorLogin, code: authorized.code });
      return res.status(authorized.status).json({ error: authorized.error, code: authorized.code });
    }

    const unpermitted = selection.candidates.filter((candidate) => !policy.verificationLevelPermitted(candidate.verification_level));
    if (unpermitted.length) {
      await remediationDb.recordApplyDenial(req.user.user_id, job, 'verification_level_not_permitted', { levels: unpermitted.map((c) => c.verification_level) });
      return res.status(422).json({ error: 'Selected fixes were not verified in an isolated sandbox', code: 'verification_level_not_permitted' });
    }
    const created = await remediationDb.createAction(job, req.user.user_id, body, actorLogin);
    if (created.kind === 'not_ready') return res.status(409).json({ error: 'Remediation is not ready', code: 'job_not_ready' });
    if (created.kind === 'stale') return res.status(409).json({ error: 'Preview revision or manifest has changed', code: 'revision_changed' });
    if (created.kind === 'manifest_mismatch') return res.status(409).json({ error: 'The manifest digest does not match the selected fixes', code: 'manifest_mismatch' });
    if (created.kind === 'candidate_stale') return res.status(409).json({ error: 'A selected fix is stale: the pull request head moved since it was verified. Regenerate remaining fixes.', code: 'candidate_stale' });
    if (created.kind === 'subset_not_verified') return res.status(422).json({ error: 'This combination of fixes was not verified together. Apply one fix at a time, or apply all verified fixes as the batch that was verified.', code: 'subset_not_verified' });
    if (created.kind === 'invalid_candidates') return res.status(422).json({ error: 'Candidate selection does not match the immutable verified batch', code: 'invalid_candidates' });
    if (created.kind === 'conflict') return res.status(409).json({ error: 'Idempotency key was already used with a different request' });
    if (created.kind === 'writer_busy') return res.status(409).json({ error: 'Another remediation write is already in progress for this pull request', code: 'writer_lease_held' });
    return res.status(202).json({ action: { id: created.action.id, state: created.action.state }, replay: Boolean(created.replay) });
  } catch (error) {
    if (error.code === 'GITHUB_NOT_CONNECTED' || error.code?.startsWith('GITHUB_REFRESH')) return res.status(403).json({ error: 'A current GitHub account connection is required to apply code' });
    return next(error);
  }
});

router.post('/remediations/:id/cancel', authenticateToken, async (req, res, next) => {
  try {
    if (!UUID.test(req.params.id)) return res.status(400).json({ error: 'Invalid remediation ID' });
    const cancelled = await remediationDb.cancelJob(req.params.id, req.user.user_id);
    if (!cancelled) return res.status(409).json({ error: 'Remediation cannot be cancelled in its current state' });
    return res.status(202).json({ job: statusShape(cancelled) });
  } catch (error) { return next(error); }
});

router.get('/remediation-actions/:id', authenticateToken, async (req, res, next) => {
  try {
    if (!UUID.test(req.params.id)) return res.status(400).json({ error: 'Invalid action ID' });
    const result = await remediationDb.getActionForUser(req.params.id, req.user.user_id);
    if (!result) return res.status(404).json({ error: 'Remediation action not found' });
    return res.json({ action: result.action, merge_intent: mergeIntentShape(result.mergeIntent), capabilities: policy.capabilityReport() });
  } catch (error) { return next(error); }
});

// Cancellation is allowed for the actor who created the intent and for anyone who
// currently holds write permission. Revoking a pending write is never harder than
// requesting it was.
async function mayCancelMerge(req, action, intent) {
  if (intent.actor_id === req.user.user_id) return { ok: true, actorLogin: action.actor_login };
  let actorLogin;
  try {
    const identity = await getGithubAccessTokenForUser(req.user.user_id);
    actorLogin = identity.githubUsername || req.user.github_username;
  } catch (_) {
    return { ok: false, status: 403, error: 'A current GitHub account connection is required to cancel this merge' };
  }
  if (!actorLogin) return { ok: false, status: 403, error: 'The actor could not be identified for this repository' };
  try {
    const authorization = await new GitHubRemediationClient().authorize({
      installation_id: action.installation_id, repository_full_name: action.repository_full_name,
      actor_login: actorLogin, pr_number: action.pr_number,
      head_sha: intent.applied_sha || intent.approved_head_sha, base_sha: intent.approved_base_sha,
      manifest_digest: intent.approved_manifest_digest, action_id: `authorize-${action.id}`,
      idempotency_key: action.idempotency_key,
    });
    if (authorization?.state !== 'authorized' || authorization.actor_write_permission !== true) {
      return { ok: false, status: 403, error: 'The actor does not currently have write permission for this repository' };
    }
  } catch (_) {
    return { ok: false, status: 403, error: 'The actor does not currently have write permission for this repository' };
  }
  return { ok: true, actorLogin };
}

router.post('/remediation-actions/:id/cancel-merge', authenticateToken, async (req, res, next) => {
  try {
    if (!UUID.test(req.params.id)) return res.status(400).json({ error: 'Invalid action ID' });
    const existing = await remediationDb.getActionForUser(req.params.id, req.user.user_id);
    if (!existing) return res.status(404).json({ error: 'Remediation action not found' });
    if (!existing.mergeIntent) return res.status(409).json({ error: 'Merge intent is not cancellable' });
    const permitted = await mayCancelMerge(req, existing.action, existing.mergeIntent);
    if (!permitted.ok) return res.status(permitted.status).json({ error: permitted.error });

    const intent = await remediationDb.cancelMerge(req.params.id, req.user.user_id);
    if (!intent) return res.status(409).json({ error: 'Merge intent is not cancellable' });

    // Cancelling the intent must also withdraw any GitHub-side scheduled merge. An
    // ambiguous answer becomes reconciling and is settled by the merge controller.
    let settled = { state: intent.state, github: null };
    try {
      const context = await remediationDb.mergeIntentContext(intent.id);
      if (context) settled = await mergeController.cancelScheduledMerge(context);
    } catch (error) {
      logger.error('Scheduled merge cancellation could not be completed on GitHub', {
        action_id: req.params.id, error: error.message,
      });
      settled = { state: intent.state, github: { state: 'failed', reason: error.message } };
    }
    const current = await remediationDb.getActionForUser(req.params.id, req.user.user_id);
    return res.status(202).json({
      merge_intent: mergeIntentShape(current?.mergeIntent || intent),
      state: current?.mergeIntent?.state || settled.state,
      github_cancellation: settled.github || null,
    });
  } catch (error) { return next(error); }
});

const FEEDBACK_OUTCOMES = new Set(['accepted', 'edited', 'rejected']);

// Feedback is an observation about a specific immutable candidate. It is stored with
// its provenance and an expiry; promotion to an approved example requires human
// review and never happens here.
router.post('/remediations/:id/feedback', authenticateToken, async (req, res, next) => {
  try {
    const body = req.body || {};
    if (!UUID.test(req.params.id)) return res.status(400).json({ error: 'Invalid remediation ID' });
    if (!UUID.test(body.candidate_id || '')) return res.status(400).json({ error: 'candidate_id must be a UUID' });
    if (!FEEDBACK_OUTCOMES.has(body.outcome)) return res.status(400).json({ error: 'outcome must be accepted, edited or rejected' });
    if (body.reason != null && (typeof body.reason !== 'string' || body.reason.length > 2000)) {
      return res.status(400).json({ error: 'reason must be a string of at most 2000 characters' });
    }
    const found = await remediationDb.getCandidateForFeedback(req.params.id, body.candidate_id, req.user.user_id);
    if (!found) return res.status(404).json({ error: 'Remediation not found' });
    if (!found.candidate) return res.status(404).json({ error: 'Candidate does not belong to this remediation' });
    await remediationDb.recordRepairMemoryObservation({
      job: found.job, candidate: found.candidate, userId: req.user.user_id,
      outcome: body.outcome, reason: body.reason || null, expiryDays: policy.repairMemoryExpiryDays(),
    });
    return res.status(204).send();
  } catch (error) { return next(error); }
});

module.exports = router;
