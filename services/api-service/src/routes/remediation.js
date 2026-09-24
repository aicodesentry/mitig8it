const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const remediationDb = require('../db/remediation');
const policy = require('../services/remediationPolicy');

const router = express.Router();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
    return res.json({ job: latest.job ? statusShape(latest.job) : null, action: latest.action ? { id: latest.action.id, state: latest.action.state, reason: latest.action.failure_reason?.code || null, rejection_reason: latest.action.failure_reason?.code || null, commit_sha: latest.action.observed_commit_sha } : null, capabilities: policy.capabilityReport() });
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

// Applying a fix in the app is gone. The Mitig8it GitHub App holds no write access to
// repository contents, so it cannot create a commit on a pull request branch. Every
// verified fix is published as a GitHub suggestion block under the finding comment, and
// GitHub's own "Commit suggestion" button applies it as a commit under the developer's
// identity. The route stays so an old client gets an explanation rather than a 404.
router.post('/remediations/:id/apply', authenticateToken, async (req, res) => res.status(410).json({
  error: 'Mitig8it no longer applies fixes. The App has no write access to your code. '
    + 'Open the finding comment on the pull request and use GitHub\'s "Commit suggestion" button, '
    + 'which commits the fix under your own identity.',
  code: 'apply_removed',
}));

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
    return res.json({ action: result.action, capabilities: policy.capabilityReport() });
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
