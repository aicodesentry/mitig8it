const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const findingsDb = require('../db/findings');
const findingOutcomes = require('../db/findingOutcomes');

const router = express.Router();

router.get('/pull-requests/:pullRequestId/findings', authenticateToken, async (req, res) => {
  const { pullRequestId } = req.params;
  const { status = 'open', min_confidence = 0 } = req.query;

  const findings = await findingsDb.listByPullRequest(pullRequestId, req.user.user_id, {
    status,
    minConfidence: min_confidence,
  });
  const pullRequest = await findingsDb.getPullRequestForUser(pullRequestId, req.user.user_id);

  res.json({
    findings,
    pull_request: pullRequest
      ? { id: pullRequest.id, number: pullRequest.pr_number, head_sha: pullRequest.head_sha, base_sha: pullRequest.base_sha }
      : null,
  });
});

router.get('/findings', authenticateToken, async (req, res) => {
  const { repository_id, status = 'open', severity, category } = req.query;

  const findings = await findingsDb.listAll(req.user.user_id, {
    repositoryId: repository_id,
    status,
    severity,
    category,
  });

  res.json({ findings });
});

router.get('/findings/:id', authenticateToken, async (req, res) => {
  const finding = await findingsDb.getById(req.params.id, req.user.user_id);

  if (!finding) {
    return res.status(404).json({ error: 'Finding not found' });
  }

  res.json({ finding });
});

router.patch('/findings/:id/status', authenticateToken, async (req, res) => {
  const { status, dismissal_reason } = req.body;
  const allowed = ['open', 'dismissed', 'accepted_risk', 'fixed'];

  if (!allowed.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  // A dismissal is only useful to the learning loop when its reason is one of the four
  // the log understands. Legacy phrasings such as 'false_positive' are mapped, an
  // unrecognised reason is refused, and an omitted one is recorded as 'other'.
  let dismissalReason = null;
  if (status === 'dismissed') {
    const given = dismissal_reason == null || dismissal_reason === '' ? 'other' : dismissal_reason;
    dismissalReason = findingOutcomes.normalizeDismissalReason(given, null);
    if (!dismissalReason) {
      return res.status(400).json({
        error: 'Invalid dismissal_reason',
        allowed: findingOutcomes.DISMISSAL_REASONS,
      });
    }
  }

  const finding = await findingsDb.updateStatus(req.params.id, req.user.user_id, {
    status,
    dismissalReason,
  });

  if (!finding) {
    return res.status(404).json({ error: 'Finding not found' });
  }

  res.json({ finding });
});

module.exports = router;
