const express = require('express');
const crypto = require('crypto');
const {
  createCheckRun,
  fetchFileContents,
  fetchPullRequestFiles,
  commitRemediationAction,
  mergeRemediationAction,
  postInlineComment,
  prepareRemediationAction,
  reconcileRemediationAction,
  submitPullRequestReview,
} = require('../services/githubInternalOperations');

const router = express.Router();

function ensureInternalAuth(req, res, next) {
  const expected = process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  if (!expected) {
    return res.status(500).json({ error: 'Internal secret is not configured' });
  }
  const provided = req.headers['x-internal-secret'] || '';
  const expectedBuf = Buffer.from(expected);
  const providedBuf = Buffer.from(provided);
  if (expectedBuf.length !== providedBuf.length || !crypto.timingSafeEqual(expectedBuf, providedBuf)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

function sendOperationError(res, fallbackMessage, error) {
  const status = error.statusCode || 502;
  return res.status(status).json({
    error: error.message || fallbackMessage,
    ...(error.detail ? { detail: error.detail } : {}),
  });
}

function routeOperation(operation, fallbackMessage) {
  return async (req, res) => {
    try {
      return res.json(await operation(req.body || {}));
    } catch (error) {
      return sendOperationError(res, fallbackMessage, error);
    }
  };
}

router.use(ensureInternalAuth);

router.post('/github/pulls/files', routeOperation(
  fetchPullRequestFiles,
  'Failed to fetch pull request files from GitHub'
));

router.post('/github/files/content', routeOperation(
  fetchFileContents,
  'Failed to fetch file contents from GitHub'
));

router.post('/github/reviews/submit', routeOperation(
  submitPullRequestReview,
  'Failed to submit review'
));

router.post('/github/comments/inline', routeOperation(
  postInlineComment,
  'Failed to post inline comment'
));

router.post('/github/check-runs', routeOperation(
  createCheckRun,
  'Failed to create check run'
));

// These are intentionally authenticated internal HTTP endpoints. Their payload is
// created from a persisted consent/action record by the control plane; no browser
// client can supply a patch directly to this service.
router.post('/github/remediation/snapshot', routeOperation(
  require('../services/githubInternalOperations').fetchRemediationSnapshot,
  'Failed to retrieve remediation snapshot'
));
router.post('/github/remediation/prepare', routeOperation(
  prepareRemediationAction,
  'Failed to prepare remediation action'
));

router.post('/github/remediation/commit', routeOperation(
  commitRemediationAction,
  'Failed to create remediation commit'
));

router.post('/github/remediation/reconcile', routeOperation(
  reconcileRemediationAction,
  'Failed to reconcile remediation action'
));

router.post('/github/remediation/merge', routeOperation(
  mergeRemediationAction,
  'Failed to merge remediation action'
));

router.post('/github/remediation/check-run', routeOperation(
  require('../services/githubInternalOperations').createRemediationCheckRun,
  'Failed to publish the remediation verification check run'
));

// One residual report comment per applied action, updated in place on retry.
router.post('/github/remediation/comment', routeOperation(
  require('../services/githubInternalOperations').publishRemediationComment,
  'Failed to publish the remediation report comment'
));

// Verified fix sections under the app's own inline finding comments, updated in place
// by candidate marker.
router.post('/github/remediation/finding-fixes', routeOperation(
  require('../services/githubInternalOperations').publishFindingFixSections,
  'Failed to publish the verified fix sections'
));

router.post('/github/remediation/cancel-merge', routeOperation(
  require('../services/githubInternalOperations').cancelScheduledMerge,
  'Failed to cancel the scheduled merge'
));

// Pre-flight reads. They report blockers and current revisions; they never mutate.
router.post('/github/remediation/merge-eligibility', routeOperation(
  require('../services/githubInternalOperations').readMergeEligibility,
  'Failed to read merge eligibility'
));

router.post('/github/remediation/pull-head', routeOperation(
  require('../services/githubInternalOperations').readPullRequestHead,
  'Failed to read pull request head'
));

// Live authorization pre-flight. The control plane calls this before persisting an
// apply intent; it proves current actor write permission and installation grant.
router.post('/github/remediation/authorize', routeOperation(
  require('../services/githubInternalOperations').authorizeRemediationActor,
  'Failed to authorize remediation actor'
));

module.exports = router;
