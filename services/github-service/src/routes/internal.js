const express = require('express');
const { ensureInternalAuth } = require('../middleware/internalAuth');
const {
  createCheckRun,
  fetchFileContents,
  fetchPullRequestFiles,
  postInlineComment,
  retireInlineComments,
  submitPullRequestReview,
} = require('../services/githubInternalOperations');

const router = express.Router();

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

// The inline comments of findings this run does not annotate, removed by fingerprint.
router.post('/github/comments/retire', routeOperation(
  retireInlineComments,
  'Failed to retire inline comments'
));

router.post('/github/check-runs', routeOperation(
  createCheckRun,
  'Failed to create check run'
));

// These are intentionally authenticated internal HTTP endpoints. None of them writes
// to a repository's code: the App holds no contents write permission. They read the
// pull request, publish comments, and publish check runs.
router.post('/github/remediation/snapshot', routeOperation(
  require('../services/githubInternalOperations').fetchRemediationSnapshot,
  'Failed to retrieve remediation snapshot'
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

module.exports = router;
