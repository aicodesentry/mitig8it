const remediationDb = require('../db/remediation');
const logger = require('../utils/logger');
const { GitHubRemediationClient } = require('./githubRemediationClient');

function client(options = {}) {
  return options.githubClient || new GitHubRemediationClient();
}

function verifiedTreeOid(action, candidates) {
  const fromAction = action.observed_tree_oid;
  const fromCandidate = candidates[0]?.preview?.verified_tree_oid || candidates[0]?.file_manifest?.verified_tree_oid;
  const tree = fromAction || fromCandidate;
  return typeof tree === 'string' && /^[0-9a-f]{40}$/i.test(tree) ? tree : null;
}

function checkOutput(action, candidates, analysis, conclusion, report = null) {
  const tree = verifiedTreeOid(action, candidates);
  const summary = [
    `Verified tree OID: ${tree || 'unavailable'}`,
    `Batch manifest digest: ${action.batch_manifest_digest}`,
    `Candidates in batch: ${candidates.length}`,
    `Applied commit: ${action.verification_head_sha || action.observed_commit_sha || 'unknown'}`,
    `Verification analysis: ${analysis.analysisState}`,
    // Every open finding of any severity in the pull request's changed files blocks;
    // informational findings in test code are listed but never fail the check.
    analysis.analysisState === 'completed'
      ? `Open findings on the applied head (any severity, excluding informational test-code findings): ${Number(analysis.blocking)}`
      : 'Open findings on the applied head: not established',
    ...(report ? ['', report] : []),
  ].join('\n');
  const title = conclusion === 'success'
    ? `${candidates.length} verified ${candidates.length === 1 ? 'fix' : 'fixes'} applied; no open findings remain`
    : (conclusion ? 'Remediation verification did not pass: findings remain open' : 'Remediation verification in progress');
  return { title, summary };
}

// Published when the action enters checking and again when it settles. Publication is
// idempotent by external_id and never changes the action state. The action it reports
// on is observed, not performed: the App has no write access to repository contents,
// so the commit it names was pushed by a developer from GitHub's own suggestion UI.
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
  // The check carries the same residual report as the pull request comment once the
  // fresh analysis completed; a failed report never blocks the check itself.
  let report = null;
  if (analysis.analysisState === 'completed') {
    try {
      const { applied, unsupported } = await remediationDb.appliedReportForAction(action);
      report = require('./remediationResidualReport').buildReport({ action, analysis, applied, unsupported });
    } catch (error) {
      logger.warn('Residual report could not be built for the verification check', { action_id: action.id, error: error.message });
    }
  }
  const { title, summary } = checkOutput(action, candidates, analysis, conclusion, report);

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
    // A failed publication never reverts the observed state. The reconciler retries it.
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

module.exports = { verifiedTreeOid, checkOutput, publishVerificationCheck, publishPendingVerificationChecks };
