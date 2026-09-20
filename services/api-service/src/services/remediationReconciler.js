const remediationDb = require('../db/remediation');
const { GitHubRemediationClient } = require('./githubRemediationClient');
const mergeController = require('./mergeController');
const residualReport = require('./remediationResidualReport');

const metrics = require('./remediationMetrics');
const logger = require('../utils/logger');

const DEFAULT_INTERVAL_MS = 60000;

function intervalMs() {
  const configured = Number(process.env.REMEDIATION_RECONCILE_INTERVAL_MS);
  return Number.isFinite(configured) && configured >= 1000 ? configured : DEFAULT_INTERVAL_MS;
}

// Every step is bounded and independent. One failing row or step never stops the rest.
async function step(name, fn, summary) {
  try {
    summary[name] = await fn();
  } catch (error) {
    summary[name] = { error: error.message };
    logger.error('Remediation reconciliation step failed', { step: name, error: error.message });
  }
  return summary;
}

async function reclaimLeases(limit) {
  const reclaimed = await remediationDb.reclaimExpiredLeases(limit);
  if (reclaimed.length) {
    metrics.leaseReclaims.inc(reclaimed.length);
    logger.warn('Reclaimed expired remediation job leases', { count: reclaimed.length });
  }
  return { reclaimed: reclaimed.length };
}

async function redispatchOutbox(stuckSeconds, limit) {
  const reset = await remediationDb.redispatchStuckOutbox(stuckSeconds, limit);
  if (reset.length) logger.warn('Re-dispatched stuck remediation outbox rows', { count: reset.length });
  return { redispatched: reset.length };
}

// An ambiguous GitHub write is settled by reading authoritative history, never by
// writing again. An unresolved outcome stays blocked and is reported at error level.
async function reconcileActions(staleSeconds, limit) {
  const actions = await remediationDb.listStaleReconcilingActions(staleSeconds, limit);
  const counts = { applied: 0, not_applied: 0, unresolved: 0, errors: 0 };
  for (const action of actions) {
    try {
      const { job, candidates, combinedTreeOid } = await remediationDb.actionMaterial(action);
      const tree = require('./remediationActionWorker').verifiedTreeOid(candidates, combinedTreeOid);
      if (!job || !tree) {
        counts.unresolved += 1;
        await remediationDb.updateAction(action, 'blocked', { reason: { code: 'verified_tree_oid_unavailable' } });
        logger.error('Remediation reconciliation has no verified tree to compare', { action_id: action.id });
        continue;
      }
      const result = await new GitHubRemediationClient().reconcile({
        installation_id: job.installation_id, repository_full_name: job.repository_full_name, actor_login: action.actor_login,
        pr_number: job.pr_number, head_sha: action.head_sha, base_sha: action.base_sha,
        manifest_digest: action.batch_manifest_digest, action_id: action.id, idempotency_key: action.idempotency_key,
        verified_tree_oid: tree,
      });
      if (result.state === 'applied') {
        counts.applied += 1;
        await remediationDb.updateAction(action, 'applied', { operationId: result.operation_id, commitSha: result.commit_sha, treeOid: result.tree_oid || tree });
        metrics.actionTransitions.labels('applied').inc();
      } else if (result.state === 'not_applied') {
        counts.not_applied += 1;
        await remediationDb.updateAction(action, 'failed', { operationId: result.operation_id, reason: { code: 'not_applied' } });
        metrics.actionTransitions.labels('failed').inc();
      } else {
        counts.unresolved += 1;
        await remediationDb.updateAction(action, 'blocked', { operationId: result.operation_id, reason: { code: 'unresolved', detail: result.reason || null } });
        metrics.actionTransitions.labels('blocked').inc();
        logger.error('Remediation write remains unresolved after reconciliation', { action_id: action.id, reason: result.reason || null });
      }
    } catch (error) {
      counts.errors += 1;
      logger.error('Remediation action reconciliation failed', { action_id: action.id, error: error.message });
    }
  }
  return counts;
}

async function completeVerifiedActions(limit) {
  const rows = await remediationDb.listActionsAwaitingVerification(limit);
  let completed = 0;
  for (const row of rows) {
    try {
      if (await remediationDb.completeAction(row.id, { headSha: row.verification_head_sha })) {
        completed += 1;
        metrics.actionTransitions.labels('completed').inc();
        // Publishing the verification check and evaluating the intent are follow-up
        // work. Neither failure reverts the completed action.
        try { await mergeController.publishVerificationCheck(row.id); } catch (error) {
          logger.error('Verification check publication failed after completion', { action_id: row.id, error: error.message });
        }
        try { await residualReport.publishResidualComment(row.id); } catch (error) {
          logger.error('Residual report publication failed after completion', { action_id: row.id, error: error.message });
        }
        try { await mergeController.evaluateForAction(row.id); } catch (error) {
          logger.error('Merge evaluation failed after completion', { action_id: row.id, error: error.message });
        }
      }
    } catch (error) {
      logger.error('Remediation action completion failed', { action_id: row.id, error: error.message });
    }
  }
  return { completed };
}

// The polling backup for merge decisions and for check publications that a transient
// GitHub failure left unpublished.
async function sweepMergeIntents(options) {
  return mergeController.sweep(options);
}

async function publishVerificationChecks(limit) {
  return mergeController.publishPendingVerificationChecks({ limit });
}

// Residual report comments that a transient GitHub failure left unpublished.
async function publishResidualComments(limit) {
  return residualReport.publishPendingResidualComments({ limit });
}

async function quarantineJobs(limit) {
  const quarantined = await remediationDb.quarantineExhaustedJobs(limit);
  if (quarantined.length) logger.error('Quarantined remediation jobs into dead_letter', { count: quarantined.length });
  return { quarantined: quarantined.length };
}

// Reservations held by jobs that have already ended can never be spent. Releasing them is
// what returns that budget to the installation.
async function releaseStrandedUsage(limit) {
  const released = await remediationDb.releaseStrandedReservations(limit);
  if (released.length) {
    metrics.usageReleases.labels('reconciler_stranded').inc(released.length);
    logger.warn('Released stranded remediation spend reservations', {
      count: released.length,
      amount: released.reduce((total, row) => total + Number(row.reserved_amount), 0),
    });
  }
  return { released: released.length };
}

async function expireIntents(limit) {
  const expired = await remediationDb.expireMergeIntents(limit);
  if (expired.length) logger.info('Expired remediation merge intents', { count: expired.length });
  return { expired: expired.length };
}

async function runReconciliation(options = {}) {
  const { leaseLimit = 50, outboxStuckSeconds = 300, outboxLimit = 100, actionStaleSeconds = 300, actionLimit = 20,
    jobLimit = 50, intentLimit = 100, mergeSweepLimit = 25, mergeSweepStaleSeconds = null, usageLimit = 200 } = options;
  const summary = {};
  await step('leases', () => reclaimLeases(leaseLimit), summary);
  await step('outbox', () => redispatchOutbox(outboxStuckSeconds, outboxLimit), summary);
  await step('actions', () => reconcileActions(actionStaleSeconds, actionLimit), summary);
  await step('verification', () => completeVerifiedActions(actionLimit), summary);
  await step('jobs', () => quarantineJobs(jobLimit), summary);
  await step('merge_intents', () => expireIntents(intentLimit), summary);
  await step('usage', () => releaseStrandedUsage(usageLimit), summary);
  await step('verification_checks', () => publishVerificationChecks(actionLimit), summary);
  await step('residual_comments', () => publishResidualComments(actionLimit), summary);
  await step('merge_controller', () => sweepMergeIntents({
    limit: mergeSweepLimit,
    ...(mergeSweepStaleSeconds == null ? {} : { staleSeconds: mergeSweepStaleSeconds }),
  }), summary);
  return summary;
}

function startReconciler(options = {}) {
  const period = options.intervalMs || intervalMs();
  let stopped = false;
  const loop = async () => {
    if (stopped) return;
    try { await runReconciliation(options); } catch (error) {
      logger.error('Remediation reconciliation failed', { error: error.message });
    }
    if (!stopped) timer = setTimeout(loop, period);
  };
  let timer = setTimeout(loop, period);
  if (typeof timer.unref === 'function') timer.unref();
  return () => { stopped = true; clearTimeout(timer); };
}

module.exports = {
  runReconciliation, startReconciler, intervalMs, reconcileActions, completeVerifiedActions, releaseStrandedUsage,
  sweepMergeIntents, publishVerificationChecks, publishResidualComments,
};
