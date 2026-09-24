const remediationDb = require('../db/remediation');
const verificationCheck = require('./remediationVerificationCheck');
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

async function completeVerifiedActions(limit) {
  const rows = await remediationDb.listActionsAwaitingVerification(limit);
  let completed = 0;
  for (const row of rows) {
    try {
      if (await remediationDb.completeAction(row.id, { headSha: row.verification_head_sha })) {
        completed += 1;
        metrics.actionTransitions.labels('completed').inc();
        // Publishing the verification check and the residual report is follow-up work.
        // Neither failure reverts the completed action.
        try { await verificationCheck.publishVerificationCheck(row.id); } catch (error) {
          logger.error('Verification check publication failed after completion', { action_id: row.id, error: error.message });
        }
        try { await residualReport.publishResidualComment(row.id); } catch (error) {
          logger.error('Residual report publication failed after completion', { action_id: row.id, error: error.message });
        }
      }
    } catch (error) {
      logger.error('Remediation action completion failed', { action_id: row.id, error: error.message });
    }
  }
  return { completed };
}

async function publishVerificationChecks(limit) {
  return verificationCheck.publishPendingVerificationChecks({ limit });
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

async function runReconciliation(options = {}) {
  const { leaseLimit = 50, outboxStuckSeconds = 300, outboxLimit = 100, actionLimit = 20,
    jobLimit = 50, usageLimit = 200 } = options;
  const summary = {};
  await step('leases', () => reclaimLeases(leaseLimit), summary);
  await step('outbox', () => redispatchOutbox(outboxStuckSeconds, outboxLimit), summary);
  await step('verification', () => completeVerifiedActions(actionLimit), summary);
  await step('jobs', () => quarantineJobs(jobLimit), summary);
  await step('usage', () => releaseStrandedUsage(usageLimit), summary);
  await step('verification_checks', () => publishVerificationChecks(actionLimit), summary);
  await step('residual_comments', () => publishResidualComments(actionLimit), summary);
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
  runReconciliation, startReconciler, intervalMs, completeVerifiedActions, releaseStrandedUsage,
  publishVerificationChecks, publishResidualComments,
};
