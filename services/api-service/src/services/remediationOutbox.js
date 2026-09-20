const { pool } = require('../config/database');
const remediationDb = require('../db/remediation');
const logger = require('../utils/logger');

const DEFAULT_MAX_ATTEMPTS = 5;

function maxAttempts() {
  const configured = Number(process.env.REMEDIATION_OUTBOX_MAX_ATTEMPTS);
  return Number.isInteger(configured) && configured > 0 ? configured : DEFAULT_MAX_ATTEMPTS;
}

async function claimPendingOutbox(limit = 20) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN'); await client.query("SELECT set_config('app.remediation_worker', '1', true)");
    const result = await client.query(`WITH pending AS (SELECT id FROM workflow_outbox WHERE status='pending' AND next_attempt_at<=NOW() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $1) UPDATE workflow_outbox o SET status='dispatching',attempts=attempts+1,updated_at=NOW() FROM pending WHERE o.id=pending.id RETURNING o.*`, [limit]);
    await client.query('COMMIT'); return result.rows;
  } catch (e) { try { await client.query('ROLLBACK'); } catch (_) { /* ignored */ } throw e; } finally { client.release(); }
}

async function writeOutboxState(id, { status, error, deadLetterReason }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN'); await client.query("SELECT set_config('app.remediation_worker', '1', true)");
    await client.query(
      `UPDATE workflow_outbox SET status=$2,
         delivered_at=CASE WHEN $2='delivered' THEN NOW() ELSE delivered_at END,
         next_attempt_at=CASE WHEN $2='pending' THEN NOW() + (LEAST(attempts, 8) * INTERVAL '15 seconds') ELSE next_attempt_at END,
         last_error=$3, dead_letter_reason=$4, updated_at=NOW()
       WHERE id=$1`,
      [id, status, error || null, deadLetterReason || null]
    );
    await client.query('COMMIT');
  } catch (e) { try { await client.query('ROLLBACK'); } catch (_) { /* ignored */ } throw e; } finally { client.release(); }
}

// Delivery is recorded only after a handler returned success.
async function markDelivered(id) { return writeOutboxState(id, { status: 'delivered' }); }

// A failure backs off; an exhausted event is quarantined with a machine-readable reason
// so an operator can replay it deliberately.
async function markFailed(id, attempts, error) {
  if (Number(attempts) >= maxAttempts()) {
    return writeOutboxState(id, { status: 'dead_letter', error, deadLetterReason: 'max_dispatch_attempts_exceeded' });
  }
  return writeOutboxState(id, { status: 'pending', error });
}

// --- In-process handler registry -------------------------------------------------
// An event is handed to the handler registered for its type. The handlers claim the
// same rows with the same compare-and-swap the polling workers use, so an event and
// the polling backup can never execute one job or action twice.

const handlers = new Map();

function registerHandler(eventType, handler) {
  if (typeof handler !== 'function') throw new Error(`Handler for ${eventType} must be a function`);
  handlers.set(eventType, handler);
}

function resolveHandler(eventType) { return handlers.get(eventType) || null; }

function registerDefaultHandlers({ executeClaimedJob, executeClaimedAction, workerId }) {
  const runJob = async (event) => {
    const job = await remediationDb.claimJobById(event.aggregate_id, workerId);
    // Not claimable means another holder owns the lease or the row is not due yet.
    // The polling backup remains responsible; the event itself is handled.
    if (!job) return { status: 'skipped', reason: 'not_claimable' };
    await executeClaimedJob(job);
    return { status: 'executed' };
  };
  const runAction = async (event) => {
    const action = await remediationDb.claimActionById(event.aggregate_id);
    if (!action) return { status: 'skipped', reason: 'not_claimable' };
    await executeClaimedAction(action);
    return { status: 'executed' };
  };
  // Terminal job states have no follow-up work in this release. Recording delivery is
  // honest: the event reached its handler, which had nothing to execute.
  const terminal = async () => ({ status: 'terminal' });

  for (const stage of ['queued', 'snapshotting', 'retrieving', 'planning', 'generating', 'verifying']) {
    registerHandler(`remediation.${stage}`, runJob);
  }
  for (const state of ['ready', 'cancelled', 'superseded', 'unsupported', 'inconclusive', 'failed', 'dead_letter']) {
    registerHandler(`remediation.${state}`, terminal);
  }
  registerHandler('remediation.action.requested', runAction);
  registerHandler('remediation.action.reconciling', runAction);

  // Merge hints are observations recorded by the webhook route. Dispatching one
  // evaluates the pull request's intents once; the reconciler sweep stays the backup.
  const mergeController = require('./mergeController');
  registerHandler('remediation.merge.reevaluate', async (event) => {
    const evaluated = await mergeController.evaluateForPullRequest(event.aggregate_id);
    return { status: 'executed', evaluated: evaluated.length };
  });
  // A completed application is the moment its merge intent becomes evaluable.
  registerHandler('remediation.action.completed', async (event) => {
    await mergeController.publishVerificationCheck(event.aggregate_id);
    // The residual report is posted once the fresh analysis finished; a failure here is
    // retried by the reconciler and never blocks the merge evaluation.
    try { await require('./remediationResidualReport').publishResidualComment(event.aggregate_id); } catch (error) {
      logger.error('Residual report publication failed from the outbox', { action_id: event.aggregate_id, error: error.message });
    }
    await mergeController.evaluateForAction(event.aggregate_id);
    return { status: 'executed' };
  });
}

async function dispatchInProcess(event) {
  const handler = resolveHandler(event.event_type);
  if (!handler) {
    const error = new Error(`No remediation outbox handler is registered for ${event.event_type}`);
    error.code = 'UNROUTABLE_EVENT';
    throw error;
  }
  return handler(event);
}

// cloud_tasks is a deployment mode this release does not implement. It fails loudly
// rather than pretending an event was enqueued.
function cloudTasksDispatcher() {
  const modulePath = process.env.REMEDIATION_DISPATCHER_MODULE;
  if (!modulePath) {
    const error = new Error('REMEDIATION_DISPATCH_MODE=cloud_tasks requires REMEDIATION_DISPATCHER_MODULE; Cloud Tasks dispatch is not implemented in this service');
    error.code = 'DISPATCH_MODE_NOT_IMPLEMENTED';
    throw error;
  }
  const provided = require(modulePath);
  const dispatch = provided?.dispatch || provided;
  if (typeof dispatch !== 'function') {
    const error = new Error(`REMEDIATION_DISPATCHER_MODULE ${modulePath} does not export a dispatch function`);
    error.code = 'DISPATCH_MODE_NOT_IMPLEMENTED';
    throw error;
  }
  return dispatch;
}

function createDispatcher(mode = process.env.REMEDIATION_DISPATCH_MODE || 'inprocess') {
  if (mode === 'inprocess') return dispatchInProcess;
  if (mode === 'cloud_tasks') return cloudTasksDispatcher();
  const error = new Error(`Unsupported REMEDIATION_DISPATCH_MODE ${mode}`);
  error.code = 'DISPATCH_MODE_UNSUPPORTED';
  throw error;
}

async function processPending({ limit = 20, dispatcher } = {}) {
  const dispatch = dispatcher || createDispatcher();
  const events = await claimPendingOutbox(limit);
  const summary = { claimed: events.length, delivered: 0, failed: 0, deadLettered: 0 };
  for (const event of events) {
    try {
      const outcome = await dispatch(event);
      if (outcome && outcome.status === 'failed') throw new Error(outcome.reason || 'dispatch_failed');
      await markDelivered(event.id);
      summary.delivered += 1;
    } catch (error) {
      const exhausted = Number(event.attempts) >= maxAttempts();
      await markFailed(event.id, event.attempts, error.message);
      summary.failed += 1;
      if (exhausted) summary.deadLettered += 1;
      logger.error('Remediation outbox dispatch failed', {
        outbox_id: event.id, event_type: event.event_type, attempts: event.attempts,
        dead_lettered: exhausted, error: error.message,
      });
    }
  }
  return summary;
}

module.exports = {
  claimPendingOutbox, markDelivered, markFailed, processPending,
  registerHandler, registerDefaultHandlers, resolveHandler, createDispatcher, dispatchInProcess, maxAttempts,
};
