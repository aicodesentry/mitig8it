const path = require('path');
// Only the standalone worker process loads the service .env. When the API starts the loop
// in-process, src/index.js has already resolved the environment and re-reading it here
// would override what the API resolved.
if (require.main === module) {
  require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });
}
const { pool } = require('../config/database');
const remediationDb = require('../db/remediation');
const outbox = require('../services/remediationOutbox');
const { executeClaimedJob } = require('../services/remediationWorkflow');
const { startReconciler } = require('../services/remediationReconciler');
const logger = require('../utils/logger');

const DEFAULT_POLL_MS = 5000;
const MIN_POLL_MS = 1000;

function resolveWorkerId() {
  return process.env.REMEDIATION_WORKER_ID || `remediation-${process.pid}`;
}

function pollIntervalMs() {
  return Math.max(Number(process.env.REMEDIATION_WORKER_POLL_MS || DEFAULT_POLL_MS), MIN_POLL_MS);
}

async function tick(dispatcher, workerId, stopped) {
  await outbox.processPending({ limit: 20, dispatcher });
  while (!stopped()) {
    const job = await remediationDb.claimNextJob(workerId);
    if (!job) break;
    await executeClaimedJob(job);
  }
}

// Starts the remediation control-plane loop and returns a stop function. The standalone
// worker process and the in-process API worker share this one implementation, so a
// single-instance deployment runs exactly the code the dedicated Deployment runs.
function startRemediationWorker(options = {}) {
  const workerId = options.workerId || resolveWorkerId();
  const interval = Number.isFinite(options.intervalMs) ? options.intervalMs : pollIntervalMs();
  let stopping = false;
  const stopped = () => stopping;

  // Dispatch hands each event to the registered in-process handler. The handler claims
  // the aggregate with the same compare-and-swap the polling loops below use, so an
  // event and the polling backup can never execute the same work twice.
  outbox.registerDefaultHandlers({ executeClaimedJob, workerId });
  // Resolved once at startup so an unimplemented dispatch mode fails loudly here
  // instead of silently dropping events later.
  const dispatcher = outbox.createDispatcher();
  const stopReconciler = startReconciler(options.reconciler || {});

  let timer = null;
  const schedule = (delay) => {
    timer = setTimeout(loop, delay);
    if (typeof timer.unref === 'function') timer.unref();
  };
  const loop = async () => {
    timer = null;
    if (stopping) return;
    try {
      await tick(dispatcher, workerId, stopped);
    } catch (error) {
      logger.error('Remediation worker tick failed', { error: error.message });
    }
    if (!stopping) schedule(interval);
  };
  schedule(0);

  return function stopRemediationWorker() {
    stopping = true;
    if (timer) clearTimeout(timer);
    timer = null;
    stopReconciler();
  };
}

function assertWorkerEnabled() {
  if (process.env.REMEDIATION_WORKER_ENABLED !== 'true') {
    throw new Error('Refusing to start remediation worker without REMEDIATION_WORKER_ENABLED=true');
  }
}

module.exports = { startRemediationWorker, assertWorkerEnabled, resolveWorkerId, pollIntervalMs };

if (require.main === module) {
  let stop = null;
  for (const signal of ['SIGTERM', 'SIGINT']) {
    process.on(signal, () => {
      if (stop) stop();
      pool.end().finally(() => process.exit(0));
    });
  }
  try {
    assertWorkerEnabled();
    stop = startRemediationWorker();
  } catch (error) {
    logger.error('Remediation worker failed to start', { error: error.message });
    process.exit(1);
  }
}
