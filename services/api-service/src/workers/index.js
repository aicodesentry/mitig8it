const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });
const { pool } = require('../config/database');
const remediationDb = require('../db/remediation');
const outbox = require('../services/remediationOutbox');
const { executeClaimedJob } = require('../services/remediationWorkflow');
const { executeClaimedAction } = require('../services/remediationActionWorker');
const { startReconciler } = require('../services/remediationReconciler');
const logger = require('../utils/logger');

const workerId = process.env.REMEDIATION_WORKER_ID || `remediation-${process.pid}`;
let stopping = false;

// Dispatch hands each event to the registered in-process handler. The handler claims
// the aggregate with the same compare-and-swap the polling loops below use, so an
// event and the polling backup can never execute the same work twice.
outbox.registerDefaultHandlers({ executeClaimedJob, executeClaimedAction, workerId });

async function tick(dispatcher) {
  await outbox.processPending({ limit: 20, dispatcher });
  while (!stopping) {
    const job = await remediationDb.claimNextJob(workerId);
    if (!job) break;
    await executeClaimedJob(job);
  }
  while (!stopping) {
    const action = await remediationDb.claimNextAction(workerId);
    if (!action) break;
    await executeClaimedAction(action);
  }
}

async function run() {
  if (process.env.REMEDIATION_WORKER_ENABLED !== 'true') throw new Error('Refusing to start remediation worker without REMEDIATION_WORKER_ENABLED=true');
  // Resolved once at startup so an unimplemented dispatch mode fails loudly here
  // instead of silently dropping events later.
  const dispatcher = outbox.createDispatcher();
  const interval = Math.max(Number(process.env.REMEDIATION_WORKER_POLL_MS || 5000), 1000);
  startReconciler();
  const loop = async () => { if (!stopping) { try { await tick(dispatcher); } catch (error) { logger.error('Remediation worker tick failed', { error: error.message }); } setTimeout(loop, interval); } };
  loop();
}
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { stopping = true; pool.end().finally(() => process.exit(0)); });
run().catch((error) => { logger.error('Remediation worker failed to start', { error: error.message }); process.exit(1); });
