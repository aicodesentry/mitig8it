const remediationDb = require('../db/remediation');
const policy = require('./remediationPolicy');
const logger = require('../utils/logger');

// Automatic generation runs after an analysis has been published and never blocks or
// fails it: a refusal here is logged and the analysis stays completed. Which findings
// the repair service can fix is its decision, reported per finding in the job's
// skipped list; nothing here hardcodes a language or a rule family.
async function enqueueForCompletedAnalysis({ pullRequestId, analysisRunId }) {
  const capabilities = policy.capabilities();
  if (!capabilities.auto_generate) {
    return { enqueued: false, reason: capabilities.generate ? 'publish_disabled' : 'generate_disabled' };
  }
  try {
    const created = await remediationDb.createAutomaticJob({ pullRequestId, analysisRunId, policy: policy.getPolicy() });
    if (created.kind === 'ok') {
      logger.info('Automatic remediation job queued after analysis', {
        pull_request_id: pullRequestId, analysis_run_id: analysisRunId, job_id: created.job.id, findings: created.selected.length,
      });
      return { enqueued: true, job_id: created.job.id, findings: created.selected.length };
    }
    return { enqueued: false, reason: created.reason || created.kind, job_id: created.job?.id || null };
  } catch (error) {
    logger.error('Automatic remediation job could not be queued', {
      pull_request_id: pullRequestId, analysis_run_id: analysisRunId, error: error.message,
    });
    return { enqueued: false, reason: 'enqueue_failed', error: error.message };
  }
}

module.exports = { enqueueForCompletedAnalysis };
