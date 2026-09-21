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

// A completed analysis re-renders the inline finding comments of its head. When a
// ready job already published its verified fixes under those comments for that same
// head, no new job is queued for it, so nothing would write the sections again. This
// republishes them. The adapter updates in place by candidate marker, so running it
// again writes the same sections rather than a second copy. Like the enqueue above it
// runs after the analysis is completed and never fails or delays it.
async function republishInlineFixesForCompletedAnalysis({ pullRequestId, headSha }) {
  if (!policy.capabilities().publish) return { republished: 0, reason: 'publish_disabled' };
  try {
    const jobs = await remediationDb.readyJobsWithPublishedInlineFixes({ pullRequestId, headSha });
    if (!jobs.length) return { republished: 0, reason: 'no_published_ready_job' };
    const inlineFixes = require('./remediationInlineFixes');
    let republished = 0;
    for (const job of jobs) {
      try {
        const result = await inlineFixes.publishInlineFixes(job.id);
        if (result?.published) {
          republished += 1;
          logger.info('Verified fixes republished after a re-analysis of the same head', {
            pull_request_id: pullRequestId, head_sha: headSha, job_id: job.id, origin: job.origin, sections: result.sections,
          });
        } else {
          logger.warn('Verified fixes were not republished after a re-analysis', {
            pull_request_id: pullRequestId, head_sha: headSha, job_id: job.id, reason: result?.reason || 'job_not_found',
          });
        }
      } catch (error) {
        logger.error('Republishing the verified fixes after a re-analysis failed', {
          pull_request_id: pullRequestId, head_sha: headSha, job_id: job.id, error: error.message,
        });
      }
    }
    return { republished, jobs: jobs.length };
  } catch (error) {
    logger.error('Ready jobs with published inline fixes could not be read', {
      pull_request_id: pullRequestId, head_sha: headSha, error: error.message,
    });
    return { republished: 0, reason: 'republish_failed', error: error.message };
  }
}

module.exports = { enqueueForCompletedAnalysis, republishInlineFixesForCompletedAnalysis };
