const remediationDb = require('../db/remediation');
const policy = require('./remediationPolicy');
const logger = require('../utils/logger');

// Automatic generation runs after an analysis has been published and never blocks or
// fails it: a refusal here is logged and the analysis stays completed. Which rule family
// the repair service can fix is its decision, reported per finding in the job's skipped
// list; nothing here hardcodes a family. The one thing the selection does decide is
// language, because a file no toolchain can check cannot be snapshotted either, so taking
// one into the job used to lose the supported findings of the same pull request with it.
async function enqueueForCompletedAnalysis({ pullRequestId, analysisRunId }) {
  const capabilities = policy.capabilities();
  if (!capabilities.auto_generate) {
    return { enqueued: false, reason: capabilities.generate ? 'publish_disabled' : 'generate_disabled' };
  }
  try {
    const created = await remediationDb.createAutomaticJob({ pullRequestId, analysisRunId, policy: policy.getPolicy() });
    const skipped = created.skipped?.length || 0;
    if (created.kind === 'ok') {
      logger.info('Automatic remediation job queued after analysis', {
        pull_request_id: pullRequestId, analysis_run_id: analysisRunId, job_id: created.job.id, findings: created.selected.length,
        skipped_unsupported_language: skipped,
      });
      return { enqueued: true, job_id: created.job.id, findings: created.selected.length, skipped };
    }
    // `skipped` is reported only where it carries something: on a queued job, and on the
    // refusal that is entirely about skipped findings. Every other refusal (an existing
    // job for this head, an exhausted budget, no completed analysis) has no skip list to
    // report, so it keeps the shape it has always had rather than a constant zero.
    if (created.reason === 'no_supported_findings') {
      logger.info('No automatic remediation job queued after analysis: every open finding is in a language no repair toolchain can check', {
        pull_request_id: pullRequestId, analysis_run_id: analysisRunId, skipped_unsupported_language: skipped,
      });
      return { enqueued: false, reason: created.reason, job_id: null, skipped };
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
