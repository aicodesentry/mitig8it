const express = require('express');
const { transaction } = require('../config/database');
const { verifyWebhookSignature } = require('../services/githubApp');
const { notifyAnalysisQueued } = require('../services/prAnalysisOrchestrator');
const logger = require('../utils/logger');
const installationsDb = require('../db/installations');
const remediationDb = require('../db/remediation');

const router = express.Router();

// Events that only hint that a merge decision may need re-evaluation. They record an
// append-only observation; a merge controller consumes it later. Nothing here decides.
const MERGE_HINT_EVENTS = new Set(['check_run', 'check_suite', 'status', 'pull_request_review']);

function mergeHintReference(event, payload) {
  const repositoryGithubId = payload.repository?.id || null;
  if (!repositoryGithubId) return null;
  if (event === 'pull_request_review') {
    return { repositoryGithubId, prNumber: payload.pull_request?.number ?? null, headSha: payload.pull_request?.head?.sha || null };
  }
  if (event === 'status') return { repositoryGithubId, headSha: payload.sha || null };
  const container = event === 'check_run' ? payload.check_run : payload.check_suite;
  const linked = Array.isArray(container?.pull_requests) ? container.pull_requests[0] : null;
  return { repositoryGithubId, prNumber: linked?.number ?? null, headSha: container?.head_sha || null };
}

function getBodyBuffer(req) {
  if (Buffer.isBuffer(req.body)) return req.body;
  return Buffer.from(JSON.stringify(req.body || {}));
}

router.post('/github', async (req, res) => {
  const signature = req.headers['x-hub-signature-256'];
  const event = req.headers['x-github-event'];
  const deliveryId = req.headers['x-github-delivery'];
  const correlationId = req.correlationId;
  let analysisPayload = null;

  if (!event || !deliveryId) {
    return res.status(400).json({ error: 'Missing webhook headers' });
  }

  const rawBody = getBodyBuffer(req);
  if (!verifyWebhookSignature(rawBody, signature)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  let payload;
  try { payload = JSON.parse(rawBody.toString('utf8')); } catch (_) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  try {
    const deduplicated = await transaction(async (client) => {
      // The row lock is held until both the job and processed marker commit.
      // A failed transaction rolls back the claim, making redelivery retryable.
      const claim = await client.query(
        `INSERT INTO webhook_deliveries (delivery_id, event_type, action, processing_status, received_at)
         VALUES ($1, $2, $3, 'received', NOW())
         ON CONFLICT (delivery_id) DO UPDATE
           SET processing_status = 'received', error_message = NULL, received_at = NOW()
         WHERE webhook_deliveries.processing_status IN ('failed', 'received')
         RETURNING delivery_id`,
        [deliveryId, event, payload.action || null]
      );
      if (claim.rowCount === 0) return true;

      if (event === 'installation' && payload.installation) {
        await installationsDb.upsertInstallation(
          client,
          payload.installation,
          payload.action === 'deleted' ? 'deleted' : payload.action === 'suspend' ? 'suspended' : 'active'
        );
      }

      if (event === 'installation_repositories' && payload.installation?.id) {
        const removedIds = (payload.repositories_removed || []).map((repo) => repo.id);
        if (removedIds.length) {
          await client.query(`DELETE FROM repository_access ra USING repositories r
            WHERE ra.repository_id = r.id AND r.installation_id = $1 AND r.github_id = ANY($2::bigint[])`,
          [payload.installation.id, removedIds]);
        }
      }

      if (event === 'installation_repositories' && payload.installation?.id && payload.repositories_added) {
        for (const repo of payload.repositories_added) {
          const repoResult = await client.query(
            `INSERT INTO repositories
              (github_id, installation_id, name, full_name, private, default_branch, language, html_url, clone_url, is_active, owner_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, NULL)
             ON CONFLICT (github_id)
             DO UPDATE SET
               installation_id = EXCLUDED.installation_id,
               name = EXCLUDED.name,
               full_name = EXCLUDED.full_name,
               private = EXCLUDED.private,
               default_branch = EXCLUDED.default_branch,
               language = EXCLUDED.language,
               html_url = EXCLUDED.html_url,
               clone_url = EXCLUDED.clone_url,
               updated_at = NOW()
             RETURNING id`,
            [
              repo.id,
              payload.installation.id,
              repo.name,
              repo.full_name,
              repo.private,
              repo.default_branch || 'main',
              repo.language,
              repo.html_url,
              repo.clone_url,
            ]
          );
          await client.query(`UPDATE repositories SET profile_status = CASE WHEN profile_status = 'profiling' THEN profile_status ELSE 'queued' END, profile_queued_at = COALESCE(profile_queued_at, NOW()) WHERE id = $1`, [repoResult.rows[0].id]);
        }
      }

      if (event === 'pull_request' && ['closed'].includes(payload.action)) {
        const repository = payload.repository;
        const pr = payload.pull_request;
        const newState = pr.merged ? 'merged' : 'closed';
        const mergedAt = pr.merged_at || null;

        await client.query(
          `UPDATE pull_requests SET state = $1, merged_at = $2, updated_at = NOW()
           WHERE repository_id = (SELECT id FROM repositories WHERE github_id = $3)
             AND pr_number = $4`,
          [newState, mergedAt, repository.id, pr.number]
        );

        // Mark profile stale if security-relevant files were changed in a merged PR
        if (pr.merged) {
          const { shouldRetriggerProfile } = require('../services/profileWorker');
          const changedFiles = (pr.changed_files_list || []).map((f) => f.filename || f);
          if (changedFiles.length > 0 && shouldRetriggerProfile(changedFiles)) {
            const repoRow = await client.query('SELECT id FROM repositories WHERE github_id = $1', [repository.id]);
            if (repoRow.rows[0]) {
              await client.query(`UPDATE repositories SET profile_status = 'stale', profile_priority = GREATEST(profile_priority, 1), profile_queued_at = NOW() WHERE id = $1 AND profile_status = 'ready'`, [repoRow.rows[0].id]);
            }
          }
        }
      }

      if (event === 'pull_request' && ['opened', 'synchronize', 'reopened'].includes(payload.action)) {
        const repository = payload.repository;
        const pr = payload.pull_request;
        const installationId = payload.installation?.id;

        if (!installationId) {
          throw new Error('Pull request webhook missing installation id');
        }

        {
          await client.query(
            `INSERT INTO repositories
              (github_id, installation_id, owner_id, name, full_name, private, default_branch, language, html_url, clone_url, is_active)
             VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, $8, $9, false)
             ON CONFLICT (github_id)
             DO UPDATE SET
               installation_id = EXCLUDED.installation_id,
               name = EXCLUDED.name,
               full_name = EXCLUDED.full_name,
               private = EXCLUDED.private,
               default_branch = EXCLUDED.default_branch,
               language = EXCLUDED.language,
               html_url = EXCLUDED.html_url,
               clone_url = EXCLUDED.clone_url,
               updated_at = NOW()
             RETURNING id`,
            [
              repository.id,
              installationId,
              repository.name,
              repository.full_name,
              repository.private,
              repository.default_branch || 'main',
              repository.language,
              repository.html_url,
              repository.clone_url,
            ]
          );

          const repoResult = await client.query('SELECT id, baseline_set, is_active FROM repositories WHERE github_id = $1', [
            repository.id,
          ]);
          const repoId = repoResult.rows[0].id;

          const prResult = await client.query(
            `INSERT INTO pull_requests
              (repository_id, github_pr_id, pr_number, title, body, state, head_sha, base_sha, head_branch, base_branch, author, html_url, draft)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             ON CONFLICT (repository_id, pr_number)
             DO UPDATE SET
               title = EXCLUDED.title,
               body = EXCLUDED.body,
               state = EXCLUDED.state,
               head_sha = EXCLUDED.head_sha,
               base_sha = EXCLUDED.base_sha,
               head_branch = EXCLUDED.head_branch,
               base_branch = EXCLUDED.base_branch,
               author = EXCLUDED.author,
               html_url = EXCLUDED.html_url,
               draft = EXCLUDED.draft,
               updated_at = NOW()
             RETURNING id`,
            [
              repoId,
              pr.id,
              pr.number,
              pr.title,
              pr.body,
              pr.state,
              pr.head.sha,
              pr.base.sha,
              pr.head.ref,
              pr.base.ref,
              pr.user?.login,
              pr.html_url,
              Boolean(pr.draft),
            ]
          );

          // A new head invalidates every in-flight job, every ready candidate, and any
          // merge intent that is not bound to this exact commit. The application commit
          // created by this system is the one exception to the cancellation.
          if (payload.action === 'synchronize') {
            const superseded = await remediationDb.supersedeForHeadChange({
              client, pullRequestId: prResult.rows[0].id, newHeadSha: pr.head.sha, reason: 'head_changed',
            });
            if (superseded.jobs.length || superseded.mergeIntents.length) {
              logger.info('Remediation state superseded by a new pull request head', {
                pull_request_id: prResult.rows[0].id, jobs: superseded.jobs.length,
                candidates: superseded.candidates.length, merge_intents: superseded.mergeIntents.length,
              });
            }
          }

          if (repoResult.rows[0].is_active) {
            const run = await client.query(
              `INSERT INTO analysis_runs
                (repository_id, pull_request_id, pr_number, commit_sha, status, triggered_by)
               VALUES ($1, $2, $3, $4, 'pending', 'webhook')
               RETURNING id`,
              [repoId, prResult.rows[0].id, pr.number, pr.head.sha]
            );

            analysisPayload = {
              correlation_id: correlationId,
              delivery_id: deliveryId,
              analysis_run_id: run.rows[0].id,
              repository_id: repoId,
              repository_github_id: repository.id,
              repository_full_name: repository.full_name,
              installation_id: installationId,
              pull_request_id: prResult.rows[0].id,
              pull_request_number: pr.number,
              commit_sha: pr.head.sha,
              base_sha: pr.base.sha,
              baseline_set: repoResult.rows[0].baseline_set,
            };
          }
        }
      }

      // A branch push moves the head of every open pull request from that branch.
      if (event === 'push' && payload.repository?.id && typeof payload.ref === 'string' && payload.ref.startsWith('refs/heads/') && payload.after) {
        await remediationDb.supersedeForBranchPush({
          client, repositoryGithubId: payload.repository.id,
          branch: payload.ref.slice('refs/heads/'.length), newHeadSha: payload.after, reason: 'head_changed',
        });
      }

      if (MERGE_HINT_EVENTS.has(event)) {
        const reference = mergeHintReference(event, payload);
        if (reference) {
          await remediationDb.recordMergeReevaluationHint(
            { client, ...reference },
            `${event}${payload.action ? `.${payload.action}` : ''}`
          );
        }
      }

      await client.query(
        `UPDATE webhook_deliveries
         SET processing_status = 'processed', processed_at = NOW()
         WHERE delivery_id = $1`,
        [deliveryId]
      );

      return false;
    });

    if (deduplicated) return res.status(200).json({ success: true, deduplicated: true });
    if (analysisPayload) notifyAnalysisQueued();

    res.status(200).json({ success: true, analysis_queued: Boolean(analysisPayload) });
  } catch (error) {
    logger.error('Webhook processing failed', {
      deliveryId,
      event,
      error: error.message,
    });

    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

module.exports = router;
