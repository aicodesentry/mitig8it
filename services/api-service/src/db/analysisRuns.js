const { pool } = require('../config/database');

async function querySummaryFromRuns(userId) {
  const result = await pool.query(
    `SELECT
       COUNT(*) AS total,
       COUNT(*) FILTER (WHERE ar.status = 'completed') AS completed,
       COUNT(*) FILTER (WHERE ar.status = 'failed') AS failed,
       COUNT(*) FILTER (WHERE COALESCE(ar.started_at, ar.created_at) >= NOW() - INTERVAL '7 days') AS recent
     FROM analysis_runs ar
     JOIN repositories r ON ar.repository_id = r.id
     JOIN repository_access ra ON ra.repository_id = r.id
     WHERE ra.user_id = $1`,
    [userId]
  );
  return result.rows[0];
}

async function querySummary(userId) {
  return querySummaryFromRuns(userId);
}

async function queryAnalysesFromRuns(userId, { repositoryId, status, limit, offset }) {
  const params = [userId];
  const where = ['ra.user_id = $1'];

  if (repositoryId) {
    where.push(`r.id = $${params.length + 1}`);
    params.push(repositoryId);
  }

  if (status) {
    where.push(`ar.status = $${params.length + 1}`);
    params.push(status);
  }

  const listQuery = `
    SELECT
      ar.id,
      ar.pr_number,
      pr.html_url AS pr_url,
      ar.status,
      ar.started_at,
      ar.completed_at,
      EXTRACT(EPOCH FROM (ar.completed_at - ar.started_at)) AS processing_time_seconds,
      r.id AS repository_id,
      r.full_name AS repository_name,
      r.name AS repo_short_name
    FROM analysis_runs ar
    JOIN repositories r ON ar.repository_id = r.id
    JOIN repository_access ra ON ra.repository_id = r.id
    LEFT JOIN pull_requests pr ON pr.id = ar.pull_request_id
    WHERE ${where.join(' AND ')}
    ORDER BY COALESCE(ar.started_at, ar.created_at) DESC
    LIMIT $${params.length + 1} OFFSET $${params.length + 2}
  `;

  const countQuery = `
    SELECT COUNT(*) AS total
    FROM analysis_runs ar
    JOIN repositories r ON ar.repository_id = r.id
    JOIN repository_access ra ON ra.repository_id = r.id
    WHERE ${where.join(' AND ')}
  `;

  const list = await pool.query(listQuery, [...params, limit, offset]);
  const count = await pool.query(countQuery, params);
  return { rows: list.rows, total: parseInt(count.rows[0].total, 10) };
}

async function listAnalyses(userId, { repositoryId, status, limit, offset }) {
  return queryAnalysesFromRuns(userId, { repositoryId, status, limit, offset });
}

async function getAnalysisById(analysisId, userId) {
  const result = await pool.query(
    `SELECT
       ar.id,
       ar.pr_number,
       pr.html_url AS pr_url,
       ar.status,
       ar.started_at,
       ar.completed_at,
       EXTRACT(EPOCH FROM (ar.completed_at - ar.started_at)) AS processing_time_seconds,
       r.id AS repository_id,
       r.full_name AS repository_name,
       r.github_id AS repository_github_id
     FROM analysis_runs ar
     JOIN repositories r ON ar.repository_id = r.id
     JOIN repository_access ra ON ra.repository_id = r.id
     LEFT JOIN pull_requests pr ON pr.id = ar.pull_request_id
     WHERE ar.id = $1 AND ra.user_id = $2`,
    [analysisId, userId]
  );
  return result.rows[0] || null;
}

// --- Internal (used by orchestrator) ---

async function countCompletedRuns(repositoryId, excludeRunId) {
  const result = await pool.query(
    `SELECT COUNT(*)::int AS count FROM analysis_runs
     WHERE repository_id = $1 AND id <> $2 AND status = 'completed'`,
    [repositoryId, excludeRunId]
  );
  return Number(result.rows[0].count);
}

function positiveInteger(value, fallback) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    return fallback;
  }
  return parsed;
}

async function claimNextQueuedRun(staleAfterMinutes = 20) {
  const staleMinutes = positiveInteger(staleAfterMinutes, 20);
  // Session ownership spans the scan, but the row-lock transaction ends at claim.
  // A crashed connection releases its lease; a slow live worker cannot be reclaimed.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const skipped = [];
    while (true) {
      const candidates = await client.query(
        `SELECT candidate.id AS analysis_run_id, candidate.repository_id,
           candidate.pr_number AS pull_request_number
         FROM analysis_runs candidate
         JOIN repositories candidate_repo ON candidate_repo.id = candidate.repository_id
         WHERE candidate_repo.is_active = true
           AND NOT (candidate.id = ANY($2::uuid[]))
           AND ((candidate.status = 'pending'
             AND COALESCE(candidate.not_before, candidate.created_at) <= NOW()) OR (
             candidate.status = 'running'
             AND candidate.started_at < NOW() - ($1::int * INTERVAL '1 minute')))
         ORDER BY CASE WHEN candidate.status = 'running' THEN 0 ELSE 1 END,
           COALESCE(candidate.started_at, candidate.created_at), candidate.created_at
         LIMIT 1 FOR UPDATE OF candidate SKIP LOCKED`,
        [staleMinutes, [...skipped]]
      );
      const candidate = candidates.rows[0];
      if (!candidate) {
        await client.query('COMMIT');
        client.release();
        return null;
      }
      const leaseKey = `analysis-pr:${candidate.repository_id}:${candidate.pull_request_number}`;
      const lock = await client.query(
        'SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS acquired', [leaseKey]
      );
      if (!lock.rows[0].acquired) {
        skipped.push(candidate.analysis_run_id);
        continue;
      }
      const result = await client.query(
        `UPDATE analysis_runs ar
         SET status = 'running', started_at = NOW(), completed_at = NULL, error_message = NULL
         FROM repositories r WHERE ar.id = $1 AND r.id = ar.repository_id
         RETURNING ar.id AS analysis_run_id, ar.repository_id,
           r.github_id AS repository_github_id, r.full_name AS repository_full_name,
           r.installation_id, ar.pull_request_id, ar.pr_number AS pull_request_number,
           ar.commit_sha, r.baseline_set, ar.auto_retry_count, ar.triggered_by,
           ar.delivery_id`, [candidate.analysis_run_id]
      );
      if (!result.rows[0]) throw new Error('Claimed analysis run disappeared');
      await client.query('COMMIT');
      let releasePromise;
      Object.defineProperty(result.rows[0], 'releaseLease', {
        enumerable: false,
        value: () => {
          if (!releasePromise) releasePromise = (async () => {
            try {
              const unlocked = await client.query(
                'SELECT pg_advisory_unlock(hashtextextended($1, 0)) AS unlocked', [leaseKey]
              );
              if (!unlocked.rows[0]?.unlocked) throw new Error('Analysis lease was not held');
            } catch (error) {
              client.release(error); // Destroy: never return a possibly locked session to the pool.
              throw error;
            }
            client.release();
          })();
          return releasePromise;
        },
      });
      return result.rows[0];
    }
  } catch (error) {
    // Destroying the connection rolls back the claim and releases any session lock.
    client.release(error);
    throw error;
  }
}

async function getQueueStats() {
  const result = await pool.query(
    `SELECT
       COUNT(*) FILTER (WHERE status = 'pending')::int AS pending,
       COUNT(*) FILTER (WHERE status = 'running')::int AS running,
       COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
       COALESCE(
         EXTRACT(EPOCH FROM (NOW() - MIN(created_at) FILTER (WHERE status = 'pending'))),
         0
       )::int AS oldest_pending_seconds,
       -- NULL, not 0, when nothing has ever started: "no run in ten minutes" and
       -- "a run started this instant" must not collapse into the same number.
       EXTRACT(EPOCH FROM (NOW() - MAX(started_at)))::int AS seconds_since_last_start
     FROM analysis_runs`
  );

  const row = result.rows[0] || {};
  return {
    pending: Number(row.pending || 0),
    running: Number(row.running || 0),
    failed: Number(row.failed || 0),
    oldest_pending_seconds: Number(row.oldest_pending_seconds || 0),
    seconds_since_last_start: row.seconds_since_last_start == null
      ? null
      : Number(row.seconds_since_last_start),
  };
}

async function markCompleted(runId, { findingsCount, counts, filesAnalyzed, checkRunId, reviewId }) {
  await pool.query(
    `UPDATE analysis_runs
     SET status = 'completed', findings_count = $2, critical_count = $3,
         high_count = $4, medium_count = $5, low_count = $6,
         files_analyzed = $7, github_check_run_id = $8, summary_comment_id = $9,
         completed_at = NOW()
     WHERE id = $1`,
    [runId, findingsCount, counts.critical || 0, counts.high || 0,
     counts.medium || 0, counts.low || 0, filesAnalyzed, checkRunId || null, reviewId || null]
  );
}

async function markFailed(runId, errorMessage) {
  await pool.query(
    `UPDATE analysis_runs SET status = 'failed', error_message = $2, completed_at = NOW() WHERE id = $1`,
    [runId, errorMessage]
  );
}

// A transient infrastructure failure is not a verdict about the code. The failed
// run keeps its evidence and error, and the retry is a new attempt, exactly as a
// manual retry is, so history stays honest about what was tried and when.
async function requeueAfterTransientFailure(runId, { errorMessage, delayMs }) {
  const delay = Number.isFinite(Number(delayMs)) && Number(delayMs) > 0 ? Math.floor(Number(delayMs)) : 0;
  const result = await pool.query(
    `WITH failed AS (
       UPDATE analysis_runs
       SET status = 'failed', error_message = $2, completed_at = NOW()
       WHERE id = $1 AND status <> 'failed'
       RETURNING repository_id, pull_request_id, pr_number, commit_sha, auto_retry_count,
         delivery_id
     )
     INSERT INTO analysis_runs
       (repository_id, pull_request_id, pr_number, commit_sha, status, triggered_by,
        auto_retry_count, not_before, delivery_id)
     SELECT repository_id, pull_request_id, pr_number, commit_sha, 'pending', 'auto_retry',
       auto_retry_count + 1, NOW() + ($3::bigint * INTERVAL '1 millisecond'), delivery_id
     FROM failed
     RETURNING id, auto_retry_count, not_before`,
    [runId, errorMessage, delay]
  );
  return result.rows[0] || null;
}

async function markBaselineSet(repositoryId) {
  await pool.query(
    'UPDATE repositories SET baseline_set = true, updated_at = NOW() WHERE id = $1',
    [repositoryId]
  );
}

module.exports = {
  querySummary, listAnalyses, getAnalysisById,
  countCompletedRuns, claimNextQueuedRun, getQueueStats, markCompleted, markFailed, markBaselineSet,
  requeueAfterTransientFailure,
};
