const { pool } = require('../config/database');

async function list(userId) {
  const rows = await pool.query(
    `SELECT
       r.id,
       r.github_id,
       r.installation_id,
       r.name,
       r.full_name,
       r.private,
       r.default_branch,
       r.language,
       r.html_url,
       r.is_active,
       r.baseline_set,
       r.profile_status,
       r.profile_confidence,
       r.profile_updated_at,
       r.updated_at,
       COUNT(DISTINCT pr.id) AS pull_request_count,
       COUNT(DISTINCT f.id) FILTER (WHERE f.status = 'open') AS open_findings_count,
       COUNT(DISTINCT f.id) FILTER (WHERE f.status = 'accepted_risk') AS accepted_risk_count
     FROM repositories r
     JOIN user_installations ui ON ui.installation_id = r.installation_id AND ui.user_id = $1
     JOIN repository_access ra ON ra.repository_id = r.id AND ra.user_id = $1
     LEFT JOIN pull_requests pr ON pr.repository_id = r.id
     LEFT JOIN findings f ON f.repository_id = r.id
     GROUP BY r.id
     ORDER BY r.is_active DESC, COUNT(DISTINCT pr.id) DESC, r.updated_at DESC`,
    [userId]
  );
  return rows.rows;
}

async function revokeMissingAccessForInstallation(userId, installationId, visibleGithubIds) {
  const githubIds = (visibleGithubIds || []).filter(Boolean);

  if (githubIds.length > 0) {
    await pool.query(
      `DELETE FROM repository_access ra
       USING repositories r
       WHERE ra.repository_id = r.id
         AND ra.user_id = $1
         AND r.installation_id = $2
         AND r.github_id <> ALL($3::bigint[])`,
      [userId, installationId, githubIds]
    );
    return;
  }

  await pool.query(
    `DELETE FROM repository_access ra
     USING repositories r
     WHERE ra.repository_id = r.id
       AND ra.user_id = $1
       AND r.installation_id = $2`,
    [userId, installationId]
  );
}

async function getById(repoId, userId) {
  const repo = await pool.query(
    `SELECT r.*
     FROM repositories r
     JOIN repository_access ra ON ra.repository_id = r.id
     WHERE r.id = $1 AND ra.user_id = $2`,
    [repoId, userId]
  );

  if (repo.rowCount === 0) return null;

  const summary = await pool.query(
    `SELECT
       COUNT(*) FILTER (WHERE status = 'open') AS open_findings,
       COUNT(*) FILTER (WHERE status = 'dismissed') AS dismissed_findings,
       COUNT(*) FILTER (WHERE status = 'accepted_risk') AS accepted_risk_findings,
       COUNT(*) FILTER (WHERE severity = 'critical' AND status = 'open') AS critical_open,
       COUNT(*) FILTER (WHERE severity = 'high' AND status = 'open') AS high_open
     FROM findings
     WHERE repository_id = $1`,
    [repoId]
  );

  return { repository: repo.rows[0], summary: summary.rows[0] };
}

async function updateBaseline(repoId, userId, enabled) {
  const updated = await pool.query(
    `UPDATE repositories
     SET baseline_set = $1, updated_at = NOW()
     WHERE id = $2
       AND EXISTS (
         SELECT 1 FROM repository_access ra
         WHERE ra.repository_id = repositories.id AND ra.user_id = $3
       )
     RETURNING id, baseline_set`,
    [Boolean(enabled), repoId, userId]
  );
  return updated.rowCount > 0 ? updated.rows[0] : null;
}

async function connect(repoId, userId) {
  const updated = await pool.query(
    `UPDATE repositories
     SET is_active = true,
         profile_status = CASE
           WHEN profile_status IN ('ready', 'profiling', 'queued', 'urgent', 'stale') THEN profile_status
           ELSE 'urgent'
         END,
         profile_priority = CASE
           WHEN profile_status IN ('ready', 'profiling') THEN profile_priority
           ELSE GREATEST(COALESCE(profile_priority, 0), 2)
         END,
         profile_queued_at = CASE
           WHEN profile_status IN ('ready', 'profiling') THEN profile_queued_at
           ELSE NOW()
         END,
         settings = settings - 'profile_error',
         updated_at = NOW()
     WHERE id = $1
       AND EXISTS (
         SELECT 1 FROM repository_access ra
         WHERE ra.repository_id = repositories.id AND ra.user_id = $2
       )
     RETURNING id, full_name, is_active, profile_status, profile_confidence, profile_updated_at`,
    [repoId, userId]
  );
  return updated.rowCount > 0 ? updated.rows[0] : null;
}

async function disconnect(repoId, userId) {
  const updated = await pool.query(
    `UPDATE repositories
     SET is_active = false, updated_at = NOW()
     WHERE id = $1
       AND EXISTS (
         SELECT 1 FROM repository_access ra
         WHERE ra.repository_id = repositories.id AND ra.user_id = $2
       )
     RETURNING id, full_name, is_active`,
    [repoId, userId]
  );
  return updated.rowCount > 0 ? updated.rows[0] : null;
}

async function queueManualReprofile(repoId, userId) {
  const result = await pool.query(
    `UPDATE repositories
     SET profile_status = CASE
           WHEN profile_status = 'profiling' THEN profile_status
           ELSE 'urgent'
         END,
         profile_priority = GREATEST(COALESCE(profile_priority, 0), 2),
         profile_queued_at = NOW(),
         settings = settings - 'profile_error',
         updated_at = NOW()
     WHERE id = $1
       AND EXISTS (
         SELECT 1 FROM repository_access ra
         WHERE ra.repository_id = repositories.id AND ra.user_id = $2
       )
     RETURNING id, full_name, profile_status, profile_confidence, profile_updated_at`,
    [repoId, userId]
  );

  return result.rowCount > 0 ? result.rows[0] : null;
}

// ── Repo profiling ──────────────────────────────────────────────────────

async function queueForProfiling(repoId, priority = 0) {
  await pool.query(
    `UPDATE repositories
     SET profile_status = CASE
           WHEN profile_status = 'profiling' THEN profile_status
           ELSE 'queued'
         END,
         profile_priority = GREATEST(profile_priority, $2),
         profile_queued_at = COALESCE(profile_queued_at, NOW())
     WHERE id = $1`,
    [repoId, priority]
  );
}

async function queueTopReposForProfiling(repoIds, limit = 10) {
  const uniqueRepoIds = [...new Set((repoIds || []).filter(Boolean))];
  if (uniqueRepoIds.length === 0) return [];

  const result = await pool.query(
    `WITH ranked AS (
       SELECT
         r.id,
         ROW_NUMBER() OVER (
           ORDER BY
             r.is_active DESC,
             COALESCE(pr_counts.pull_request_count, 0) DESC,
             r.updated_at DESC
         ) AS rank
       FROM repositories r
       LEFT JOIN (
         SELECT repository_id, COUNT(*) AS pull_request_count
         FROM pull_requests
         GROUP BY repository_id
       ) pr_counts ON pr_counts.repository_id = r.id
       WHERE r.id = ANY($1::uuid[])
     )
     UPDATE repositories r
     SET profile_status = CASE
           WHEN r.profile_status IN ('ready', 'profiling', 'stale', 'urgent') THEN r.profile_status
           ELSE 'queued'
         END,
         profile_priority = CASE
           WHEN ranked.rank <= $2 THEN GREATEST(r.profile_priority, 0)
           ELSE r.profile_priority
         END,
         profile_queued_at = CASE
           WHEN ranked.rank <= $2 THEN COALESCE(r.profile_queued_at, NOW())
           ELSE r.profile_queued_at
         END
     FROM ranked
     WHERE r.id = ranked.id
       AND ranked.rank <= $2
     RETURNING r.id`,
    [uniqueRepoIds, limit]
  );

  return result.rows.map((row) => row.id);
}

async function queueUrgentProfiling(repoId, pendingRetriage) {
  await pool.query(
    `UPDATE repositories
     SET profile_status = CASE
           WHEN profile_status IN ('ready', 'profiling') THEN profile_status
           ELSE 'urgent'
         END,
         profile_priority = GREATEST(profile_priority, 2),
         profile_queued_at = COALESCE(profile_queued_at, NOW()),
         settings = settings || $2::jsonb
     WHERE id = $1`,
    [repoId, JSON.stringify({ pending_retriage: pendingRetriage })]
  );
}

async function markProfileStale(repoId) {
  await pool.query(
    `UPDATE repositories
     SET profile_status = CASE
           WHEN profile_status = 'profiling' THEN profile_status
           ELSE 'stale'
         END,
         profile_priority = GREATEST(profile_priority, 1),
         profile_queued_at = NOW()
     WHERE id = $1 AND profile_status = 'ready'`,
    [repoId]
  );
}

async function recoverStaleProfilingJobs(maxAgeMinutes = 30) {
  const result = await pool.query(
    `UPDATE repositories
     SET profile_status = 'urgent',
         profile_priority = GREATEST(COALESCE(profile_priority, 0), 2),
         profile_queued_at = NOW(),
         settings = settings || $2::jsonb
     WHERE profile_status = 'profiling'
       AND profile_queued_at IS NOT NULL
       AND profile_queued_at < NOW() - ($1 || ' minutes')::interval
     RETURNING id`,
    [String(maxAgeMinutes), JSON.stringify({ profile_error: `Profiling job exceeded ${maxAgeMinutes} minutes and was re-queued` })]
  );
  return result.rowCount;
}

async function claimNextProfileJob() {
  const result = await pool.query(
    `UPDATE repositories
     SET profile_status = 'profiling'
     WHERE id = (
       SELECT id FROM repositories
       WHERE profile_status IN ('queued', 'stale', 'urgent')
         AND installation_id IS NOT NULL
         -- An uninstalled installation's data is being deleted; never profile for it.
         AND installation_id IN (SELECT id FROM installations WHERE deleted_at IS NULL)
       ORDER BY profile_priority DESC, profile_queued_at ASC
       LIMIT 1
       FOR UPDATE SKIP LOCKED
     )
     RETURNING id, github_id, installation_id, full_name, default_branch, settings`
  );
  return result.rows[0] || null;
}

async function saveProfile(repoId, profileData, confidence) {
  await pool.query(
    `UPDATE repositories
     SET profile_status = 'ready',
         profile_data = $2,
         profile_confidence = $3,
         profile_priority = 0,
         profile_updated_at = NOW(),
         settings = settings - 'pending_retriage' - 'profile_error'
     WHERE id = $1`,
    [repoId, JSON.stringify(profileData), confidence]
  );
}

async function markProfileFailed(repoId, errorMessage) {
  await pool.query(
    `UPDATE repositories
     SET profile_status = 'failed',
         profile_priority = 0,
         settings = settings || $2::jsonb
     WHERE id = $1`,
    [repoId, JSON.stringify({ profile_error: errorMessage })]
  );
}

async function getProfile(repoId) {
  const result = await pool.query(
    `SELECT profile_status, profile_data, profile_confidence, profile_updated_at
     FROM repositories WHERE id = $1`,
    [repoId]
  );
  return result.rows[0] || null;
}

module.exports = {
  list, getById, updateBaseline, connect, disconnect, revokeMissingAccessForInstallation,
  queueManualReprofile, queueForProfiling, queueTopReposForProfiling, queueUrgentProfiling, markProfileStale, recoverStaleProfilingJobs,
  claimNextProfileJob, saveProfile, markProfileFailed, getProfile,
};
