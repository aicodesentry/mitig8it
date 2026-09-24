const { pool, transaction } = require('../config/database');

// The SQL behind quality_metrics_daily: one recompute that rebuilds a trailing window
// from finding_outcomes and findings, and the reads the report route and the reconciler
// need. No caller writes to the table directly.

const DEFAULT_WINDOW_DAYS = 35;

// A finding is identified by its row id while the row exists and by its fingerprint once
// it is gone, which is exactly what makes the outcome log survive a disconnect.
const FINDING_KEY = `COALESCE(o.finding_id::text, 'fp:' || o.fingerprint)`;

// Every count below is a count of distinct findings, never of outcome rows: a finding
// dismissed twice on the same day is one dismissal. applied_on_github excludes a finding
// already counted as applied in the app that day so the two columns stay disjoint and
// their sum is an exact count of distinct findings applied.
const RECOMPUTE_SQL = `
WITH bounds AS (
  SELECT (CURRENT_DATE - ($2::int - 1))::date AS from_day, CURRENT_DATE AS to_day
),
new_findings AS (
  SELECT f.repository_id, f.rule_id, f.created_at::date AS day, COUNT(DISTINCT f.id)::int AS findings_new
    FROM findings f
    JOIN repositories r ON r.id = f.repository_id
    CROSS JOIN bounds b
   WHERE r.installation_id = $1
     AND f.created_at >= b.from_day
     AND f.created_at < (b.to_day + 1)
   GROUP BY 1, 2, 3
),
facts AS (
  SELECT o.repository_id,
         COALESCE(o.rule_id, 'unknown') AS rule_id,
         o.created_at::date AS day,
         ${FINDING_KEY} AS finding_key,
         o.outcome
    FROM finding_outcomes o
    CROSS JOIN bounds b
   WHERE o.installation_id = $1
     AND o.created_at >= b.from_day
     AND o.created_at < (b.to_day + 1)
),
-- A finding that was ever applied or ever re-analysed away has a fix behind it, whatever
-- day that happened on. The whole history is read here, not just the window.
fixed_keys AS (
  SELECT DISTINCT ${FINDING_KEY} AS finding_key
    FROM finding_outcomes o
   WHERE o.installation_id = $1
     AND o.outcome IN ('applied_in_app', 'applied_on_github', 'fixed_by_reanalysis')
),
per_finding_day AS (
  SELECT repository_id, rule_id, day, finding_key,
         bool_or(outcome = 'fix_published') AS fix_published,
         bool_or(outcome = 'applied_in_app') AS applied_in_app,
         bool_or(outcome = 'applied_on_github') AS applied_on_github,
         bool_or(outcome = 'dismissed') AS dismissed,
         bool_or(outcome = 'accepted_risk') AS accepted_risk,
         bool_or(outcome = 'suppressed') AS suppressed,
         bool_or(outcome = 'thread_resolved') AS thread_resolved,
         bool_or(outcome = 'fixed_by_reanalysis') AS fixed_by_reanalysis,
         bool_or(outcome = 'residual_after_apply') AS residual_after_apply
    FROM facts
   GROUP BY 1, 2, 3, 4
),
outcome_counts AS (
  SELECT p.repository_id, p.rule_id, p.day,
         COUNT(*) FILTER (WHERE p.fix_published)::int AS fixes_published,
         COUNT(*) FILTER (WHERE p.applied_in_app)::int AS applied_in_app,
         COUNT(*) FILTER (WHERE p.applied_on_github AND NOT p.applied_in_app)::int AS applied_on_github,
         COUNT(*) FILTER (WHERE p.dismissed)::int AS dismissed,
         COUNT(*) FILTER (WHERE p.accepted_risk)::int AS accepted_risk,
         COUNT(*) FILTER (WHERE p.suppressed)::int AS suppressed,
         COUNT(*) FILTER (WHERE p.thread_resolved)::int AS thread_resolved,
         COUNT(*) FILTER (WHERE p.thread_resolved AND k.finding_key IS NULL)::int AS thread_resolved_without_fix,
         COUNT(*) FILTER (WHERE p.fixed_by_reanalysis)::int AS fixed_by_reanalysis,
         COUNT(*) FILTER (WHERE p.residual_after_apply)::int AS residual_after_apply
    FROM per_finding_day p
    LEFT JOIN fixed_keys k ON k.finding_key = p.finding_key
   GROUP BY 1, 2, 3
),
base AS (
  SELECT COALESCE(n.repository_id, c.repository_id) AS repository_id,
         COALESCE(n.rule_id, c.rule_id) AS rule_id,
         COALESCE(n.day, c.day) AS day,
         COALESCE(n.findings_new, 0) AS findings_new,
         COALESCE(c.fixes_published, 0) AS fixes_published,
         COALESCE(c.applied_in_app, 0) AS applied_in_app,
         COALESCE(c.applied_on_github, 0) AS applied_on_github,
         COALESCE(c.dismissed, 0) AS dismissed,
         COALESCE(c.accepted_risk, 0) AS accepted_risk,
         COALESCE(c.suppressed, 0) AS suppressed,
         COALESCE(c.thread_resolved, 0) AS thread_resolved,
         COALESCE(c.thread_resolved_without_fix, 0) AS thread_resolved_without_fix,
         COALESCE(c.fixed_by_reanalysis, 0) AS fixed_by_reanalysis,
         COALESCE(c.residual_after_apply, 0) AS residual_after_apply
    FROM new_findings n
    FULL OUTER JOIN outcome_counts c
      ON c.repository_id = n.repository_id AND c.rule_id = n.rule_id AND c.day = n.day
)
INSERT INTO quality_metrics_daily (
  installation_id, repository_id, rule_id, day, findings_new, fixes_published,
  applied_in_app, applied_on_github, dismissed, accepted_risk, suppressed,
  thread_resolved, thread_resolved_without_fix, fixed_by_reanalysis,
  residual_after_apply, computed_at
)
SELECT $1, repository_id, rule_id, day,
       SUM(findings_new)::int, SUM(fixes_published)::int, SUM(applied_in_app)::int,
       SUM(applied_on_github)::int, SUM(dismissed)::int, SUM(accepted_risk)::int,
       SUM(suppressed)::int, SUM(thread_resolved)::int, SUM(thread_resolved_without_fix)::int,
       SUM(fixed_by_reanalysis)::int, SUM(residual_after_apply)::int, $3::timestamptz
  FROM base
 WHERE day IS NOT NULL
 -- The four grains of the table, written in one statement so they can never disagree.
 GROUP BY GROUPING SETS ((repository_id, rule_id, day), (repository_id, day), (rule_id, day), (day))
ON CONFLICT (installation_id, day,
             COALESCE(repository_id, '00000000-0000-0000-0000-000000000000'::uuid),
             COALESCE(rule_id, ''))
DO UPDATE SET
  findings_new = EXCLUDED.findings_new,
  fixes_published = EXCLUDED.fixes_published,
  applied_in_app = EXCLUDED.applied_in_app,
  applied_on_github = EXCLUDED.applied_on_github,
  dismissed = EXCLUDED.dismissed,
  accepted_risk = EXCLUDED.accepted_risk,
  suppressed = EXCLUDED.suppressed,
  thread_resolved = EXCLUDED.thread_resolved,
  thread_resolved_without_fix = EXCLUDED.thread_resolved_without_fix,
  fixed_by_reanalysis = EXCLUDED.fixed_by_reanalysis,
  residual_after_apply = EXCLUDED.residual_after_apply,
  computed_at = EXCLUDED.computed_at`;

// A day whose findings were all deleted with their repository produces no row this pass.
// Its old row would otherwise survive with counts that no longer describe anything, so
// every window row this pass did not touch is removed.
const PRUNE_SQL = `
  DELETE FROM quality_metrics_daily
   WHERE installation_id = $1
     AND day >= (CURRENT_DATE - ($2::int - 1))::date
     AND computed_at < $3::timestamptz`;

/**
 * Rebuild the trailing window for one installation. Safe to run repeatedly: the same
 * inputs produce the same rows, and a second pass in the same second changes nothing.
 */
async function recomputeInstallation(installationId, { days = DEFAULT_WINDOW_DAYS } = {}) {
  const window = Number.isFinite(Number(days)) && Number(days) > 0 ? Math.floor(Number(days)) : DEFAULT_WINDOW_DAYS;
  return transaction(async (client) => {
    const computedAt = new Date().toISOString();
    const written = await client.query(RECOMPUTE_SQL, [installationId, window, computedAt]);
    const pruned = await client.query(PRUNE_SQL, [installationId, window, computedAt]);
    return { installation_id: String(installationId), days: window, rows: written.rowCount, pruned: pruned.rowCount };
  });
}

// The installations worth recomputing: the ones that saw a finding or an outcome inside
// the window. An installation with no activity keeps the rows it already has.
async function installationsWithActivity({ days = DEFAULT_WINDOW_DAYS, limit = 500 } = {}) {
  const result = await pool.query(
    `SELECT DISTINCT installation_id FROM (
       SELECT o.installation_id FROM finding_outcomes o
        WHERE o.created_at >= (CURRENT_DATE - ($1::int - 1))::date
       UNION
       SELECT r.installation_id FROM findings f JOIN repositories r ON r.id = f.repository_id
        WHERE f.created_at >= (CURRENT_DATE - ($1::int - 1))::date
     ) active
      WHERE installation_id IS NOT NULL
      LIMIT $2`,
    [days, limit]
  );
  return result.rows.map((row) => String(row.installation_id));
}

// The installations a user can reach, through the repositories they have access to. The
// same boundary every other report route enforces.
async function installationIdsForUser(userId) {
  const result = await pool.query(
    `SELECT DISTINCT r.installation_id
       FROM repositories r
       JOIN repository_access ra ON ra.repository_id = r.id
      WHERE ra.user_id = $1 AND r.installation_id IS NOT NULL`,
    [userId]
  );
  return result.rows.map((row) => String(row.installation_id));
}

/**
 * The daily rows behind one window. `repositoryId` null reads the installation-wide
 * grain; a repository id reads that repository's own grain. `byRule` picks the per-rule
 * grain over the totals grain.
 */
async function readWindow({ installationIds = [], days = 30, repositoryId = null, byRule = false } = {}) {
  if (!installationIds.length) return [];
  const result = await pool.query(
    `SELECT installation_id, repository_id, rule_id, day, findings_new, fixes_published,
            applied_in_app, applied_on_github, dismissed, accepted_risk, suppressed,
            thread_resolved, thread_resolved_without_fix, fixed_by_reanalysis, residual_after_apply
       FROM quality_metrics_daily
      WHERE installation_id = ANY($1::bigint[])
        AND day >= (CURRENT_DATE - ($2::int - 1))::date
        AND (($3::uuid IS NULL AND repository_id IS NULL) OR repository_id = $3::uuid)
        AND ($4::bool = (rule_id IS NOT NULL))`,
    [installationIds, days, repositoryId, byRule]
  );
  return result.rows;
}

// The repository ids inside the installations a user can reach, used to refuse a
// repository_id the caller has no access to rather than silently returning nothing.
async function userCanReadRepository(userId, repositoryId) {
  const result = await pool.query(
    `SELECT 1 FROM repository_access WHERE user_id = $1 AND repository_id = $2 LIMIT 1`,
    [userId, repositoryId]
  );
  return result.rowCount > 0;
}

module.exports = {
  DEFAULT_WINDOW_DAYS, recomputeInstallation, installationsWithActivity,
  installationIdsForUser, readWindow, userCanReadRepository,
};
