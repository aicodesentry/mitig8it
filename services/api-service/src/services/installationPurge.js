const { pool } = require('../config/database');
const logger = require('../utils/logger');

// Uninstalling the App deletes every stored row for that installation.
//
// `installation.deleted` marks the row immediately (`deleted_at`) and schedules the
// purge for 24 hours later (`purge_after`). The grace period is what makes an
// accidental uninstall recoverable: a reinstall of the same GitHub installation id
// inside it clears both columns and nothing is deleted. While an installation is
// marked, every worker and reconciler query skips it, so no analysis, remediation or
// publication runs for data that is about to be deleted.

const DEFAULT_GRACE_HOURS = 24;

function graceHours() {
  const configured = Number(process.env.INSTALLATION_PURGE_GRACE_HOURS);
  return Number.isFinite(configured) && configured >= 0 ? configured : DEFAULT_GRACE_HOURS;
}

// Deletion order: children before parents. Every FK to `installations` is NO ACTION or
// SET NULL, so nothing here can be left to cascade; each table is named explicitly and
// each count is recorded. The order is the one the schema forces:
//
//   - the remediation control plane, deepest first, because remediation_actions points
//     at remediation_jobs with NO ACTION and merge_intents points at remediation_actions;
//   - then the analysis tables, which hang off repositories;
//   - then repositories themselves, whose FK to installations is ON DELETE SET NULL and
//     would otherwise silently orphan every row rather than delete it;
//   - then user_installations, and the installation row last.
//
// A table is scoped by `installation_id` when it has that column, and through
// `repositories` when it does not. `findings` carries both, and legacy rows may have a
// null installation_id, so it is scoped by either.
const PURGE_STEPS = [
  ['remediation_job_evidence', 'DELETE FROM remediation_job_evidence WHERE installation_id = $1'],
  ['usage_reservations', 'DELETE FROM usage_reservations WHERE installation_id = $1'],
  ['remediation_attempts', 'DELETE FROM remediation_attempts WHERE installation_id = $1'],
  ['verification_runs', 'DELETE FROM verification_runs WHERE installation_id = $1'],
  ['merge_intents', 'DELETE FROM merge_intents WHERE installation_id = $1'],
  ['remediation_writer_leases', 'DELETE FROM remediation_writer_leases WHERE installation_id = $1'],
  ['remediation_actions', 'DELETE FROM remediation_actions WHERE installation_id = $1'],
  ['repair_memory', 'DELETE FROM repair_memory WHERE installation_id = $1'],
  ['remediation_candidates', 'DELETE FROM remediation_candidates WHERE installation_id = $1'],
  ['remediation_jobs', 'DELETE FROM remediation_jobs WHERE installation_id = $1'],
  ['workflow_outbox', 'DELETE FROM workflow_outbox WHERE installation_id = $1'],
  ['workflow_events', 'DELETE FROM workflow_events WHERE installation_id = $1'],
  ['analysis_run_findings', `DELETE FROM analysis_run_findings WHERE analysis_run_id IN (
      SELECT ar.id FROM analysis_runs ar JOIN repositories r ON r.id = ar.repository_id
       WHERE r.installation_id = $1)`],
  ['suppressions', `DELETE FROM suppressions WHERE repository_id IN (
      SELECT id FROM repositories WHERE installation_id = $1)`],
  ['findings', `DELETE FROM findings WHERE installation_id = $1
      OR repository_id IN (SELECT id FROM repositories WHERE installation_id = $1)`],
  ['analysis_runs', `DELETE FROM analysis_runs WHERE repository_id IN (
      SELECT id FROM repositories WHERE installation_id = $1)`],
  ['analysis', `DELETE FROM analysis WHERE repository_id IN (
      SELECT id FROM repositories WHERE installation_id = $1)`],
  ['pull_requests', `DELETE FROM pull_requests WHERE repository_id IN (
      SELECT id FROM repositories WHERE installation_id = $1)`],
  // audit_logs.repository_id is ON DELETE SET NULL, so these rows survive the
  // repositories delete unless they are removed explicitly. The purge's own audit row
  // is written after this step and carries no repository_id, so it is not deleted here.
  ['audit_logs', `DELETE FROM audit_logs WHERE repository_id IN (
      SELECT id FROM repositories WHERE installation_id = $1)`],
  ['webhook_events', `DELETE FROM webhook_events WHERE repository_id IN (
      SELECT id FROM repositories WHERE installation_id = $1)`],
  ['repository_access', `DELETE FROM repository_access WHERE repository_id IN (
      SELECT id FROM repositories WHERE installation_id = $1)`],
  ['repositories', 'DELETE FROM repositories WHERE installation_id = $1'],
  ['user_installations', 'DELETE FROM user_installations WHERE installation_id = $1'],
];

// `users.installation_id` is a denormalized BIGINT with no foreign key, so deleting the
// installation would leave a dangling value rather than fail. The user account itself
// belongs to the person, not to the installation, and is never deleted here.
const CLEAR_USER_INSTALLATION = 'UPDATE users SET installation_id = NULL WHERE installation_id = $1';

function purgeTables() {
  return PURGE_STEPS.map(([table]) => table);
}

// Mark the installation and schedule its purge. Called from the installation.deleted
// webhook inside that webhook's own transaction, so the mark and the delivery record
// commit together.
async function markInstallationDeleted(client, installationId, { hours = graceHours() } = {}) {
  const result = await client.query(
    `UPDATE installations
        SET status = 'deleted',
            deleted_at = COALESCE(deleted_at, NOW()),
            purge_after = COALESCE(purge_after, NOW() + ($2::numeric * INTERVAL '1 hour')),
            updated_at = NOW()
      WHERE id = $1
      RETURNING id, deleted_at, purge_after`,
    [installationId, hours]
  );
  return result.rows[0] || null;
}

// A reinstall of the same GitHub installation id inside the grace period cancels the
// purge. Clearing both columns is what makes the installation live again for every
// worker, so it must happen in the same transaction as the reactivating upsert.
async function cancelScheduledPurge(client, installationId) {
  const result = await client.query(
    `UPDATE installations
        SET deleted_at = NULL, purge_after = NULL, updated_at = NOW()
      WHERE id = $1 AND (deleted_at IS NOT NULL OR purge_after IS NOT NULL)
      RETURNING id`,
    [installationId]
  );
  return result.rowCount > 0;
}

async function listInstallationsDueForPurge(limit = 5) {
  const result = await pool.query(
    `SELECT id, account_login, deleted_at, purge_after FROM installations
      WHERE purge_after IS NOT NULL AND purge_after <= NOW()
      ORDER BY purge_after
      LIMIT $1`,
    [limit]
  );
  return result.rows;
}

// One transaction for the whole installation. A partial purge is worse than none: it
// would leave rows whose parents are gone and no honest count to record. The tables are
// small enough per installation that one transaction is the right unit, and the
// re-check under FOR UPDATE is what makes a reinstall that lands mid-purge win.
async function purgeInstallation(installationId, options = {}) {
  const client = options.client || await pool.connect();
  const ownsClient = !options.client;
  try {
    if (ownsClient) await client.query('BEGIN');
    // The remediation tables force row level security. The purge runs as the worker for
    // this one tenant; without both settings the deletes would silently affect no rows.
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [String(installationId)]);
    await client.query("SELECT set_config('app.remediation_worker', '1', true)");

    const locked = await client.query(
      'SELECT id, purge_after FROM installations WHERE id = $1 FOR UPDATE', [installationId]
    );
    const row = locked.rows[0];
    if (!row) {
      if (ownsClient) await client.query('COMMIT');
      return { purged: false, reason: 'installation_not_found' };
    }
    // A reinstall inside the grace period cleared purge_after. Honour that here too, so
    // a purge already claimed by the reconciler still loses to the reinstall.
    if (!row.purge_after) {
      if (ownsClient) await client.query('COMMIT');
      return { purged: false, reason: 'purge_cancelled' };
    }
    if (!options.force && new Date(row.purge_after).getTime() > Date.now()) {
      if (ownsClient) await client.query('COMMIT');
      return { purged: false, reason: 'grace_period_active', purge_after: row.purge_after };
    }

    const counts = {};
    for (const [table, sql] of PURGE_STEPS) {
      const deleted = await client.query(sql, [installationId]);
      counts[table] = deleted.rowCount;
    }
    const cleared = await client.query(CLEAR_USER_INSTALLATION, [installationId]);
    counts.users_unlinked = cleared.rowCount;

    // One audit row for the whole purge, written before the installation row goes so the
    // deletion of that row is itself covered by the record. It carries no repository_id,
    // because every repository of this installation has just been deleted.
    await client.query(
      `INSERT INTO audit_logs (user_id, repository_id, action, resource_type, resource_id, details)
       VALUES (NULL, NULL, 'installation.purged', 'installation', NULL, $1)`,
      [JSON.stringify({ installation_id: String(installationId), counts, purged_at: new Date().toISOString() })]
    );

    const removed = await client.query('DELETE FROM installations WHERE id = $1', [installationId]);
    counts.installations = removed.rowCount;

    if (ownsClient) await client.query('COMMIT');
    logger.warn('Purged all stored data for an uninstalled installation', {
      installation_id: String(installationId), counts,
    });
    return { purged: true, counts };
  } catch (error) {
    if (ownsClient) {
      try { await client.query('ROLLBACK'); } catch (_) { /* connection will be released */ }
    }
    throw error;
  } finally {
    if (ownsClient) client.release();
  }
}

// The reconciler step. Each installation is purged independently: one failure never
// stops the rest, and the failed one is retried on the next tick because its
// `purge_after` is still in the past.
async function purgeDeletedInstallations(limit = 5) {
  const due = await listInstallationsDueForPurge(limit);
  const summary = { due: due.length, purged: 0, skipped: 0, failed: 0 };
  for (const installation of due) {
    try {
      const result = await purgeInstallation(installation.id);
      if (result.purged) summary.purged += 1;
      else summary.skipped += 1;
    } catch (error) {
      summary.failed += 1;
      logger.error('Installation purge failed', {
        installation_id: String(installation.id), error: error.message,
      });
    }
  }
  return summary;
}

// The reconciler runs this step too, but the reconciler only runs when the remediation
// control plane is enabled. Deleting a customer's data after they uninstall cannot
// depend on an unrelated feature flag, so the API also runs it on its own timer. Both
// callers are safe together: the purge locks the installation row and re-checks
// `purge_after` under that lock, so a second runner finds nothing to do.
const DEFAULT_SWEEP_MS = 15 * 60 * 1000;

function startPurgeLoop(options = {}) {
  const period = Number.isFinite(options.intervalMs)
    ? options.intervalMs
    : Math.max(Number(process.env.INSTALLATION_PURGE_SWEEP_MS) || DEFAULT_SWEEP_MS, 60000);
  let stopped = false;
  const loop = async () => {
    if (stopped) return;
    try {
      const summary = await purgeDeletedInstallations(options.limit || 5);
      if (summary.purged || summary.failed) logger.info('Installation purge sweep', summary);
    } catch (error) {
      logger.error('Installation purge sweep failed', { error: error.message });
    }
    if (!stopped) timer = setTimeout(loop, period);
  };
  let timer = setTimeout(loop, period);
  if (typeof timer.unref === 'function') timer.unref();
  return () => { stopped = true; clearTimeout(timer); };
}

module.exports = {
  DEFAULT_GRACE_HOURS, DEFAULT_SWEEP_MS, PURGE_STEPS, purgeTables, graceHours, startPurgeLoop,
  markInstallationDeleted, cancelScheduledPurge,
  listInstallationsDueForPurge, purgeInstallation, purgeDeletedInstallations,
};
