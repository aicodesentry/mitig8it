-- Uninstalling the App deletes every stored row for that installation.
--
-- `installation.deleted` marks the installation immediately: `deleted_at` stops all
-- processing for it, and `purge_after` schedules the deletion for 24 hours later. The
-- grace period is what makes an accidental uninstall recoverable, and a reinstall of
-- the same GitHub installation id inside it cancels the purge by clearing both columns.
--
-- The reconciler runs the purge after `purge_after`. It deletes in dependency order,
-- keeps one audit_logs row with the per-table counts, and deletes the installation row
-- last.

ALTER TABLE installations ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE installations ADD COLUMN IF NOT EXISTS purge_after TIMESTAMPTZ;

-- The reconciler's claim query: the few installations whose grace period has expired.
CREATE INDEX IF NOT EXISTS idx_installations_purge_due
  ON installations (purge_after)
  WHERE purge_after IS NOT NULL;

-- Every worker and reconciler query joins this to skip a deleted installation, so the
-- partial index is the one that matters: live installations are the common case.
CREATE INDEX IF NOT EXISTS idx_installations_live
  ON installations (id)
  WHERE deleted_at IS NULL;

-- Rows already marked deleted before this migration never got a timestamp. Give them
-- one so they are purged on the same schedule as everything after it, rather than
-- staying invisible to both the workers and the purge.
UPDATE installations
   SET deleted_at = COALESCE(deleted_at, updated_at, NOW()),
       purge_after = COALESCE(purge_after, COALESCE(updated_at, NOW()) + INTERVAL '24 hours')
 WHERE status = 'deleted' AND deleted_at IS NULL;
