# Data retention

Uninstalling the App deletes all stored data for that installation within 24 hours.

## What happens on uninstall

GitHub sends `installation` with action `deleted`. In the same transaction as the
webhook delivery record, the API:

1. sets `installations.status = 'deleted'`,
2. sets `installations.deleted_at = NOW()`, which stops all processing for that
   installation, and
3. sets `installations.purge_after = NOW() + 24 hours`, which schedules the deletion.

`deleted_at` is a hard stop, not a hint. The remediation job claim, the outbox dispatch,
the analysis queue claim and the repository profiling claim all skip an installation
whose `deleted_at` is set, so nothing analyses, repairs or publishes for data that is
about to be deleted.

## The grace period

The 24 hours exist so an accidental uninstall is recoverable. If GitHub sends
`installation` with action `created` (or `unsuspend`) for the same GitHub installation
id inside the window, the API clears `deleted_at` and `purge_after` and no data is
deleted. The installation becomes live again for every worker in the same transaction.

Marking an installation deleted also fires the existing
`revoke_inactive_installation_access` trigger, which revokes the derived
`repository_access` and `user_installations` rows. Those hold no review data and are
re-derived from GitHub on the next installation sync, so a reinstall recovers them.

`INSTALLATION_PURGE_GRACE_HOURS` changes the window. `0` purges on the next sweep.

## The purge

The purge runs from the API's own sweep (every 15 minutes by default,
`INSTALLATION_PURGE_SWEEP_MS`) and from the remediation reconciler. Both call the same
function, which locks the installation row and re-reads `purge_after` under that lock,
so a reinstall that lands after a purge was claimed still wins and two runners never
duplicate work.

Everything for one installation is deleted in one transaction. A partial purge would
leave rows whose parents are gone and no honest count to record. Deletion runs in
dependency order, children before parents, because every foreign key to `installations`
is `NO ACTION` or `ON DELETE SET NULL`: nothing cascades on its own, and `repositories`
in particular would be silently orphaned rather than deleted.

The order is:

1. `remediation_job_evidence`, `usage_reservations`, `remediation_attempts`,
   `verification_runs`
2. `merge_intents`, `remediation_writer_leases`, `remediation_actions`
3. `repair_memory`, `remediation_candidates`, `remediation_jobs`
4. `workflow_outbox`, `workflow_events`
5. `analysis_run_findings`, `suppressions`, `findings`, `analysis_runs`, `analysis`,
   `pull_requests`
6. `audit_logs` and `webhook_events` for that installation's repositories, explicitly,
   because their foreign key only nulls the reference
7. `repository_access`, `repositories`
8. `user_installations`, and `users.installation_id` cleared
9. `installations`, last

The user account itself is never deleted: it belongs to the person, not to the
installation, and a person may have other installations.

## What is kept

One `audit_logs` row, action `installation.purged`, with the deleted row count per
table, the installation id and the time. It is written before the installation row is
deleted, so the deletion of that row is itself covered by the record. It carries no
repository reference, because every repository of that installation has just been
deleted, and it is therefore not removed by the `audit_logs` step above.

Nothing else survives. `webhook_deliveries` rows carry no tenant column and hold only a
delivery id, event type and status; they are not scoped to an installation and are aged
out by their own retention, not by the purge.

## Tests

- `services/api-service/tests/installationPurge.test.js` covers the deletion ordering,
  the single transaction, the audit row and the grace-period cancellation.
- `services/api-service/tests/integration/installation-purge.integration.js` seeds one
  installation across every table the purge touches plus a second installation with the
  same shape, purges the first, and asserts zero rows remain for it and that the second
  is untouched. Run it with
  `NODE_ENV=test DATABASE_URL=postgres://.../mitig8it_purge_test npm run test:integration:purge`.
