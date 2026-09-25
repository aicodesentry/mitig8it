// Uninstalling the App deletes every stored row for that installation. These are the
// unit tests for the ordering and the grace period; the integration test in
// tests/integration/installation-purge.integration.js proves it against real Postgres.
jest.mock('../src/config/database', () => ({
  pool: { query: jest.fn(), connect: jest.fn() },
  transaction: jest.fn(),
  query: jest.fn(),
}));

const { pool } = require('../src/config/database');
const purge = require('../src/services/installationPurge');

const INSTALLATION = 4242;

function fakeClient({ purgeAfter = new Date(Date.now() - 1000).toISOString(), exists = true } = {}) {
  const statements = [];
  const client = {
    statements,
    release: jest.fn(),
    query: jest.fn(async (sql, params) => {
      statements.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params });
      if (/FROM installations WHERE id = \$1 FOR UPDATE/.test(sql)) {
        return { rows: exists ? [{ id: INSTALLATION, purge_after: purgeAfter }] : [], rowCount: exists ? 1 : 0 };
      }
      return { rows: [], rowCount: 1 };
    }),
  };
  return client;
}

// The tables a delete was issued against, in the order they were issued.
function deletedTables(client) {
  return client.statements
    .map(({ sql }) => /^DELETE FROM (\w+)/.exec(sql)?.[1])
    .filter(Boolean);
}

beforeEach(() => {
  jest.clearAllMocks();
  delete process.env.INSTALLATION_PURGE_GRACE_HOURS;
});

describe('deletion ordering', () => {
  test('every table is deleted, children before the parents their rows point at', async () => {
    const client = fakeClient();
    pool.connect.mockResolvedValue(client);
    const result = await purge.purgeInstallation(INSTALLATION);

    expect(result.purged).toBe(true);
    const order = deletedTables(client);
    expect(order).toEqual([...purge.purgeTables(), 'installations']);

    const at = (table) => order.indexOf(table);
    // Each of these foreign keys is NO ACTION or SET NULL, so the order is what makes
    // the deletes succeed rather than fail or silently orphan rows.
    expect(at('merge_intents')).toBeLessThan(at('remediation_actions'));
    expect(at('remediation_actions')).toBeLessThan(at('remediation_jobs'));
    expect(at('remediation_candidates')).toBeLessThan(at('remediation_jobs'));
    expect(at('analysis_run_findings')).toBeLessThan(at('analysis_runs'));
    expect(at('suppressions')).toBeLessThan(at('findings'));
    expect(at('findings')).toBeLessThan(at('analysis_runs'));
    expect(at('analysis_runs')).toBeLessThan(at('pull_requests'));
    expect(at('pull_requests')).toBeLessThan(at('repositories'));
    expect(at('audit_logs')).toBeLessThan(at('repositories'));
    expect(at('repository_access')).toBeLessThan(at('repositories'));
    expect(at('repositories')).toBeLessThan(at('installations'));
    expect(at('user_installations')).toBeLessThan(at('installations'));
    // The installation row is last, so nothing can reference a row that is already gone.
    expect(at('installations')).toBe(order.length - 1);
  });

  test('the whole purge runs in one transaction and sets the tenant scope the RLS tables need', async () => {
    const client = fakeClient();
    pool.connect.mockResolvedValue(client);
    await purge.purgeInstallation(INSTALLATION);

    const sql = client.statements.map((s) => s.sql);
    expect(sql[0]).toBe('BEGIN');
    expect(sql[sql.length - 1]).toBe('COMMIT');
    expect(sql).not.toContain('ROLLBACK');
    expect(sql.some((s) => s.includes("set_config('app.tenant_id'"))).toBe(true);
    expect(sql.some((s) => s.includes("set_config('app.remediation_worker'"))).toBe(true);
    expect(client.release).toHaveBeenCalledTimes(1);
  });

  test('one audit row records the per-table counts and is written before the installation row goes', async () => {
    const client = fakeClient();
    pool.connect.mockResolvedValue(client);
    const result = await purge.purgeInstallation(INSTALLATION);

    const auditIndex = client.statements.findIndex((s) => s.sql.startsWith('INSERT INTO audit_logs'));
    const installationIndex = client.statements.findIndex((s) => s.sql.startsWith('DELETE FROM installations'));
    expect(auditIndex).toBeGreaterThan(-1);
    expect(auditIndex).toBeLessThan(installationIndex);

    const audits = client.statements.filter((s) => s.sql.startsWith('INSERT INTO audit_logs'));
    expect(audits).toHaveLength(1);
    const details = JSON.parse(audits[0].params[0]);
    expect(details.installation_id).toBe(String(INSTALLATION));
    for (const table of purge.purgeTables()) expect(details.counts).toHaveProperty(table);
    expect(details.counts).toHaveProperty('users_unlinked');
    expect(result.counts.installations).toBe(1);
  });

  test('a failure anywhere rolls the whole purge back rather than leaving it half done', async () => {
    const client = fakeClient();
    client.query.mockImplementation(async (sql) => {
      if (/FROM installations WHERE id = \$1 FOR UPDATE/.test(sql)) {
        return { rows: [{ id: INSTALLATION, purge_after: new Date(Date.now() - 1000).toISOString() }], rowCount: 1 };
      }
      if (/^DELETE FROM findings/.test(String(sql).trim())) throw new Error('deadlock detected');
      return { rows: [], rowCount: 0 };
    });
    pool.connect.mockResolvedValue(client);

    await expect(purge.purgeInstallation(INSTALLATION)).rejects.toThrow('deadlock detected');
    expect(client.query).toHaveBeenCalledWith('ROLLBACK');
    expect(client.release).toHaveBeenCalledTimes(1);
  });

  test('every scoped table is covered, and audit_logs and webhook_events are explicit because their FK only nulls', () => {
    const tables = purge.purgeTables();
    for (const table of ['remediation_jobs', 'remediation_candidates', 'remediation_attempts', 'remediation_actions',
      'remediation_writer_leases', 'remediation_job_evidence', 'merge_intents', 'verification_runs',
      'workflow_events', 'workflow_outbox', 'usage_reservations', 'repair_memory',
      'repositories', 'pull_requests', 'analysis_runs', 'analysis_run_findings', 'findings', 'suppressions',
      'audit_logs', 'webhook_events', 'repository_access', 'user_installations']) {
      expect(tables).toContain(table);
    }
  });
});

describe('the grace period', () => {
  test('marking an installation deleted schedules the purge 24 hours out', async () => {
    const client = { query: jest.fn(async () => ({ rows: [{ id: INSTALLATION }], rowCount: 1 })) };
    await purge.markInstallationDeleted(client, INSTALLATION);
    const [sql, params] = client.query.mock.calls[0];
    expect(sql).toMatch(/UPDATE installations/);
    expect(sql).toMatch(/deleted_at = COALESCE\(deleted_at, NOW\(\)\)/);
    expect(sql).toMatch(/purge_after = COALESCE\(purge_after, NOW\(\) \+ /);
    expect(params).toEqual([INSTALLATION, 24]);
  });

  test('a purge is not run while the grace period is still open', async () => {
    const client = fakeClient({ purgeAfter: new Date(Date.now() + 3600_000).toISOString() });
    pool.connect.mockResolvedValue(client);
    const result = await purge.purgeInstallation(INSTALLATION);

    expect(result).toMatchObject({ purged: false, reason: 'grace_period_active' });
    expect(deletedTables(client)).toEqual([]);
    expect(client.query).toHaveBeenCalledWith('COMMIT');
  });

  test('a reinstall inside the grace period cancels the purge', async () => {
    const client = { query: jest.fn(async () => ({ rows: [{ id: INSTALLATION }], rowCount: 1 })) };
    const cancelled = await purge.cancelScheduledPurge(client, INSTALLATION);
    expect(cancelled).toBe(true);
    const [sql] = client.query.mock.calls[0];
    expect(sql).toMatch(/deleted_at = NULL, purge_after = NULL/);
  });

  test('a reinstall that lands after the purge was claimed still wins: nothing is deleted', async () => {
    // cancelScheduledPurge cleared purge_after. The purge re-reads it under FOR UPDATE.
    const client = fakeClient({ purgeAfter: null });
    pool.connect.mockResolvedValue(client);
    const result = await purge.purgeInstallation(INSTALLATION);

    expect(result).toMatchObject({ purged: false, reason: 'purge_cancelled' });
    expect(deletedTables(client)).toEqual([]);
  });

  test('cancelling reports false when there was no scheduled purge to cancel', async () => {
    const client = { query: jest.fn(async () => ({ rows: [], rowCount: 0 })) };
    expect(await purge.cancelScheduledPurge(client, INSTALLATION)).toBe(false);
  });

  test('an installation that no longer exists is not an error', async () => {
    const client = fakeClient({ exists: false });
    pool.connect.mockResolvedValue(client);
    expect(await purge.purgeInstallation(INSTALLATION)).toMatchObject({
      purged: false, reason: 'installation_not_found',
    });
  });

  test('the grace period is configurable but defaults to 24 hours', async () => {
    expect(purge.graceHours()).toBe(24);
    process.env.INSTALLATION_PURGE_GRACE_HOURS = '1';
    expect(purge.graceHours()).toBe(1);
    // A zero grace period is a deliberate operator choice, not a missing value.
    process.env.INSTALLATION_PURGE_GRACE_HOURS = '0';
    expect(purge.graceHours()).toBe(0);
    process.env.INSTALLATION_PURGE_GRACE_HOURS = 'not-a-number';
    expect(purge.graceHours()).toBe(24);
  });
});

describe('the sweep', () => {
  test('one installation failing never stops the others', async () => {
    pool.query.mockResolvedValue({ rows: [{ id: 1 }, { id: 2 }, { id: 3 }], rowCount: 3 });
    let call = 0;
    pool.connect.mockImplementation(async () => {
      call += 1;
      if (call === 2) {
        return {
          release: jest.fn(),
          query: jest.fn(async (sql) => {
            if (/FOR UPDATE/.test(sql)) throw new Error('connection reset');
            return { rows: [], rowCount: 0 };
          }),
        };
      }
      return fakeClient();
    });

    const summary = await purge.purgeDeletedInstallations(10);
    expect(summary).toEqual({ due: 3, purged: 2, skipped: 0, failed: 1 });
  });

  test('only installations whose grace period has expired are selected', async () => {
    pool.query.mockResolvedValue({ rows: [], rowCount: 0 });
    await purge.listInstallationsDueForPurge(5);
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toMatch(/purge_after IS NOT NULL AND purge_after <= NOW\(\)/);
    expect(params).toEqual([5]);
  });
});
