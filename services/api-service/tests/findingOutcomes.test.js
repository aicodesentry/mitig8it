jest.mock('../src/config/database', () => ({ pool: { query: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }));

const { pool } = require('../src/config/database');
const logger = require('../src/utils/logger');
const findingOutcomes = require('../src/db/findingOutcomes');

// A client that behaves like the table: the replay key is unique, so a second insert of
// the same fact returns no row exactly as ON CONFLICT DO NOTHING does.
function replayAwareClient() {
  const keys = new Set();
  const rows = [];
  return {
    rows,
    query: jest.fn(async (sql, params = []) => {
      if (sql.includes('SELECT installation_id FROM repositories')) {
        return { rowCount: 1, rows: [{ installation_id: 77 }] };
      }
      if (sql.includes('INSERT INTO finding_outcomes')) {
        const [, , , findingId, fingerprint, , , , , , outcome, source, , , , , , , externalId] = params;
        const key = [findingId || 'none', fingerprint, outcome, source, externalId || ''].join('|');
        if (keys.has(key)) return { rowCount: 0, rows: [] };
        keys.add(key);
        rows.push(params);
        return { rowCount: 1, rows: [{ id: `outcome-${keys.size}` }] };
      }
      return { rowCount: 0, rows: [] };
    }),
  };
}

const FINDING = {
  id: 'finding-1',
  fingerprint: 'a'.repeat(64),
  rule_id: 'sql.injection.raw_query',
  cwe_id: 'CWE-89',
  severity: 'high',
  confidence: 0.91,
  category: 'SQL injection',
  repository_id: 'repo-1',
  installation_id: 77,
  pull_request_id: 'pr-1',
};

beforeEach(() => {
  jest.clearAllMocks();
});

describe('recordOutcome', () => {
  test('appends once and ignores the replay of the same fact', async () => {
    const client = replayAwareClient();
    const outcome = {
      ...findingOutcomes.identityOf(FINDING),
      outcome: 'dismissed',
      source: 'workspace',
      reason: 'not_exploitable',
    };

    expect(await findingOutcomes.recordOutcome(client, outcome)).toBe('outcome-1');
    expect(await findingOutcomes.recordOutcome(client, outcome)).toBeNull();
    expect(client.rows).toHaveLength(1);
  });

  test('separates outcomes that differ only by their external id', async () => {
    const client = replayAwareClient();
    const base = { ...findingOutcomes.identityOf(FINDING), outcome: 'applied_on_github', source: 'github_push' };

    expect(await findingOutcomes.recordOutcome(client, { ...base, externalId: 'sha-1' })).toBeTruthy();
    expect(await findingOutcomes.recordOutcome(client, { ...base, externalId: 'sha-2' })).toBeTruthy();
    expect(await findingOutcomes.recordOutcome(client, { ...base, externalId: 'sha-1' })).toBeNull();
    expect(client.rows).toHaveLength(2);
  });

  test('copies the finding identity onto the row', async () => {
    const client = replayAwareClient();
    await findingOutcomes.recordOutcome(client, {
      ...findingOutcomes.identityOf(FINDING),
      outcome: 'fix_published',
      source: 'remediation',
      candidateId: 'candidate-1',
      jobId: 'job-1',
      externalId: 'candidate-1',
    });

    const [row] = client.rows;
    expect(row[0]).toBe('77');
    expect(row[1]).toBe('repo-1');
    expect(row[2]).toBe('pr-1');
    expect(row[3]).toBe('finding-1');
    expect(row[5]).toBe('sql.injection.raw_query');
    expect(row[6]).toBe('CWE-89');
    expect(row[9]).toBe('SQL injection');
    expect(row[10]).toBe('fix_published');
    expect(row[11]).toBe('remediation');
  });

  test('resolves a missing installation from the repository', async () => {
    const client = replayAwareClient();
    await findingOutcomes.recordOutcome(client, {
      ...findingOutcomes.identityOf({ ...FINDING, installation_id: null }),
      outcome: 'suppressed',
      source: 'suppression',
    });

    expect(client.query).toHaveBeenCalledWith(
      expect.stringContaining('SELECT installation_id FROM repositories'), ['repo-1']
    );
    expect(client.rows[0][0]).toBe('77');
  });

  test('skips rather than throws when the row has no repository or fingerprint', async () => {
    const client = replayAwareClient();
    expect(await findingOutcomes.recordOutcome(client, {
      findingId: 'finding-1', outcome: 'dismissed', source: 'workspace',
    })).toBeNull();
    expect(client.rows).toHaveLength(0);
    expect(logger.warn).toHaveBeenCalled();
  });

  test('refuses an outcome or a source the log does not define', async () => {
    const client = replayAwareClient();
    await expect(findingOutcomes.recordOutcome(client, { outcome: 'invented', source: 'workspace' }))
      .rejects.toThrow(/Unknown finding outcome/);
    await expect(findingOutcomes.recordOutcome(client, { outcome: 'dismissed', source: 'telepathy' }))
      .rejects.toThrow(/Unknown finding outcome source/);
  });

  test('falls back to the pool when no transaction client is given', async () => {
    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ id: 'outcome-pool' }] });
    const id = await findingOutcomes.recordOutcome(null, {
      ...findingOutcomes.identityOf(FINDING), outcome: 'reopened', source: 'workspace',
    });
    expect(id).toBe('outcome-pool');
    expect(pool.query).toHaveBeenCalled();
  });
});

describe('recordOutcomesForFindings', () => {
  test('records one row per finding and leaves absent common fields to the finding', async () => {
    const client = replayAwareClient();
    const second = { ...FINDING, id: 'finding-2', fingerprint: 'b'.repeat(64) };

    const ids = await findingOutcomes.recordOutcomesForFindings(client, [FINDING, second], {
      outcome: 'fixed_by_reanalysis',
      source: 'reanalysis',
      commitSha: undefined,
      externalId: 'run-1',
    });

    expect(ids).toHaveLength(2);
    expect(client.rows.map((row) => row[3])).toEqual(['finding-1', 'finding-2']);
    expect(client.rows.every((row) => row[1] === 'repo-1')).toBe(true);
  });

  test('a replayed run records nothing new', async () => {
    const client = replayAwareClient();
    const common = { outcome: 'fixed_by_reanalysis', source: 'reanalysis', externalId: 'run-1' };
    await findingOutcomes.recordOutcomesForFindings(client, [FINDING], common);
    const second = await findingOutcomes.recordOutcomesForFindings(client, [FINDING], common);
    expect(second).toHaveLength(0);
    expect(client.rows).toHaveLength(1);
  });
});

describe('normalizeDismissalReason', () => {
  test('maps the legacy and spoken phrasings onto the enum', () => {
    expect(findingOutcomes.normalizeDismissalReason('false_positive')).toBe('not_exploitable');
    expect(findingOutcomes.normalizeDismissalReason('False Positive')).toBe('not_exploitable');
    expect(findingOutcomes.normalizeDismissalReason('test code')).toBe('test_or_sample_code');
    expect(findingOutcomes.normalizeDismissalReason('wrong_rule_match')).toBe('wrong_rule_match');
  });

  test('uses the fallback for anything it does not recognise', () => {
    expect(findingOutcomes.normalizeDismissalReason('because I said so')).toBe('other');
    expect(findingOutcomes.normalizeDismissalReason('nonsense', null)).toBeNull();
    expect(findingOutcomes.normalizeDismissalReason(null, null)).toBeNull();
  });
});
