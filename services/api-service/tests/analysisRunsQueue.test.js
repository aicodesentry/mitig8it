jest.mock('../src/config/database', () => ({
  pool: {
    query: jest.fn(),
    connect: jest.fn(),
  },
}));

const { pool } = require('../src/config/database');
const analysisRuns = require('../src/db/analysisRuns');

describe('analysis run queue', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  const queuedRun = { analysis_run_id: 'run-1', repository_id: 'repo-1', pull_request_number: 7 };
  let client;
  const prepare = (candidates = [queuedRun], locks = [true]) => {
    pool.query.mockResolvedValue({ rows: candidates.length ? [candidates[0]] : [] });
    client = { query: jest.fn(async (sql) => {
      if (sql.includes('SELECT candidate.id')) return { rows: candidates.length ? [candidates.shift()] : [] };
      if (sql.includes('pg_try_advisory_lock')) return { rows: [{ acquired: locks.shift() }] };
      if (sql.includes('pg_advisory_unlock')) return { rows: [{ unlocked: true }] };
      if (sql.includes('UPDATE analysis_runs')) return { rows: [{ ...queuedRun }] };
      return { rows: [] };
    }), release: jest.fn() };
    pool.connect.mockResolvedValue(client);
  };

  test('holds a per-PR session lease after committing the claim until explicitly released', async () => {
    prepare();
    const result = await analysisRuns.claimNextQueuedRun(10);
    expect(result).toEqual(queuedRun);
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('FOR UPDATE OF candidate SKIP LOCKED'), [10, []]);
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('pg_try_advisory_lock'), ['analysis-pr:repo-1:7']);
    expect(client.query).toHaveBeenCalledWith('COMMIT');
    expect(client.release).not.toHaveBeenCalled();
    expect(Object.keys(result)).not.toContain('releaseLease');
    await Promise.all([result.releaseLease(), result.releaseLease()]);
    expect(client.query.mock.calls.filter(([sql]) => sql.includes('pg_advisory_unlock'))).toHaveLength(1);
    expect(client.release).toHaveBeenCalledTimes(1);
  });

  test('skips a candidate whose PR is still leased, including stale live runs', async () => {
    prepare([{ ...queuedRun, analysis_run_id: 'busy' }, queuedRun], [false, true]);
    const result = await analysisRuns.claimNextQueuedRun();
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('FOR UPDATE OF candidate SKIP LOCKED'), [20, ['busy']]);
    expect(client.query.mock.calls.filter(([sql]) => sql.includes('UPDATE analysis_runs'))).toHaveLength(1);
    await result.releaseLease();
  });

  test('falls back to default threshold and releases an empty queue connection', async () => {
    prepare([]);
    await expect(analysisRuns.claimNextQueuedRun('abc')).resolves.toBeNull();
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('FOR UPDATE OF candidate SKIP LOCKED'), [20, []]);
    expect(client.release).toHaveBeenCalledTimes(1);
  });

  test('destroys the retained connection when unlocking fails', async () => {
    prepare();
    const result = await analysisRuns.claimNextQueuedRun();
    client.query.mockRejectedValueOnce(new Error('connection lost'));
    await expect(result.releaseLease()).rejects.toThrow('connection lost');
    expect(client.release).toHaveBeenCalledWith(expect.any(Error));
  });

  test('destroys a connection on claim failure so session locks cannot leak', async () => {
    prepare();
    client.query.mockRejectedValueOnce(new Error('claim failed'));
    await expect(analysisRuns.claimNextQueuedRun()).rejects.toThrow('claim failed');
    expect(client.release).toHaveBeenCalledWith(expect.any(Error));
  });

  test('destroys the session if updating a locked candidate fails', async () => {
    prepare();
    const query = client.query.getMockImplementation();
    client.query.mockImplementation(async (...args) => {
      if (args[0].includes('UPDATE analysis_runs')) throw new Error('write failed');
      return query(...args);
    });
    await expect(analysisRuns.claimNextQueuedRun()).rejects.toThrow('write failed');
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('pg_try_advisory_lock'), expect.any(Array));
    expect(client.release).toHaveBeenCalledWith(expect.any(Error));
  });

  test('releases the empty claim when every candidate belongs to a leased PR', async () => {
    prepare([queuedRun], [false]);
    await expect(analysisRuns.claimNextQueuedRun()).resolves.toBeNull();
    expect(client.query.mock.calls.some(([sql]) => sql.includes('UPDATE analysis_runs'))).toBe(false);
    expect(client.release).toHaveBeenCalledTimes(1);
  });

  test('only claims a pending run once its retry delay has elapsed', async () => {
    prepare();
    await analysisRuns.claimNextQueuedRun();
    const [candidateSql] = client.query.mock.calls.find(([sql]) => sql.includes('SELECT candidate.id'));
    expect(candidateSql).toContain("candidate.status = 'pending'");
    expect(candidateSql).toContain('COALESCE(candidate.not_before, candidate.created_at) <= NOW()');
  });

  test('re-queues a transient failure as a new delayed attempt without losing the failed run', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ id: 'retry-1', auto_retry_count: 2, not_before: null }] });

    await expect(analysisRuns.requeueAfterTransientFailure('run-1', {
      errorMessage: 'Metadata token request timed out',
      delayMs: 60_000,
    })).resolves.toEqual({ id: 'retry-1', auto_retry_count: 2, not_before: null });

    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toContain("SET status = 'failed'");
    expect(sql).toContain('INSERT INTO analysis_runs');
    expect(sql).toContain("'pending', 'auto_retry'");
    expect(sql).toContain('auto_retry_count + 1');
    expect(params).toEqual(['run-1', 'Metadata token request timed out', 60_000]);
  });

  test('re-queue reports nothing when the run was already failed', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });
    await expect(analysisRuns.requeueAfterTransientFailure('run-1', {
      errorMessage: 'gone', delayMs: 'not-a-number',
    })).resolves.toBeNull();
    expect(pool.query.mock.calls[0][1][2]).toBe(0);
  });

  test('returns normalized queue stats', async () => {
    pool.query.mockResolvedValueOnce({
      rows: [{
        pending: '3',
        running: '1',
        failed: '2',
        oldest_pending_seconds: '90',
      }],
    });

    await expect(analysisRuns.getQueueStats()).resolves.toEqual({
      pending: 3,
      running: 1,
      failed: 2,
      oldest_pending_seconds: 90,
    });
  });
});
