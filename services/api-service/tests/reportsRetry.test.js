const request = require('supertest');
const jwt = require('jsonwebtoken');
jest.mock('../src/config/database', () => ({ pool: { query: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/db/analysisRuns', () => ({ getAnalysisById: jest.fn() }));
jest.mock('../src/services/prAnalysisOrchestrator', () => ({ notifyAnalysisQueued: jest.fn() }));
const { pool } = require('../src/config/database');
const runs = require('../src/db/analysisRuns');
const { createApp } = require('../src/app');

test('retry creates a new attempt and leaves failed report history unchanged', async () => {
  process.env.JWT_SECRET = 'retry-fixture';
  runs.getAnalysisById.mockResolvedValue({ id: 'old', status: 'failed' });
  pool.query.mockResolvedValueOnce({ rows: [{ id: 'old', status: 'failed', repository_id: 'repo',
    pull_request_id: 'pr', pr_number: 1, commit_sha: 'a'.repeat(40), is_active: true }] })
    .mockResolvedValueOnce({ rows: [{ id: 'new' }] });
  const response = await request(createApp()).post('/api/reports/pr-analyses/old/retry')
    .auth(jwt.sign({ user_id: 'fixture' }, 'retry-fixture'), { type: 'bearer' });
  expect(response.status).toBe(200);
  expect(response.body.analysis_run_id).toBe('new');
  expect(pool.query.mock.calls.some(([sql]) => sql.includes('UPDATE analysis_runs'))).toBe(false);
  expect(pool.query.mock.calls.some(([sql]) => sql.includes('INSERT INTO analysis_runs'))).toBe(true);
});
