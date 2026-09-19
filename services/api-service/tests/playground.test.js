const request = require('supertest');
const jwt = require('jsonwebtoken');

jest.mock('../src/config/database', () => ({
  pool: { query: jest.fn() },
  transaction: jest.fn(),
}));
jest.mock('../src/services/prAnalysisOrchestrator', () => ({
  callAnalysisTier: jest.fn(), notifyAnalysisQueued: jest.fn(),
}));
const { pool, transaction } = require('../src/config/database');
const { callAnalysisTier } = require('../src/services/prAnalysisOrchestrator');
const { createApp } = require('../src/app');
const userId = '12345678-1234-4234-8234-123456789abc';
const client = { query: jest.fn() };
let token;

beforeEach(() => {
  jest.clearAllMocks();
  process.env.JWT_SECRET = 'playground-test-secret';
  token = jwt.sign({ user_id: userId }, process.env.JWT_SECRET);
  transaction.mockImplementation(fn => fn(client));
  client.query.mockResolvedValue({ rows: [{ count: 0 }], rowCount: 1 });
  pool.query.mockResolvedValue({ rows: [{ count: 1 }], rowCount: 1 });
  callAnalysisTier.mockResolvedValue({ findings: [] });
});

test('requires authentication before interactive analysis', async () => {
  const res = await request(createApp()).post('/api/analysis/analyze').send({ code: 'x = 1', language: 'python' });
  expect(res.status).toBe(401);
  expect(callAnalysisTier).not.toHaveBeenCalled();
});

test('analyzes a full source file through internal tiers and returns the UI contract', async () => {
  callAnalysisTier.mockResolvedValueOnce({ findings: [{ rule_id: 'eval', severity: 'critical', confidence: 0.9,
    line_start: 2, title: 'Unsafe eval', description: 'User code execution', code_snippet: 'eval(value)', remediation: 'Use safe parsing' }] });
  const res = await request(createApp()).post('/api/analysis/analyze').auth(token, { type: 'bearer' })
    .send({ code: 'value = input()\neval(value)', language: 'python', file_path: '../../escape.py' });
  expect(res.status).toBe(200);
  expect(res.body).toMatchObject({ status: 'completed', total_vulnerabilities: 1, critical_count: 1,
    vulnerabilities: [{ line_number: 2, code_snippet: 'eval(value)', confidence: 0.9 }] });
  expect(callAnalysisTier.mock.calls[1][1].files[0]).toMatchObject({ path: 'playground.py', content: 'value = input()\neval(value)' });
  expect(client.query.mock.calls.some(([, args]) => args?.includes(userId))).toBe(true);
});

test('rejects unsupported language or oversized source before reserving work', async () => {
  for (const body of [{ code: 'x', language: 'unknown' }, { code: 'x'.repeat(100001), language: 'python' }]) {
    const res = await request(createApp()).post('/api/analysis/analyze').auth(token, { type: 'bearer' }).send(body);
    expect(res.status).toBe(400);
  }
  expect(transaction).not.toHaveBeenCalled();
});

test('rejects exhausted server-side quota without calling the scanner', async () => {
  client.query.mockResolvedValue({ rows: [{ count: 5 }], rowCount: 1 });
  const res = await request(createApp()).post('/api/analysis/analyze').auth(token, { type: 'bearer' })
    .send({ code: 'x = 1', language: 'python' });
  expect(res.status).toBe(429);
  expect(res.body.code).toBe('DAILY_LIMIT');
  expect(callAnalysisTier).not.toHaveBeenCalled();
});

test('does not return a successful result when a required tier fails', async () => {
  callAnalysisTier.mockRejectedValue(new Error('service unavailable'));
  const res = await request(createApp()).post('/api/analysis/analyze').auth(token, { type: 'bearer' })
    .send({ code: 'eval(input())', language: 'python' });
  expect(res.status).toBe(502);
  expect(res.body.status).not.toBe('completed');
  expect(pool.query.mock.calls.some(([sql]) => sql.includes("status = 'failed'"))).toBe(true);
});

test('history queries are scoped to the authenticated user', async () => {
  pool.query.mockResolvedValue({ rows: [], rowCount: 0 });
  const res = await request(createApp()).get('/api/analysis/history?user_id=someone-else&limit=999')
    .auth(token, { type: 'bearer' });
  expect(res.status).toBe(200);
  expect(pool.query.mock.calls[0][1]).toEqual([userId, 20]);
});

test('health checks the analysis transport rather than merely the API process', async () => {
  callAnalysisTier.mockRejectedValue(new Error('analysis offline'));
  const res = await request(createApp()).get('/api/analysis/health').auth(token, { type: 'bearer' });
  expect(res.status).toBe(503);
});

test('health rejects a malformed successful HTTP response from the scanner', async () => {
  callAnalysisTier.mockResolvedValue({ error: 'incomplete' });
  const res = await request(createApp()).get('/api/analysis/health').auth(token, { type: 'bearer' });
  expect(res.status).toBe(503);
});
