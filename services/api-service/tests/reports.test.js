const request = require('supertest');
const jwt = require('jsonwebtoken');

jest.mock('../src/config/database', () => ({
  pool: { query: jest.fn() },
  transaction: jest.fn(),
}));

jest.mock('../src/db/analysisRuns', () => ({
  listAnalyses: jest.fn(),
  getAnalysisById: jest.fn(),
  querySummary: jest.fn(),
}));

jest.mock('../src/db/findings', () => ({
  listByAnalysisRun: jest.fn(),
  listByPullRequest: jest.fn(),
  listAll: jest.fn(),
  getById: jest.fn(),
  updateStatus: jest.fn(),
}));

const analysisDb = require('../src/db/analysisRuns');
const findingsDb = require('../src/db/findings');
const { createApp } = require('../src/app');

const JWT_SECRET = 'test-jwt-secret';
process.env.JWT_SECRET = JWT_SECRET;

function authToken(userId = 'user-uuid-1') {
  return jwt.sign({ user_id: userId, github_id: 123, github_username: 'testuser' }, JWT_SECRET);
}

describe('GET /api/reports/pr-analyses', () => {
  test('returns analyses list with pagination', async () => {
    analysisDb.listAnalyses.mockResolvedValueOnce({
      rows: [{ id: 'run-1', pr_number: 42, status: 'completed' }],
      total: 1,
    });

    const app = createApp();
    const res = await request(app)
      .get('/api/reports/pr-analyses')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.analyses).toHaveLength(1);
    expect(res.body.total).toBe(1);
  });

  test('validates repository_id format', async () => {
    const app = createApp();
    const res = await request(app)
      .get('/api/reports/pr-analyses?repository_id=not-a-uuid')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Invalid repository ID');
  });

  test('passes filters to DB query', async () => {
    analysisDb.listAnalyses.mockResolvedValueOnce({ rows: [], total: 0 });

    const app = createApp();
    await request(app)
      .get('/api/reports/pr-analyses?status=completed&limit=10&offset=5')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(analysisDb.listAnalyses).toHaveBeenCalledWith(
      'user-uuid-1',
      expect.objectContaining({ status: 'completed', limit: 10, offset: 5 })
    );
  });

  test('returns 401 without auth', async () => {
    const app = createApp();
    const res = await request(app).get('/api/reports/pr-analyses');
    expect(res.status).toBe(401);
  });
});

describe('GET /api/reports/pr-analyses/:analysisId', () => {
  test('returns analysis with findings and severity counts', async () => {
    analysisDb.getAnalysisById.mockResolvedValueOnce({
      id: 'run-1',
      pr_number: 42,
      status: 'completed',
    });
    findingsDb.listByAnalysisRun.mockResolvedValueOnce([
      { id: 'f1', severity: 'critical', title: 'SQL Injection' },
      { id: 'f2', severity: 'high', title: 'XSS' },
      { id: 'f3', severity: 'critical', title: 'Hardcoded secret' },
    ]);

    const app = createApp();
    const res = await request(app)
      .get('/api/reports/pr-analyses/run-1')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(res.status).toBe(200);
    expect(res.body.analysis.total_findings).toBe(3);
    expect(res.body.analysis.severity_counts).toEqual({
      critical: 2, high: 1, medium: 0, low: 0, info: 0,
    });
    expect(res.body.analysis.findings).toHaveLength(3);
  });

  test('returns 404 for non-existent analysis', async () => {
    analysisDb.getAnalysisById.mockResolvedValueOnce(null);

    const app = createApp();
    const res = await request(app)
      .get('/api/reports/pr-analyses/nonexistent')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(res.status).toBe(404);
  });
});

describe('GET /api/reports/summary', () => {
  test('returns summary stats', async () => {
    analysisDb.querySummary.mockResolvedValueOnce({
      total: '25', completed: '20', failed: '3', recent: '8',
    });

    const app = createApp();
    const res = await request(app)
      .get('/api/reports/summary')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(res.status).toBe(200);
    expect(res.body.summary).toEqual({
      total_analyses: 25,
      completed: 20,
      failed: 3,
      recent_7_days: 8,
    });
  });
});
