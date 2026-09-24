const request = require('supertest');
const jwt = require('jsonwebtoken');

jest.mock('../src/config/database', () => ({
  pool: { query: jest.fn() },
  transaction: jest.fn(),
}));

jest.mock('../src/db/qualityMetrics', () => ({
  installationIdsForUser: jest.fn(),
  userCanReadRepository: jest.fn(),
  readWindow: jest.fn(),
}));

const qualityMetricsDb = require('../src/db/qualityMetrics');
const { createApp } = require('../src/app');

const JWT_SECRET = 'test-jwt-secret';
process.env.JWT_SECRET = JWT_SECRET;

const REPOSITORY_ID = '11111111-2222-3333-4444-555555555555';

function authToken(userId = 'user-uuid-1') {
  return jwt.sign({ user_id: userId, github_id: 123, github_username: 'testuser' }, JWT_SECRET);
}

function get(path) {
  return request(createApp()).get(path).set('Authorization', `Bearer ${authToken()}`);
}

function daily(overrides = {}) {
  return {
    installation_id: '42', repository_id: null, rule_id: null, day: '2026-09-20',
    findings_new: 0, fixes_published: 0, applied_in_app: 0, applied_on_github: 0,
    dismissed: 0, accepted_risk: 0, suppressed: 0, thread_resolved: 0,
    thread_resolved_without_fix: 0, fixed_by_reanalysis: 0, residual_after_apply: 0,
    ...overrides,
  };
}

beforeEach(() => {
  jest.clearAllMocks();
  qualityMetricsDb.installationIdsForUser.mockResolvedValue(['42']);
  qualityMetricsDb.userCanReadRepository.mockResolvedValue(true);
  qualityMetricsDb.readWindow.mockResolvedValue([]);
});

describe('GET /api/reports/quality', () => {
  test('returns the three rates computed from the rows of the window', async () => {
    qualityMetricsDb.readWindow.mockImplementation(async ({ byRule }) => (byRule ? [] : [
      daily({ findings_new: 20, fixes_published: 10, applied_in_app: 4, applied_on_github: 1, dismissed: 5, residual_after_apply: 1 }),
    ]));

    const res = await get('/api/reports/quality?window=30');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.window).toBe(30);
    expect(res.body.overall.apply_rate).toBe(0.5);
    expect(res.body.overall.dismiss_rate).toBe(0.25);
    expect(res.body.overall.residual_rate).toBe(0.2);
  });

  test('reports a rate with no denominator as null rather than zero', async () => {
    const res = await get('/api/reports/quality?window=7');

    expect(res.status).toBe(200);
    expect(res.body.overall.apply_rate).toBeNull();
    expect(res.body.overall.dismiss_rate).toBeNull();
    expect(res.body.overall.residual_rate).toBeNull();
  });

  test('defaults to the 30 day window', async () => {
    await get('/api/reports/quality');
    expect(qualityMetricsDb.readWindow).toHaveBeenCalledWith(expect.objectContaining({ days: 30 }));
  });

  test('refuses a window the roll-up does not answer', async () => {
    const res = await get('/api/reports/quality?window=90');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid window');
    expect(qualityMetricsDb.readWindow).not.toHaveBeenCalled();
  });

  test('groups and ranks the rules by dismiss rate, then by how often they fired', async () => {
    qualityMetricsDb.readWindow.mockImplementation(async ({ byRule }) => (byRule ? [
      daily({ rule_id: 'quiet', findings_new: 10, dismissed: 1 }),
      daily({ rule_id: 'noisy', findings_new: 4, dismissed: 3 }),
      daily({ rule_id: 'noisy', findings_new: 6, dismissed: 3 }),
    ] : []));

    const res = await get('/api/reports/quality?window=30');

    expect(res.status).toBe(200);
    expect(res.body.by_rule.map((rule) => rule.rule_id)).toEqual(['noisy', 'quiet']);
    // The two 'noisy' days are summed before the rate is taken, never averaged.
    expect(res.body.by_rule[0].findings_new).toBe(10);
    expect(res.body.by_rule[0].dismiss_rate).toBe(0.6);
  });

  test('returns at most twenty rules', async () => {
    qualityMetricsDb.readWindow.mockImplementation(async ({ byRule }) => (byRule
      ? Array.from({ length: 30 }, (_, index) => daily({ rule_id: `rule-${index}`, findings_new: 10, dismissed: index % 10 }))
      : []));

    const res = await get('/api/reports/quality?window=30');
    expect(res.body.by_rule).toHaveLength(20);
  });

  test('reads the repository grain when a repository is named', async () => {
    await get(`/api/reports/quality?window=7&repository_id=${REPOSITORY_ID}`);
    expect(qualityMetricsDb.readWindow).toHaveBeenCalledWith(
      expect.objectContaining({ repositoryId: REPOSITORY_ID, days: 7 })
    );
  });

  test('reads the installation grain when no repository is named', async () => {
    await get('/api/reports/quality?window=7');
    expect(qualityMetricsDb.readWindow).toHaveBeenCalledWith(expect.objectContaining({ repositoryId: null }));
  });

  test('scopes every read to the installations the caller can reach', async () => {
    qualityMetricsDb.installationIdsForUser.mockResolvedValue(['7', '9']);
    await get('/api/reports/quality?window=30');
    expect(qualityMetricsDb.installationIdsForUser).toHaveBeenCalledWith('user-uuid-1');
    for (const call of qualityMetricsDb.readWindow.mock.calls) {
      expect(call[0].installationIds).toEqual(['7', '9']);
    }
  });

  test('returns an empty report, not an unscoped one, when the caller reaches no installation', async () => {
    qualityMetricsDb.installationIdsForUser.mockResolvedValue([]);
    const res = await get('/api/reports/quality?window=30');

    expect(res.status).toBe(200);
    expect(res.body.overall.apply_rate).toBeNull();
    expect(res.body.by_rule).toEqual([]);
    expect(qualityMetricsDb.readWindow).not.toHaveBeenCalled();
  });

  test('refuses a repository the caller cannot reach', async () => {
    qualityMetricsDb.userCanReadRepository.mockResolvedValue(false);
    const res = await get(`/api/reports/quality?window=30&repository_id=${REPOSITORY_ID}`);

    expect(res.status).toBe(404);
    expect(qualityMetricsDb.readWindow).not.toHaveBeenCalled();
  });

  test('rejects a repository id that is not a UUID', async () => {
    const res = await get('/api/reports/quality?window=30&repository_id=not-a-uuid');
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Invalid repository ID');
  });

  test('returns 401 without auth', async () => {
    const res = await request(createApp()).get('/api/reports/quality');
    expect(res.status).toBe(401);
  });

  test('answers 500 rather than leaking the database error', async () => {
    qualityMetricsDb.readWindow.mockRejectedValue(new Error('relation does not exist'));
    const res = await get('/api/reports/quality?window=30');

    expect(res.status).toBe(500);
    expect(JSON.stringify(res.body)).not.toContain('relation does not exist');
  });
});
