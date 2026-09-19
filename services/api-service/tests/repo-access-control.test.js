const request = require('supertest');
const jwt = require('jsonwebtoken');

jest.mock('../src/config/database', () => ({
  pool: { query: jest.fn() },
  transaction: jest.fn(),
}));

const { pool, transaction } = require('../src/config/database');
const { createApp } = require('../src/app');

const JWT_SECRET = 'test-jwt-secret';
process.env.JWT_SECRET = JWT_SECRET;

function tokenFor(userId) {
  return jwt.sign({ user_id: userId, github_id: 123, github_username: 'user' }, JWT_SECRET);
}

const USER_A = 'user-a-uuid';
const USER_B = 'user-b-uuid';

beforeEach(() => jest.clearAllMocks());

describe('Repository access control', () => {
  test('user only sees repos they can access', async () => {
    pool.query.mockResolvedValueOnce({
      rows: [
        { id: 'repo-1', full_name: 'userA/repo1' },
      ],
    });

    const app = createApp();
    const res = await request(app)
      .get('/api/repositories')
      .set('Authorization', `Bearer ${tokenFor(USER_A)}`);

    expect(res.status).toBe(200);
    expect(res.body.repositories).toHaveLength(1);
    expect(res.body.repositories[0].full_name).toBe('userA/repo1');

    // Verify query uses repository_access
    const queryCall = pool.query.mock.calls[0];
    expect(queryCall[0]).toContain('repository_access');
    expect(queryCall[1]).toContain(USER_A);
  });

  test('user cannot access another user repo by ID', async () => {
    pool.query.mockResolvedValueOnce({ rowCount: 0, rows: [] });

    const app = createApp();
    const res = await request(app)
      .get('/api/repositories/repo-owned-by-other')
      .set('Authorization', `Bearer ${tokenFor(USER_B)}`);

    expect(res.status).toBe(404);
  });

  test('user cannot connect another user repo', async () => {
    pool.query.mockResolvedValueOnce({ rowCount: 0, rows: [] });

    const app = createApp();
    const res = await request(app)
      .post('/api/repositories/repo-owned-by-other/connect')
      .set('Authorization', `Bearer ${tokenFor(USER_B)}`);

    expect(res.status).toBe(404);
  });

  test('user cannot disconnect another user repo', async () => {
    pool.query.mockResolvedValueOnce({ rowCount: 0, rows: [] });

    const app = createApp();
    const res = await request(app)
      .post('/api/repositories/repo-owned-by-other/disconnect')
      .set('Authorization', `Bearer ${tokenFor(USER_B)}`);

    expect(res.status).toBe(404);
  });

  test('user cannot update baseline on another user repo', async () => {
    pool.query.mockResolvedValueOnce({ rowCount: 0, rows: [] });

    const app = createApp();
    const res = await request(app)
      .patch('/api/repositories/repo-owned-by-other/baseline')
      .set('Authorization', `Bearer ${tokenFor(USER_B)}`)
      .send({ enabled: true });

    expect(res.status).toBe(404);
  });

  test('getById scopes by repository_access', async () => {
    pool.query
      .mockResolvedValueOnce({
        rowCount: 1,
        rows: [{ id: 'repo-1', full_name: 'userA/repo1' }],
      })
      .mockResolvedValueOnce({
        rows: [{ open_findings: 0, dismissed_findings: 0, accepted_risk_findings: 0, critical_open: 0, high_open: 0 }],
      });

    const app = createApp();
    const res = await request(app)
      .get('/api/repositories/repo-1')
      .set('Authorization', `Bearer ${tokenFor(USER_A)}`);

    expect(res.status).toBe(200);

    // Verify query uses repository_access, not legacy owner scoping
    const queryCall = pool.query.mock.calls[0];
    expect(queryCall[0]).toContain('repository_access');
  });
});

describe('PR webhook repository access', () => {
  test('upserts repository history without granting linked installation users access', async () => {
    const { createHmac } = require('crypto');
    process.env.GITHUB_WEBHOOK_SECRET = 'fixture-webhook-secret';
    const client = { query: jest.fn(async (sql) => {
      if (sql.includes('INSERT INTO webhook_deliveries')) return { rowCount: 1, rows: [{ delivery_id: 'access-test' }] };
      if (sql.includes('SELECT id, baseline_set')) return { rowCount: 1, rows: [{ id: 'repo-1', baseline_set: false, is_active: false }] };
      if (sql.includes('INSERT INTO pull_requests')) return { rowCount: 1, rows: [{ id: 'pr-1' }] };
      if (sql.includes('user_installations')) return { rowCount: 1, rows: [{ user_id: USER_A }] };
      return { rowCount: 1, rows: [{ id: 'repo-1' }] };
    }) };
    transaction.mockImplementation(fn => fn(client));
    const payload = JSON.stringify({ action: 'opened', installation: { id: 42 },
      repository: { id: 999, name: 'private', full_name: 'org/private', private: true },
      pull_request: { id: 777, number: 1, title: 'Fixture', state: 'open',
        head: { sha: 'a'.repeat(40), ref: 'branch' }, base: { sha: 'b'.repeat(40), ref: 'main' } } });
    const response = await request(createApp()).post('/webhooks/github')
      .set('Content-Type', 'application/json').set('x-github-event', 'pull_request')
      .set('x-github-delivery', 'access-test')
      .set('x-hub-signature-256', `sha256=${createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET).update(payload).digest('hex')}`)
      .send(payload);
    expect(response.status).toBe(200);
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO repositories'), expect.any(Array));
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO pull_requests'), expect.any(Array));
    expect(client.query).not.toHaveBeenCalledWith(expect.stringContaining('INSERT INTO repository_access'), expect.anything());
  });
});
