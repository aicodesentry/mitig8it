const request = require('supertest');
const jwt = require('jsonwebtoken');

jest.mock('../src/config/database', () => ({
  pool: { query: jest.fn() },
  transaction: jest.fn(),
}));

jest.mock('../src/db/findings', () => ({
  listByPullRequest: jest.fn(),
  listAll: jest.fn(),
  getById: jest.fn(),
  updateStatus: jest.fn(),
  listByAnalysisRun: jest.fn(),
  getPullRequestForUser: jest.fn(),
}));

const findingsDb = require('../src/db/findings');
const { createApp } = require('../src/app');

const JWT_SECRET = 'test-jwt-secret';
process.env.JWT_SECRET = JWT_SECRET;

function authToken(userId = 'user-uuid-1') {
  return jwt.sign({ user_id: userId, github_id: 123, github_username: 'testuser' }, JWT_SECRET);
}

const MOCK_FINDING = {
  id: 'finding-1',
  title: 'SQL Injection',
  severity: 'critical',
  confidence: 0.92,
  file_path: 'app.py',
  line_start: 10,
  status: 'open',
  cwe_id: 'CWE-89',
};

const ENRICHED_FINDING = {
  ...MOCK_FINDING,
  exploit_scenario: 'An attacker who controls this input can alter the SQL query and read or modify unintended database records.',
  remediation: 'Use parameterized queries and avoid building SQL with string concatenation.',
  remediation_patch: 'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
};

describe('GET /api/findings', () => {
  test('returns all findings for user', async () => {
    findingsDb.listAll.mockResolvedValueOnce([MOCK_FINDING]);

    const app = createApp();
    const res = await request(app)
      .get('/api/findings')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(res.status).toBe(200);
    expect(res.body.findings).toHaveLength(1);
    expect(res.body.findings[0].title).toBe('SQL Injection');
  });

  test('passes filters to query', async () => {
    findingsDb.listAll.mockResolvedValueOnce([]);

    const app = createApp();
    await request(app)
      .get('/api/findings?severity=critical&status=open&category=SQL+injection')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(findingsDb.listAll).toHaveBeenCalledWith(
      'user-uuid-1',
      expect.objectContaining({ severity: 'critical', status: 'open', category: 'SQL injection' })
    );
  });

  test('returns 401 without auth', async () => {
    const app = createApp();
    const res = await request(app).get('/api/findings');
    expect(res.status).toBe(401);
  });
});

describe('GET /api/findings/:id', () => {
  test('returns finding by id', async () => {
    findingsDb.getById.mockResolvedValueOnce(MOCK_FINDING);

    const app = createApp();
    const res = await request(app)
      .get('/api/findings/finding-1')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(res.status).toBe(200);
    expect(res.body.finding.id).toBe('finding-1');
  });

  test('preserves recommendation enrichment fields on read', async () => {
    findingsDb.getById.mockResolvedValueOnce(ENRICHED_FINDING);

    const app = createApp();
    const res = await request(app)
      .get('/api/findings/finding-1')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(res.status).toBe(200);
    expect(res.body.finding.exploit_scenario).toBe(ENRICHED_FINDING.exploit_scenario);
    expect(res.body.finding.remediation).toBe(ENRICHED_FINDING.remediation);
    expect(res.body.finding.remediation_patch).toBe(ENRICHED_FINDING.remediation_patch);
  });

  test('returns 404 for non-existent finding', async () => {
    findingsDb.getById.mockResolvedValueOnce(null);

    const app = createApp();
    const res = await request(app)
      .get('/api/findings/nonexistent')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(res.status).toBe(404);
  });
});

describe('PATCH /api/findings/:id/status', () => {
  test('updates finding status to dismissed', async () => {
    findingsDb.updateStatus.mockResolvedValueOnce({ ...MOCK_FINDING, status: 'dismissed' });

    const app = createApp();
    const res = await request(app)
      .patch('/api/findings/finding-1/status')
      .set('Authorization', `Bearer ${authToken()}`)
      .send({ status: 'dismissed', dismissal_reason: 'False positive' });

    expect(res.status).toBe(200);
    expect(res.body.finding.status).toBe('dismissed');
    // The legacy phrasing maps onto the enum the outcome log records.
    expect(findingsDb.updateStatus).toHaveBeenCalledWith(
      'finding-1',
      'user-uuid-1',
      expect.objectContaining({ status: 'dismissed', dismissalReason: 'not_exploitable' })
    );
  });

  test('accepts each of the four dismissal reasons unchanged', async () => {
    for (const reason of ['not_exploitable', 'test_or_sample_code', 'wrong_rule_match', 'other']) {
      findingsDb.updateStatus.mockResolvedValueOnce({ ...MOCK_FINDING, status: 'dismissed' });
      const res = await request(createApp())
        .patch('/api/findings/finding-1/status')
        .set('Authorization', `Bearer ${authToken()}`)
        .send({ status: 'dismissed', dismissal_reason: reason });

      expect(res.status).toBe(200);
      expect(findingsDb.updateStatus).toHaveBeenLastCalledWith(
        'finding-1',
        'user-uuid-1',
        expect.objectContaining({ status: 'dismissed', dismissalReason: reason })
      );
    }
  });

  test('refuses a dismissal reason outside the enum', async () => {
    findingsDb.updateStatus.mockClear();
    const res = await request(createApp())
      .patch('/api/findings/finding-1/status')
      .set('Authorization', `Bearer ${authToken()}`)
      .send({ status: 'dismissed', dismissal_reason: 'because I said so' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid dismissal_reason');
    expect(findingsDb.updateStatus).not.toHaveBeenCalled();
  });

  test('records an omitted dismissal reason as other', async () => {
    findingsDb.updateStatus.mockResolvedValueOnce({ ...MOCK_FINDING, status: 'dismissed' });
    const res = await request(createApp())
      .patch('/api/findings/finding-1/status')
      .set('Authorization', `Bearer ${authToken()}`)
      .send({ status: 'dismissed' });

    expect(res.status).toBe(200);
    expect(findingsDb.updateStatus).toHaveBeenCalledWith(
      'finding-1',
      'user-uuid-1',
      expect.objectContaining({ status: 'dismissed', dismissalReason: 'other' })
    );
  });

  test('rejects invalid status', async () => {
    const app = createApp();
    const res = await request(app)
      .patch('/api/findings/finding-1/status')
      .set('Authorization', `Bearer ${authToken()}`)
      .send({ status: 'invalid-status' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Invalid status');
  });

  test('returns 404 if finding not found', async () => {
    findingsDb.updateStatus.mockResolvedValueOnce(null);

    const app = createApp();
    const res = await request(app)
      .patch('/api/findings/nonexistent/status')
      .set('Authorization', `Bearer ${authToken()}`)
      .send({ status: 'dismissed' });

    expect(res.status).toBe(404);
  });

  test('accepts all valid statuses', async () => {
    const app = createApp();
    for (const status of ['open', 'dismissed', 'accepted_risk', 'fixed']) {
      findingsDb.updateStatus.mockResolvedValueOnce({ ...MOCK_FINDING, status });
      const res = await request(app)
        .patch('/api/findings/finding-1/status')
        .set('Authorization', `Bearer ${authToken()}`)
        .send({ status });
      expect(res.status).toBe(200);
    }
  });
});

describe('GET /api/pull-requests/:pullRequestId/findings', () => {
  test('returns findings for a PR with the exact revision they describe', async () => {
    findingsDb.listByPullRequest.mockResolvedValueOnce([MOCK_FINDING]);
    findingsDb.getPullRequestForUser.mockResolvedValueOnce({
      id: 'pr-uuid-1', pr_number: 7, head_sha: 'a'.repeat(40), base_sha: 'b'.repeat(40),
    });

    const app = createApp();
    const res = await request(app)
      .get('/api/pull-requests/pr-uuid-1/findings')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(res.status).toBe(200);
    expect(res.body.findings).toHaveLength(1);
    expect(res.body.pull_request).toEqual({
      id: 'pr-uuid-1', number: 7, head_sha: 'a'.repeat(40), base_sha: 'b'.repeat(40),
    });
  });

  test('a pull request the actor cannot reach reports no revision rather than guessing one', async () => {
    findingsDb.listByPullRequest.mockResolvedValueOnce([]);
    findingsDb.getPullRequestForUser.mockResolvedValueOnce(null);

    const app = createApp();
    const res = await request(app)
      .get('/api/pull-requests/pr-uuid-1/findings')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(res.status).toBe(200);
    expect(res.body.pull_request).toBeNull();
  });

  test('preserves recommendation enrichment fields in PR findings list', async () => {
    findingsDb.listByPullRequest.mockResolvedValueOnce([ENRICHED_FINDING]);
    findingsDb.getPullRequestForUser.mockResolvedValueOnce(null);

    const app = createApp();
    const res = await request(app)
      .get('/api/pull-requests/pr-uuid-1/findings')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(res.status).toBe(200);
    expect(res.body.findings[0]).toMatchObject({
      exploit_scenario: ENRICHED_FINDING.exploit_scenario,
      remediation: ENRICHED_FINDING.remediation,
      remediation_patch: ENRICHED_FINDING.remediation_patch,
    });
  });

  test('passes status and confidence filters', async () => {
    findingsDb.listByPullRequest.mockResolvedValueOnce([]);

    const app = createApp();
    await request(app)
      .get('/api/pull-requests/pr-uuid-1/findings?status=all&min_confidence=0.8')
      .set('Authorization', `Bearer ${authToken()}`);

    expect(findingsDb.listByPullRequest).toHaveBeenCalledWith(
      'pr-uuid-1',
      'user-uuid-1',
      expect.objectContaining({ status: 'all', minConfidence: '0.8' })
    );
  });
});
