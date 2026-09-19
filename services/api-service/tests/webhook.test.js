const request = require('supertest');

jest.mock('../src/config/database', () => ({
  pool: {
    query: jest.fn(),
  },
  transaction: jest.fn(),
}));

jest.mock('../src/services/githubApp', () => ({
  verifyWebhookSignature: jest.fn(() => false),
}));
jest.mock('../src/services/prAnalysisOrchestrator', () => ({
  notifyAnalysisQueued: jest.fn(),
}));
jest.mock('../src/db/installations', () => ({
  upsertInstallation: jest.fn(),
}));

const { pool, transaction } = require('../src/config/database');
const { verifyWebhookSignature } = require('../src/services/githubApp');
const { notifyAnalysisQueued } = require('../src/services/prAnalysisOrchestrator');
const { createApp } = require('../src/app');

describe('webhook route', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('rejects invalid webhook signature', async () => {
    const app = createApp();

    const response = await request(app)
      .post('/webhooks/github')
      .set('x-github-event', 'pull_request')
      .set('x-github-delivery', 'delivery-1')
      .set('x-hub-signature-256', 'sha256=invalid')
      .send({ action: 'opened' });

    expect(response.status).toBe(401);
    expect(response.body.error).toBe('Invalid signature');
  });

  test('reclaims failed deliveries atomically rather than acknowledging them', async () => {
    verifyWebhookSignature.mockReturnValue(true);
    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ processing_status: 'failed' }] });
    const client = { query: jest.fn().mockResolvedValue({ rowCount: 1, rows: [{ delivery_id: 'retry' }] }) };
    transaction.mockImplementation(async (fn) => fn(client));
    const res = await request(createApp()).post('/webhooks/github')
      .set('x-github-event', 'ping').set('x-github-delivery', 'retry')
      .set('x-hub-signature-256', 'sha256=valid').send({});
    expect(res.body.deduplicated).not.toBe(true);
    expect(transaction).toHaveBeenCalled();
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('ON CONFLICT (delivery_id)'), expect.any(Array));
  });

  test('deduplicates only when the transactional claim returns no row', async () => {
    verifyWebhookSignature.mockReturnValue(true);
    const client = { query: jest.fn().mockResolvedValue({ rowCount: 0, rows: [] }) };
    transaction.mockImplementation(async (fn) => fn(client));
    const res = await request(createApp()).post('/webhooks/github')
      .set('x-github-event', 'ping').set('x-github-delivery', 'processed')
      .set('x-hub-signature-256', 'sha256=valid').send({});
    expect(res.body.deduplicated).toBe(true);
    expect(client.query).toHaveBeenCalledTimes(1);
    expect(notifyAnalysisQueued).not.toHaveBeenCalled();
  });

  test('returns retryable failure when the transaction fails', async () => {
    verifyWebhookSignature.mockReturnValue(true);
    transaction.mockRejectedValueOnce(new Error('database unavailable'));
    const res = await request(createApp()).post('/webhooks/github')
      .set('x-github-event', 'ping').set('x-github-delivery', 'failed')
      .set('x-hub-signature-256', 'sha256=valid').send({});
    expect(res.status).toBe(500);
    expect(notifyAnalysisQueued).not.toHaveBeenCalled();
  });

  test('does not queue analysis for an inactive repository', async () => {
    verifyWebhookSignature.mockReturnValue(true);

    pool.query
      .mockResolvedValueOnce({ rowCount: 0, rows: [] })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({});

    const client = {
      query: jest.fn()
        .mockResolvedValueOnce({ rowCount: 1, rows: [{ delivery_id: 'delivery-2' }] })
        .mockResolvedValueOnce({ rows: [{ id: 'repo-1' }] })
        .mockResolvedValueOnce({ rows: [{ id: 'repo-1', baseline_set: false, is_active: false }] })
        .mockResolvedValueOnce({ rows: [{ id: 'pr-1' }] })
        .mockResolvedValueOnce({ rowCount: 1 }),
    };
    transaction.mockImplementation(async (fn) => fn(client));

    const app = createApp();
    const response = await request(app)
      .post('/webhooks/github')
      .set('x-github-event', 'pull_request')
      .set('x-github-delivery', 'delivery-2')
      .set('x-hub-signature-256', 'sha256=valid')
      .send({
        action: 'opened',
        installation: { id: 42 },
        repository: {
          id: 999,
          name: 'service',
          full_name: 'acme/service',
          private: true,
          default_branch: 'main',
          language: 'JavaScript',
          html_url: 'https://github.com/acme/service',
          clone_url: 'https://github.com/acme/service.git',
        },
        pull_request: {
          id: 555,
          number: 12,
          title: 'Fix auth redirect',
          body: '',
          state: 'open',
          html_url: 'https://github.com/acme/service/pull/12',
          draft: false,
          head: { sha: 'abc123', ref: 'feature' },
          base: { sha: 'def456', ref: 'main' },
          user: { login: 'octocat' },
        },
      });

    expect(response.status).toBe(200);
    expect(response.body.analysis_queued).toBe(false);
    expect(client.query).not.toHaveBeenCalledWith(
      expect.stringContaining('INSERT INTO analysis_runs'),
      expect.anything()
    );
    expect(notifyAnalysisQueued).not.toHaveBeenCalled();
    expect(client.query).not.toHaveBeenCalledWith(expect.stringContaining('INSERT INTO repository_access'), expect.anything());
  });
});
