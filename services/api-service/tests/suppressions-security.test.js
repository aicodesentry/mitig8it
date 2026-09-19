const request = require('supertest');
const jwt = require('jsonwebtoken');
jest.mock('../src/config/database', () => ({ pool: { query: jest.fn() }, transaction: jest.fn() }));
const { pool } = require('../src/config/database');
const { createApp } = require('../src/app');

describe('suppression finding identity', () => {
  beforeEach(() => {
    jest.resetAllMocks();
    process.env.JWT_SECRET = 'test-secret';
  });
  test('cannot attach a finding from another repository by supplying a fingerprint', async () => {
    pool.query.mockResolvedValueOnce({ rowCount: 1, rows: [{ id: 'own-repo' }] })
      .mockResolvedValueOnce({ rowCount: 0, rows: [] });
    const res = await request(createApp()).post('/api/suppressions')
      .set('Authorization', `Bearer ${jwt.sign({ user_id: 'u' }, 'test-secret')}`)
      .send({ repository_id: 'own-repo', finding_id: 'private-finding', fingerprint: 'known-hash', reason: 'test' });
    expect(res.status).toBe(404);
    expect(pool.query).not.toHaveBeenCalledWith(expect.stringContaining('INSERT INTO suppressions'), expect.anything());
  });
  test('rejects a fingerprint that does not identify the supplied finding', async () => {
    pool.query.mockResolvedValueOnce({ rowCount: 1, rows: [{ id: 'own-repo' }] })
      .mockResolvedValueOnce({ rowCount: 1, rows: [{ fingerprint: 'actual' }] });
    const res = await request(createApp()).post('/api/suppressions')
      .set('Authorization', `Bearer ${jwt.sign({ user_id: 'u' }, 'test-secret')}`)
      .send({ repository_id: 'own-repo', finding_id: 'own-finding', fingerprint: 'other', reason: 'test' });
    expect(res.status).toBe(400);
    expect(pool.query).not.toHaveBeenCalledWith(expect.stringContaining('INSERT INTO suppressions'), expect.anything());
  });
});
