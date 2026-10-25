jest.mock('../src/config/database', () => ({
  pool: { query: jest.fn() },
  transaction: jest.fn(),
}));

const { pool } = require('../src/config/database');
const findings = require('../src/db/findings');

beforeEach(() => jest.clearAllMocks());

test('dismissMany applies every suppression with one update statement', async () => {
  pool.query.mockResolvedValue({ rows: [{ id: '00000000-0000-0000-0000-000000000001' }] });

  await findings.dismissMany([
    { id: '00000000-0000-0000-0000-000000000001', reason: 'false_positive' },
    { id: '00000000-0000-0000-0000-000000000002', reason: 'accepted_risk' },
  ]);

  expect(pool.query).toHaveBeenCalledTimes(1);
  expect(pool.query.mock.calls[0][0]).toContain('jsonb_to_recordset');
  expect(JSON.parse(pool.query.mock.calls[0][1][0])).toEqual([
    { id: '00000000-0000-0000-0000-000000000001', reason: 'false_positive' },
    { id: '00000000-0000-0000-0000-000000000002', reason: 'accepted_risk' },
  ]);
});

test('dismissMany does not query for an empty batch', async () => {
  await expect(findings.dismissMany([])).resolves.toEqual([]);
  expect(pool.query).not.toHaveBeenCalled();
});
