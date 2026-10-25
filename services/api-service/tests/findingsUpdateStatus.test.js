jest.mock('../src/config/database', () => ({ pool: { query: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/db/findingOutcomes', () => ({
  recordOutcome: jest.fn().mockResolvedValue('outcome-1'),
  identityOf: jest.requireActual('../src/db/findingOutcomes').identityOf,
  normalizeDismissalReason: jest.requireActual('../src/db/findingOutcomes').normalizeDismissalReason,
}));

const { transaction } = require('../src/config/database');
const findingOutcomes = require('../src/db/findingOutcomes');
const findings = require('../src/db/findings');

// A client that answers the access check with the joined repository and pull request
// fields, and the UPDATE with the bare findings row, exactly as Postgres would.
function client() {
  return {
    query: jest.fn(async (sql) => {
      if (sql.includes('FROM findings f') && sql.includes('repository_access')) {
        return {
          rowCount: 1,
          rows: [{
            id: 'finding-1', repository_id: 'repo-1', actor_login: 'octocat',
            repository_full_name: 'acme/api', pr_number: 42,
          }],
        };
      }
      if (sql.includes('UPDATE findings')) {
        return {
          rowCount: 1,
          rows: [{
            id: 'finding-1', repository_id: 'repo-1', pull_request_id: 'pr-1',
            pull_request_number: 42, status: 'dismissed', dismissal_reason: 'not_exploitable',
          }],
        };
      }
      return { rowCount: 1, rows: [] };
    }),
  };
}

beforeEach(() => {
  jest.clearAllMocks();
});

test('returns the same joined shape as getById, so the header keeps repository and PR', async () => {
  const c = client();
  transaction.mockImplementation((fn) => fn(c));

  const updated = await findings.updateStatus('finding-1', 'user-1', {
    status: 'dismissed', dismissalReason: 'not_exploitable',
  });

  expect(updated).toEqual(expect.objectContaining({
    id: 'finding-1',
    status: 'dismissed',
    dismissal_reason: 'not_exploitable',
    repository_full_name: 'acme/api',
    pr_number: 42,
  }));
  expect(findingOutcomes.recordOutcome).toHaveBeenCalledTimes(1);
});

test('returns null when the user has no access to the finding', async () => {
  const c = { query: jest.fn().mockResolvedValue({ rowCount: 0, rows: [] }) };
  transaction.mockImplementation((fn) => fn(c));

  expect(await findings.updateStatus('finding-1', 'user-2', { status: 'open' })).toBeNull();
  expect(c.query).toHaveBeenCalledTimes(1);
});
