const { isTransientRepairFailure } = require('../src/services/remediationWorkflow');

describe('transient repair failure classification', () => {
  test.each([
    ['Cloud Run abort while an instance starts', { response: { status: 429 } }],
    ['service unavailable', { response: { status: 503 } }],
    ['bad gateway', { response: { status: 502 } }],
    ['internal error', { response: { status: 500 } }],
    ['client timeout', { code: 'ECONNABORTED' }],
    ['connection refused', { code: 'ECONNREFUSED' }],
    ['connection reset', { code: 'ECONNRESET' }],
  ])('%s is retried', (_name, error) => {
    expect(isTransientRepairFailure(error)).toBe(true);
  });

  test.each([
    ['validation rejection', { response: { status: 422 }, code: 'ERR_BAD_REQUEST' }],
    ['forbidden', { response: { status: 403 } }],
    ['not found', { response: { status: 404 } }],
    ['conflict', { response: { status: 409 } }],
    ['unknown error without status', new Error('boom')],
  ])('%s is not retried', (_name, error) => {
    expect(isTransientRepairFailure(error)).toBe(false);
  });
});
