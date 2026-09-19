jest.mock('axios', () => ({ create: jest.fn() }));
jest.mock('../src/clients/grpcConnection', () => ({
  getIdentityToken: jest.fn(),
  normalizeAudience: jest.requireActual('../src/clients/grpcConnection').normalizeAudience,
}));

const axios = require('axios');
const { getIdentityToken } = require('../src/clients/grpcConnection');
const { RemediationServiceClient } = require('../src/services/remediationServiceClient');

let instance;

beforeEach(() => {
  jest.clearAllMocks();
  instance = { post: jest.fn(async () => ({ data: { state: 'queued' } })), get: jest.fn(async () => ({ data: { state: 'ready' } })) };
  axios.create.mockReturnValue(instance);
  process.env.REMEDIATION_SERVICE_URL = 'https://repair.example.run.app/';
  process.env.REMEDIATION_SERVICE_INTERNAL_SECRET = 'internal-secret';
  delete process.env.REMEDIATION_SERVICE_AUDIENCE;
});

afterEach(() => {
  delete process.env.REMEDIATION_SERVICE_URL;
  delete process.env.REMEDIATION_SERVICE_INTERNAL_SECRET;
  delete process.env.REMEDIATION_SERVICE_AUDIENCE;
});

test('without an audience the internal secret stays in both Authorization and x-internal-secret', async () => {
  const client = new RemediationServiceClient();
  const headers = axios.create.mock.calls[0][0].headers;
  expect(headers.Authorization).toBe('Bearer internal-secret');
  expect(headers['x-internal-secret']).toBe('internal-secret');

  await client.repair({ job_id: 'job-1' }, { traceparent: 'tp' });
  expect(getIdentityToken).not.toHaveBeenCalled();
  expect(instance.post).toHaveBeenCalledWith('/v1/repair-stages', { job_id: 'job-1' }, { headers: { traceparent: 'tp' } });
});

test('with an audience the identity token takes Authorization and the secret stays in x-internal-secret', async () => {
  process.env.REMEDIATION_SERVICE_AUDIENCE = 'https://repair.example.run.app/';
  getIdentityToken.mockResolvedValue('id-token');
  const client = new RemediationServiceClient();
  const headers = axios.create.mock.calls[0][0].headers;
  expect(headers.Authorization).toBeUndefined();
  expect(headers['x-internal-secret']).toBe('internal-secret');

  await client.repair({ job_id: 'job-2' }, { traceparent: 'tp' });
  // The audience is normalized: Cloud Run signs a token for the URL without a trailing slash.
  expect(getIdentityToken).toHaveBeenCalledWith('https://repair.example.run.app');
  expect(instance.post).toHaveBeenCalledWith(
    '/v1/repair-stages',
    { job_id: 'job-2' },
    { headers: { traceparent: 'tp', Authorization: 'Bearer id-token' } }
  );
});

test('the status read carries the same identity token header layout', async () => {
  process.env.REMEDIATION_SERVICE_AUDIENCE = 'https://repair.example.run.app';
  getIdentityToken.mockResolvedValue('id-token');
  await new RemediationServiceClient().getExecution('exec 1');
  expect(instance.get).toHaveBeenCalledWith('/v1/repair/exec%201', { headers: { Authorization: 'Bearer id-token' } });
});

test('a token failure is surfaced rather than falling back to an unauthenticated call', async () => {
  process.env.REMEDIATION_SERVICE_AUDIENCE = 'https://repair.example.run.app';
  getIdentityToken.mockRejectedValue(new Error('metadata unavailable'));
  await expect(new RemediationServiceClient().repair({ job_id: 'job-3' })).rejects.toThrow('metadata unavailable');
  expect(instance.post).not.toHaveBeenCalled();
});
