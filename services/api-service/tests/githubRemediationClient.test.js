jest.mock('axios', () => ({ create: jest.fn() }));
jest.mock('../src/clients/grpcConnection', () => ({
  getIdentityToken: jest.fn(),
  normalizeAudience: jest.requireActual('../src/clients/grpcConnection').normalizeAudience,
}));

const axios = require('axios');
const { getIdentityToken } = require('../src/clients/grpcConnection');
const { GitHubRemediationClient } = require('../src/services/githubRemediationClient');

let instance;

beforeEach(() => {
  jest.clearAllMocks();
  instance = { post: jest.fn(async () => ({ data: { ok: true } })) };
  axios.create.mockReturnValue(instance);
  process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'internal-secret';
  delete process.env.GITHUB_SERVICE_AUDIENCE;
  delete process.env.GITHUB_GRPC_AUDIENCE;
  delete process.env.INTERNAL_SERVICE_TRANSPORT;
});

afterEach(() => {
  delete process.env.GITHUB_SERVICE_URL;
  delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  delete process.env.GITHUB_SERVICE_AUDIENCE;
  delete process.env.GITHUB_GRPC_AUDIENCE;
});

test('an https base URL sends a Cloud Run identity token and keeps the internal secret header', async () => {
  process.env.GITHUB_SERVICE_URL = 'https://github.example.run.app/';
  getIdentityToken.mockResolvedValue('id-token');
  const client = new GitHubRemediationClient();
  await client.snapshot({ pull_number: 1 });
  expect(axios.create.mock.calls[0][0].headers['x-internal-secret']).toBe('internal-secret');
  expect(getIdentityToken).toHaveBeenCalledWith('https://github.example.run.app');
  expect(instance.post).toHaveBeenCalledWith('/internal/github/remediation/snapshot', { pull_number: 1 }, { headers: { Authorization: 'Bearer id-token' } });
});

test('an explicit audience wins over the base URL', async () => {
  process.env.GITHUB_SERVICE_URL = 'https://github.example.run.app';
  process.env.GITHUB_GRPC_AUDIENCE = 'https://audience.example.run.app/';
  getIdentityToken.mockResolvedValue('id-token');
  await new GitHubRemediationClient().prepare({});
  expect(getIdentityToken).toHaveBeenCalledWith('https://audience.example.run.app');
});

test('a plain http base URL sends no identity token', async () => {
  process.env.GITHUB_SERVICE_URL = 'http://github:8081';
  await new GitHubRemediationClient().commit({});
  expect(getIdentityToken).not.toHaveBeenCalled();
  expect(instance.post).toHaveBeenCalledWith('/internal/github/remediation/commit', {}, { headers: {} });
});
