jest.mock('axios', () => jest.fn());
jest.mock('../services/githubAppAuth', () => ({ getInstallationToken: jest.fn(), getAppBotLogin: jest.fn() }));

const axios = require('axios');
const githubAppAuth = require('../services/githubAppAuth');
const { authorizeRemediationActor, OperationError } = require('../services/githubInternalOperations');

const head = 'a'.repeat(40);
const base = 'b'.repeat(40);

function payload(overrides = {}) {
  return {
    installation_id: 77,
    repository_full_name: 'owner/repo',
    actor_login: 'developer',
    pr_number: 4,
    head_sha: head,
    base_sha: base,
    manifest_digest: 'd'.repeat(64),
    action_id: 'authorize-000000001',
    idempotency_key: 'idempotency-key-0001',
    ...overrides,
  };
}

function respond(request, permission) {
  if (request.url.endsWith('/repos/owner/repo')) return { data: { full_name: 'owner/repo' } };
  if (request.url.includes('/installation/repositories')) return { data: { repositories: [{ full_name: 'owner/repo' }] } };
  if (request.url.includes('/collaborators/developer/permission')) return { data: { permission } };
  if (request.url.includes('/pulls/4')) return {
    data: {
      state: 'open', draft: false, merged: false,
      head: { sha: head, ref: 'feature-branch', repo: { full_name: 'owner/repo' } },
      base: { sha: base, ref: 'main', repo: { full_name: 'owner/repo' } },
    },
  };
  throw new Error(`Unexpected request ${request.method} ${request.url}`);
}

beforeEach(() => {
  jest.clearAllMocks();
  githubAppAuth.getInstallationToken.mockResolvedValue('installation-token');
});

test('authorize reports live write permission and current revisions', async () => {
  axios.mockImplementation(async request => respond(request, 'write'));
  const result = await authorizeRemediationActor(payload());
  expect(result).toMatchObject({
    state: 'authorized', installation_active: true, repository_granted: true, actor_write_permission: true,
    head_sha: head, base_sha: base, head_branch: 'feature-branch', base_branch: 'main',
  });
});

test('authorize denies an actor whose permission is only read', async () => {
  axios.mockImplementation(async request => respond(request, 'read'));
  await expect(authorizeRemediationActor(payload())).rejects.toMatchObject({ statusCode: 403 });
});

test('authorize denies a repository that is not granted to the installation', async () => {
  axios.mockImplementation(async request => {
    if (request.url.includes('/installation/repositories')) return { data: { repositories: [{ full_name: 'other/repo' }] } };
    return respond(request, 'write');
  });
  await expect(authorizeRemediationActor(payload())).rejects.toBeInstanceOf(OperationError);
});

test('authorize rejects a head that no longer matches the consented revision', async () => {
  axios.mockImplementation(async request => {
    if (request.url.includes('/pulls/4')) return {
      data: {
        state: 'open', draft: false, merged: false,
        head: { sha: 'c'.repeat(40), ref: 'feature-branch', repo: { full_name: 'owner/repo' } },
        base: { sha: base, ref: 'main', repo: { full_name: 'owner/repo' } },
      },
    };
    return respond(request, 'write');
  });
  await expect(authorizeRemediationActor(payload())).rejects.toMatchObject({ statusCode: 409 });
});
