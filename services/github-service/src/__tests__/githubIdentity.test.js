// The identity seam exists so the publishing code can run as something other than the App.
// Its whole value depends on the App path being untouched, so that is what most of this file
// asserts: the default provider makes the same calls, against the same URLs, with the same
// predicates, as the code did before the seam existed.

jest.mock('axios', () => {
  const fn = jest.fn();
  fn.get = jest.fn();
  fn.post = jest.fn();
  fn.patch = jest.fn();
  return fn;
});
jest.mock('../services/githubAppAuth', () => ({
  getInstallationToken: jest.fn(),
  getAppBotLogin: jest.fn(),
}));

const githubAppAuth = require('../services/githubAppAuth');
const githubIdentity = require('../services/githubIdentity');

class OperationError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.statusCode = statusCode;
  }
}

const envelope = {
  owner: 'acme',
  repo: 'widgets',
  repository_full_name: 'acme/widgets',
  installation_id: '4242',
  actor_login: 'dana',
};

beforeEach(() => {
  jest.clearAllMocks();
  githubIdentity.resetProvider();
});

afterEach(() => {
  githubIdentity.resetProvider();
});

describe('the default provider is the GitHub App', () => {
  test('it is active without any configuration', () => {
    expect(githubIdentity.currentProvider().kind).toBe(githubIdentity.APP_PROVIDER_KIND);
    expect(githubIdentity.currentProvider()).toBe(githubIdentity.appProvider);
  });

  test('a token is an installation token for the installation named by the caller', async () => {
    githubAppAuth.getInstallationToken.mockResolvedValue('ghs_installation');
    await expect(githubIdentity.token('4242')).resolves.toBe('ghs_installation');
    expect(githubAppAuth.getInstallationToken).toHaveBeenCalledWith('4242');
  });

  test('the bot login is the app identity, not a guess', async () => {
    githubAppAuth.getAppBotLogin.mockResolvedValue('mitig8it[bot]');
    await expect(githubIdentity.botLogin()).resolves.toBe('mitig8it[bot]');
    expect(githubAppAuth.getAppBotLogin).toHaveBeenCalledTimes(1);
  });

  test('a check run is the app\'s own only when the app id created it', () => {
    process.env.GITHUB_APP_ID = '99';
    expect(githubIdentity.ownsCheckRun({ app: { id: 99 } })).toBe(true);
    expect(githubIdentity.ownsCheckRun({ app: { id: '99' } })).toBe(true);
    // Another app may post a check run with the same name; it is not ours to update.
    expect(githubIdentity.ownsCheckRun({ app: { id: 100 } })).toBe(false);
    expect(githubIdentity.ownsCheckRun({})).toBe(false);
    delete process.env.GITHUB_APP_ID;
  });

  test('repository access enumerates the installation repositories', async () => {
    const githubRequest = jest.fn()
      .mockResolvedValueOnce({ data: { full_name: 'acme/widgets' } })
      .mockResolvedValueOnce({ data: { repositories: [{ full_name: 'acme/widgets' }] } });

    await expect(githubIdentity.assertRepositoryAccess({
      envelope, token: 'ghs_x', githubRequest, OperationError,
    })).resolves.toBeUndefined();

    expect(githubRequest).toHaveBeenNthCalledWith(1, 'get', 'https://api.github.com/repos/acme/widgets', 'ghs_x');
    expect(githubRequest).toHaveBeenNthCalledWith(2, 'get',
      'https://api.github.com/installation/repositories?per_page=100&page=1', 'ghs_x');
  });

  test('a repository outside the installation is refused', async () => {
    const githubRequest = jest.fn()
      .mockResolvedValueOnce({ data: { full_name: 'acme/widgets' } })
      .mockResolvedValueOnce({ data: { repositories: [{ full_name: 'acme/other' }] } });

    await expect(githubIdentity.assertRepositoryAccess({
      envelope, token: 'ghs_x', githubRequest, OperationError,
    })).rejects.toThrow('Repository is not enabled for this installation');
  });

  test('a repository the token cannot name is refused before enumeration', async () => {
    const githubRequest = jest.fn().mockResolvedValueOnce({ data: { full_name: 'someone/else' } });

    await expect(githubIdentity.assertRepositoryAccess({
      envelope, token: 'ghs_x', githubRequest, OperationError,
    })).rejects.toThrow('Repository is not accessible through this installation');
    expect(githubRequest).toHaveBeenCalledTimes(1);
  });

  test('an unreadable installation repository list is a 502, not a pass', async () => {
    const githubRequest = jest.fn()
      .mockResolvedValueOnce({ data: { full_name: 'acme/widgets' } })
      .mockResolvedValueOnce({ data: { repositories: 'nope' } });

    await expect(githubIdentity.assertRepositoryAccess({
      envelope, token: 'ghs_x', githubRequest, OperationError,
    })).rejects.toThrow('Invalid installation repository response');
  });

  test('actor write permission is read from the collaborator permission endpoint', async () => {
    const githubRequest = jest.fn().mockResolvedValue({ data: { permission: 'write' } });
    await expect(githubIdentity.assertActorWritePermission({
      envelope, token: 'ghs_x', githubRequest, OperationError,
    })).resolves.toBeUndefined();
    expect(githubRequest).toHaveBeenCalledWith('get',
      'https://api.github.com/repos/acme/widgets/collaborators/dana/permission', 'ghs_x');
  });

  test('a read-only actor is refused', async () => {
    const githubRequest = jest.fn().mockResolvedValue({ data: { permission: 'read' } });
    await expect(githubIdentity.assertActorWritePermission({
      envelope, token: 'ghs_x', githubRequest, OperationError,
    })).rejects.toThrow('Actor does not currently have write permission for this repository');
  });

  test('an admin actor is accepted', async () => {
    const githubRequest = jest.fn().mockResolvedValue({ data: { permission: 'admin' } });
    await expect(githubIdentity.assertActorWritePermission({
      envelope, token: 'ghs_x', githubRequest, OperationError,
    })).resolves.toBeUndefined();
  });
});

describe('swapping the provider', () => {
  const tokenProvider = {
    kind: 'workflow_token',
    token: jest.fn(async () => 'gh_workflow'),
    botLogin: jest.fn(async () => 'github-actions[bot]'),
    ownsCheckRun: jest.fn(() => true),
    assertRepositoryAccess: jest.fn(async () => {}),
    assertActorWritePermission: jest.fn(async () => {}),
  };

  test('the swapped provider answers every call', async () => {
    githubIdentity.useProvider(tokenProvider);
    await expect(githubIdentity.token('ignored')).resolves.toBe('gh_workflow');
    await expect(githubIdentity.botLogin()).resolves.toBe('github-actions[bot]');
    expect(githubIdentity.ownsCheckRun({})).toBe(true);
    expect(githubAppAuth.getInstallationToken).not.toHaveBeenCalled();
    expect(githubAppAuth.getAppBotLogin).not.toHaveBeenCalled();
  });

  test('resetting restores the App without a process restart', async () => {
    githubIdentity.useProvider(tokenProvider);
    githubIdentity.resetProvider();
    githubAppAuth.getInstallationToken.mockResolvedValue('ghs_installation');
    await expect(githubIdentity.token('4242')).resolves.toBe('ghs_installation');
  });

  test('an incomplete provider is refused rather than half-installed', () => {
    expect(() => githubIdentity.useProvider({ token: async () => 'x' }))
      .toThrow('GitHub identity provider is missing botLogin()');
    expect(githubIdentity.currentProvider().kind).toBe(githubIdentity.APP_PROVIDER_KIND);
  });

  test('a missing provider is refused', () => {
    expect(() => githubIdentity.useProvider(null)).toThrow('a GitHub identity provider is required');
    expect(githubIdentity.currentProvider().kind).toBe(githubIdentity.APP_PROVIDER_KIND);
  });
});
