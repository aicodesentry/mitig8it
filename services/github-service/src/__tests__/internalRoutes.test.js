jest.mock('axios');
jest.mock('../services/githubAppAuth', () => ({
  getInstallationToken: jest.fn(),
}));

const axios = require('axios');
const githubAppAuth = require('../services/githubAppAuth');
const internalRouter = require('../routes/internal');

function findRouteHandler(path) {
  const layer = internalRouter.stack.find(
    (entry) => entry.route && entry.route.path === path && entry.route.methods.post
  );
  return layer.route.stack[layer.route.stack.length - 1].handle;
}

function createRes() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

describe('internal GitHub routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    githubAppAuth.getInstallationToken.mockResolvedValue('installation-token');
  });

  test('POST /github/files/content returns decoded file contents', async () => {
    const handler = findRouteHandler('/github/files/content');
    axios.mockResolvedValueOnce({
      data: 'const value = req.query.file;\nfs.readFile(value);\n',
    });

    const req = {
      body: {
        repository_full_name: 'owner/repo',
        installation_id: 12345,
        ref: 'abc123',
        paths: ['src/app.js'],
      },
    };
    const res = createRes();

    await handler(req, res);

    expect(res.statusCode).toBe(200);
    expect(res.body.files).toEqual([
      {
        path: 'src/app.js',
        content: 'const value = req.query.file;\nfs.readFile(value);\n',
      },
    ]);
    expect(githubAppAuth.getInstallationToken).toHaveBeenCalledWith(12345);
  });
});

describe('internal remediation routes', () => {
  const head = 'a'.repeat(40);
  const base = 'b'.repeat(40);
  const tree = 'c'.repeat(40);
  const digest = 'd'.repeat(64);

  function envelope(extra = {}) {
    return {
      installation_id: 41,
      repository_full_name: 'owner/repo',
      actor_login: 'developer',
      pr_number: 9,
      head_sha: head,
      base_sha: base,
      manifest_digest: digest,
      action_id: 'action-identity-0001',
      idempotency_key: 'idempotency-key-0001',
      ...extra,
    };
  }

  // Every remediation endpoint, with a body that passes payload validation so the
  // request reaches the authorization checks inside the operation.
  const remediationRequests = {
    '/github/remediation/prepare': envelope(),
    '/github/remediation/snapshot': envelope({ finding_paths: [] }),
    '/github/remediation/commit': envelope({
      branch: 'repair-branch',
      expected_head_oid: head,
      verified_tree_oid: tree,
      commit_message: 'Apply verified remediation',
      changes: [{ path: 'src/app.js', contents_base64: Buffer.from('const safe = true;\n').toString('base64') }],
    }),
    '/github/remediation/reconcile': envelope({ verified_tree_oid: tree }),
    '/github/remediation/merge': envelope({
      expected_head_sha: head,
      expected_base_sha: base,
      merge_method: 'squash',
      verification_check_name: 'Mitig8it Remediation Verification',
    }),
    '/github/remediation/check-run': envelope({
      external_id: 'verification-0001',
      conclusion: 'success',
      title: 'Remediation verified',
      summary: 'Independent verification succeeded.',
    }),
    '/github/remediation/comment': envelope({ external_id: 'report-0001', body: 'Applied 1 fix. Remaining open findings: 0.' }),
    '/github/remediation/cancel-merge': envelope({ pull_number: 9, expected_head_sha: head }),
    '/github/remediation/merge-eligibility': envelope({ pull_number: 9, expected_head_sha: head }),
    '/github/remediation/pull-head': envelope({ pull_number: 9 }),
  };

  const remediationPaths = Object.keys(remediationRequests);
  const configuredSecret = process.env.GITHUB_SERVICE_INTERNAL_SECRET;

  beforeEach(() => {
    jest.clearAllMocks();
    githubAppAuth.getInstallationToken.mockResolvedValue('installation-token');
  });

  afterAll(() => {
    if (configuredSecret === undefined) delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
    else process.env.GITHUB_SERVICE_INTERNAL_SECRET = configuredSecret;
  });

  function internalAuthMiddleware() {
    return internalRouter.stack.find((entry) => !entry.route).handle;
  }

  test('the ten remediation operations are each reachable over HTTP', () => {
    expect(remediationPaths).toHaveLength(10);
    for (const path of remediationPaths) {
      expect(typeof findRouteHandler(path)).toBe('function');
    }
  });

  test.each([
    ['a missing secret', undefined],
    ['an incorrect secret', 'wrong-internal-secret-value'],
  ])('the internal secret guard rejects %s', (_label, provided) => {
    process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'correct-internal-secret';
    const res = createRes();
    const next = jest.fn();
    internalAuthMiddleware()({ headers: provided ? { 'x-internal-secret': provided } : {} }, res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('the internal secret guard refuses to serve when no secret is configured', () => {
    delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
    const res = createRes();
    const next = jest.fn();
    internalAuthMiddleware()({ headers: { 'x-internal-secret': 'anything' } }, res, next);
    expect(res.statusCode).toBe(500);
    expect(next).not.toHaveBeenCalled();
  });

  test('the internal secret guard admits the configured secret', () => {
    process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'correct-internal-secret';
    const next = jest.fn();
    internalAuthMiddleware()({ headers: { 'x-internal-secret': 'correct-internal-secret' } }, createRes(), next);
    expect(next).toHaveBeenCalledTimes(1);
  });

  test.each(remediationPaths)('POST %s rejects an invalid consent envelope with 400', async (path) => {
    axios.mockImplementation(async () => {
      throw new Error('No GitHub call may be made for an invalid envelope');
    });
    const res = createRes();
    await findRouteHandler(path)({ body: {} }, res);
    expect(res.statusCode).toBe(400);
    expect(axios).not.toHaveBeenCalled();
  });

  test.each(remediationPaths)('POST %s maps a repository authorization failure to 403', async (path) => {
    process.env.GITHUB_APP_ID = '123';
    axios.mockImplementation(async (request) => {
      if (request.url.endsWith('/repos/owner/repo')) return { data: { full_name: 'owner/repo' } };
      if (request.url.includes('/installation/repositories')) return { data: { repositories: [] } };
      throw new Error(`Unexpected request ${request.url}`);
    });
    const res = createRes();
    await findRouteHandler(path)({ body: remediationRequests[path] }, res);
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toMatch(/not enabled for this installation/);
  });
});
