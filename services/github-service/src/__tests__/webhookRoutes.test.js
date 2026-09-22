jest.mock('axios');
jest.mock('pg', () => ({ Pool: jest.fn(() => ({ query: jest.fn() })) }));

const axios = require('axios');
const webhookRouter = require('../routes/webhooks');

function createRes() {
  return {
    statusCode: 200,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; },
  };
}

// Runs the route's stack the way Express does: each layer either answers or calls next.
async function dispatch(path, req) {
  const layer = webhookRouter.stack.find((entry) => entry.route && entry.route.path === path && entry.route.methods.post);
  const res = createRes();
  for (const { handle } of layer.route.stack) {
    let advanced = false;
    await handle(req, res, () => { advanced = true; });
    if (!advanced) break;
  }
  return res;
}

const body = { repository_full_name: 'owner/repo', webhook_id: 42, github_token: 'user-token' };

describe('POST /webhooks/unregister', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'internal-secret';
    axios.delete.mockResolvedValue({ status: 204 });
  });

  afterAll(() => {
    delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  });

  test('rejects a caller without the internal secret before touching GitHub', async () => {
    const res = await dispatch('/unregister', { headers: {}, body });
    expect(res.statusCode).toBe(401);
    expect(axios.delete).not.toHaveBeenCalled();
  });

  test('rejects a wrong internal secret', async () => {
    const res = await dispatch('/unregister', { headers: { 'x-internal-secret': 'guess' }, body });
    expect(res.statusCode).toBe(401);
    expect(axios.delete).not.toHaveBeenCalled();
  });

  test('fails closed when the secret is not configured', async () => {
    delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
    const res = await dispatch('/unregister', { headers: { 'x-internal-secret': '' }, body });
    expect(res.statusCode).toBe(500);
    expect(axios.delete).not.toHaveBeenCalled();
  });

  test('deletes the webhook for the control plane', async () => {
    const res = await dispatch('/unregister', { headers: { 'x-internal-secret': 'internal-secret' }, body });
    expect(res.statusCode).toBe(200);
    expect(res.body).toMatchObject({ success: true });
    expect(axios.delete).toHaveBeenCalledWith(
      'https://api.github.com/repos/owner/repo/hooks/42',
      expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer user-token' }) })
    );
  });

  test('still validates the body once authenticated', async () => {
    const res = await dispatch('/unregister', { headers: { 'x-internal-secret': 'internal-secret' }, body: { repository_full_name: 'owner/repo' } });
    expect(res.statusCode).toBe(400);
    expect(axios.delete).not.toHaveBeenCalled();
  });
});
