// An installation token is valid for an hour. Minting one per GitHub operation cost a
// signed JWT and an extra API call each time (about 45 for a run with 40 comments),
// and spends the App's rate limit on token requests. One token per installation is
// reused until five minutes before it expires.
jest.mock('axios', () => {
  const fn = jest.fn();
  fn.post = jest.fn();
  fn.get = jest.fn();
  fn.patch = jest.fn();
  return fn;
});

const crypto = require('crypto');
let axios;

const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PEM = privateKey.export({ type: 'pkcs1', format: 'pem' });

let auth;
let now;
let minted;

function tokenResponse(expiresInMs) {
  minted += 1;
  return { data: { token: `token-${minted}`, expires_at: new Date(now + expiresInMs).toISOString() } };
}

beforeEach(() => {
  jest.resetModules();
  axios = require('axios');
  process.env.GITHUB_APP_ID = '123';
  process.env.GITHUB_APP_PRIVATE_KEY = PEM;
  now = Date.parse('2026-10-24T12:00:00Z');
  jest.spyOn(Date, 'now').mockImplementation(() => now);
  minted = 0;
  axios.post.mockImplementation(async () => tokenResponse(60 * 60 * 1000));
  auth = require('../services/githubAppAuth');
});

afterEach(() => { jest.restoreAllMocks(); });

test('two operations in a row for one installation mint one token', async () => {
  expect(await auth.getInstallationToken(7)).toBe('token-1');
  expect(await auth.getInstallationToken(7)).toBe('token-1');
  expect(axios.post).toHaveBeenCalledTimes(1);
});

test('concurrent requests for one installation share one mint', async () => {
  const tokens = await Promise.all([auth.getInstallationToken(7), auth.getInstallationToken(7)]);
  expect(tokens).toEqual(['token-1', 'token-1']);
  expect(axios.post).toHaveBeenCalledTimes(1);
});

test('each installation has its own token', async () => {
  expect(await auth.getInstallationToken(7)).toBe('token-1');
  expect(await auth.getInstallationToken(8)).toBe('token-2');
  expect(axios.post).toHaveBeenCalledTimes(2);
});

test('a token is replaced five minutes before it expires, not after', async () => {
  expect(await auth.getInstallationToken(7)).toBe('token-1');
  now += 54 * 60 * 1000;
  expect(await auth.getInstallationToken(7)).toBe('token-1');
  now += 2 * 60 * 1000; // 4 minutes left
  expect(await auth.getInstallationToken(7)).toBe('token-2');
  expect(axios.post).toHaveBeenCalledTimes(2);
});

test('a failed mint is not cached', async () => {
  const error = new Error('denied');
  error.response = { status: 401, data: { message: 'Bad credentials' } };
  axios.post.mockRejectedValueOnce(error);
  await expect(auth.getInstallationToken(7)).rejects.toThrow(/401/);
  expect(await auth.getInstallationToken(7)).toBe('token-1');
});

test('two GitHub operations through the adapter mint one token', async () => {
  const operations = require('../services/githubInternalOperations');
  axios.mockImplementation(async () => ({ data: { size: 4, encoding: 'base64', content: Buffer.from('x=1\n').toString('base64') } }));
  const request = { repository_full_name: 'owner/repo', installation_id: 9, ref: 'head-a', paths: ['a.py'] };
  await operations.fetchFileContents(request);
  await operations.fetchFileContents(request);
  expect(axios).toHaveBeenCalledTimes(2);
  expect(axios.post).toHaveBeenCalledTimes(1);
});
